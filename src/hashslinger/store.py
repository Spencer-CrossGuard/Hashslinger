"""Unified, sorted, fixed-width NTLM hash store with atomic streaming merge.

Record layout (17 bytes): 16-byte raw NT hash + 1-byte source bitmask.
The file is sorted ascending by hash, so lookups are binary searches over an
mmap and a new source is merged in one linear pass (never re-sorting the master).
"""
from __future__ import annotations

import heapq
import json
import mmap
import os
import tempfile
from array import array
from itertools import groupby
from operator import itemgetter
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .ntlm import nt_hash
from .wipe import secure_delete_dir

HASH_LEN = 16
RECORD = 17
SOURCE_BITS = {"HIBP": 1, "rockyou": 2, "custom": 4}
BIT_TO_SOURCE = {v: k for k, v in SOURCE_BITS.items()}
# Default parse format per source tag: hex NTLM lines vs plaintext candidates.
DEFAULT_FORMAT = {"HIBP": "ntlm", "rockyou": "plaintext", "custom": "plaintext"}


class StoreError(Exception):
    pass


def sources_from_mask(mask: int) -> list[str]:
    return [name for bit, name in BIT_TO_SOURCE.items() if mask & bit]


class HashStore:
    """Read-only, mmap-backed lookup over the master file."""

    def __init__(self, path: Path, build_index: bool | None = None) -> None:
        self.path = Path(path)
        size = self.path.stat().st_size
        if size % RECORD:
            raise StoreError(f"{path}: size {size} is not a multiple of {RECORD}")
        self.count = size // RECORD
        self._f = open(self.path, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ) if size else None
        self._prefix: array | None = None
        if build_index is None:
            build_index = self.count > 1_000_000
        if build_index and self._mm is not None:
            self._build_prefix_index()

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        self._f.close()

    def __enter__(self) -> "HashStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _lower_bound(self, key: bytes, lo: int, hi: int) -> int:
        mm = self._mm
        while lo < hi:
            mid = (lo + hi) // 2
            o = mid * RECORD
            if mm[o : o + HASH_LEN] < key:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _build_prefix_index(self) -> None:
        """Offset table per 2-byte prefix, so lookups start inside a tiny range."""
        tbl = array("Q", [0]) * 65537
        lo = 0
        for p in range(65536):
            lo = self._lower_bound(p.to_bytes(2, "big") + b"\x00" * 14, lo, self.count)
            tbl[p] = lo
        tbl[65536] = self.count
        self._prefix = tbl

    def lookup(self, h: bytes) -> int:
        """Return the source bitmask for a 16-byte hash, 0 when absent."""
        if self._mm is None:
            return 0
        if self._prefix is not None:
            p = (h[0] << 8) | h[1]
            lo, hi = self._prefix[p], self._prefix[p + 1]
        else:
            lo, hi = 0, self.count
        i = self._lower_bound(h, lo, hi)
        if i < self.count:
            o = i * RECORD
            if self._mm[o : o + HASH_LEN] == h:
                return self._mm[o + HASH_LEN]
        return 0


# ---------------------------------------------------------------- source parsing

def iter_source_hashes(path: Path, fmt: str) -> Iterator[bytes]:
    """Yield raw 16-byte hashes from a source file.

    fmt 'ntlm': lines of 32 hex chars, optionally 'HASH:count' (HIBP release).
    fmt 'plaintext': one candidate password per line, hashed here.
    """
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            if fmt == "ntlm":
                tok = line.split(b":", 1)[0].strip()
                if len(tok) != 32:
                    continue
                try:
                    yield bytes.fromhex(tok.decode("ascii"))
                except ValueError:
                    continue
            elif fmt == "plaintext":
                yield nt_hash(line.decode("utf-8", errors="replace"))
            else:
                raise StoreError(f"unknown source format {fmt!r}")


def _sorted_unique(hashes: Iterable[bytes], work_dir: Path, chunk: int) -> Iterator[bytes]:
    """External sort + dedupe: sorted spill runs merged lazily."""
    runs: list[Path] = []
    buf: list[bytes] = []

    def spill() -> None:
        buf.sort()
        p = work_dir / f"run{len(runs):05d}.bin"
        with open(p, "wb") as out:
            prev = None
            for h in buf:
                if h != prev:
                    out.write(h)
                    prev = h
        runs.append(p)
        buf.clear()

    for h in hashes:
        buf.append(h)
        if len(buf) >= chunk:
            spill()

    def read_run(p: Path) -> Iterator[bytes]:
        with open(p, "rb", buffering=1 << 20) as f:
            while True:
                b = f.read(HASH_LEN * 65536)
                if not b:
                    return
                for i in range(0, len(b), HASH_LEN):
                    yield b[i : i + HASH_LEN]

    if not runs:
        buf.sort()
        prev = None
        for h in buf:
            if h != prev:
                yield h
                prev = h
        return
    if buf:
        spill()
    prev = None
    for h in heapq.merge(*(read_run(p) for p in runs)):
        if h != prev:
            yield h
            prev = h


def _iter_master(path: Path) -> Iterator[tuple[bytes, int]]:
    if not path.exists():
        return
    with open(path, "rb", buffering=1 << 20) as f:
        while True:
            b = f.read(RECORD * 65536)
            if not b:
                return
            if len(b) % RECORD:
                raise StoreError("truncated master file")
            for i in range(0, len(b), RECORD):
                yield b[i : i + HASH_LEN], b[i + HASH_LEN]


def merge_source(
    master: Path,
    source: Path,
    tag: str,
    fmt: str | None = None,
    chunk: int = 2_000_000,
) -> int:
    """Merge one source file into the master; returns the new record count.

    The new source is sorted externally, then streamed together with the existing
    sorted master in a single pass. The result is written beside the master,
    fsynced, and swapped in with os.replace so a scan never sees a partial file.
    """
    if tag not in SOURCE_BITS:
        raise StoreError(f"unknown source tag {tag!r}")
    bit = SOURCE_BITS[tag]
    fmt = fmt or DEFAULT_FORMAT[tag]
    master = Path(master)
    master.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="merge-", dir=master.parent))
    tmp_out = master.with_name(master.name + ".new")
    count = 0
    try:
        new_stream = ((h, bit) for h in _sorted_unique(iter_source_hashes(Path(source), fmt), work, chunk))
        merged = heapq.merge(_iter_master(master), new_stream, key=itemgetter(0))
        with open(tmp_out, "wb", buffering=1 << 20) as out:
            for h, grp in groupby(merged, key=itemgetter(0)):
                mask = 0
                for _, m in grp:
                    mask |= m
                out.write(h + bytes((mask,)))
                count += 1
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_out, master)
    finally:
        secure_delete_dir(work)
        if tmp_out.exists():
            tmp_out.unlink()
    return count


# ---------------------------------------------------------------- staging pipeline

def _manifest_path(master: Path) -> Path:
    return master.with_name(master.name + ".manifest.json")


def _load_manifest(master: Path) -> dict:
    p = _manifest_path(master)
    return json.loads(p.read_text()) if p.exists() else {}


def _fingerprint(p: Path) -> str:
    st = p.stat()
    return f"{st.st_size}:{int(st.st_mtime)}"


def process_staging(
    master: Path,
    staging: Path,
    log: Callable[[str], None] = lambda m: None,
) -> list[str]:
    """Merge any new or changed files under staging/<TAG>/ into the master.

    Layout: staging/HIBP/*, staging/rockyou/*, staging/custom/*.
    A '.ntlm' extension forces hex-hash parsing; anything else uses the tag default.
    Merges are idempotent (masks are OR-ed), and a manifest skips unchanged files,
    so a custom term list edited between runs takes effect on the next run.
    """
    master, staging = Path(master), Path(staging)
    manifest = _load_manifest(master)
    merged: list[str] = []
    for tag in SOURCE_BITS:
        d = staging / tag
        if not d.is_dir():
            continue
        for f in sorted(p for p in d.iterdir() if p.is_file()):
            key = f"{tag}/{f.name}"
            fp = _fingerprint(f)
            if manifest.get(key) == fp:
                continue
            fmt = "ntlm" if f.suffix.lower() == ".ntlm" else DEFAULT_FORMAT[tag]
            log(f"merging {key} ({fmt})")
            merge_source(master, f, tag, fmt)
            manifest[key] = fp
            _manifest_path(master).write_text(json.dumps(manifest, indent=2))
            merged.append(key)
    return merged
