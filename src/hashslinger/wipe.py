"""Best-effort secure wiping of in-memory hash data and temp files.

Caveat: overwriting files is best effort on SSDs / journaling or copy-on-write
filesystems. Volume encryption (BitLocker) is the real control; wiping reduces
the window and the exposure of the plaintext-equivalent data.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path


class HashVault:
    """Holds account NT hashes in one zeroable buffer (bytes objects cannot be zeroed)."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._wiped = False

    def add(self, h: bytes) -> int:
        if self._wiped:
            raise RuntimeError("vault already wiped")
        if len(h) != 16:
            raise ValueError("NT hash must be 16 bytes")
        off = len(self._buf)
        self._buf += h
        return off

    def get(self, off: int) -> bytes:
        return bytes(self._buf[off : off + 16])

    def wipe(self) -> bool:
        n = len(self._buf)
        for i in range(n):
            self._buf[i] = 0
        confirmed = not any(self._buf)
        self._buf = bytearray()
        self._wiped = True
        return confirmed


def secure_delete(path: Path) -> bool:
    """Overwrite (zeros then random) and unlink. Returns True when the file is gone."""
    path = Path(path)
    try:
        if path.exists():
            size = path.stat().st_size
            with open(path, "r+b", buffering=0) as f:
                for fill in (b"\x00", None):
                    f.seek(0)
                    left = size
                    while left > 0:
                        n = min(left, 1 << 20)
                        f.write(fill * n if fill else secrets.token_bytes(n))
                        left -= n
                    f.flush()
                    os.fsync(f.fileno())
            path.unlink()
    except FileNotFoundError:
        pass
    return not path.exists()


def secure_delete_dir(path: Path) -> bool:
    """Securely delete every file under path, then the directory itself."""
    path = Path(path)
    ok = True
    if not path.exists():
        return True
    for p in sorted(path.rglob("*"), key=lambda q: len(q.parts), reverse=True):
        if p.is_file() or p.is_symlink():
            ok &= secure_delete(p)
        elif p.is_dir():
            try:
                p.rmdir()
            except OSError:
                ok = False
    try:
        path.rmdir()
    except OSError:
        ok = False
    return ok and not path.exists()
