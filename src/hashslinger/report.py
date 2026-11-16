"""CSV report: flagged accounts only, never hashes or plaintext."""
from __future__ import annotations

import csv
import os
import re
from pathlib import Path

from .analysis import Finding
from .wipe import HashVault

COLUMNS = ["Username", "OU / Distinguished Name", "Account Type", "Flag Reason", "Severity",
           "Scan Run ID / Date"]
_HEX32 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")


class ReportLeakError(Exception):
    pass


def parent_container(dn: str) -> str:
    """Strip the leading RDN so the column routes remediation to an OU."""
    head, sep, rest = dn.partition(",")
    return rest if sep and head.upper().startswith("CN=") else dn


def _safe(v: str) -> str:
    """Neutralize spreadsheet formula injection from AD-controlled strings."""
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def write_report(
    findings: list[Finding],
    run_id: str,
    out_dir: Path,
    vault: HashVault,
    account_hashes_hex: set[str] | None = None,
) -> Path:
    """Write report_<date>.csv atomically and verify it; returns the path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    date_part = run_id.rsplit("-", 1)[0]
    final = out_dir / f"report_{date_part}.csv"
    if final.exists():
        final = out_dir / f"report_{run_id}.csv"
    rows = [
        [_safe(f.account.sam), _safe(parent_container(f.account.dn)), f.account.acct_type,
         "; ".join(r for r, _ in f.reasons), f.severity, run_id]
        for f in findings
    ]
    banned = account_hashes_hex or set()
    for row in rows:
        for cell in row:
            for tok in _HEX32.findall(cell):
                if tok.upper() in banned:
                    raise ReportLeakError("a hash value would be written to the report")
    tmp = final.with_name(final.name + ".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        w.writerows(rows)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, final)
    with open(final, newline="", encoding="utf-8") as f:  # confirm written
        n = sum(1 for _ in csv.reader(f)) - 1
    if n != len(rows):
        raise RuntimeError("report verification failed: row count mismatch")
    return final


def purge_old_reports(out_dir: Path, retention_days: int | None) -> int:
    if not retention_days:
        return 0
    import time
    cutoff = time.time() - retention_days * 86400
    n = 0
    for p in Path(out_dir).glob("report_*.csv"):
        if p.stat().st_mtime < cutoff:
            from .wipe import secure_delete
            secure_delete(p)
            n += 1
    return n
