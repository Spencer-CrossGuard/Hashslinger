"""Linear pipeline: merge staging, enumerate, match, report, wipe, audit."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import engine
from .analysis import Account, analyze
from .audit import AuditLog
from .config import Config
from .patterns import build_pattern_map
from .preflight import check_output_allowed, run_preflight
from .report import purge_old_reports, write_report
from .store import HashStore, process_staging
from .wipe import HashVault, secure_delete_dir


@dataclass
class RunResult:
    run_id: str
    status: str
    accounts: int
    flagged: int
    output: Path | None
    wipe_confirmed: bool


class ScanRequestError(Exception):
    pass


@dataclass
class ScanRequest:
    ou: str
    output_dir: Path
    edipi: str
    reason: str
    requested_by: str | None


def load_request(cfg: Config, path: Path) -> ScanRequest:
    """Validate an analyst request. Raises ScanRequestError (carrying raw fields) on any problem."""
    req = json.loads(Path(path).read_text(encoding="utf-8"))
    edipi = str(req.get("edipi", "")).strip()
    reason = str(req.get("reason", "")).strip()
    who = req.get("requested_by")

    def bad(msg: str) -> ScanRequestError:
        e = ScanRequestError(msg)
        e.meta = (edipi, reason, who)  # type: ignore[attr-defined]
        return e

    if not re.fullmatch(r"\d{10}", edipi):
        raise bad("EDIPI must be exactly 10 digits")
    if cfg.authorized_edipis and edipi not in cfg.authorized_edipis:
        raise bad("EDIPI is not authorized to request scans")
    if not (10 <= len(reason) <= 500):
        raise bad("a reason of 10 to 500 characters is required")
    ou = req.get("ou")
    if ou not in cfg.target_ous:
        raise bad("requested OU is not in the configured list")
    try:
        out = check_output_allowed(cfg, Path(req["output_dir"]))
    except Exception as e:
        raise bad(str(e))
    return ScanRequest(ou, out, edipi, reason, who)


def run_scan(
    cfg: Config,
    ous: list[str] | None = None,
    output_dir: Path | None = None,
    trigger: str = "scheduled",
    requested_by: str | None = None,
    edipi: str | None = None,
    reason: str | None = None,
    skip_preflight: bool = False,
) -> RunResult:
    ous = ous or list(cfg.target_ous)
    for ou in ous:
        if ou not in cfg.target_ous:
            raise ScanRequestError(f"OU not in configured list: {ou}")
    out_dir = Path(output_dir) if output_dir else cfg.output_path
    log = AuditLog(cfg.log_path)
    run_id = log.next_run_id()
    log.start(run_id, trigger, ous, requested_by, edipi, reason)

    vault = HashVault()
    hex_seen: set[str] = set()
    accounts: list[Account] = []
    out_path: Path | None = None
    status, error, flagged = "failed", None, 0
    try:
        if not skip_preflight:
            run_preflight(cfg, out_dir)
        process_staging(cfg.hash_store_path, cfg.staging_path)
        pattern_map = build_pattern_map(cfg.pattern_rules_path)
        for ou in ous:
            accounts.extend(engine.fetch_accounts(cfg, ou, vault, hex_seen))
        with HashStore(cfg.hash_store_path) as store:
            findings = analyze(accounts, vault, store, pattern_map)
        flagged = len(findings)
        out_path = write_report(findings, run_id, out_dir, vault, hex_seen)
        purge_old_reports(out_dir, cfg.retention_days)
        status = "success"
    except Exception as e:  # logged below; never swallow silently
        error = f"{type(e).__name__}: {e}"
    finally:
        wipe_ok = vault.wipe()
        hex_seen.clear()
        accounts_n = len(accounts)
        accounts.clear()
        tmp_ok = True
        for d in cfg.hash_store_path.parent.glob("merge-*"):  # leftover merge temp dirs
            tmp_ok &= secure_delete_dir(d)
        log.end(run_id, status, accounts_n, str(out_path) if out_path else None,
                wipe_ok and tmp_ok, error)
    if status != "success":
        raise RuntimeError(error)
    return RunResult(run_id, status, accounts_n, flagged, out_path, wipe_ok and tmp_ok)
