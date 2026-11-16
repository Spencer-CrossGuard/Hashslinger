"""Linear pipeline: merge staging, enumerate, match, report, wipe, audit."""
from __future__ import annotations

import json
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


def load_request(cfg: Config, path: Path) -> tuple[str, Path, str | None]:
    """Validate an analyst request (from the GUI). Only config-listed OUs are accepted."""
    req = json.loads(Path(path).read_text(encoding="utf-8"))
    ou = req.get("ou")
    if ou not in cfg.target_ous:
        raise ScanRequestError("requested OU is not in the configured list")
    out = check_output_allowed(cfg, Path(req["output_dir"]))
    return ou, out, req.get("requested_by")


def run_scan(
    cfg: Config,
    ous: list[str] | None = None,
    output_dir: Path | None = None,
    trigger: str = "scheduled",
    requested_by: str | None = None,
    skip_preflight: bool = False,
) -> RunResult:
    ous = ous or list(cfg.target_ous)
    for ou in ous:
        if ou not in cfg.target_ous:
            raise ScanRequestError(f"OU not in configured list: {ou}")
    out_dir = Path(output_dir) if output_dir else cfg.output_path
    log = AuditLog(cfg.log_path)
    run_id = log.next_run_id()
    log.start(run_id, trigger, ous, requested_by)

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
