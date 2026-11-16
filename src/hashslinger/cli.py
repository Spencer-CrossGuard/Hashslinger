from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config
from .runner import ScanRequestError, load_request, run_scan
from .store import HashStore, process_staging


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hashslinger")
    ap.add_argument("--config", required=True, type=Path)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="run the audit pipeline")
    sc.add_argument("--request", type=Path, help="GUI request file (OU + output folder)")
    sc.add_argument("--ou", help="a single configured OU (default: all configured)")
    sc.add_argument("--output-dir", type=Path)
    sc.add_argument("--trigger", default="scheduled")
    sub.add_parser("merge", help="merge staging sources into the master hash store")
    sub.add_parser("info", help="show hash store record count")
    args = ap.parse_args(argv)
    cfg = Config.load(args.config)

    if args.cmd == "merge":
        done = process_staging(cfg.hash_store_path, cfg.staging_path, print)
        print(f"merged {len(done)} source file(s)")
        return 0
    if args.cmd == "info":
        with HashStore(cfg.hash_store_path) as s:
            print(f"{s.count} records")
        return 0
    try:
        if args.request:
            ou, out, who = load_request(cfg, args.request)
            args.request.unlink(missing_ok=True)
            res = run_scan(cfg, [ou], out, "on-demand", who)
        else:
            res = run_scan(cfg, [args.ou] if args.ou else None, args.output_dir, args.trigger)
    except (ScanRequestError, RuntimeError) as e:
        print(f"scan failed: {e}", file=sys.stderr)
        return 2
    print(f"{res.run_id}: {res.accounts} accounts, {res.flagged} flagged -> {res.output}")
    return 0
