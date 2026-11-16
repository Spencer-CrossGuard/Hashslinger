"""Bridge to the PowerShell engine. Hashes travel over the stdout pipe only.

The engine emits one JSON object per line:
  {"sam","dn","type","nt"(hex|null),"lm"(bool),"reversible"(bool)}
They are loaded straight into the zeroable HashVault; nothing touches disk.
"""
from __future__ import annotations

import json
import subprocess
import threading
from typing import Iterator

from .analysis import Account
from .config import Config
from .wipe import HashVault


class EngineError(Exception):
    pass


def build_command(cfg: Config, ou: str) -> list[str]:
    if cfg.engine_command:
        return [a.replace("{ou}", ou) for a in cfg.engine_command]
    cmd = [cfg.powershell_path, "-NoProfile", "-NonInteractive", "-File", str(cfg.engine_script),
           "-Mode", cfg.mode, "-SearchBase", ou,
           "-AccountTypes", ",".join(cfg.account_types)]
    if cfg.uac_exclude:
        cmd += ["-ExcludeUacFlags", ",".join(str(f) for f in cfg.uac_exclude)]
    if cfg.uac_require:
        cmd += ["-RequireUacFlags", ",".join(str(f) for f in cfg.uac_require)]
    if cfg.mode == "live":
        cmd += ["-Server", cfg.target_server]
    else:
        cmd += ["-NtdsPath", cfg.ntds_path, "-SystemHivePath", cfg.system_hive_path]
    return cmd


def fetch_accounts(cfg: Config, ou: str, vault: HashVault, hex_seen: set[str]) -> Iterator[Account]:
    """Stream accounts for one OU. hex_seen collects hash hex for the report leak guard."""
    proc = subprocess.Popen(build_command(cfg, ou), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8")
    err: list[str] = []
    t = threading.Thread(target=lambda: err.append(proc.stderr.read()), daemon=True)
    t.start()
    timer = threading.Timer(cfg.engine_timeout_seconds, proc.kill)
    timer.start()
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except ValueError as e:
                raise EngineError("engine produced non-JSON output") from e
            nt = o.get("nt")
            off = None
            if nt:
                off = vault.add(bytes.fromhex(nt))
                hex_seen.add(nt.upper())
            yield Account(o["sam"], o["dn"], o.get("type", "User"), off,
                          bool(o.get("lm")), bool(o.get("reversible")))
        rc = proc.wait()
        t.join(timeout=5)
        if rc != 0:
            raise EngineError(f"engine exited {rc}: {(err[0] if err else '').strip()[:500]}")
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        t.join(timeout=5)
        proc.stderr.close()
