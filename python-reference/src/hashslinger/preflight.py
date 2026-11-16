"""Pre-run checks: encrypted volume for sensitive paths, access scope."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .config import Config


class PreflightError(Exception):
    pass


def _bitlocker_protected(path: Path) -> bool:
    drive = Path(path).resolve().drive.rstrip(":\\")
    if not drive:
        return False
    ps = (f"(Get-BitLockerVolume -MountPoint '{drive}:').ProtectionStatus -eq 'On'")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip().lower() == "true"


def check_output_allowed(cfg: Config, out_dir: Path) -> Path:
    """Output must sit under an allowed root so a request cannot redirect it anywhere."""
    out = Path(out_dir).resolve()
    roots = [Path(r).resolve() for r in (cfg.allowed_output_roots or [cfg.output_path])]
    if not any(out == r or r in out.parents for r in roots):
        raise PreflightError(f"output folder {out} is outside the allowed roots")
    return out


def run_preflight(cfg: Config, out_dir: Path) -> None:
    check_output_allowed(cfg, out_dir)
    if cfg.require_encrypted_volume:
        if not sys.platform.startswith("win"):
            raise PreflightError("require_encrypted_volume is set but BitLocker can only be "
                                 "verified on Windows")
        for label, p in (("hash store", cfg.hash_store_path), ("staging", cfg.staging_path),
                         ("output", out_dir)):
            if not _bitlocker_protected(Path(p)):
                raise PreflightError(f"{label} path {p} is not on a BitLocker-protected volume")
