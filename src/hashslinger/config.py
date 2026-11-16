"""Runtime configuration. Everything the engine reads lives here, not in code."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

UAC_FLAGS = {
    "ACCOUNTDISABLE": 0x2,
    "PASSWD_NOTREQD": 0x20,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x80,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "SMARTCARD_REQUIRED": 0x40000,
}


class ConfigError(Exception):
    pass


def _flags(names: list) -> list[int]:
    out = []
    for n in names:
        if isinstance(n, int):
            out.append(n)
        elif n in UAC_FLAGS:
            out.append(UAC_FLAGS[n])
        else:
            raise ConfigError(f"unknown UAC flag {n!r}")
    return out


@dataclass
class Config:
    mode: str = "live"  # live (DRS replication) | offline (ntds.dit)
    target_server: str = ""
    target_ous: list[str] = field(default_factory=list)
    account_types: list[str] = field(default_factory=lambda: ["User", "Service"])
    uac_require: list[int] = field(default_factory=list)
    uac_exclude: list[int] = field(default_factory=lambda: [0x40000])  # smart-card-required accounts have no usable password
    hash_store_path: Path = Path("store/master.ntlm")
    staging_path: Path = Path("staging")
    log_path: Path = Path("logs/audit.jsonl")
    output_path: Path = Path("output")
    allowed_output_roots: list[Path] = field(default_factory=list)
    request_dir: Path = Path("requests")
    pattern_rules_path: Path = Path("config/pattern_rules.json")
    require_encrypted_volume: bool = False
    retention_days: int | None = None
    powershell_path: str = "powershell.exe"
    engine_script: Path = Path("powershell/Get-AccountHashes.ps1")
    engine_command: list[str] | None = None  # test hook: replaces the PowerShell call
    engine_timeout_seconds: int = 3600
    ntds_path: str = ""
    system_hive_path: str = ""
    authorized_edipis: list[str] = field(default_factory=list)  # empty = any valid EDIPI

    @classmethod
    def load(cls, path: Path) -> "Config":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        base = Path(path).resolve().parent
        uac = raw.get("uac", {})
        c = cls()
        c.mode = raw.get("mode", c.mode)
        c.target_server = raw.get("target_server", "")
        c.target_ous = list(raw.get("target_ous", []))
        c.account_types = list(raw.get("account_types", c.account_types))
        if "require_flags" in uac:
            c.uac_require = _flags(uac["require_flags"])
        if "exclude_flags" in uac:
            c.uac_exclude = _flags(uac["exclude_flags"])
        for key in ("hash_store_path", "staging_path", "log_path", "output_path",
                    "request_dir", "pattern_rules_path", "engine_script"):
            if key in raw:
                p = Path(raw[key])
                setattr(c, key, p if p.is_absolute() else base / p)
        c.allowed_output_roots = [Path(p) for p in raw.get("allowed_output_roots", [])]
        c.require_encrypted_volume = raw.get("require_encrypted_volume", False)
        c.authorized_edipis = [str(e) for e in raw.get("authorized_edipis", [])]
        c.retention_days = raw.get("retention_days")
        c.powershell_path = raw.get("powershell_path", c.powershell_path)
        c.engine_command = raw.get("engine_command")
        c.engine_timeout_seconds = raw.get("engine_timeout_seconds", c.engine_timeout_seconds)
        c.ntds_path = raw.get("ntds_path", "")
        c.system_hive_path = raw.get("system_hive_path", "")
        c.validate()
        return c

    def validate(self) -> None:
        if self.mode not in ("live", "offline"):
            raise ConfigError("mode must be 'live' or 'offline'")
        if not self.target_ous:
            raise ConfigError("target_ous must list at least one OU distinguished name")
        for t in self.account_types:
            if t not in ("User", "Service", "Computer"):
                raise ConfigError(f"bad account type {t!r}")
        if self.mode == "offline" and not (self.ntds_path and self.system_hive_path):
            raise ConfigError("offline mode needs ntds_path and system_hive_path")
