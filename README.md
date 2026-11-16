# Hashslinger

Internal AD credential exposure audit for authorized DCO engagements. It pulls NT hashes
for in-scope accounts, matches them against breached and weak-password hash lists, and writes a
CSV of accounts needing a forced reset. No plaintext passwords or hashes are written to the report.
Run only with documented, signed authorization for the target network.

## Layout

| Spec component | Where |
| --- | --- |
| Core engine | `powershell/Get-AccountHashes.ps1` (DSInternals), bridged by `src/hashslinger/engine.py` |
| Data layer | `src/hashslinger/store.py` (17-byte records: 16-byte NT hash + source bitmask, sorted, mmap binary search, optional 2-byte prefix index, atomic streaming merge) and `patterns.py` |
| Interface layer | `powershell/Start-HashslingerGui.ps1` |
| Output layer | `src/hashslinger/report.py`, `analysis.py` |
| Orchestration / logging | `runner.py`, `audit.py`, `wipe.py`, `preflight.py`, `powershell/Install-Hashslinger.ps1` |

## Usage

```
python -m hashslinger --config hashslinger.json merge     # merge staging/<HIBP|rockyou|custom>/* into the store
python -m hashslinger --config hashslinger.json scan      # all configured OUs
python -m hashslinger --config hashslinger.json scan --ou "OU=Finance,DC=contoso,DC=com"
python -m unittest discover -s tests                      # tests (stdlib only, no dependencies)
```

Updating lists: drop a file in `staging/HIBP/` (NTLM hex, `HASH:count` ok), `staging/rockyou/`
(plaintext), or `staging/custom/` (plaintext terms). The next run merges it (linear merge into the
sorted master, atomic swap). Files ending `.ntlm` are parsed as hex hashes in any folder.

## Deviations from the spec, and why

1. **Filtering before hashes leave the DC.** DRS replication cannot filter by OU or UAC server side.
   The engine first runs an LDAP query (SearchBase + bitwise UAC clauses), then replicates only the
   matching accounts by ObjectGuid. Offline `ntds.dit` mode can only filter after loading.
2. **On-demand scans.** Analysts lack replication rights, so the GUI only writes a validated request
   file and starts a scheduled task that runs as the GMSA. The task re-validates OU against config and
   output folder against `allowed_output_roots`.
3. **Encryption at rest** is enforced as a preflight check that the hash store, staging and output
   paths sit on BitLocker-protected volumes (`require_encrypted_volume`), not app-level crypto.
4. **Wiping is best effort.** Account hashes live in one zeroed buffer, temp files are overwritten then
   deleted, but Python strings and SSD/CoW filesystems can retain remnants. Volume encryption is the
   real control. The audit log records `wipe_confirmed`.

## Defaults I chose for the open questions (change freely)

- Live replication by default, offline ntds.dit as `mode: "offline"`.
- Cadence weekly (`Install-Hashslinger.ps1 -Cadence Monthly` for monthly); per-engagement via config.
- CSV lands in `output_path`; retention is `retention_days` (unset = keep forever).
- "Password-enabled" is interpreted as excluding `ACCOUNTDISABLE` plus the configurable smart-card
  flag. Both are in `uac.exclude_flags`/`require_flags`. Confirm this reading.
- Starter pattern rules are in `config/pattern_rules.json`; the analyst owns them.
- Multiple findings for one account are merged into one row (reasons joined with `; `, highest severity).

## Verification status

- Python layers: unit and end-to-end tests pass using a fake engine (`tests/fake_engine.py`).
- **PowerShell scripts are untested.** No Windows or AD host was available. Lab-test the engine,
  GUI and installer (`-WhatIf` first) before any client use. Parameter names for DSInternals
  (`Get-ADReplAccount -ObjectGuid`, `SupplementalCredentials.ClearText`) should be confirmed against the
  installed module version.
- Performance: pure-Python merge of a full HIBP NTLM release (~1B hashes) will be slow (hours). Lookup
  is fast (mmap + prefix index). If merge time matters, port `merge_source` to Go or Rust; the file
  format is language-neutral.
