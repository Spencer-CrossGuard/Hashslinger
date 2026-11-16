# Hashslinger

Internal AD credential exposure audit for authorized DCO engagements. It pulls NT hashes for
in-scope accounts, matches them against breached and weak-password hash lists, and writes a CSV
of accounts needing a forced reset. No plaintext passwords or hashes are written to the report.
Run only with documented, signed authorization for the target network.

## Setup (one command, any location)

1. Drop the whole Hashslinger folder anywhere.
2. Double-click `Setup-Hashslinger.cmd`. First run creates `hashslinger.init.json` from
   `config/hashslinger.init.example.json` and opens it. Set the install root, **drives/paths** (store,
   staging, logs, output, status, requests can each be on a different drive), DC, OUs, gMSA/analyst
   group names, optional wordlist source files, and save.
3. Run it again. `-Phase Local` (default) does everything except AD changes: folders, install to
   `<root>\bin`, build the exe, DSInternals + AD tools, unblock, runtime config, then verifies (script
   syntax parse, exe selftest, AD-free smoke test, DC and OU reachability) and prints a PASS/WARN/FAIL board.
4. On the scan server, as a domain admin: `Setup-Hashslinger.cmd -Phase Domain -WhatIf`, review, then without
   `-WhatIf`. It creates the gMSA, grants minimum replication rights on the domain NC, applies least-privilege
   folder ACLs, registers the scheduled and on-demand tasks, and lets analysts start only the on-demand task.
   `-CreateKdsRootKey` is for labs only. `-Phase Check` changes nothing.

The setup log is `<root>\setup-<timestamp>.log` and `<root>\SETUP-SUMMARY.txt` lists every path and command.
Domain-phase steps are untested against a live domain; use `-WhatIf` first. If a scan request arrives while one
is running it is logged as rejected, so resubmit when the viewer shows the run finished.

## Build (no SDK, no install)

```
build.cmd            :: uses the csc.exe that ships with Windows (.NET Framework 4.x, C# 5)
Hashslinger.exe selftest
```

`selftest` needs no AD. It checks NT/MD4 vectors, store merge and lookup, patterns, the full
pipeline with a fake account source, audit logging, wipe, and request validation. **Verified: built with
`build.cmd` on the author's Windows PC, 38/38 checks pass.
`cs/Hashslinger.csproj` is an optional SDK-style build if you prefer one.

## Layout

| Spec component | Where |
| --- | --- |
| Core engine | `powershell/Get-AccountHashes.ps1` (DSInternals), bridged by `cs/Engine.cs` over a stdout pipe |
| Data layer | `cs/HashStore.cs` (mmap + binary search + 2-byte prefix index), `cs/StoreMerge.cs` (external sort, linear merge, atomic swap), `cs/Patterns.cs` |
| Interface layer | `powershell/Start-HashslingerGui.ps1` |
| Output layer | `cs/Report.cs`, `cs/Runner.cs` (analysis) |
| Orchestration / logging | `cs/Runner.cs`, `cs/Audit.cs`, `cs/Wipe.cs`, `cs/Preflight.cs`, `powershell/Setup-Hashslinger.ps1 -Phase Domain` |

## Usage

```
Hashslinger.exe --config hashslinger.json merge     # merge staging/<HIBP|rockyou|custom>/* into the store
Hashslinger.exe --config hashslinger.json scan      # all configured OUs, one replication pass
Hashslinger.exe --config hashslinger.json scan --ou "OU=Finance,DC=contoso,DC=com"
```

Updating lists: drop a file in `staging/HIBP/` (NTLM hex, `HASH:count` ok), `staging/rockyou/`
(plaintext), or `staging/custom/` (plaintext terms). The next run merges it (linear merge into the
sorted master, atomic swap). Files ending `.ntlm` are parsed as hex hashes in any folder.

## Progress

Every run writes `status\status.json` (stage, detail, accounts received, who started it, heartbeat every
~5s). `powershell\Show-HashslingerProgress.ps1` is a read-only live viewer for it, so progress does not
depend on who started the scan: anyone with read access to the status folder can open it at any time.
Only one scan runs at a time (a second start is refused and logged). `Start-HashslingerRun.ps1`
(or `Start-HashslingerRun.cmd`) is the one-window admin/dev launcher: setup, start, then the viewer.
It runs under the launching user and ends at logoff. Unattended or logoff-proof runs use the GMSA
scheduled tasks from `Setup-Hashslinger.ps1 -Phase Domain`.

## Duplicate passwords

Off by default. Set `"check_duplicates": true` to flag accounts that share a password with another
account ("Duplicate password shared with another account", Medium). At millions of accounts a single
default password can add many rows, so enable it deliberately.

## Scale (millions of accounts)

- **Bulk replication by default** (`"replication": "bulk"`). One `Get-ADReplAccount -All` stream,
  filtered against the LDAP-derived in-scope GUID set. Per-account replication does a separate call
  per account and would take days at millions. `"per-account"` stays available for small OUs.
  **Deviation:** in bulk mode out-of-scope hashes cross the wire to the scan host and are dropped
  immediately; they are never stored. Per-account mode never requests them.
- **Memory:** accounts live in compact arrays and UTF-8 pages, roughly 150-250 bytes per account
  plus 40 for sorting. 5M accounts is about 1-1.5 GB RAM. Size the scan host accordingly.
- **Lookups** run over hashes sorted ascending, so the mmap'd store is read forward, not randomly.
- **Engine output** is tab separated, not JSON, because PowerShell JSON serialization per account is
  too slow at this size. The PowerShell enumeration loop is the likely bottleneck; measure it first
  on your test environment.
- **Merge** of a full HIBP NTLM release (about 1B hashes): external sort in 16M-hash chunks plus a
  linear merge. Expect disk-bound, tens of minutes to hours depending on the volume. Needs free space
  of roughly 2x the store size during the swap.

## Deviations from the spec, and why

1. **Scope before replication** is LDAP-first (SearchBase + bitwise UAC clauses), then bulk or
   per-account replication as above. DRS cannot filter by OU/UAC server side. Offline `ntds.dit`
   mode filters after loading.
2. **On-demand scans.** Analysts lack replication rights, so the GUI writes a request file and starts
   a scheduled task that runs as the GMSA. Analysts must enter a 10-digit EDIPI and a reason (10-500
   chars). Both go into the request and the audit log (`start` entry; invalid or unauthorized requests
   are logged as `rejected`). Optional `authorized_edipis` allowlist in config. The request folder is a
   write-only drop box for analysts; only the GMSA can read the file, and it is deleted after being
   read. The task re-validates OU against config and output folder against `allowed_output_roots`.
   Requests queue one per task start.
3. **Encryption at rest** is an optional preflight check (`require_encrypted_volume`, default off)
   that the hash store, staging and output paths sit on BitLocker volumes.
4. **Wiping is best effort.** Hashes live in one zeroed buffer, temp files are overwritten then
   deleted, but the runtime and SSD/CoW filesystems can retain remnants. Volume encryption is the
   real control. The audit log records `wipe_confirmed`.

## Defaults I chose (change freely)

- Live replication; offline ntds.dit as `"mode": "offline"`. Weekly cadence (`-Cadence Monthly` in the installer).
- "Password-enabled" means smart-card-required is NOT set. Default `uac.exclude_flags` is
  `["SMARTCARD_REQUIRED"]`; disabled accounts are still audited.
- CSV lands in `output_path`; retention is `retention_days` (0 or unset = keep forever).
- Starter pattern rules are in `config/pattern_rules.json`; the analyst owns them.
- One CSV row per flagged account (reasons joined with `; `, highest severity).

## Verification status

- C#: compiled with csc.exe, `selftest` 38/38 PASS (core, store, pipeline with fake source, audit, wipe, requests).
- **PowerShell: not yet run.** Needs a lab run: engine, GUI, and installer (`-WhatIf` first). Confirm DSInternals
  names (`Get-ADReplAccount -All/-ObjectGuid`, `.Guid`, `SupplementalCredentials.ClearText`) against
  the installed module version.
