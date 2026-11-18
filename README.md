# Hashslinger

Internal AD credential exposure audit for authorized DCO engagements. It pulls NT hashes for
in-scope accounts, matches them against breached and weak-password hash lists, and writes a CSV
of accounts needing a forced reset. No plaintext passwords or hashes are written to the report.
Run only with documented, signed authorization for the target network.

## Safety guarantees (read-only AD, everything local)

- **The tool never changes Active Directory.** The scripts in `powershell\` only read AD: LDAP searches, directory
  replication reads (`Get-ADReplAccount`), and read-only `Get-AD*` / `Get-Acl` queries. Everything that changes AD is
  isolated in `extras\` (optional helpers a Domain Admin may run by hand, `-WhatIf` first) and `diagnostics\` (lab only). Setup never
  calls those. `Hashslinger.exe selftest` scans the shipped `powershell\` scripts and FAILS if it finds any AD-write
  command (New/Set/Add/Remove-AD*, Add-KdsRootKey, Set-Acl on AD:, ldifde, dsacls, ...) or any network command.
- **Who requested a scan.** The EDIPI and reason are typed by the requester, so they are self-asserted. The audit log
  also records the Windows account that actually created the request file (`request file created by:`), which the
  requester cannot choose. If the creator is a member of Administrators, Windows may show the Administrators group.
- **Everything stays on the machine.** Account hashes exist only in memory and the pipe from the engine, and are wiped
  after the run. Written to disk: the breach-hash store, staging lists, the audit log, status file, runtime config, and the
  CSV report (no hashes in it). Nothing is sent anywhere. The only network traffic is to the domain controller (LDAP and
  directory replication RPC). Setup may download the DSInternals module from the PowerShell Gallery unless you set
  `dsinternals_offline_path`.
- **gMSA not installed on this server:** if Finish reports `Test-ADServiceAccount` is False, run
  `Install-ADServiceAccount <gMSA name>` on the scan server yourself, elevated, then click Finish again. Setup does not
  run it, so that nothing in the tool is even arguably an AD write.

## DSInternals needs explicit -Properties (Schema NC)

Recent DSInternals versions (reported 6.3 and later) make a default `Get-ADReplAccount` also read the Schema partition
(for LAPS attributes), which fails with "Replication access was denied" for an account that, as designed, only has
replication rights on the domain root. The engine and the setup probe therefore pass explicit `-Properties` sets
(widest first, with fallbacks) that exclude LAPS, so domain-root-only rights are enough. The probe's output names the
DSInternals version and which property set worked. An upstream fix was proposed; not confirmed released.

## FIPS mode

Reading password hashes over AD replication needs MD5 and RC4 to decrypt the data. DSInternals therefore refuses to
run when .NET is FIPS-only ("Only FIPS certified cryptographic algorithms are enabled in .NET ... MD5"). Our own
code is unaffected (its MD4 is hand-written), but the DSInternals pull is blocked on a FIPS-enforced server. Setup,
permissions and scheduled tasks are all fine; the Finish live test reports it as `FIPS MODE`.
Check: `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy -Name Enabled` (1 = on).
Options (each needs your security / ISSO approval, none is applied by this tool):
1. A policy exception for the scan server only: "System cryptography: Use FIPS compliant algorithms" = Disabled.
2. Run the scan from a dedicated, approved host that is not FIPS-enforced.
3. A native engine whose `Hashslinger.exe.config` opts only that process out of .NET FIPS enforcement
   (`enforceFIPSPolicy`). Not built; unverified with DSInternals' replication code.

## Setup and administration (two separate tools)

**One folder, one settings file.** You choose where Hashslinger lives (drive and folder, with a folder picker); everything
is created inside it:

```
<your folder>\Hashslinger\
  app\        the program and scripts
  config\     hashslinger.json = the ONE settings file, pattern_rules.json
  data\       store\ (the merged hash store) and staging\ (wordlists: HIBP, rockyou, custom)
  reports\    the CSV from each scan
  logs\       audit log, setup logs, SETUP-SUMMARY.txt
  status\     live progress file
  requests\   analyst request drop box (only if you use an analyst group)
  app-backups\  last 3 copies of app\, taken automatically before an upgrade or reinstall
  extras\     (package folder only, NOT installed on the scan server) optional gMSA helper scripts for a Domain Admin
  Hashslinger-Admin.cmd, Hashslinger-Uninstall.cmd
  Hashslinger-Admin.cmd   opens the Admin tool
```

**1. Setup wizard** (`Setup-Hashslinger.cmd`, double-click, local administrator is enough): pick the install folder, the
domain controller, the service account name, and tick what to scan in a **nested tree that looks like AD** (search keeps the
parents visible; ticking an OU includes everything underneath). *Check readiness* tells you in plain language what would fail.
**You create the service account (gMSA) by hand first** (SOP section 4); the wizard does not create it and there is no
hand-off package. *Install* installs locally and then runs the **service account checks** (read-only AD checks that the
account exists, only this server may use it, it is not in a privileged group, it has the two replication rights on the
domain root, then folder permissions, scheduled tasks, and a live replication test AS the account). If a check fails, fix it
and click *Re-run service account checks*.

**2. Admin tool** (`<folder>\Hashslinger-Admin.cmd`): change **any** setting, with an explanation under each one:
where files live, the domain controller, mode, replication, account types, UAC flags, the nested scope tree, duplicate
checking, schedule (day, time, how often), retention, timeouts, service account, analyst group, EDIPIs, BitLocker
requirement. Also: add wordlists, merge them, start and watch scans, open the newest report, last-scan timings, readiness
re-check, and a **support bundle** (settings and logs only, no hashes) you can send for help. A backup of the settings is
kept on every save. Changes apply to the next scan.

**Hashslinger never creates or changes anything in Active Directory.** The gMSA is created by hand; the optional helper
scripts are in `extras\`. The full procedure is the **SOP**: `docs\Hashslinger-SOP.html` (opens in any browser; also reachable
from the Admin tool, *Run and logs*, *Open the SOP*).

**Upgrade / reinstall / uninstall:** see the SOP. Short version: run the new package's `Setup-Hashslinger.cmd` against the same folder
(settings and data are kept, the old `app\` is backed up); `Hashslinger-Uninstall.cmd` removes the scheduled tasks (files stay),
with switches `-RemoveData -RemoveReports -RemoveLogs -RemoveApp -RemoveAll -SecureWipe` to delete things.

**Results file:** column 1 is `sAMAccountName` (the engine falls back to a read-only LDAP lookup if DSInternals returns it
empty, and the report falls back to the CN, so it is never blank).

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
| Orchestration / logging | `cs/Runner.cs`, `cs/Audit.cs`, `cs/Wipe.cs`, `cs/Preflight.cs`, `powershell/Setup-Hashslinger.ps1` |

## Usage

```
Hashslinger.exe --config hashslinger.json merge     # merge staging/<HIBP|rockyou|custom>/* into the store
Hashslinger.exe --config hashslinger.json scan      # asks for an EDIPI and a reason / CTO number, then scans all configured OUs
Hashslinger.exe --config hashslinger.json scan --scheduled   # unattended (what the scheduled task runs): no prompt, logged as scheduled
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
scheduled tasks from `Setup-Hashslinger.cmd -Phase Finish`.

## Table files in `custom\` (hash column + password column)

Drop `.tsv` or `.csv` files (any size, any number) into `staging\custom\` (or `HIBP`, `rockyou`). Layout is detected from a
sample: tab, `:` or `,` separated, the hash in the first or the last column, an optional header row. Then the first rows are
TESTED: if NT(password) equals the hash column, the hash column is NT and is used as is. If not, the hash column is some other
algorithm and would never match AD, so the NT hash is computed from the password column and the hash column is ignored. The log
says which happened. **Passwords are never stored.** Only the 16-byte NT hash is kept (17 bytes per unique hash including the
source tag, roughly a third of the size of the TSV, sorted for fast lookup, duplicates across files collapse). All new files for
a folder are merged in ONE pass (one rewrite of the store however many files), parsed in parallel. Single-column files are
treated as NT hash lists; `.ntlm` files as `HASH` or `HASH:count`. Keep the originals somewhere protected or delete them; they
are plaintext password lists.

## Duplicate passwords

Off by default. Set `"check_duplicates": true` to flag accounts that share a password with another
account ("Duplicate password shared with another account", Medium). At millions of accounts a single
default password can add many rows, so enable it deliberately.

## Performance: measure first

- Every run records milliseconds per stage in the audit log (`timings_ms`) and an accounts/sec rate during the
  pull, so a real scan shows where the time goes.
- `Hashslinger.exe bench 5000000 100000000` times the C# side (ingest, sort + lookup, report) with synthetic
  data and no AD. It does NOT measure the AD pull, which is expected to dominate (PowerShell loop + DC).

## Small scopes use per-account replication automatically

Bulk replication pulls the whole domain and discards everything out of scope, so it costs the same for 2 accounts as for
all of them, and sends out-of-scope hashes to the scan server. The engine therefore counts the in-scope accounts first and,
at or below `per_account_threshold` (default 5000), replicates only those accounts, using `workers` (default 4) parallel DC connections. Larger scopes use the single bulk pull.

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

- Live replication; offline ntds.dit as `"mode": "offline"`. Scheduled scan weekly on Sunday at 02:00 (the setup wizard and Admin tool set daily, weekly or monthly, the day and time; on-demand scans are optional).
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
