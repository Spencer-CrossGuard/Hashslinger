# Hashslinger

Internal AD credential exposure audit for authorized DCO engagements. It pulls NT hashes for
in-scope accounts, matches them against breached and weak-password hash lists, and writes a CSV
of accounts needing a forced reset. No plaintext passwords or hashes are written to the report.
Run only with documented, signed authorization for the target network.

## Safety guarantees (read-only AD, everything local)

- **The tool never changes Active Directory.** The scripts in `powershell\` only read AD: LDAP searches, directory
  replication reads (`Get-ADReplAccount`), and read-only `Get-AD*` / `Get-Acl` queries. Everything that changes AD is
  isolated in `ad-admin\` (a Domain Admin runs it by hand, `-WhatIf` first) and `diagnostics\` (lab only). Setup never
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

## Easy setup (recommended)

Two roles, and **Hashslinger never creates or changes anything in Active Directory**:

- **Server operator** (local administrator on the scan server, NOT a Domain Admin):
  1. Drop the Hashslinger folder on the scan server and double-click **Setup-Hashslinger.cmd**.
  2. Pick the domain controller, the data drive, and the OUs to scan (optionally password list files).
  3. Click **Install**. It installs locally and writes `<root>\AD-HANDOFF\` for the Domain Admin.
- **Domain Admin** (once, by hand): follow `README-FOR-DOMAIN-ADMIN.txt` in that folder: a KDS root key, a
  gMSA that only the scan server can use, and the two directory replication rights on the domain root.
  `New-HashslingerGmsa.ps1` (in the same folder, copied from `ad-admin\`) does it with a `-WhatIf` preview, or do it in ADUC/ADSI Edit.
- **Server operator again:** click **Finish**. It checks, read-only, that the AD pieces exist, then sets
  folder permissions and the scheduled tasks on the server. Then **Run first scan**.

**Existing gMSA:** if your Domain Admin already created the account, type its name in the wizard and tick
"Already created" (or set `security.gmsa_name` and `security.gmsa_precreated: true` in the init config). Setup
then skips the hand-off and runs the read-only checks and local finish straight away. It still verifies the
account exists, that this server may retrieve its password, and that it has the two replication rights.

The wizard and Finish step are untested (no Windows host available when written); report anything odd.
The sections below describe the advanced, scriptable path (`-Phase Check|Local|Handoff|Finish|All`).

## Setup (advanced, scriptable)

1. Drop the whole Hashslinger folder anywhere.
2. Double-click `Setup-Hashslinger.cmd`. First run creates `hashslinger.init.json` from
   `config/hashslinger.init.example.json` and opens it. Set the install root, **drives/paths** (store,
   staging, logs, output, status, requests can each be on a different drive), DC, OUs, gMSA/analyst
   group names, optional wordlist source files, and save.
3. Run it again. `-Phase Local` (default) does everything except AD changes: folders, install to
   `<root>\bin`, build the exe, DSInternals + AD tools, unblock, runtime config, then verifies (script
   syntax parse, exe selftest, AD-free smoke test, DC and OU reachability) and prints a PASS/WARN/FAIL board.
4. `-Phase Handoff` writes `<root>\AD-HANDOFF\` (a plain-language request plus the `ad-admin` scripts) for a
   Domain Admin, who does the AD part by hand. Setup itself never creates or edits anything in AD.
5. After the Domain Admin is done, `-Phase Finish` (on the scan server, local admin is enough): read-only
   checks that the gMSA and its two replication rights exist, installs the gMSA locally, applies least-privilege
   folder ACLs, and registers the scheduled and on-demand tasks. `-Phase Check` changes nothing.

The setup log is `<root>\setup-<timestamp>.log` and `<root>\SETUP-SUMMARY.txt` lists every path and command.
Handoff/Finish steps are untested against a live domain. If a scan request arrives while one is running it is
logged as rejected, so resubmit when the viewer shows the run finished.

**Replication rights only (for the Domain Admin):** `ad-admin\Grant-HashslingerReplicationRights.ps1 -GmsaName <name>` grants just the two
rights on the domain root to an existing gMSA (idempotent, `-WhatIf` previews, verifies afterwards).

**gMSA script (for the Domain Admin only):** `ad-admin\New-HashslingerGmsa.ps1` creates the gMSA
(`-RunServer <scan server>` is required, `-WhatIf` previews, optional `-GrantReplicationRights`). Setup never
runs it. Untested against a live domain.

**Access model:** with `security.analyst_group` empty (the example default), only the gMSA, the local
Administrators group on the scan server, and SYSTEM can read or write any Hashslinger folder or start the
tasks. Set a group only if you want analysts to use the request GUI (it grants them: start the on-demand task,
create-only requests, read output/status/config, modify staging). No group is ever given replication rights
or access to the hash store or audit log.

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
scheduled tasks from `Setup-Hashslinger.cmd -Phase Finish`.

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
at or below `per_account_threshold` (default 5000), replicates only those accounts. Larger scopes use the single bulk pull.

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
