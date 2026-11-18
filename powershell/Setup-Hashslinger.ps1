<#
.SYNOPSIS
  Setup engine, driven by the ONE settings file <root>\config\hashslinger.json (written by the Setup wizard,
  edited later in the Admin tool). Works from wherever the Hashslinger folder is dropped.
.DESCRIPTION
  THIS SCRIPT NEVER CREATES OR CHANGES ANYTHING IN ACTIVE DIRECTORY. It runs fine as a local administrator
  on the scan server (no Domain Admin needed).
    Phase Check    preflight only, no changes
    Phase Local    folders under <root> (app, config, data, reports, logs, status, requests, extras), install to
                   <root>\app, build the exe if missing, DSInternals + AD tools, unblock files, verify
                   (PowerShell syntax parse, exe selftest, AD-free smoke test, DC/OU reachability)
    Phase Finish   READ-ONLY checks of the service account you created by hand (exists, only this server may use it,
                   not in a privileged group, has the two replication rights on the domain root), then local-only
                   steps: folder permissions, scheduled tasks, and a live replication test AS the service account.
    Phase All      Local then Finish
  AD SAFETY: the scripts in powershell\ only READ AD. Anything that changes AD lives in extras\ (optional
  helpers for a Domain Admin to run by hand) and diagnostics\ (lab only). 'Hashslinger.exe selftest' re-verifies this on your machine.
.NOTES
  Finish-phase steps are UNTESTED against a live domain.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Alias('InitConfig')][string]$Config,
  [ValidateSet('Check', 'Local', 'Finish', 'All')][string]$Phase = 'Local'
)
$ErrorActionPreference = 'Stop'
$srcRoot = Split-Path -Parent $PSScriptRoot      # the dropped folder (repo root)

# ---------------------------------------------------------------- self-elevate
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  $argList = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
  foreach ($k in $PSBoundParameters.Keys) {
    $v = $PSBoundParameters[$k]
    if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $argList += "-$k" } }
    else { $argList += "-$k"; $argList += "`"$v`"" }
  }
  Write-Host 'Not elevated. Relaunching as administrator...'
  Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
  exit
}

# NOTE: PowerShell variables are case-insensitive. The paths table is $Dir, never $P/$p.
# ---------------------------------------------------------------- results board
$script:results = New-Object System.Collections.ArrayList
function Result([string]$name, [string]$status, [string]$detail = '') {
  [void]$script:results.Add([pscustomobject]@{ Check = $name; Status = $status; Detail = $detail })
  $color = switch ($status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } 'SKIP' { 'DarkGray' } default { 'White' } }
  Write-Host ('[{0}] {1}  {2}' -f $status, $name, $detail) -ForegroundColor $color
}
function Step([string]$m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }

# ---------------------------------------------------------------- settings (ONE file: <root>\config\hashslinger.json)
if (-not $Config -or -not (Test-Path $Config)) {
  Write-Host 'No settings file found. Run Setup-Hashslinger.cmd (the wizard) first, or pass -Config <path to hashslinger.json>.' -ForegroundColor Red
  exit 1
}
$Config = (Resolve-Path $Config).Path
Write-Host "Settings file: $Config"
$init = Get-Content $Config -Raw | ConvertFrom-Json

function Opt([string]$path, $default) {
  $o = $init
  foreach ($k in $path -split '\.') {
    if ($null -eq $o -or -not ($o.PSObject.Properties.Name -contains $k)) { return $default }
    $o = $o.$k
  }
  if ($null -eq $o) { return $default }
  if ($o -is [string] -and $o -eq '') { return $default }
  return $o
}

$root = Opt 'install_root' (Split-Path -Parent (Split-Path -Parent $Config))
$Dir = @{
  root = $root; bin = "$root\app"; config = "$root\config"
  store = Split-Path -Parent (Opt 'hash_store_path' "$root\data\store\master.ntlm")
  staging = Opt 'staging_path' "$root\data\staging"
  logs = Split-Path -Parent (Opt 'log_path' "$root\logs\audit.jsonl")
  output = Opt 'output_path' "$root\reports"
  status = Split-Path -Parent (Opt 'status_path' "$root\status\status.json")
  requests = Opt 'request_dir' "$root\requests"
}
$exe = "$($Dir.bin)\Hashslinger.exe"
$runtimeCfg = $Config
$dc = Opt 'target_server' ''
$ous = @(Opt 'target_ous' @())
$gmsa = Opt 'gmsa_name' 'svc-hashslinger'
$runServer = Opt 'run_server' $env:COMPUTERNAME
$analystGroup = Opt 'analyst_group' ''
$minFree = @{ store = [double](Opt 'min_free_space_gb.store' 60); output = [double](Opt 'min_free_space_gb.output' 5) }

# ---------------------------------------------------------------- phase: preflight
Step 'Preflight'
$haveExe = Test-Path (Join-Path $srcRoot 'Hashslinger.exe')
foreach ($need in 'cs', 'powershell', 'config') {
  if ($need -eq 'cs' -and $haveExe) { Result 'Source folder: cs' 'SKIP' 'not needed, a built Hashslinger.exe is present'; continue }
  if (Test-Path (Join-Path $srcRoot $need)) { Result "Source folder: $need" 'PASS' }
  else { Result "Source folder: $need" 'FAIL' "missing under $srcRoot (is the whole Hashslinger folder here?)" }
}
Result 'PowerShell version' $(if ($PSVersionTable.PSVersion.Major -ge 5) { 'PASS' } else { 'FAIL' }) "$($PSVersionTable.PSVersion)"
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
Result 'C# compiler (csc.exe)' $(if (Test-Path $csc) { 'PASS' } else { 'WARN' }) $(if (Test-Path $csc) { $csc } else { 'not found; a prebuilt Hashslinger.exe must be in the folder' })
$csName = (Get-CimInstance Win32_ComputerSystem)
Result 'Domain joined' $(if ($csName.PartOfDomain) { 'PASS' } else { 'WARN' }) $csName.Domain
if (-not $dc) { Result 'Domain controller set' 'WARN' 'live scans need it (Admin tool > Active Directory)' } else { Result 'Domain controller set' 'PASS' $dc }
if ($ous.Count -eq 0) { Result 'Scan scope set' 'FAIL' 'pick at least one OU to scan (Admin tool > Active Directory)' } else { Result 'Scan scope set' 'PASS' "$($ous.Count) scope(s)" }

foreach ($k in 'store', 'staging', 'logs', 'output', 'status', 'requests') {
  $drive = [IO.Path]::GetPathRoot($Dir[$k])
  try {
    $di = New-Object IO.DriveInfo($drive)
    $freeGb = [math]::Round($di.AvailableFreeSpace / 1GB, 1)
    $want = if ($minFree.ContainsKey($k)) { $minFree[$k] } else { 1 }
    Result "Drive for $k ($drive)" $(if ($freeGb -ge $want) { 'PASS' } else { 'WARN' }) "$freeGb GB free, wants $want GB"
  } catch { Result "Drive for $k ($drive)" 'FAIL' 'drive not found' }
}
if ($Phase -eq 'Check') { Step 'Check only. No changes made.'; $results | Format-Table -AutoSize; exit 0 }
if (($results | Where-Object Status -eq 'FAIL')) { Write-Host 'Fix the FAIL items above, then re-run.' -ForegroundColor Red; exit 1 }

New-Item -ItemType Directory -Force $Dir.logs | Out-Null
$transcript = Join-Path $Dir.logs ("setup-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $transcript | Out-Null

# ---------------------------------------------------------------- phase: Local
function Do-Local {
  if (Get-Process -Name Hashslinger -ErrorAction SilentlyContinue) {
    Result 'No scan is running' 'FAIL' 'a scan is running (Hashslinger.exe). Wait for it or stop it, then run setup again.'; return
  }
  Step 'Folders'
  foreach ($d in $Dir.bin, $Dir.config, $Dir.store, $Dir.staging, "$($Dir.staging)\HIBP", "$($Dir.staging)\rockyou", "$($Dir.staging)\custom", $Dir.logs, $Dir.output, $Dir.status, $Dir.requests, "$($Dir.root)\extras") {
    New-Item -ItemType Directory -Force $d | Out-Null
  }
  Result 'Folders created' 'PASS' "root $($Dir.root)"

  Step 'Program files'
  $srcExe = Join-Path $srcRoot 'Hashslinger.exe'
  if (-not (Test-Path $srcExe)) {
    if (-not (Test-Path $csc)) { Result 'Build exe' 'FAIL' 'no exe and no csc.exe'; return }
    Push-Location $srcRoot
    & $csc /nologo /optimize+ /unsafe /platform:x64 /target:exe /out:Hashslinger.exe /r:System.dll /r:System.Core.dll 'cs\*.cs'
    Pop-Location
    if (-not (Test-Path $srcExe)) { Result 'Build exe' 'FAIL' 'compile errors above'; return }
    Result 'Build exe' 'PASS' 'built with in-box csc.exe'
  } else { Result 'Build exe' 'SKIP' 'Hashslinger.exe already present' }
  if ((Resolve-Path $srcRoot).Path -ne (Resolve-Path $Dir.bin).Path) {
    if (Test-Path "$($Dir.bin)\Hashslinger.exe") {
      $bk = "$($Dir.root)\app-backups\app-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
      New-Item -ItemType Directory -Force $bk | Out-Null
      Copy-Item "$($Dir.bin)\*" $bk -Recurse -Force
      Get-ChildItem "$($Dir.root)\app-backups" -Directory | Sort-Object Name -Descending | Select-Object -Skip 3 | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
      Result 'Previous app files backed up' 'PASS' $bk
    }
    Copy-Item $srcExe $Dir.bin -Force
    New-Item -ItemType Directory -Force "$($Dir.bin)\powershell", "$($Dir.bin)\config", "$($Dir.bin)\docs" | Out-Null
    Copy-Item "$srcRoot\extras\*" "$($Dir.root)\extras" -Force -ErrorAction SilentlyContinue   # optional gMSA helper scripts
    Copy-Item "$srcRoot\powershell\*.ps1" "$($Dir.bin)\powershell" -Force
    Copy-Item "$srcRoot\config\*" "$($Dir.bin)\config" -Force
    Copy-Item "$srcRoot\docs\*" "$($Dir.bin)\docs" -Force -ErrorAction SilentlyContinue
    Copy-Item "$srcRoot\*.cmd", "$srcRoot\README.md" $Dir.bin -Force -ErrorAction SilentlyContinue
  }
  Result 'Installed to app' 'PASS' $Dir.bin
  Set-Content (Join-Path $Dir.root 'Hashslinger-Admin.cmd') @'
@echo off
rem Hashslinger Admin: change any setting, run scans, manage wordlists.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\powershell\Hashslinger-Admin.ps1" -ConfigPath "%~dp0config\hashslinger.json"
'@ -Encoding ASCII
  Result 'Admin tool shortcut' 'PASS' (Join-Path $Dir.root 'Hashslinger-Admin.cmd')
  Set-Content (Join-Path $Dir.root 'Hashslinger-Uninstall.cmd') @'
@echo off
rem Hashslinger uninstall. No switches = remove scheduled tasks only (files stay). See the SOP for the switches.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\powershell\Uninstall-Hashslinger.ps1" -Config "%~dp0config\hashslinger.json" %*
pause
'@ -Encoding ASCII
  if (-not (Test-Path "$($Dir.config)\pattern_rules.json")) { Copy-Item "$srcRoot\config\pattern_rules.json" $Dir.config }
  Get-ChildItem $Dir.root, $srcRoot -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
  Result 'Files unblocked' 'PASS'

  Step 'Dependencies'
  if (Get-Module -ListAvailable -Name ActiveDirectory) { Result 'ActiveDirectory module' 'PASS' }
  elseif (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
    try { Install-WindowsFeature RSAT-AD-PowerShell | Out-Null; Result 'ActiveDirectory module' 'PASS' 'installed RSAT-AD-PowerShell' }
    catch { Result 'ActiveDirectory module' 'FAIL' $_.Exception.Message }
  } else { Result 'ActiveDirectory module' 'WARN' 'install RSAT AD PowerShell tools' }

  if (Get-Module -ListAvailable -Name DSInternals) { Result 'DSInternals module' 'PASS' }
  else {
    $off = Opt 'dsinternals_offline_path' ''
    try {
      if ($off -and (Test-Path $off)) {
        Copy-Item $off "$env:ProgramFiles\WindowsPowerShell\Modules\DSInternals" -Recurse -Force
        Result 'DSInternals module' 'PASS' "copied from $off"
      } else {
        Install-Module DSInternals -Scope AllUsers -Force -AllowClobber
        Result 'DSInternals module' 'PASS' 'installed from the PowerShell Gallery'
      }
    } catch { Result 'DSInternals module' 'FAIL' ($_.Exception.Message + ' (set dsinternals_offline_path for offline hosts)') }
  }
  try { Import-Module DSInternals -ErrorAction Stop; Result 'DSInternals loads' 'PASS' } catch { Result 'DSInternals loads' 'FAIL' $_.Exception.Message }

  Step 'Wordlists'
  foreach ($pair in @(@('hibp', 'HIBP'), @('rockyou', 'rockyou'), @('custom', 'custom'))) {
    $src = Opt "wordlists.$($pair[0])" ''
    if (-not $src) { continue }
    if (-not (Test-Path $src)) { Result "Wordlist $($pair[0])" 'WARN' "not found: $src"; continue }
    $dest = Join-Path "$($Dir.staging)\$($pair[1])" (Split-Path $src -Leaf)
    if (Test-Path $dest) { Result "Wordlist $($pair[0])" 'SKIP' 'already staged'; continue }
    # always COPY: a copy inherits the staging folder permissions (so the gMSA can read it). A hard link would keep
    # the original file's permissions and the scan, which runs as the gMSA, would be denied.
    Copy-Item $src $dest
    Result "Wordlist $($pair[0])" 'PASS' 'copied to staging (inherits the folder permissions)'
  }

  Step 'Settings'
  Result 'Settings file' 'PASS' "$Config (change any setting in the Admin tool: $($Dir.root)\Hashslinger-Admin.cmd)"
}

# ---------------------------------------------------------------- verification
function Do-Verify {
  Step 'Verification'
  $errs = 0
  foreach ($f in Get-ChildItem "$($Dir.bin)\powershell" -Filter *.ps1) {
    $t = $null; $e = $null
    [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    if ($e -and $e.Count) { $errs++; Result "PowerShell syntax: $($f.Name)" 'FAIL' $e[0].Message }
  }
  if ($errs -eq 0) { Result 'PowerShell syntax (all scripts)' 'PASS' }

  if (-not (Test-Path $exe)) { Result 'Exe selftest' 'FAIL' 'exe missing'; return }
  $out = & $exe selftest 2>&1
  if ($LASTEXITCODE -eq 0) { Result 'Exe selftest' 'PASS' ($out | Select-Object -Last 1) } else { Result 'Exe selftest' 'FAIL' (($out | Where-Object { $_ -like 'FAIL*' }) -join '; ') }

  # AD-free smoke test: exact exe -> powershell child -> csv path, isolated from the real store
  $v = Join-Path $Dir.root 'verify'
  Remove-Item $v -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force "$v\staging\rockyou", "$v\staging\custom", "$v\output" | Out-Null
  Set-Content "$v\staging\rockyou\r.txt" 'password'
  Set-Content "$v\staging\custom\c.txt" 'SharedSecretXyz!9'
  $ou = 'OU=Finance,DC=contoso,DC=com'
  $vc = [ordered]@{
    target_ous = @($ou); hash_store_path = "$v\store\master.ntlm"; staging_path = "$v\staging"; log_path = "$v\logs\audit.jsonl"
    output_path = "$v\output"; allowed_output_roots = @("$v\output"); status_path = "$v\status\status.json"
    pattern_rules_path = "$($Dir.config)\pattern_rules.json"; require_encrypted_volume = $false
    engine_command = @('powershell.exe', '-NoProfile', '-File', "$($Dir.bin)\powershell\Fake-Engine.ps1", '-SearchBases', '{ous}')
  }
  $vc | ConvertTo-Json -Depth 5 | Set-Content "$v\verify.json" -Encoding UTF8
  $so = & $exe --config "$v\verify.json" scan 2>&1
  $csv = Get-ChildItem "$v\output\*.csv" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($LASTEXITCODE -ne 0 -or -not $csv) { Result 'Smoke test (fake engine)' 'FAIL' (($so | Out-String).Trim() + '  (blocked script policy? run Unblock-File on the bin folder)') }
  else {
    $names = ((Import-Csv $csv.FullName).sAMAccountName | Sort-Object) -join ','
    $raw = Get-Content $csv.FullName -Raw
    if ($names -eq 'alice,carol,dave,erin,frank,gina' -and $raw -notmatch '[0-9A-Fa-f]{32}') { Result 'Smoke test (fake engine)' 'PASS' 'exe -> powershell -> csv, no hashes in report' }
    else { Result 'Smoke test (fake engine)' 'FAIL' "unexpected flagged set: $names" }
  }
  Remove-Item $v -Recurse -Force -ErrorAction SilentlyContinue

  # AD reachability and scope check (read-only)
  if ($dc) {
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      $d = Get-ADDomain -Server $dc
      Result 'Domain controller reachable' 'PASS' $d.DNSRoot
      foreach ($o in $ous) {
        # Exists() is reliable. Reading a property on a failed bind can silently return $null.
        if ([DirectoryServices.DirectoryEntry]::Exists("LDAP://$dc/$o")) { Result "Scope exists: $o" 'PASS' }
        else { Result "Scope exists: $o" 'FAIL' 'not found on that DC. Note the built-in Users container is CN=Users, not OU=Users.' }
      }
    } catch { Result 'Domain controller reachable' 'FAIL' $_.Exception.Message }
  }
}

# ---------------------------------------------------------------- folder permissions helper
function Set-FolderAcl([string]$path, $gmsaSid, $analystSid, $analystRights, [string]$analystInherit = 'ContainerInherit,ObjectInherit', [string]$gmsaRights = 'FullControl') {
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $full = [Security.AccessControl.FileSystemRights]::FullControl
  $inh = 'ContainerInherit,ObjectInherit'
  # Identities are SIDs, never names: no name lookup is needed, so this works on any Windows language and even
  # when the server cannot resolve account names. The gMSA / group SIDs come from the (read-only) AD queries.
  $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')   # BUILTIN\Administrators
  $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')       # NT AUTHORITY\SYSTEM
  $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')      # Everyone
  # The service account gets only what it needs: read-only on program and settings folders (otherwise anyone who could
  # change those files could run code as the replication account), write only where it must write.
  foreach ($who in @($gmsaSid, $admins, $system)) {
    $r = if ($who -eq $gmsaSid) { [Security.AccessControl.FileSystemRights]$gmsaRights } else { $full }
    try { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, $r, $inh, 'None', 'Allow'))) }
    catch { throw "Could not add identity $who to the permissions of ${path}: $($_.Exception.Message)" }
  }
  if ($analystSid -and $analystRights) {
    try { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($analystSid, $analystRights, $analystInherit, 'None', 'Allow'))) }
    catch { throw "Could not add the analyst group $analystSid to the permissions of ${path}: $($_.Exception.Message)" }
  }
  # failed access attempts are audited (needs the 'Audit File System' policy plus alerting on events 4656/4663 failures)
  $acl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule($everyone, $full, $inh, 'None', 'Failure')))
  Set-Acl -Path $path -AclObject $acl
}

# ---------------------------------------------------------------- phase: Finish (read-only AD checks, local changes only)
function Do-Finish {
  Step 'Finish: check the service account you created (read-only), then set up permissions and tasks locally'
  if ($env:COMPUTERNAME -ne $runServer.Split('.')[0] -and $env:COMPUTERNAME -ne $runServer) {
    Result 'Running on the run server' 'FAIL' "this is $env:COMPUTERNAME, the settings say $runServer (Admin tool > Security and accounts)."; return
  }
  try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Result 'ActiveDirectory module' 'FAIL' 'install RSAT-AD-PowerShell'; return }
  $dom = Get-ADDomain
  $domainNC = $dom.DistinguishedName
  $gmsaSam = "$($dom.NetBIOSName)\${gmsa}$"
  $svc = Get-ADServiceAccount -Filter "Name -eq '$gmsa' -or SamAccountName -eq '$gmsa' -or SamAccountName -eq '${gmsa}$'" -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue
  if (-not $svc) { Result 'gMSA exists in AD' 'FAIL' "not found. Create the service account first (by hand, see the SOP section 'Create the service account'; helper scripts are in $($Dir.root)\extras), or fix the name in the Admin tool (Security and accounts)."; return }
  Result 'gMSA exists in AD' 'PASS' "$($svc.SamAccountName) ($($svc.SID))"
  $gmsaSid = $svc.SID
  # use the REAL account name AD reports, and prove this server can resolve it (task scheduler and ACLs need that)
  $gmsaSam = "$($dom.NetBIOSName)\$($svc.SamAccountName)"
  try {
    $gmsaSam = $gmsaSid.Translate([Security.Principal.NTAccount]).Value
    Result 'This server can resolve the gMSA account name' 'PASS' $gmsaSam
  } catch {
    Result 'This server can resolve the gMSA account name' 'FAIL' "Windows on this server cannot translate the gMSA SID $gmsaSid to a name ($($_.Exception.Message)). Scheduled tasks and folder permissions need this. Typical causes: this server cannot reach a domain controller over SMB/RPC (TCP 445 and 135) for account lookups (AD reads over LDAP can still work), DNS problems, or a broken secure channel. Check: Test-ComputerSecureChannel ; and that TCP 445/135 to the DC are open."
    return
  }
  $me = Get-ADComputer $env:COMPUTERNAME
  $allowed = @($svc.PrincipalsAllowedToRetrieveManagedPassword)
  if ($allowed.Count -gt 1) { Result 'Only this server may retrieve the gMSA password' 'WARN' ("$($allowed.Count) principals may retrieve it: " + ($allowed -join '; ') + '. The design is ONE server (this one).') }
  if ($allowed -contains $me.DistinguishedName) { Result 'This server may retrieve the gMSA password' 'PASS' }
  else { Result 'This server may retrieve the gMSA password' 'FAIL' "not allowed. The Domain Admin used a different -RunServer than $env:COMPUTERNAME."; return }

  # Read-only effective-access check: anyone can read the domain root ACL and the gMSA's token groups.
  # Counts Allow/Deny entries for the gMSA, its groups, Everyone and Authenticated Users. It cannot prove the
  # DC will honor them; the live test below is authoritative.
  try {
    $tg = (Get-ADObject -Identity $svc.DistinguishedName -Properties tokenGroups).tokenGroups
    $sids = New-Object 'System.Collections.Generic.HashSet[string]'
    [void]$sids.Add($svc.SID.Value); [void]$sids.Add('S-1-1-0'); [void]$sids.Add('S-1-5-11')
    foreach ($b in $tg) {
      # the AD module may hand back SecurityIdentifier objects or raw bytes, depending on version
      if ($b -is [Security.Principal.SecurityIdentifier]) { [void]$sids.Add($b.Value) }
      else { [void]$sids.Add((New-Object Security.Principal.SecurityIdentifier([byte[]]$b, 0)).Value) }
    }
    $rules = (Get-Acl "AD:$domainNC").GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $want = [ordered]@{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes'; '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes All' }
    $problems = @()
    $aceDump = @()
    foreach ($k in $want.Keys) {
      $g = [Guid]$k
      $cand = @($rules | Where-Object {
          $sids.Contains($_.IdentityReference.Value) -and
          (($_.ActiveDirectoryRights -band [DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0) -and
          ($_.ObjectType -eq $g -or $_.ObjectType -eq [Guid]::Empty) })
      foreach ($c in $cand) {
        $who = try { $c.IdentityReference.Translate([Security.Principal.NTAccount]).Value } catch { $c.IdentityReference.Value }
        $aceDump += ('{0} | {1} | {2} | applies to: {3}' -f $who, $want[$k], $c.AccessControlType, $c.InheritanceType)
      }
      # an entry only counts if it applies to the domain root object itself (not descendants-only)
      $mine = @($cand | Where-Object { $_.InheritanceType -in 'None', 'All', 'SelfAndChildren' })
      if (@($mine | Where-Object { $_.AccessControlType -eq 'Deny' }).Count) { $problems += "$($want[$k]): denied by an entry" }
      elseif (-not @($mine | Where-Object { $_.AccessControlType -eq 'Allow' }).Count) {
        if ($cand.Count) { $problems += "$($want[$k]): entry exists but does NOT apply to the domain root itself (it is descendants-only); it must apply to 'this object'" }
        else { $problems += "$($want[$k]): no allow entry for the gMSA or any of its groups" }
      }
    }
    # least privilege: the service account should hold ONLY the two replication rights, not admin group membership
    $privNames = @()
    foreach ($sv in $sids) {
      if ($sv -match '-512$') { $privNames += 'Domain Admins' } elseif ($sv -match '-518$') { $privNames += 'Schema Admins' }
      elseif ($sv -match '-519$') { $privNames += 'Enterprise Admins' } elseif ($sv -eq 'S-1-5-32-544') { $privNames += 'BUILTIN\Administrators' }
    }
    if ($privNames.Count) { Result 'Service account is NOT in a privileged group' 'WARN' ("it is (indirectly) a member of: " + ($privNames -join ', ') + '. Remove it: the scan needs only the two replication rights.') }
    else { Result 'Service account is NOT in a privileged group' 'PASS' }
    if ($problems.Count -eq 0) { Result 'Replication rights on the domain root (effective, read-only)' 'PASS' 'allowed for the gMSA directly or via a group' }
    else { Result 'Replication rights on the domain root (effective, read-only)' 'WARN' (($problems -join '; ') + '. Scans will fail until a Domain Admin fixes this.') }
  } catch { Result 'Replication rights on the domain root' 'WARN' ('could not compute: ' + $_.Exception.Message) }

  $ok = Test-ADServiceAccount -Identity $gmsa
  if (-not $ok) { & klist.exe -li 0x3e7 purge | Out-Null; Start-Sleep -Seconds 5; $ok = Test-ADServiceAccount -Identity $gmsa }
  if ($ok) { Result 'gMSA works on this server' 'PASS' } else { Result 'gMSA works on this server' 'FAIL' "Test-ADServiceAccount is False. This tool never changes AD. If the gMSA is not installed on this server yet, install it here yourself (see the README section 'gMSA not installed on this server'), or wait for AD replication / reboot, then Finish again."; return }

  # folder permissions (local) : gMSA, local Administrators, SYSTEM only unless an analyst group is set
  $analystSam = $null; $analystSid = $null
  if ($analystGroup) { try { $grp = Get-ADGroup $analystGroup; $analystSid = $grp.SID; $analystSam = "$($dom.NetBIOSName)\$analystGroup" } catch { Result 'Analyst group' 'WARN' "group '$analystGroup' not found; ignoring"; $analystSam = $null; $analystSid = $null } }
  $plan = @(
    @($Dir.root, $null, 'ContainerInherit,ObjectInherit', 'ReadAndExecute'),      # keeps ordinary users from replacing the program folders
    @($Dir.bin, $null, 'ContainerInherit,ObjectInherit', 'ReadAndExecute'),       # program and scripts: the service account only reads them
    @($Dir.store, $null, 'ContainerInherit,ObjectInherit'),
    @($Dir.config, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'ReadAndExecute'),
    @($Dir.staging, 'Modify', 'ContainerInherit,ObjectInherit'),
    @($Dir.logs, $null, 'ContainerInherit,ObjectInherit'),
    @($Dir.output, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.status, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.requests, 'CreateFiles', 'None')
  )
  foreach ($entry in $plan) {
    if ($PSCmdlet.ShouldProcess($entry[0], 'Restrict ACL')) { if ($entry.Count -gt 3) { Set-FolderAcl $entry[0] $gmsaSid $analystSid $entry[1] $entry[2] $entry[3] } else { Set-FolderAcl $entry[0] $gmsaSid $analystSid $entry[1] $entry[2] } }
  }
  # Files that were moved/linked in earlier keep their old permissions and the gMSA could not read them.
  # Reset them to the permissions inherited from their (now locked-down) folder.
  $fixed = 0
  foreach ($d in $Dir.staging, $Dir.store) {
    Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { & icacls.exe $_.FullName /reset 2>&1 | Out-Null; $fixed++ }
  }
  Result 'Existing files in staging and store readable by the gMSA' 'PASS' "$fixed file(s) reset to inherited permissions"
  Result 'Folder permissions' 'PASS' $(if ($analystSam) { 'gMSA, Administrators, SYSTEM; analyst group limited access' } else { 'gMSA, local Administrators and SYSTEM only' })

  # scheduled tasks under the gMSA (local; no stored password)
  $principal = New-ScheduledTaskPrincipal -UserId $gmsaSam -LogonType Password -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  $cadence = Opt 'cadence' 'Weekly'
  $day = Opt 'schedule_day' 'Sunday'
  $at = [datetime]::ParseExact([string](Opt 'schedule_time' '02:00'), 'HH:mm', $null)
  $enableSched = [bool](Opt 'enable_scheduled' $true)
  $enableOnDemand = [bool](Opt 'enable_ondemand' ([bool]$analystGroup))
  $trigger = switch ($cadence) {
    'Daily'   { New-ScheduledTaskTrigger -Daily -At $at }
    'Monthly' { New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek $day -At $at }
    default   { New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $day -At $at }
  }
  $when = switch ($cadence) { 'Daily' { "daily at $($at.ToString('HH:mm'))" } 'Monthly' { "every 4 weeks on $day at $($at.ToString('HH:mm'))" } default { "weekly on $day at $($at.ToString('HH:mm'))" } }
  if ($PSCmdlet.ShouldProcess('Hashslinger tasks', 'Register')) {
    if ($enableSched) {
      Register-ScheduledTask -TaskName 'Hashslinger-Scheduled' -Force -Principal $principal -Settings $settings -Trigger $trigger `
        -Action (New-ScheduledTaskAction -Execute $exe -Argument "--config `"$runtimeCfg`" scan" -WorkingDirectory $Dir.bin) | Out-Null
      Result 'Scheduled scan task registered' 'PASS' "Hashslinger-Scheduled, $when, as $gmsaSam"
    } else {
      if (Get-ScheduledTask -TaskName 'Hashslinger-Scheduled' -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName 'Hashslinger-Scheduled' -Confirm:$false }
      Result 'Scheduled scan task' 'SKIP' 'not enabled in the settings (no Hashslinger-Scheduled task)'
    }
    if ($enableOnDemand) {
      Register-ScheduledTask -TaskName 'Hashslinger-OnDemand' -Force -Principal $principal -Settings $settings `
        -Action (New-ScheduledTaskAction -Execute $exe -Argument "--config `"$runtimeCfg`" scan --request-dir `"$($Dir.requests)`"" -WorkingDirectory $Dir.bin) | Out-Null
      Result 'On-demand scan task registered' 'PASS' "Hashslinger-OnDemand, started by analyst requests, as $gmsaSam"
      if ($analystSam) {
        try {
          $asid = (Get-ADGroup $analystGroup).SID.Value
          $svcCom = New-Object -ComObject Schedule.Service; $svcCom.Connect()
          $svcCom.GetFolder('\').GetTask('Hashslinger-OnDemand').SetSecurityDescriptor("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$asid)", 0)
          Result 'Analysts may start the on-demand task' 'PASS' $analystGroup
        } catch { Result 'Analysts may start the on-demand task' 'WARN' $_.Exception.Message }
      }
    } else {
      if (Get-ScheduledTask -TaskName 'Hashslinger-OnDemand' -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName 'Hashslinger-OnDemand' -Confirm:$false }
      Result 'On-demand scan task' 'SKIP' 'not enabled in the settings (no Hashslinger-OnDemand task)'
    }
  }

  # ---- live test AS THE gMSA: the only check that proves the logon, the batch right and the replication rights all work
  Step 'Live test as the gMSA (replicates this server''s own computer object; prints no secrets)'
  if (-not $dc) { Result 'Live replication test as the gMSA' 'WARN' 'no domain controller is set (Admin tool > Active Directory), skipped'; return }
  if ($WhatIfPreference) { Result 'Live replication test as the gMSA' 'SKIP' 'preview (-WhatIf): nothing was registered, so nothing to test'; return }
  $probeOut = Join-Path $Dir.status 'gmsa-probe.txt'
  Remove-Item $probeOut -ErrorAction SilentlyContinue
  $probeArgs = "-NoProfile -File `"$($Dir.bin)\powershell\Test-GmsaReplication.ps1`" -Server $dc -Sam `"$($env:COMPUTERNAME)`$`" -OutFile `"$probeOut`""
  Register-ScheduledTask -TaskName 'Hashslinger-Probe' -Force -Principal $principal -Settings $settings `
    -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $probeArgs) | Out-Null
  Start-ScheduledTask -TaskName 'Hashslinger-Probe'
  $deadline = (Get-Date).AddSeconds(90)
  while (-not (Test-Path $probeOut) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
  $info = Get-ScheduledTaskInfo -TaskName 'Hashslinger-Probe'
  Unregister-ScheduledTask -TaskName 'Hashslinger-Probe' -Confirm:$false
  if (Test-Path $probeOut) {
    $txt = @(Get-Content $probeOut); Remove-Item $probeOut -ErrorAction SilentlyContinue
    $who = ($txt | Where-Object { $_ -like 'identity:*' } | Select-Object -First 1)
    if ($txt | Where-Object { $_ -like 'OK*' }) { Result 'Live replication test as the gMSA' 'PASS' "$who; replication works" }
    else {
      $err = ($txt | Where-Object { $_ -like 'ERROR*' } | Select-Object -First 1)
      $hint = if ($err -match 'Replication access was denied') { 'The DC accepted the logon but refused replication: the two permissions are not effective for this gMSA. Check they are on the DOMAIN ROOT (not an OU) as Allow entries; ask the Domain Admin to grant them via a group that contains only the gMSA.' }
              elseif ($err -match 'RPC server|unavailable') { 'This server cannot reach the DC over RPC (firewall or DC name).' }
              elseif ($err -match 'Schema') { 'DSInternals is asking for Schema partition replication rights. This tool normally avoids that with explicit -Properties sets; check the DSInternals version and send the note lines above.' }
              elseif ($err -match 'FIPS') { 'FIPS MODE: this server enforces FIPS-only cryptography in .NET. DSInternals needs MD5 (and RC4) to decrypt the data AD replicates, so it refuses to run. Setup, permissions and tasks are fine; only the scan is blocked. See the README section FIPS mode for the options (all need your security approval).' }
              elseif ($err -match 'DSInternals') { 'DSInternals did not load for this account (module path or policy).' } else { '' }
      $dumpText = if ($aceDump) { "`n      Permission entries found for this gMSA:`n        " + ($aceDump -join "`n        ") } else { '' }
      Result 'Live replication test as the gMSA' 'FAIL' "$who | $err | $hint$dumpText"
    }
  } else {
    $code = '0x{0:X}' -f $info.LastTaskResult
    $hint = if ($code -in '0x80070569', '0x8007052E', '0x8007052F') { 'LOGON FAILURE: the gMSA lacks "Log on as a batch job" on this server (Local Security Policy > User Rights Assignment, or the GPO).' }
            elseif ($code -eq '0x1') { 'The probe script ran and failed. Check the script execution policy (unsigned scripts) and that DSInternals is installed for all users.' }
            else { 'The task did not produce output. Run: Get-ScheduledTaskInfo Hashslinger-Probe, and check Task Scheduler history.' }
    Result 'Live replication test as the gMSA' 'FAIL' "task result $code | $hint"
  }
}

try {
  if ($Phase -in 'Local', 'All') { Do-Local; Do-Verify }
  if ($Phase -in 'Finish', 'All') { Do-Finish }
}
finally { Stop-Transcript | Out-Null }

Step 'Summary'
$problemRows = @($results | Where-Object { $_.Status -in 'FAIL', 'WARN' })
if ($problemRows.Count) {
  Write-Host 'PROBLEMS AND WARNINGS:' -ForegroundColor Yellow
  foreach ($r in $problemRows) { Write-Host ''; Write-Host ("[{0}] {1}" -f $r.Status, $r.Check) -ForegroundColor $(if ($r.Status -eq 'FAIL') { 'Red' } else { 'Yellow' }); if ($r.Detail) { Write-Host ("      " + $r.Detail) } }
  Write-Host ''
}
Write-Host ('{0} passed, {1} skipped, {2} warning(s), {3} failed' -f @($results | Where-Object Status -eq 'PASS').Count, @($results | Where-Object Status -eq 'SKIP').Count, @($results | Where-Object Status -eq 'WARN').Count, @($results | Where-Object Status -eq 'FAIL').Count)
$fail = @($results | Where-Object Status -eq 'FAIL').Count
$warn = @($results | Where-Object Status -eq 'WARN').Count
$summary = Join-Path $Dir.logs 'SETUP-SUMMARY.txt'
@"
Hashslinger setup summary ($(Get-Date))
Install folder: $($Dir.root)
  app:      $($Dir.bin)
  settings: $Config   (the ONE settings file; edit it in the Admin tool)
  data:     store $($Dir.store)    wordlists $($Dir.staging)
  reports:  $($Dir.output)
  logs:     $($Dir.logs)    status: $($Dir.status)
  extras:   $($Dir.root)\extras   (optional gMSA helper scripts)
Admin tool: $($Dir.root)\Hashslinger-Admin.cmd
Progress:   powershell -File "$($Dir.bin)\powershell\Show-HashslingerProgress.ps1" -ConfigPath "$Config"
Setup log:  $transcript
Result:     $fail FAIL, $warn WARN
"@ | Set-Content $summary
Write-Host ''
if ($fail) { Write-Host "$fail check(s) FAILED. See above and $transcript" -ForegroundColor Red; exit 1 }
Write-Host "Setup complete ($warn warning(s)). Summary: $summary" -ForegroundColor Green
