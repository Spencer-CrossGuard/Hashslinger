<#
.SYNOPSIS
  Full setup, driven by an init config. Works from wherever the Hashslinger folder is dropped.
.DESCRIPTION
  THIS SCRIPT NEVER CREATES OR CHANGES ANYTHING IN ACTIVE DIRECTORY. It runs fine as a local administrator
  on the scan server (no Domain Admin needed). Reads init config (drives, paths, AD scope, names), then:
    Phase Check    preflight only, no changes
    Phase Local    folders on the configured drives, install to <root>\bin, build the exe if missing,
                   DSInternals + AD tools, unblock files, generate the runtime config, verify
                   (PowerShell syntax parse, exe selftest, AD-free smoke test, DC/OU reachability)
    Phase Handoff  write <root>\AD-HANDOFF\ for a Domain Admin: plain-language request + the gMSA script.
                   The Domain Admin does the AD part by hand, separately.
    Phase Finish   after the Domain Admin is done: READ-ONLY checks that the gMSA and its rights exist,
                   then local-only steps: install the gMSA here, folder permissions, scheduled tasks.
    Phase All      Local then Handoff
  Re-running is safe: it backs up the previous runtime config.
.NOTES
  Finish-phase steps are UNTESTED against a live domain.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$InitConfig,
  [ValidateSet('Check', 'Local', 'Handoff', 'Finish', 'All')][string]$Phase = 'Local'
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

# ---------------------------------------------------------------- init config
if (-not $InitConfig) {
  foreach ($c in @((Join-Path $srcRoot 'hashslinger.init.json'), (Join-Path $srcRoot 'config\hashslinger.init.json'))) {
    if (Test-Path $c) { $InitConfig = $c; break }
  }
}
if (-not $InitConfig) {
  $target = Join-Path $srcRoot 'hashslinger.init.json'
  Copy-Item (Join-Path $srcRoot 'config\hashslinger.init.example.json') $target
  Write-Host "No init config found. Created $target from the example." -ForegroundColor Yellow
  Write-Host 'Edit it (drives, DC, OUs, names), save, then run this setup again.'
  Start-Process notepad.exe $target
  exit 1
}
Write-Host "Init config: $InitConfig"
$init = Get-Content $InitConfig -Raw | ConvertFrom-Json

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

$root = Opt 'install_root' 'C:\Hashslinger'
$Dir = @{
  root = $root; bin = "$root\bin"; config = "$root\config"
  store = Opt 'paths.store' "$root\store"; staging = Opt 'paths.staging' "$root\staging"
  logs = Opt 'paths.logs' "$root\logs"; output = Opt 'paths.output' "$root\output"
  status = Opt 'paths.status' "$root\status"; requests = Opt 'paths.requests' "$root\requests"
}
$exe = "$($Dir.bin)\Hashslinger.exe"
$runtimeCfg = "$($Dir.config)\hashslinger.json"
$dc = Opt 'ad.domain_controller' ''
$ous = @(Opt 'ad.target_ous' @())
$gmsa = Opt 'security.gmsa_name' 'svc-hashslinger'
$runServer = Opt 'security.run_server' $env:COMPUTERNAME
$analystGroup = Opt 'security.analyst_group' ''
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
if (-not $dc) { Result 'ad.domain_controller set' 'WARN' 'live scans need it' } else { Result 'ad.domain_controller set' 'PASS' $dc }
if ($ous.Count -eq 0) { Result 'ad.target_ous set' 'FAIL' 'list at least one OU/DN' } else { Result 'ad.target_ous set' 'PASS' "$($ous.Count) scope(s)" }

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

New-Item -ItemType Directory -Force $root | Out-Null
$transcript = Join-Path $root ("setup-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $transcript | Out-Null

# ---------------------------------------------------------------- phase: Local
function Do-Local {
  Step 'Folders'
  foreach ($d in $Dir.bin, $Dir.config, $Dir.store, $Dir.staging, "$($Dir.staging)\HIBP", "$($Dir.staging)\rockyou", "$($Dir.staging)\custom", $Dir.logs, $Dir.output, $Dir.status, $Dir.requests) {
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
    Copy-Item $srcExe $Dir.bin -Force
    New-Item -ItemType Directory -Force "$($Dir.bin)\powershell", "$($Dir.bin)\config", "$($Dir.bin)\docs" | Out-Null
    Copy-Item "$srcRoot\powershell\*.ps1" "$($Dir.bin)\powershell" -Force
    Copy-Item "$srcRoot\config\*" "$($Dir.bin)\config" -Force
    Copy-Item "$srcRoot\docs\*" "$($Dir.bin)\docs" -Force -ErrorAction SilentlyContinue
    Copy-Item "$srcRoot\*.cmd", "$srcRoot\README.md" $Dir.bin -Force -ErrorAction SilentlyContinue
  }
  Result 'Installed to bin' 'PASS' $Dir.bin
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
    if ((Split-Path $src -Qualifier) -eq (Split-Path $dest -Qualifier)) {
      try { New-Item -ItemType HardLink -Path $dest -Value $src | Out-Null; Result "Wordlist $($pair[0])" 'PASS' 'hard-linked (no copy)' }
      catch { Copy-Item $src $dest; Result "Wordlist $($pair[0])" 'PASS' 'copied' }
    } else { Copy-Item $src $dest; Result "Wordlist $($pair[0])" 'PASS' 'copied to staging' }
  }

  Step 'Runtime config'
  if (Test-Path $runtimeCfg) { Copy-Item $runtimeCfg ("$runtimeCfg.bak-{0:yyyyMMddHHmmss}" -f (Get-Date)) }
  $cfg = [ordered]@{
    mode = Opt 'ad.mode' 'live'; replication = Opt 'ad.replication' 'bulk'
    check_duplicates = [bool](Opt 'scan.check_duplicates' $false)
    target_server = $dc; target_ous = @($ous); account_types = @(Opt 'ad.account_types' @('User', 'Service'))
    uac = @{ exclude_flags = @(Opt 'ad.uac_exclude_flags' @('SMARTCARD_REQUIRED')) }
    ntds_path = Opt 'ad.ntds_path' ''; system_hive_path = Opt 'ad.system_hive_path' ''
    hash_store_path = "$($Dir.store)\master.ntlm"; staging_path = $Dir.staging
    log_path = "$($Dir.logs)\audit.jsonl"; output_path = $Dir.output; allowed_output_roots = @($Dir.output)
    request_dir = $Dir.requests; status_path = "$($Dir.status)\status.json"
    pattern_rules_path = "$($Dir.config)\pattern_rules.json"
    engine_script = "$($Dir.bin)\powershell\Get-AccountHashes.ps1"
    require_encrypted_volume = [bool](Opt 'security.require_encrypted_volume' $false)
    retention_days = [int](Opt 'scan.retention_days' 0)
    engine_timeout_seconds = [int](Opt 'scan.engine_timeout_seconds' 86400)
    authorized_edipis = @(Opt 'security.authorized_edipis' @())
  }
  $cfg | ConvertTo-Json -Depth 6 | Set-Content $runtimeCfg -Encoding UTF8
  Result 'Runtime config written' 'PASS' $runtimeCfg
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
    $names = ((Import-Csv $csv.FullName).Username | Sort-Object) -join ','
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

# ---------------------------------------------------------------- phase: Handoff (writes NO Active Directory changes)
function Set-FolderAcl([string]$path, [string]$gmsaSam, [string]$analystSam, $analystRights, [string]$analystInherit = 'ContainerInherit,ObjectInherit') {
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $full = [Security.AccessControl.FileSystemRights]::FullControl
  $inh = 'ContainerInherit,ObjectInherit'
  foreach ($who in @($gmsaSam, 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, $full, $inh, 'None', 'Allow')))
  }
  if ($analystSam -and $analystRights) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($analystSam, $analystRights, $analystInherit, 'None', 'Allow')))
  }
  # failed access attempts are audited (needs the 'Audit File System' policy plus alerting on events 4656/4663 failures)
  $acl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule('Everyone', $full, $inh, 'None', 'Failure')))
  Set-Acl -Path $path -AclObject $acl
}

function Do-Handoff {
  if ([bool](Opt 'security.gmsa_precreated' $false)) { Result 'Domain Admin hand-off' 'SKIP' "gMSA '$gmsa' is marked as already created"; return }
  Step 'Hand-off package for a Domain Admin (nothing in AD is changed by this tool)'
  $h = Join-Path $Dir.root 'AD-HANDOFF'
  New-Item -ItemType Directory -Force $h | Out-Null
  Copy-Item (Join-Path $Dir.bin 'powershell\New-HashslingerGmsa.ps1') $h -Force
  $domName = try { (Get-CimInstance Win32_ComputerSystem).Domain } catch { '(this domain)' }
  $short = $env:COMPUTERNAME
  $text = @"
HASHSLINGER - ACTIVE DIRECTORY REQUEST (for a Domain Admin)
Generated $(Get-Date)   Domain: $domName   Scan server: $short   Authorization ref: ____________________

WHAT THIS IS
Hashslinger is an authorized internal tool that checks AD password hashes against breached-password lists
and reports accounts that need a reset. It never changes Active Directory and never stores or shows plaintext
passwords. The server operator is NOT a Domain Admin, so these three one-time items need to be done by you.

WHAT WE NEED (about 2 minutes)
1. A KDS root key must exist (required by any group Managed Service Account).
     Check:  Get-KdsRootKey
     If none: Add-KdsRootKey -EffectiveImmediately      (usable in about 10 hours; every DC must have replicated it)
2. A group Managed Service Account named '$gmsa' whose password only the computer '$short' can retrieve.
3. That account granted two permissions on the DOMAIN root only (not forest, not schema):
     Replicating Directory Changes   (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
     Replicating Directory Changes All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
   These are the directory replication ("DCSync") rights. The tool needs them to read password hashes so it
   can compare them to the lists. Nothing else is requested.

HOW (run elevated, as a Domain Admin, on any machine with the AD PowerShell module; READ the script first)
   cd to this folder, then preview and apply:
     .\New-HashslingerGmsa.ps1 -Name $gmsa -RunServer $short -WhatIf
     .\New-HashslingerGmsa.ps1 -Name $gmsa -RunServer $short -GrantReplicationRights
   Or do the same by hand in ADUC / ADSI Edit. The script is a convenience, not a requirement.

BEFORE THE FIRST SCAN
   * Tell the SOC: the scan server '$short' and account '$gmsa' will trigger DCSync / replication alerts.
   * Expect replication traffic from '$short' to a domain controller.

TO UNDO
     Remove-ADServiceAccount $gmsa
     and remove that account's two permissions from the domain root (ADSI Edit > domain root > Security).

WHEN DONE
   Tell the server operator. They finish with:  Setup-Hashslinger.cmd -Phase Finish   (or the wizard's Finish button).
"@
  Set-Content (Join-Path $h 'README-FOR-DOMAIN-ADMIN.txt') $text -Encoding UTF8
  Result 'Domain Admin hand-off written' 'PASS' $h
}

# ---------------------------------------------------------------- phase: Finish (read-only AD checks, local changes only)
function Do-Finish {
  Step 'Finish: verify the AD prerequisites (read-only), then install locally'
  if ($env:COMPUTERNAME -ne $runServer.Split('.')[0] -and $env:COMPUTERNAME -ne $runServer) {
    Result 'Running on the run server' 'FAIL' "this is $env:COMPUTERNAME, init says $runServer."; return
  }
  try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Result 'ActiveDirectory module' 'FAIL' 'install RSAT-AD-PowerShell'; return }
  $dom = Get-ADDomain
  $domainNC = $dom.DistinguishedName
  $gmsaSam = "$($dom.NetBIOSName)\${gmsa}$"
  $svc = Get-ADServiceAccount -Filter "Name -eq '$gmsa'" -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue
  if (-not $svc) { Result 'gMSA exists in AD' 'FAIL' "not found. Check the name in the init config (security.gmsa_name), or have a Domain Admin complete the request in $($Dir.root)\AD-HANDOFF."; return }
  Result 'gMSA exists in AD' 'PASS' $gmsaSam
  $me = Get-ADComputer $env:COMPUTERNAME
  if (@($svc.PrincipalsAllowedToRetrieveManagedPassword) -contains $me.DistinguishedName) { Result 'This server may retrieve the gMSA password' 'PASS' }
  else { Result 'This server may retrieve the gMSA password' 'FAIL' "not allowed. The Domain Admin used a different -RunServer than $env:COMPUTERNAME."; return }

  try {
    $want = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    $aces = @((Get-Acl "AD:$domainNC").Access | Where-Object { $_.IdentityReference.Value -eq $gmsaSam -and $_.AccessControlType -eq 'Allow' })
    $have = @($want | Where-Object { $g = [Guid]$_; ($aces | Where-Object { $_.ObjectType -eq $g }) })
    if ($have.Count -eq 2) { Result 'gMSA has both replication rights (domain root)' 'PASS' }
    else { Result 'gMSA has both replication rights (domain root)' 'WARN' "found $($have.Count) of 2. Scans will fail until a Domain Admin grants them." }
  } catch { Result 'gMSA replication rights' 'WARN' ('could not read the domain root permissions: ' + $_.Exception.Message) }

  Install-ADServiceAccount -Identity $gmsa -ErrorAction SilentlyContinue
  $ok = Test-ADServiceAccount -Identity $gmsa
  if (-not $ok) { & klist.exe -li 0x3e7 purge | Out-Null; Start-Sleep -Seconds 5; $ok = Test-ADServiceAccount -Identity $gmsa }
  if ($ok) { Result 'gMSA works on this server' 'PASS' } else { Result 'gMSA works on this server' 'FAIL' 'Test-ADServiceAccount is False. Wait for AD replication or reboot, then Finish again.'; return }

  # folder permissions (local) : gMSA, local Administrators, SYSTEM only unless an analyst group is set
  $analystSam = $null
  if ($analystGroup) { try { $analystSam = "$($dom.NetBIOSName)\$analystGroup"; $null = Get-ADGroup $analystGroup } catch { Result 'Analyst group' 'WARN' "group '$analystGroup' not found; ignoring"; $analystSam = $null } }
  $plan = @(
    @($Dir.store, $null, 'ContainerInherit,ObjectInherit'),
    @($Dir.config, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.staging, 'Modify', 'ContainerInherit,ObjectInherit'),
    @($Dir.logs, $null, 'ContainerInherit,ObjectInherit'),
    @($Dir.output, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.status, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.requests, 'CreateFiles', 'None')
  )
  foreach ($entry in $plan) {
    if ($PSCmdlet.ShouldProcess($entry[0], 'Restrict ACL')) { Set-FolderAcl $entry[0] $gmsaSam $analystSam $entry[1] $entry[2] }
  }
  Result 'Folder permissions' 'PASS' $(if ($analystSam) { 'gMSA, Administrators, SYSTEM; analyst group limited access' } else { 'gMSA, local Administrators and SYSTEM only' })

  # scheduled tasks under the gMSA (local; no stored password)
  $principal = New-ScheduledTaskPrincipal -UserId $gmsaSam -LogonType Password -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  $cadence = Opt 'scan.cadence' 'Weekly'
  $trigger = if ($cadence -eq 'Monthly') { New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At 2am } else { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am }
  if ($PSCmdlet.ShouldProcess('Hashslinger tasks', 'Register')) {
    Register-ScheduledTask -TaskName 'Hashslinger-Scheduled' -Force -Principal $principal -Settings $settings -Trigger $trigger `
      -Action (New-ScheduledTaskAction -Execute $exe -Argument "--config `"$runtimeCfg`" scan" -WorkingDirectory $Dir.bin) | Out-Null
    Register-ScheduledTask -TaskName 'Hashslinger-OnDemand' -Force -Principal $principal -Settings $settings `
      -Action (New-ScheduledTaskAction -Execute $exe -Argument "--config `"$runtimeCfg`" scan --request-dir `"$($Dir.requests)`"" -WorkingDirectory $Dir.bin) | Out-Null
    Result 'Scheduled tasks registered' 'PASS' "$cadence scan + on-demand, both as $gmsaSam"
    if ($analystSam) {
      try {
        $asid = (Get-ADGroup $analystGroup).SID.Value
        $svcCom = New-Object -ComObject Schedule.Service; $svcCom.Connect()
        $svcCom.GetFolder('\').GetTask('Hashslinger-OnDemand').SetSecurityDescriptor("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$asid)", 0)
        Result 'Analysts may start the on-demand task' 'PASS' $analystGroup
      } catch { Result 'Analysts may start the on-demand task' 'WARN' $_.Exception.Message }
    }
  }

  # ---- live test AS THE gMSA: the only check that proves the logon, the batch right and the replication rights all work
  Step 'Live test as the gMSA (replicates this server''s own computer object; prints no secrets)'
  if (-not $dc) { Result 'Live replication test as the gMSA' 'WARN' 'ad.domain_controller is not set, skipped'; return }
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
              elseif ($err -match 'DSInternals') { 'DSInternals did not load for this account (module path or policy).' } else { '' }
      Result 'Live replication test as the gMSA' 'FAIL' "$who | $err | $hint"
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
  if ($Phase -in 'Handoff', 'All') { Do-Handoff }
  if ($Phase -eq 'Finish') { Do-Finish }
}
finally { Stop-Transcript | Out-Null }

Step 'Summary'
$results | Format-Table -AutoSize -Wrap
$fail = @($results | Where-Object Status -eq 'FAIL').Count
$warn = @($results | Where-Object Status -eq 'WARN').Count
$summary = Join-Path $Dir.root 'SETUP-SUMMARY.txt'
@"
Hashslinger setup summary ($(Get-Date))
Program:   $($Dir.bin)\Hashslinger.exe
Config:    $runtimeCfg  (generated from $InitConfig)
Store:     $($Dir.store)    Staging: $($Dir.staging)
Logs:      $($Dir.logs)     Output:  $($Dir.output)    Status: $($Dir.status)
Progress:  powershell -File "$($Dir.bin)\powershell\Show-HashslingerProgress.ps1" -ConfigPath "$runtimeCfg"
Launcher:  $($Dir.bin)\Start-HashslingerRun.cmd
Analyst:   powershell -File "$($Dir.bin)\powershell\Start-HashslingerGui.ps1"
Setup log: $transcript
Result:    $fail FAIL, $warn WARN
"@ | Set-Content $summary
Write-Host ''
if ($fail) { Write-Host "$fail check(s) FAILED. See above and $transcript" -ForegroundColor Red; exit 1 }
Write-Host "Setup complete ($warn warning(s)). Summary: $summary" -ForegroundColor Green
