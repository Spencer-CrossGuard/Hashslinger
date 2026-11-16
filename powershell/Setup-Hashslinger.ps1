<#
.SYNOPSIS
  Full setup, driven by an init config. Works from wherever the Hashslinger folder is dropped.
.DESCRIPTION
  Reads hashslinger.init.json (drives, paths, AD scope, security names), then:
    Phase Check   preflight only, no changes
    Phase Local   folders on the configured drives, install to <root>\bin, build the exe if missing,
                  DSInternals + AD tools, unblock files, generate the runtime config, verify
                  (PowerShell syntax parse, exe selftest, AD-free smoke test, AD reachability)
    Phase Domain  gMSA, minimum replication rights on the domain NC, folder ACLs, scheduled tasks,
                  analyst permission to start the on-demand task. Must run on the run server, as a
                  domain admin. Honors -WhatIf.
    Phase All     Local then Domain
  Re-running is safe: it rebuilds nothing unnecessarily and backs up the previous runtime config.
.NOTES
  Domain-phase steps are UNTESTED against a live domain. Run Phase Domain with -WhatIf first.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$InitConfig,
  [ValidateSet('Check', 'Local', 'Domain', 'All')][string]$Phase = 'Local',
  [switch]$CreateKdsRootKey   # lab only: makes the KDS root key effective immediately
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
foreach ($need in 'cs', 'powershell', 'config') {
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

# ---------------------------------------------------------------- phase: Domain
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

function Do-Domain {
  Step 'Domain: gMSA, rights, ACLs, tasks'
  if ($env:COMPUTERNAME -ne $runServer.Split('.')[0] -and $env:COMPUTERNAME -ne $runServer) {
    Result 'Running on the run server' 'FAIL' "this is $env:COMPUTERNAME, init says $runServer. Run the Domain phase on the run server."
    return
  }
  if (-not $analystGroup) { Result 'Analyst group' 'SKIP' 'none set: only the gMSA, local Administrators and SYSTEM get access' }
  Import-Module ActiveDirectory
  $dom = Get-ADDomain
  $domainNC = $dom.DistinguishedName
  $gmsaSam = "$($dom.NetBIOSName)\$gmsa$"

  # KDS root key
  if (-not (Get-KdsRootKey)) {
    if ($CreateKdsRootKey) {
      if ($PSCmdlet.ShouldProcess('KDS root key', 'Create (effective immediately, LAB ONLY)')) { Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null; Result 'KDS root key' 'PASS' 'created (lab shortcut)' }
    } else { Result 'KDS root key' 'FAIL' 'none exists. Create one (production waits 10h) or pass -CreateKdsRootKey in a lab.'; return }
  } else { Result 'KDS root key' 'PASS' }

  # gMSA
  $server = Get-ADComputer ($runServer.Split('.')[0])
  $existing = Get-ADServiceAccount -Filter "Name -eq '$gmsa'" -ErrorAction SilentlyContinue
  if ($PSCmdlet.ShouldProcess($gmsa, 'Create or update gMSA (password retrievable only by the run server)')) {
    if ($existing) { Set-ADServiceAccount -Identity $gmsa -PrincipalsAllowedToRetrieveManagedPassword $server }
    else { New-ADServiceAccount -Name $gmsa -DNSHostName "$gmsa.$($dom.DNSRoot)" -PrincipalsAllowedToRetrieveManagedPassword $server -KerberosEncryptionType AES256 }
    Install-ADServiceAccount -Identity $gmsa
    if (Test-ADServiceAccount -Identity $gmsa) { Result 'gMSA installed and working on this server' 'PASS' $gmsaSam } else { Result 'gMSA installed and working on this server' 'FAIL' 'Test-ADServiceAccount failed' }
  }

  # replication rights: domain NC only (never forest/schema)
  if ($PSCmdlet.ShouldProcess($domainNC, 'Grant Replicating Directory Changes (+All) to the gMSA')) {
    $sid = (Get-ADServiceAccount $gmsa).SID
    $acl = Get-Acl "AD:$domainNC"
    foreach ($g in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
      $rule = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, [DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [Security.AccessControl.AccessControlType]::Allow, [Guid]$g, [DirectoryServices.ActiveDirectorySecurityInheritance]::None)
      $acl.AddAccessRule($rule)
    }
    Set-Acl "AD:$domainNC" $acl
    Result 'Replication rights (domain NC only)' 'PASS' $domainNC
  }

  # folder ACLs
  $analystSam = if ($analystGroup) { "$($dom.NetBIOSName)\$analystGroup" } else { $null }
  $plan = @(
    @($Dir.store, $null, 'ContainerInherit,ObjectInherit'),
    @($Dir.config, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),   # the analyst GUI reads the scope list
    @($Dir.staging, 'Modify', 'ContainerInherit,ObjectInherit'),
    @($Dir.logs, $null, 'ContainerInherit,ObjectInherit'),
    @($Dir.output, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.status, 'ReadAndExecute', 'ContainerInherit,ObjectInherit'),
    @($Dir.requests, 'CreateFiles', 'None')          # write-only drop box: this folder only, no read/list
  )
  foreach ($entry in $plan) {
    if ($PSCmdlet.ShouldProcess($entry[0], 'Restrict ACL')) { Set-FolderAcl $entry[0] $gmsaSam $analystSam $entry[1] $entry[2] }
  }
  Result 'Folder ACLs (least privilege)' 'PASS' $(if ($analystGroup) { 'gMSA, Administrators, SYSTEM full; analysts: staging modify, output/status read, requests create-only' } else { 'gMSA, local Administrators and SYSTEM only' })

  # scheduled tasks under the gMSA (no stored password)
  $principal = New-ScheduledTaskPrincipal -UserId $gmsaSam -LogonType Password -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  $cadence = Opt 'scan.cadence' 'Weekly'
  $trigger = if ($cadence -eq 'Monthly') { New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At 2am } else { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am }
  if ($PSCmdlet.ShouldProcess('Hashslinger-Scheduled', 'Register task')) {
    Register-ScheduledTask -TaskName 'Hashslinger-Scheduled' -Force -Principal $principal -Settings $settings -Trigger $trigger `
      -Action (New-ScheduledTaskAction -Execute $exe -Argument "--config `"$runtimeCfg`" scan" -WorkingDirectory $Dir.bin) | Out-Null
    Register-ScheduledTask -TaskName 'Hashslinger-OnDemand' -Force -Principal $principal -Settings $settings `
      -Action (New-ScheduledTaskAction -Execute $exe -Argument "--config `"$runtimeCfg`" scan --request-dir `"$($Dir.requests)`"" -WorkingDirectory $Dir.bin) | Out-Null
    Result 'Scheduled tasks registered' 'PASS' "$cadence scan + on-demand, both as $gmsaSam"
    # let analysts START the on-demand task only (skipped when no analyst group is set)
    if ($analystGroup) { try {
      $asid = (Get-ADGroup $analystGroup).SID.Value
      $sddl = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$asid)"
      $svc = New-Object -ComObject Schedule.Service; $svc.Connect()
      $svc.GetFolder('\').GetTask('Hashslinger-OnDemand').SetSecurityDescriptor($sddl, 0)
      Result 'Analysts may start the on-demand task' 'PASS' $analystGroup
    } catch { Result 'Analysts may start the on-demand task' 'WARN' ($_.Exception.Message + ' (set the task security descriptor manually)') } }
  }
  Result 'gMSA log-on-as-batch right' 'WARN' 'confirm "Log on as a batch job" allows the gMSA (check on the first task run)'
}

try {
  if ($Phase -in 'Local', 'All') { Do-Local; Do-Verify }
  if ($Phase -in 'Domain', 'All') { Do-Domain }
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
