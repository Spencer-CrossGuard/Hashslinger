<#
.SYNOPSIS
  One-time setup for an AUTHORIZED engagement: GMSA, minimum replication rights,
  scheduled tasks, folder ACLs. Run by a domain admin. Supports -WhatIf.
.NOTES
  UNTESTED against a live domain (written without a Windows/AD host available).
  Review each step in a lab before using it on a client network.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][string]$GmsaName,           # e.g. svc-hashslinger
  [Parameter(Mandatory)][string]$RunServer,          # computer name allowed to retrieve the gMSA password
  [Parameter(Mandatory)][string]$AnalystGroup,       # small, named group
  [Parameter(Mandatory)][string]$InstallRoot,        # e.g. D:\Hashslinger
  [string]$Cadence = 'Weekly',                       # Weekly | Monthly handled below
  [string]$ExePath = ''                              # default: <InstallRoot>\Hashslinger.exe
)
$ErrorActionPreference = 'Stop'
if (-not $ExePath) { $ExePath = Join-Path $InstallRoot 'Hashslinger.exe' }
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dnsRoot = $domain.DNSRoot
$domainNC = $domain.DistinguishedName   # domain naming context only, never the Schema/forest

# 1. gMSA, retrievable only by the one server that runs the task
$server = Get-ADComputer $RunServer
if ($PSCmdlet.ShouldProcess($GmsaName, 'Create gMSA')) {
  New-ADServiceAccount -Name $GmsaName -DNSHostName "$GmsaName.$dnsRoot" `
    -PrincipalsAllowedToRetrieveManagedPassword $server
}

# 2. Replicating Directory Changes + Replicating Directory Changes All on the domain NC
$gmsaSam = "$($domain.NetBIOSName)\$GmsaName$"
$rights = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
foreach ($g in $rights) {
  if ($PSCmdlet.ShouldProcess($domainNC, "Grant replication right $g")) {
    & dsacls.exe $domainNC /G "${gmsaSam}:CA;;$g" | Out-Null
  }
}

# 3. Folder layout + ACLs: only the gMSA, the named analyst group, and local admins
$dirs = 'store', 'staging', 'logs', 'output', 'requests', 'status' | ForEach-Object { Join-Path $InstallRoot $_ }
foreach ($d in $dirs) {
  if ($PSCmdlet.ShouldProcess($d, 'Create + restrict ACL, audit failures')) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $inh = 'ContainerInherit,ObjectInherit'
    $analyst = "$($domain.NetBIOSName)\$AnalystGroup"
    # Analysts: drop requests, maintain custom terms, read reports. No access to the hash store or audit log.
    # requests: create-only (write-only drop box). Analysts cannot list or read request files; only the gMSA can.
    $analystRights = switch -Wildcard ($d) { '*requests' { 'CreateFiles' } '*staging' { 'Modify' } '*output' { 'ReadAndExecute' } '*status' { 'ReadAndExecute' } default { $null } }
    foreach ($who in @($gmsaSam, 'BUILTIN\Administrators')) {
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, $full, $inh, 'None', 'Allow')))
    }
    if ($analystRights) {
      $aInh = if ($d -like '*requests') { 'None' } else { $inh }   # drop box: this folder only, nothing inherited by files
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($analyst, $analystRights, $aInh, 'None', 'Allow')))
    }
    # Failed access attempts by anyone else are audited (needs 'Audit File System' policy
    # and a forwarder/alert rule on event 4656/4663 failures to meet the alerting requirement).
    $acl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule('Everyone', $full, $inh, 'None', 'Failure')))
    Set-Acl -Path $d -AclObject $acl
  }
}

# 4. Scheduled tasks under the gMSA (no stored password)
$cfg = Join-Path $InstallRoot 'config\hashslinger.json'
$action = New-ScheduledTaskAction -Execute $ExePath -Argument "--config `"$cfg`" scan" -WorkingDirectory $InstallRoot
$principal = New-ScheduledTaskPrincipal -UserId $gmsaSam -LogonType Password -RunLevel Limited
$trigger = if ($Cadence -eq 'Monthly') { New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At 2am }
           else { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am }
if ($PSCmdlet.ShouldProcess('Hashslinger-Scheduled', 'Register task')) {
  Register-ScheduledTask -TaskName 'Hashslinger-Scheduled' -Action $action -Trigger $trigger -Principal $principal | Out-Null
}
# On-demand task: the analyst GUI drops a request file here, then starts this task.
$reqAction = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $InstallRoot -Argument (
  "-NoProfile -Command `"Get-ChildItem '$InstallRoot\requests\req_*.json' | Sort-Object LastWriteTime | Select-Object -First 1 | " +
  "ForEach-Object { & '$ExePath' --config '$cfg' scan --request `$_.FullName }`"")
if ($PSCmdlet.ShouldProcess('Hashslinger-OnDemand', 'Register task')) {
  Register-ScheduledTask -TaskName 'Hashslinger-OnDemand' -Action $reqAction -Principal $principal | Out-Null
  Write-Warning "Grant '$AnalystGroup' the right to START 'Hashslinger-OnDemand' only (task security descriptor)."
}
