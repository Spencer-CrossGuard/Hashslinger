<#
.SYNOPSIS
  Creates (or updates) the Hashslinger group Managed Service Account. Standalone; no init config needed.
.DESCRIPTION
  FOR A DOMAIN ADMIN to run by hand (Hashslinger setup never changes AD). Run elevated, on any machine with
  the AD PowerShell module. -RunServer is the SCAN SERVER, which may differ from where this is run.
  It: checks the AD module and KDS root key, creates the gMSA (or updates who may retrieve its password),
  installs it on this server, and verifies it with Test-ADServiceAccount.
  The password can be retrieved ONLY by the computer accounts you list (default: this server).
  Optional -GrantReplicationRights adds Replicating Directory Changes + Changes All on the DOMAIN naming
  context only (never forest/schema), the minimum the scan needs. It changes AD permissions, so preview first.
.EXAMPLE
  .\New-HashslingerGmsa.ps1 -WhatIf
  .\New-HashslingerGmsa.ps1 -Name svc-hashslinger
  .\New-HashslingerGmsa.ps1 -Name svc-hashslinger -GrantReplicationRights
.NOTES
  UNTESTED against a live domain. Use -WhatIf first.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [ValidateLength(1, 15)][string]$Name = 'svc-hashslinger',     # gMSA sAMAccountName limit is 15 chars + $
  [Parameter(Mandatory)][string]$RunServer,                     # the scan server: the only computer allowed to retrieve the password
  [string[]]$AdditionalHosts = @(),                             # e.g. a standby scan server
  [switch]$GrantReplicationRights,
  [switch]$CreateKdsRootKey                                     # LAB ONLY: effective immediately
)
$ErrorActionPreference = 'Stop'

function Say([string]$status, [string]$msg) {
  $color = switch ($status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Cyan' } }
  Write-Host ("[{0}] {1}" -f $status, $msg) -ForegroundColor $color
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Say 'FAIL' 'Run this elevated (Run as administrator).'; exit 1 }
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { Say 'FAIL' 'ActiveDirectory module missing. Install RSAT-AD-PowerShell.'; exit 1 }
Import-Module ActiveDirectory

$dom = Get-ADDomain
$domainNC = $dom.DistinguishedName
$shortRun = $RunServer.Split('.')[0]
$hosts = @($shortRun) + @($AdditionalHosts | ForEach-Object { $_.Split('.')[0] }) | Select-Object -Unique
Say 'INFO' "Domain $($dom.DNSRoot); gMSA '$Name'; password retrievable only by: $($hosts -join ', ')"

# computer accounts that may retrieve the password must exist
$computers = @()
foreach ($h in $hosts) {
  try { $computers += Get-ADComputer $h } catch { Say 'FAIL' "Computer account '$h' not found in AD."; exit 1 }
}

# KDS root key (required for any gMSA)
if (-not (Get-KdsRootKey)) {
  if ($CreateKdsRootKey) {
    if ($PSCmdlet.ShouldProcess('KDS root key', 'Create (LAB ONLY, effective immediately)')) {
      Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
      Say 'OK' 'KDS root key created (lab shortcut).'
    }
  } else {
    Say 'FAIL' 'No KDS root key. Run Add-KdsRootKey -EffectiveImmediately and wait ~10 hours (production), or use -CreateKdsRootKey in a lab.'
    exit 1
  }
} else { Say 'OK' 'KDS root key present.' }

# create or update
$existing = Get-ADServiceAccount -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
if ($PSCmdlet.ShouldProcess($Name, $(if ($existing) { 'Update who may retrieve the gMSA password' } else { 'Create gMSA' }))) {
  if ($existing) {
    Set-ADServiceAccount -Identity $Name -PrincipalsAllowedToRetrieveManagedPassword $computers
    Say 'OK' "Updated existing gMSA '$Name'."
  } else {
    New-ADServiceAccount -Name $Name -DNSHostName "$Name.$($dom.DNSRoot)" `
      -PrincipalsAllowedToRetrieveManagedPassword $computers -KerberosEncryptionType AES256 `
      -Description 'Hashslinger credential exposure audit (scheduled scan identity)'
    Say 'OK' "Created gMSA '$Name'."
  }

  # install on THIS server if it is one of the allowed hosts
  if ($hosts -contains $env:COMPUTERNAME) {
    Install-ADServiceAccount -Identity $Name
    $ok = Test-ADServiceAccount -Identity $Name
    if (-not $ok) {
      Say 'WARN' 'Test failed. Refreshing this computer''s Kerberos tickets and retrying once.'
      & klist.exe -li 0x3e7 purge | Out-Null
      Start-Sleep -Seconds 5
      $ok = Test-ADServiceAccount -Identity $Name
    }
    if ($ok) { Say 'OK' "Test-ADServiceAccount: True. Use $($dom.NetBIOSName)\$Name$ in scheduled tasks." }
    else { Say 'FAIL' 'Test-ADServiceAccount still False. Wait for AD replication or reboot this server, then rerun.' }
  } else {
    Say 'WARN' "This is $env:COMPUTERNAME, not an allowed host. Run Install-ADServiceAccount $Name on $shortRun."
  }
}

if ($GrantReplicationRights) {
  if ($PSCmdlet.ShouldProcess($domainNC, 'Grant Replicating Directory Changes + Changes All to the gMSA (domain NC only)')) {
    $sid = (Get-ADServiceAccount $Name).SID
    $acl = Get-Acl "AD:$domainNC"
    foreach ($g in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
      $rule = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, [DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [Security.AccessControl.AccessControlType]::Allow, [Guid]$g, [DirectoryServices.ActiveDirectorySecurityInheritance]::None)
      $acl.AddAccessRule($rule)
    }
    Set-Acl "AD:$domainNC" $acl
    Say 'OK' "Replication rights granted on $domainNC (domain NC only)."
  }
} else {
  Say 'INFO' 'Replication rights NOT granted. Rerun with -GrantReplicationRights when ready (preview with -WhatIf).'
}

Write-Host ''
Say 'INFO' "Next: give the task 'Log on as a batch job' if it fails to start (local policy or GPO), then run Setup-Hashslinger -Phase Domain or register tasks."
