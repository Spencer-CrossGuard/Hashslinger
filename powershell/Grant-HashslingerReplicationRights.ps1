<#
.SYNOPSIS
  Grants an existing gMSA the two directory replication rights Hashslinger needs, on the DOMAIN root only.
.DESCRIPTION
  FOR A DOMAIN ADMIN to run by hand, elevated, on any machine with the AD PowerShell module.
  Rights granted (domain naming context only; never forest, never schema):
    Replicating Directory Changes      1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    Replicating Directory Changes All  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
  These are the "DCSync" rights. Idempotent: rights that are already present are skipped.
  Verifies afterwards by re-reading the permissions. Use -WhatIf to preview.
.EXAMPLE
  .\Grant-HashslingerReplicationRights.ps1 -GmsaName svc-hashslinger -WhatIf
  .\Grant-HashslingerReplicationRights.ps1 -GmsaName svc-hashslinger
.NOTES
  To undo: ADSI Edit > domain root > Properties > Security, remove the gMSA's two entries.
#>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$GmsaName)
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this elevated (Run as administrator).' -ForegroundColor Red; exit 1 }
Import-Module ActiveDirectory

$dom = Get-ADDomain
$domainNC = $dom.DistinguishedName
$gmsa = Get-ADServiceAccount -Filter "Name -eq '$GmsaName'" -ErrorAction SilentlyContinue
if (-not $gmsa) { Write-Host "gMSA '$GmsaName' not found in $($dom.DNSRoot)." -ForegroundColor Red; exit 1 }
$sid = $gmsa.SID
$samName = "$($dom.NetBIOSName)\$GmsaName`$"
$rights = [ordered]@{
  'Replicating Directory Changes'     = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
  'Replicating Directory Changes All' = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
}

function Has-Right($acl, [Guid]$g) {
  @($acl.Access | Where-Object { $_.IdentityReference.Value -eq $samName -and $_.AccessControlType -eq 'Allow' -and $_.ObjectType -eq $g }).Count -gt 0
}

$acl = Get-Acl "AD:$domainNC"
$changed = $false
foreach ($name in $rights.Keys) {
  $g = $rights[$name]
  if (Has-Right $acl $g) { Write-Host "[SKIP] $name already granted to $samName" -ForegroundColor DarkGray; continue }
  if ($PSCmdlet.ShouldProcess($domainNC, "Grant '$name' to $samName")) {
    $rule = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, [DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
      [Security.AccessControl.AccessControlType]::Allow, $g, [DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    $acl.AddAccessRule($rule)
    $changed = $true
    Write-Host "[OK]   queued: $name" -ForegroundColor Green
  }
}
if ($changed) {
  Set-Acl "AD:$domainNC" $acl
  $verify = Get-Acl "AD:$domainNC"
  $missing = @($rights.Keys | Where-Object { -not (Has-Right $verify $rights[$_]) })
  if ($missing.Count -eq 0) { Write-Host "[OK]   Both rights are now present for $samName on $domainNC." -ForegroundColor Green }
  else { Write-Host "[FAIL] Still missing: $($missing -join ', ')" -ForegroundColor Red; exit 1 }
}
Write-Host 'Tell the SOC: scans from the scan server / this account will look like DCSync.' -ForegroundColor Yellow
