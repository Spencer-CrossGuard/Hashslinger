<#
Test 3 (run on the DC as a Domain Admin, LAB ONLY): make the DC record why it refuses replication.
  .\03-DsAudit-DC.ps1 -Enable      turn on Directory Service Access auditing + an audit entry on the domain root
  (rerun Finish on GW1)
  .\03-DsAudit-DC.ps1 -Read        show the gMSA's recent 4662 / 4625 events (names the exact right being refused)
  .\03-DsAudit-DC.ps1 -Disable     turn auditing back off
The audit entry stays on the domain root unless you remove it in ADSI Edit (Auditing tab); it is harmless.
#>
param([switch]$Enable, [switch]$Read, [switch]$Disable, [string]$Gmsa = 'svc-hashslinger')
Import-Module ActiveDirectory
if ($Enable) {
  & auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable
  $dn = (Get-ADDomain).DistinguishedName
  $acl = Get-Acl "AD:$dn"
  foreach ($g in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
    $acl.AddAuditRule((New-Object DirectoryServices.ActiveDirectoryAuditRule([Security.Principal.NTAccount]'Everyone', 'ExtendedRight', 'Failure', [Guid]$g, 'None')))
  }
  try { Set-Acl "AD:$dn" $acl; Write-Host 'Audit entry added on the domain root.' -ForegroundColor Green }
  catch { Write-Host ('Could not set the audit entry: ' + $_.Exception.Message + '. Add it in ADSI Edit (domain root > Security > Advanced > Auditing) or skip this test.') -ForegroundColor Yellow }
  Write-Host 'Now rerun Finish on GW1, then run this script with -Read.'
}
if ($Read) {
  Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662, 4625; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $Gmsa } | Select-Object TimeCreated, Id, Message | Format-List
}
if ($Disable) { & auditpol.exe /set /subcategory:"Directory Service Access" /success:disable /failure:disable }
if (-not ($Enable -or $Read -or $Disable)) { Write-Host 'Use -Enable, -Read or -Disable.' }
