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
$stateFile = Join-Path $env:ProgramData 'hashslinger-dsaudit-before.txt'
$guids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
if ($Enable) {
  # remember how the DC was set BEFORE we touch it, so -Disable can put it back exactly (the SOC may rely on this auditing)
  if (-not (Test-Path $stateFile)) {
    $prev = (& auditpol.exe /get /subcategory:"Directory Service Access" /r | ConvertFrom-Csv).'Inclusion Setting'
    Set-Content $stateFile $prev
    Write-Host "Saved the previous auditing setting ($prev) to $stateFile" -ForegroundColor DarkGray
  }
  & auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable
  $dn = (Get-ADDomain).DistinguishedName
  $acl = Get-Acl "AD:$dn"
  foreach ($g in $guids) {
    $acl.AddAuditRule((New-Object DirectoryServices.ActiveDirectoryAuditRule([Security.Principal.NTAccount]'Everyone', 'ExtendedRight', 'Failure', [Guid]$g, 'None')))
  }
  try { Set-Acl "AD:$dn" $acl; Write-Host 'Audit entry added on the domain root.' -ForegroundColor Green }
  catch { Write-Host ('Could not set the audit entry: ' + $_.Exception.Message + '. Add it in ADSI Edit (domain root > Security > Advanced > Auditing) or skip this test.') -ForegroundColor Yellow }
  Write-Host 'Now rerun Finish on GW1, then run this script with -Read. Afterwards run -Disable to restore the previous setting.'
}
if ($Read) {
  Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662, 4625; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $Gmsa } | Select-Object TimeCreated, Id, Message | Format-List
}
if ($Disable) {
  if (-not (Test-Path $stateFile)) { Write-Host "No saved previous setting ($stateFile). Refusing to change auditing: it may be needed by your SOC. Set it by hand if you are sure." -ForegroundColor Yellow }
  else {
    $prev = (Get-Content $stateFile -Raw).Trim()
    $s = if ($prev -match 'Success') { 'enable' } else { 'disable' }
    $f = if ($prev -match 'Failure') { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:"Directory Service Access" /success:$s /failure:$f
    Write-Host "Restored Directory Service Access auditing to: $prev" -ForegroundColor Green
    Remove-Item $stateFile -ErrorAction SilentlyContinue
  }
  # remove the audit entry this script added on the domain root
  try {
    $dn = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl "AD:$dn"
    $mine = @($acl.GetAuditRules($true, $false, [Security.Principal.NTAccount]) | Where-Object { $_.IdentityReference.Value -eq 'Everyone' -and $guids -contains [string]$_.ObjectType -and $_.AuditFlags -eq 'Failure' })
    foreach ($r in $mine) { [void]$acl.RemoveAuditRule($r) }
    if ($mine.Count) { Set-Acl "AD:$dn" $acl; Write-Host "Removed $($mine.Count) audit entry(ies) from the domain root." -ForegroundColor Green }
  } catch { Write-Host ('Could not remove the audit entry (remove it in ADSI Edit, Auditing tab): ' + $_.Exception.Message) -ForegroundColor Yellow }
}
if (-not ($Enable -or $Read -or $Disable)) { Write-Host 'Use -Enable, -Read or -Disable.' }
