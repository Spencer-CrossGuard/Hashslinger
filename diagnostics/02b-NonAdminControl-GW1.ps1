<#
Test 2, part B (run on the scan server GW1). Tries one replication AS the throwaway test user.
Prints only the account name or the exact error. No hashes.
  prints the account name  -> an ordinary user with these rights CAN replicate, so the gMSA logon is the issue
  "access was denied"      -> any non-admin with these rights is refused on this DC
#>
param(
  [string]$Server = 'DC1.corp.contoso.com',
  [string]$Sam = 'TestUser1',
  [string]$User = 'CORP\hs-test'
)
$c = Get-Credential $User
$cmd = 'Import-Module DSInternals; try { (Get-ADReplAccount -SamAccountName ' + $Sam + ' -Server ' + $Server + ').SamAccountName } catch { $_.Exception.Message }; Read-Host "Press Enter to close"'
Start-Process powershell.exe -Credential $c -ArgumentList @('-NoProfile', '-Command', $cmd)
