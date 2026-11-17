<#
Test 2, part A (run on the DC as a Domain Admin, LAB ONLY).
Creates a throwaway user and puts it in the two groups that hold the replication rights, so Part B can
check whether an ordinary user with those rights can replicate. Use -Cleanup afterwards.
  .\02a-NonAdminControl-DC.ps1
  .\02a-NonAdminControl-DC.ps1 -Cleanup
#>
param(
  [string]$UserName = 'hs-test',
  [string[]]$Groups = @('bhr-repl-changes', 'bhr-repl-all'),
  [switch]$Cleanup
)
Import-Module ActiveDirectory
if ($Cleanup) {
  Remove-ADUser $UserName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Removed $UserName (its group memberships go with it)." -ForegroundColor Green
  return
}
if (Get-ADUser -Filter "SamAccountName -eq '$UserName'") { Write-Host "$UserName already exists." -ForegroundColor Yellow }
else {
  New-ADUser -Name $UserName -SamAccountName $UserName -AccountPassword (Read-Host -AsSecureString 'Pick a lab password for the test user') -Enabled $true
  Write-Host "Created $UserName." -ForegroundColor Green
}
foreach ($g in $Groups) { Add-ADGroupMember -Identity $g -Members $UserName; Write-Host "Added $UserName to $g" }
Write-Host 'Now run 02b-NonAdminControl-GW1.ps1 on the scan server.'
