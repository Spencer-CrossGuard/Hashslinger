<#
gMSA probe (run on the scan server GW1, elevated). Runs one replication AS the gMSA through a throwaway
scheduled task and prints the result (account name or exact error; whoami; kerberos tickets). No hashes.
#>
param(
  [string]$GmsaSam = 'CORP\svc-hashslinger$',
  [string]$Server = 'DC1.corp.contoso.com',
  [string]$Sam = 'TestUser1'
)
$work = 'C:\Hashslinger'
$script = Join-Path $work 'gmsa-probe-run.ps1'
$out = Join-Path $work 'gmsa-probe-out.txt'
@"
Start-Transcript '$out'
whoami
whoami /groups
Import-Module DSInternals
try { (Get-ADReplAccount -SamAccountName $Sam -Server $Server).SamAccountName } catch { `$_.Exception.Message }
klist
Stop-Transcript
"@ | Set-Content $script
$act = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$pr = New-ScheduledTaskPrincipal -UserId $GmsaSam -LogonType Password
Register-ScheduledTask GmsaProbe -Action $act -Principal $pr -Force | Out-Null
Start-ScheduledTask GmsaProbe
Start-Sleep 25
Get-Content $out
Unregister-ScheduledTask GmsaProbe -Confirm:$false
Remove-Item $script, $out -ErrorAction SilentlyContinue
