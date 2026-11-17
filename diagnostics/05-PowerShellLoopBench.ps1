<#
Measures the PowerShell engine's per-account overhead on THIS machine, with fake accounts. No AD, no DC.
It reproduces the work Get-AccountHashes.ps1 does for each account (scope lookup, property reads, string
building, output line). It does NOT include the DC streaming and decrypting secrets, which is unknown until
a real scan. Whatever this prints is roughly what a native C# engine would save.
  .\05-PowerShellLoopBench.ps1             (500000 accounts)
  .\05-PowerShellLoopBench.ps1 -Count 1000000
#>
param([int]$Count = 500000)
Add-Type -TypeDefinition @"
public class FakeAcct {
  public string SamAccountName; public string DistinguishedName; public System.Guid Guid;
  public byte[] NTHash; public byte[] LMHash; public int UserAccountControl; public object SupplementalCredentials;
}
"@
Write-Host "Building $Count fake accounts (not timed)..."
$scope = New-Object 'System.Collections.Generic.Dictionary[Guid,string]'
$accts = New-Object 'System.Collections.Generic.List[FakeAcct]'
$nt = [byte[]](1..16)
for ($i = 0; $i -lt $Count; $i++) {
  $a = New-Object FakeAcct
  $a.SamAccountName = "user$i"; $a.DistinguishedName = "CN=user$i,OU=Bench,DC=corp,DC=contoso,DC=com"
  $a.Guid = [guid]::NewGuid(); $a.NTHash = $nt; $a.UserAccountControl = 512
  $accts.Add($a); $scope[$a.Guid] = 'User'
}

# same helper code as Get-AccountHashes.ps1
$out = [IO.TextWriter]::Null
function ToHex($b) { if ($b) { [BitConverter]::ToString([byte[]]$b).Replace('-', '') } else { '' } }
function Clean([string]$s) { $s -replace '[\t\r\n]', ' ' }
function Emit($acct, [string]$type) {
  $clear = ($null -ne $acct.SupplementalCredentials) -and ($null -ne $acct.SupplementalCredentials.ClearText)
  $uac = [int]$acct.UserAccountControl
  $rev = if ($clear -or (($uac -band 0x80) -ne 0)) { '1' } else { '0' }
  $lm = if ($null -ne $acct.LMHash) { '1' } else { '0' }
  $out.WriteLine((Clean $acct.SamAccountName) + "`t" + (Clean $acct.DistinguishedName) + "`t" + $type + "`t" +
                 (ToHex $acct.NTHash) + "`t" + $lm + "`t" + $rev)
}

Write-Host 'Timing the per-account loop...'
$type = $null
$t = Measure-Command {
  $accts | ForEach-Object { if ($scope.TryGetValue($_.Guid, [ref]$type)) { Emit $_ $type } }
}
$usPer = $t.TotalMilliseconds * 1000 / $Count
'{0:N0} accounts in {1:N1}s = {2:N1} microseconds per account ({3:N0} accounts/s)' -f $Count, $t.TotalSeconds, $usPer, ($Count / $t.TotalSeconds)
foreach ($n in 1e6, 5e6, 10e6) { 'Projected PowerShell loop overhead for {0:N0} accounts: {1:N1} minutes' -f $n, ($n * $usPer / 1e6 / 60) }
Write-Host 'This is overhead only. The DC pull itself is not included.'
