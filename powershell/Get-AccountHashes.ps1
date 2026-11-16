<#
.SYNOPSIS
  Core engine: enumerate in-scope accounts and emit NT hashes, tab separated, on stdout.
.DESCRIPTION
  Output line: sam <TAB> dn <TAB> type <TAB> nt-hex-or-empty <TAB> lm(0/1) <TAB> reversible(0/1)
  Hashes go to stdout only (read by Hashslinger.exe through a pipe). Never to disk, never to the
  error stream.

  Scope is decided first by LDAP (SearchBases + bitwise userAccountControl clauses), which returns
  account metadata only. Then:
    -Replication bulk         (default, for millions of accounts) streams one Get-ADReplAccount -All
                              pass and DROPS every account not in the LDAP scope. Out-of-scope
                              hashes cross the wire to this host but are discarded immediately.
    -Replication per-account  replicates ONLY in-scope accounts, one call each (strict, but far too
                              slow for large scopes).
  Offline mode reads an ntds.dit copy and filters after loading.
  Multi-value args are strings: SearchBases separated by '|', the rest by ','. (-File mode does not
  reliably bind arrays, and DNs contain commas.)
#>
[CmdletBinding()]
param(
  [ValidateSet('live', 'offline')][string]$Mode = 'live',
  [ValidateSet('bulk', 'per-account')][string]$Replication = 'bulk',
  [Parameter(Mandatory)][string]$SearchBases,
  [string]$Server,
  [string]$AccountTypes = 'User,Service',
  [string]$ExcludeUacFlags = '',
  [string]$RequireUacFlags = '',
  [string]$NtdsPath,
  [string]$SystemHivePath
)
$ErrorActionPreference = 'Stop'
Import-Module DSInternals
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$bases = $SearchBases -split '\|' | Where-Object { $_ }
$types = $AccountTypes -split ',' | Where-Object { $_ }
$exFlags = @($ExcludeUacFlags -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
$reqFlags = @($RequireUacFlags -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
$out = [Console]::Out

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

# LDAP matching rule 1.2.840.113556.1.4.803 = bitwise AND.
function UacClause {
  $c = ''
  foreach ($f in $exFlags) { $c += "(!(userAccountControl:1.2.840.113556.1.4.803:=$f))" }
  foreach ($f in $reqFlags) { $c += "(userAccountControl:1.2.840.113556.1.4.803:=$f)" }
  $c
}
function TypeFilter([string]$t) {
  switch ($t) {
    'User'     { '(&(objectCategory=person)(objectClass=user)(!(servicePrincipalName=*)))' }
    'Service'  { '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' }
    'Computer' { '(objectCategory=computer)' }
    default    { throw "Unknown account type $t" }
  }
}
function ClassifyType($spn, [bool]$isComputer) {
  if ($isComputer) { 'Computer' } elseif ($spn -and @($spn).Count -gt 0) { 'Service' } else { 'User' }
}

if ($Mode -eq 'live') {
  if (-not $Server) { throw '-Server is required in live mode' }
  # objectGuid -> type, built with a paged DirectorySearcher (streams; handles millions of objects).
  $scope = New-Object 'System.Collections.Generic.Dictionary[Guid,string]'
  foreach ($b in $bases) {
    foreach ($t in $types) {
      $ds = New-Object System.DirectoryServices.DirectorySearcher
      $ds.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$b")
      $ds.Filter = "(&$(TypeFilter $t)$(UacClause))"
      $ds.PageSize = 1000
      $ds.SearchScope = 'Subtree'
      [void]$ds.PropertiesToLoad.Add('objectguid')
      $res = $ds.FindAll()
      foreach ($r in $res) {
        $g = New-Object Guid (, [byte[]]$r.Properties['objectguid'][0])
        $scope[$g] = $t
      }
      $res.Dispose(); $ds.Dispose()
    }
  }
  if ($Replication -eq 'per-account') {
    foreach ($kv in $scope.GetEnumerator()) {
      Emit (Get-ADReplAccount -ObjectGuid $kv.Key -Server $Server) $kv.Value
    }
  }
  else {
    $type = $null
    Get-ADReplAccount -All -Server $Server | ForEach-Object {
      if ($scope.TryGetValue($_.Guid, [ref]$type)) { Emit $_ $type }
    }
  }
}
else {
  if (-not ($NtdsPath -and $SystemHivePath)) { throw 'offline mode needs -NtdsPath and -SystemHivePath' }
  $key = Get-BootKey -SystemHivePath $SystemHivePath
  Get-ADDBAccount -All -DatabasePath $NtdsPath -BootKey $key | ForEach-Object {
    $a = $_
    $inScope = $false
    foreach ($b in $bases) { if ($a.DistinguishedName.EndsWith($b, [StringComparison]::OrdinalIgnoreCase)) { $inScope = $true; break } }
    if (-not $inScope) { return }
    $type = ClassifyType $a.ServicePrincipalName $a.SamAccountName.EndsWith('$')
    if ($types -notcontains $type) { return }
    $uac = [int]$a.UserAccountControl
    foreach ($f in $exFlags) { if (($uac -band $f) -ne 0) { return } }
    foreach ($f in $reqFlags) { if (($uac -band $f) -eq 0) { return } }
    Emit $a $type
  }
}
