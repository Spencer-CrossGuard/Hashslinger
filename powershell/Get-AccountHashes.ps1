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
  [string]$SystemHivePath,
  # Explicit property sets. DSInternals 6.3+ otherwise also fetches the Schema NC (for LAPS), which needs replication
  # rights on the Schema partition and fails with 'Replication access was denied' for a domain-root-only account.
  # Bulk mode pulls the WHOLE domain and drops everything out of scope, so a small scope would cost as much as a full
  # scan (and would receive out-of-scope hashes). At or below this many in-scope accounts, per-account is used instead.
  [int]$PerAccountThreshold = 5000,
  [string]$ReplProperties = 'GenericAccountInfo,NTHash,LMHash,SupplementalCredentials'
)
$ErrorActionPreference = 'Stop'
Import-Module DSInternals
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$bases = $SearchBases -split '\|' | Where-Object { $_ }
$types = $AccountTypes -split ',' | Where-Object { $_ }
$exFlags = @($ExcludeUacFlags -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
$reqFlags = @($RequireUacFlags -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
$out = [Console]::Out
# Progress lines for the exe (it shows them in the console and the progress viewer). Marker chosen so it can never
# be mistaken for an account line (account lines have 6 tab-separated fields and never start with this).
function Status([string]$m) { $out.WriteLine('##HS## ' + $m) }

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

# Pick the widest property set this DSInternals version accepts (names differ between versions). Access-denied errors
# are NOT swallowed here: they propagate so the real error is visible.
function Resolve-ReplProperties($guid) {
  $ladder = @($ReplProperties, 'GenericAccountInfo,NTHash,LMHash', 'GenericAccountInfo,NTHash') | Select-Object -Unique
  foreach ($set in $ladder) {
    try { $null = Get-ADReplAccount -ObjectGuid $guid -Server $Server -Properties ($set -split ','); return ($set -split ',') }
    catch [System.Management.Automation.ParameterBindingException] { continue }
    catch [System.ArgumentException] { continue }
  }
  return $null   # no explicit set accepted: fall back to the module default
}

if ($Mode -eq 'live') {
  if (-not $Server) { throw '-Server is required in live mode' }
  # objectGuid -> type, built with a paged DirectorySearcher (streams; handles millions of objects).
  foreach ($b in $bases) {
    if (-not [DirectoryServices.DirectoryEntry]::Exists("LDAP://$Server/$b")) { throw "Search base not found on ${Server}: $b (the built-in Users container is CN=Users, not OU=Users)" }
  }
  $scope = New-Object 'System.Collections.Generic.Dictionary[Guid,string]'
  $script:found = 0
  foreach ($b in $bases) {
    foreach ($t in $types) {
      $ds = New-Object System.DirectoryServices.DirectorySearcher
      $ds.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$b")
      $ds.Filter = "(&$(TypeFilter $t)$(UacClause))"
      $ds.PageSize = 1000
      $ds.SearchScope = 'Subtree'
      [void]$ds.PropertiesToLoad.Add('objectguid')
      Status "scope search: looking for $t accounts under $b"
      $res = $ds.FindAll()
      foreach ($r in $res) {
        $g = New-Object Guid (, [byte[]]$r.Properties['objectguid'][0])
        $scope[$g] = $t
        $script:found++
        if (($script:found % 50000) -eq 0) { Status "scope search: $($script:found) accounts found so far" }
      }
      $res.Dispose(); $ds.Dispose()
    }
  }
  Status "scope ready: $($scope.Count) accounts in scope. Starting replication from the DC (the first batch can take a while)..."
  $props = $null
  foreach ($k in $scope.Keys) { $props = Resolve-ReplProperties $k; break }
  $propArgs = @{}
  if ($props) { $propArgs['Properties'] = $props }
  $mode = $Replication
  if ($Replication -eq 'bulk' -and $scope.Count -le $PerAccountThreshold) {
    $mode = 'per-account'
    Status "only $($scope.Count) accounts in scope (threshold $PerAccountThreshold): replicating just those accounts instead of pulling the whole domain"
  }
  if ($mode -eq 'per-account') {
    $script:done = 0
    foreach ($kv in $scope.GetEnumerator()) {
      Emit (Get-ADReplAccount -ObjectGuid $kv.Key -Server $Server @propArgs) $kv.Value
      $script:done++
      if (($script:done % 1000) -eq 0) { Status "replicated $($script:done) of $($scope.Count) accounts" }
    }
  }
  else {
    $type = $null
    $script:seen = 0; $script:kept = 0
    Get-ADReplAccount -All -Server $Server @propArgs | ForEach-Object {
      $script:seen++
      if ($scope.TryGetValue($_.Guid, [ref]$type)) { $script:kept++; Emit $_ $type }
      if (($script:seen % 100000) -eq 0) { Status "replicated $($script:seen) objects from the DC, $($script:kept) in scope" }
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
