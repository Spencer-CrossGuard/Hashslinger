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
  # Parallel replication workers for per-account mode (each is its own connection to the DC). 1 = no parallelism.
  [int]$Workers = 4,
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

# Formatting helpers live in one block so the parallel workers (separate runspaces) use the exact same code.
$global:HsMode = $Mode; $global:HsServer = $Server
$sharedBlock = {
  function ToHex($b) { if ($b) { [BitConverter]::ToString([byte[]]$b).Replace('-', '') } else { '' } }
  function Clean([string]$s) { $s -replace '[\t\r\n]', ' ' }
  # sAMAccountName must never be blank in the report. Normally DSInternals supplies it; if not, read it from AD (LDAP, read-only).
  function Get-SamFromLdap($guid) {
    if ($global:HsMode -ne 'live' -or -not $global:HsServer -or -not $guid) { return '' }
    try {
      $hex = (([Guid]$guid).ToByteArray() | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
      $ds = New-Object System.DirectoryServices.DirectorySearcher
      $ds.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($global:HsServer)")
      $ds.Filter = "(objectGUID=$hex)"
      [void]$ds.PropertiesToLoad.Add('samaccountname')
      $r = $ds.FindOne()
      if ($r -and $r.Properties['samaccountname'].Count) { return [string]$r.Properties['samaccountname'][0] }
    } catch { }
    return ''
  }
  function FormatLine($acct, [string]$type) {
    if ($null -eq $acct) { return $null }   # object vanished between the scope search and replication
    $sam = [string]$acct.SamAccountName
    if (-not $sam) { $sam = Get-SamFromLdap $acct.Guid }
    if (-not $sam) { $sam = '(unknown)' }
    $clear = ($null -ne $acct.SupplementalCredentials) -and ($null -ne $acct.SupplementalCredentials.ClearText)
    $uac = [int]$acct.UserAccountControl
    $rev = if ($clear -or (($uac -band 0x80) -ne 0)) { '1' } else { '0' }
    $lm = if ($null -ne $acct.LMHash) { '1' } else { '0' }
    $nopw = if (($null -eq $acct.NTHash) -and (($uac -band 0x20) -ne 0)) { '1' } else { '0' }   # PASSWD_NOTREQD and no hash = no password
    (Clean $sam) + "`t" + (Clean $acct.DistinguishedName) + "`t" + $type + "`t" + (ToHex $acct.NTHash) + "`t" + $lm + "`t" + $rev + "`t" + $nopw
  }
}
. $sharedBlock
function Emit($acct, [string]$type) { $l = FormatLine $acct $type; if ($l) { $out.WriteLine($l) } }

# Time-based progress (every ~5s): what is done, how fast, how long so far, and a rough time left.
$script:clock = [Diagnostics.Stopwatch]::StartNew()
$script:lastTick = -10
function Tick([string]$label, [long]$done, [long]$total, [bool]$force = $false) {
  $el = $script:clock.Elapsed.TotalSeconds
  if (-not $force -and ($el - $script:lastTick) -lt 5) { return }
  $script:lastTick = $el
  $rate = if ($el -gt 0) { $done / $el } else { 0 }
  $msg = "$label $done"
  if ($total -gt 0) { $msg += " of $total ($([Math]::Floor(100 * $done / $total))%)" }
  $msg += ", $([Math]::Round($rate, 1))/s, elapsed $([TimeSpan]::FromSeconds([int]$el).ToString('hh\:mm\:ss'))"
  if ($total -gt 0 -and $rate -gt 0 -and $done -lt $total) { $msg += ", about $([TimeSpan]::FromSeconds([int](($total - $done) / $rate)).ToString('hh\:mm\:ss')) left" }
  Status $msg
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
  $script:clock.Restart(); $script:lastTick = -10
  Status "step A: searching AD for the accounts in scope ($($types -join ', ') under $($bases.Count) location(s))"
  foreach ($b in $bases) {
    foreach ($t in $types) {
      $ds = New-Object System.DirectoryServices.DirectorySearcher
      $ds.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$b")
      $ds.Filter = "(&$(TypeFilter $t)$(UacClause))"
      $ds.PageSize = 1000
      $ds.CacheResults = $false
      $ds.SearchScope = 'Subtree'
      [void]$ds.PropertiesToLoad.Add('objectguid')
      Status "scope search: looking for $t accounts under $b"
      $res = $ds.FindAll()
      foreach ($r in $res) {
        $g = New-Object Guid (, [byte[]]$r.Properties['objectguid'][0])
        $scope[$g] = $t
        $script:found++
        Tick 'scope search: accounts found' $script:found 0
      }
      $res.Dispose(); $ds.Dispose()
    }
  }
  Status "step A done: $($scope.Count) accounts in scope (took $([int]$script:clock.Elapsed.TotalSeconds)s)"

  Status 'step B: testing which replication property set this DSInternals version accepts (one test call to the DC)'
  $props = $null
  foreach ($k in $scope.Keys) { $props = Resolve-ReplProperties $k; break }
  $propArgs = @{}
  if ($props) { $propArgs['Properties'] = $props }
  Status "step B done: properties = $(if ($props) { $props -join ',' } else { 'module default' })"

  $replMode = $Replication
  if ($Replication -eq 'bulk' -and $scope.Count -le $PerAccountThreshold) {
    $replMode = 'per-account'
    Status "only $($scope.Count) accounts in scope (threshold $PerAccountThreshold): replicating just those accounts instead of pulling the whole domain"
  }
  $script:clock.Restart(); $script:lastTick = -10

  if ($replMode -eq 'per-account') {
    $n = [Math]::Max(1, [Math]::Min($Workers, [Math]::Max(1, $scope.Count)))
    Status "step C: replicating $($scope.Count) accounts one by one with $n parallel connection(s) to $Server"
    if ($n -le 1) {
      $script:done = 0
      foreach ($kv in $scope.GetEnumerator()) {
        Emit (Get-ADReplAccount -ObjectGuid $kv.Key -Server $Server @propArgs) $kv.Value
        $script:done++
        Tick 'replicated' $script:done $scope.Count
      }
    }
    else {
      $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
      foreach ($kv in $scope.GetEnumerator()) { $queue.Enqueue("$($kv.Key)`t$($kv.Value)") }
      $outQ = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
      $errQ = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
      $flag = [hashtable]::Synchronized(@{ stop = $false })
      $worker = {
        param($fmtText, $queue, $outQ, $errQ, $flag, $server, $props)
        $ErrorActionPreference = 'Stop'
        try {
          Import-Module DSInternals
          $global:HsMode = 'live'; $global:HsServer = $server
          . ([scriptblock]::Create($fmtText))
          $pa = @{}
          if ($props) { $pa['Properties'] = $props }
          $item = $null
          while (-not $flag.stop -and $queue.TryDequeue([ref]$item)) {
            $f = $item -split "`t"
            $acct = Get-ADReplAccount -ObjectGuid ([Guid]$f[0]) -Server $server @pa
            $fl = FormatLine $acct $f[1]
            if ($fl) { $outQ.Enqueue($fl) }
          }
        }
        catch { $flag.stop = $true; $errQ.Enqueue([string]$_.Exception.Message) }
      }
      $pool = [runspacefactory]::CreateRunspacePool(1, $n)
      $pool.Open()
      $jobs = @()
      for ($i = 0; $i -lt $n; $i++) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker).AddArgument($sharedBlock.ToString()).AddArgument($queue).AddArgument($outQ).AddArgument($errQ).AddArgument($flag).AddArgument($Server).AddArgument($props)
        $jobs += [pscustomobject]@{ PS = $ps; Async = $ps.BeginInvoke() }
      }
      $script:done = 0
      try {
        while ($true) {
          $line = $null
          while ($outQ.TryDequeue([ref]$line)) { $out.WriteLine($line); $script:done++ }
          $msg = $null
          if ($errQ.TryDequeue([ref]$msg)) { $flag.stop = $true; throw "replication worker failed: $msg" }
          Tick "replicated ($n connections)" $script:done $scope.Count
          $allDone = $true
          foreach ($j in $jobs) { if (-not $j.Async.IsCompleted) { $allDone = $false } }
          if ($allDone -and $outQ.IsEmpty) { break }
          Start-Sleep -Milliseconds 100
        }
        if ($errQ.TryDequeue([ref]$msg)) { throw "replication worker failed: $msg" }
      }
      finally {
        $flag.stop = $true
        foreach ($j in $jobs) { try { $j.PS.Stop() } catch { }; $j.PS.Dispose() }
        $pool.Close(); $pool.Dispose()
      }
    }
    Tick 'replicated' $scope.Count $scope.Count $true
  }
  else {
    Status "step C: pulling the whole domain from $Server in one pass (the first object can take a while; nothing is reported until it arrives)"
    $type = $null
    $script:seen = 0; $script:kept = 0
    Get-ADReplAccount -All -Server $Server @propArgs | ForEach-Object {
      $script:seen++
      if ($scope.TryGetValue($_.Guid, [ref]$type)) { $script:kept++; Emit $_ $type }
      Tick "received from the DC ($($script:kept) kept in scope):" $script:seen 0
    }
    Tick 'received from the DC, total objects:' $script:seen 0 $true
  }
  Status "step C done: $($script:clock.Elapsed.ToString('hh\:mm\:ss'))"
}
else {
  if (-not ($NtdsPath -and $SystemHivePath)) { throw 'offline mode needs -NtdsPath and -SystemHivePath' }
  $key = Get-BootKey -SystemHivePath $SystemHivePath
  Get-ADDBAccount -All -DatabasePath $NtdsPath -BootKey $key | ForEach-Object {
    $a = $_
    $inScope = $false
    foreach ($b in $bases) { if ($a.DistinguishedName -ieq $b -or $a.DistinguishedName.EndsWith(',' + $b, [StringComparison]::OrdinalIgnoreCase)) { $inScope = $true; break } }
    if (-not $inScope) { return }
    $type = ClassifyType $a.ServicePrincipalName $a.SamAccountName.EndsWith('$')
    if ($types -notcontains $type) { return }
    $uac = [int]$a.UserAccountControl
    foreach ($f in $exFlags) { if (($uac -band $f) -ne 0) { return } }
    foreach ($f in $reqFlags) { if (($uac -band $f) -eq 0) { return } }
    Emit $a $type
  }
}
