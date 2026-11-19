<#
.SYNOPSIS
  LAB ONLY. Creates a large set of test accounts (default about 60,000) for a Hashslinger load test: some whose passwords
  SHOULD be flagged and many that should NOT be. Also removes them again, and checks a scan report against what it created.
.DESCRIPTION
  *** THIS SCRIPT WRITES TO ACTIVE DIRECTORY. Run it only in a LAB domain, as a Domain Admin, on a DC or any machine with
  the AD PowerShell module. It is NOT part of the installed tool. ***

  What it creates, under one new OU (default OU=HS-LoadTest) with nested department and team OUs:

    Category          Password                                              Scan should
    ----------------  ----------------------------------------------------  --------------------------------------
    strong            random 20 characters (nothing in any list)            NOT flag
    service-strong    random, account has a service principal name          NOT flag (type Service)
    smartcard-weak    weak password, but "smart card required" is set       NOT flag (excluded by default; AD also
                                                                            randomizes the password when it is set)
    pattern-weak      seasons+year, leet words, keyboard waterfalls         FLAG (Medium, pattern rules)
    service-weak      pattern-weak password on a service account            FLAG (type Service)
    rockyou-weak      passwords taken from YOUR rockyou file (-RockyouFile) FLAG (High, rockyou list)
    custom-weak       strings from hs-loadtest-custom-list.txt              FLAG (High) once you put that file in
                                                                            data\staging\custom and merge
    duplicate         groups of accounts sharing one random password        FLAG (Medium) ONLY with check_duplicates
    nopassword        no password, "password not required"                  FLAG (High, "No password set")

  Writes hs-loadtest-expected.csv (account, category, expected result; NO passwords) and hs-loadtest-custom-list.txt.
  Accounts are created with several parallel LDAP connections, so 60,000 usually takes minutes, not hours (depends on the DC).
  The domain password policy applies: the weak passwords are chosen to pass the default complexity rule (8+ characters, 3 of
  4 character types). If your lab policy is stricter, some accounts are rejected; the script says how many.

  Steps:
    1. .\06-LoadTest-Accounts.ps1 -ThisIsALabOnly -RockyouFile C:\Hashslinger\data\staging\rockyou\rockyou.txt
    2. Copy hs-loadtest-custom-list.txt into C:\Hashslinger\data\staging\custom\ (then run Merge now, or just scan).
    3. Add the OU to the Hashslinger scope (Admin tool, Active Directory tab, Reload from AD, tick HS-LoadTest). Turn on
       "Duplicate passwords" if you want the duplicate group checked. 60,000 accounts uses the bulk replication path.
    4. Run the scan with the Running Tool.
    5. .\06-LoadTest-Accounts.ps1 -CompareReport C:\Hashslinger\reports\report_<date>.csv -ExpectedFile .\hs-loadtest-expected.csv
    6. When done: .\06-LoadTest-Accounts.ps1 -ThisIsALabOnly -Cleanup
.EXAMPLE
  .\06-LoadTest-Accounts.ps1 -ThisIsALabOnly -Total 5000 -RockyouFile C:\rockyou.txt      (small trial first)
#>
[CmdletBinding()]
param(
  [string]$Server,
  [int]$Total = 60000,
  [int]$PatternWeak = 1500,
  [int]$RockyouWeak = 500,
  [string]$RockyouFile,
  [int]$CustomWeak = 300,
  [int]$DuplicateGroups = 150,
  [int]$DuplicateSize = 4,
  [int]$NoPassword = 20,
  [int]$ServiceStrong = 2000,
  [int]$ServiceWeak = 100,
  [int]$SmartCardWeak = 200,
  [int]$Departments = 12,
  [int]$Threads = 8,
  [string]$RootOuName = 'HS-LoadTest',
  [string]$OutDir = (Get-Location).Path,
  [switch]$ThisIsALabOnly,
  [switch]$Force,
  [switch]$Cleanup,
  [string]$CompareReport,
  [string]$ExpectedFile
)
$ErrorActionPreference = 'Stop'
if (-not $ExpectedFile) { $ExpectedFile = Join-Path $OutDir 'hs-loadtest-expected.csv' }

# ------------------------------------------------------------------ compare mode (read only)
if ($CompareReport) {
  if (-not (Test-Path -LiteralPath $ExpectedFile)) { throw "Expected file not found: $ExpectedFile" }
  if (-not (Test-Path -LiteralPath $CompareReport)) { throw "Report not found: $CompareReport" }
  $exp = @(Import-Csv -LiteralPath $ExpectedFile)
  $flagged = @{}
  foreach ($r in (Import-Csv -LiteralPath $CompareReport)) { $flagged[([string]$r.sAMAccountName).ToLowerInvariant()] = [string]$r.'Flag Reason' }
  $problems = 0
  $table = foreach ($g in ($exp | Group-Object Category | Sort-Object Name)) {
    $n = $g.Count
    $hit = @($g.Group | Where-Object { $flagged.ContainsKey($_.sAMAccountName.ToLowerInvariant()) }).Count
    $rule = $g.Group[0].Expected
    $verdict = switch ($rule) {
      'Y'       { if ($hit -eq $n) { 'PASS' } else { $problems++; "MISSED $($n - $hit)" } }
      'N'       { if ($hit -eq 0) { 'PASS' } else { $problems++; "FALSE POSITIVES $hit" } }
      default   { 'info (flagged only when duplicate checking is on)' }
    }
    [pscustomobject]@{ Category = $g.Name; Accounts = $n; Flagged = $hit; ShouldFlag = $rule; Result = $verdict }
  }
  $table | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
  foreach ($rule in 'Y', 'N') {
    $bad = @($exp | Where-Object { $_.Expected -eq $rule -and (($flagged.ContainsKey($_.sAMAccountName.ToLowerInvariant())) -ne ($rule -eq 'Y')) } | Select-Object -First 15)
    if ($bad.Count) { Write-Host "First mismatches for ShouldFlag=${rule}:"; $bad | ForEach-Object { Write-Host ("  {0}  ({1})" -f $_.sAMAccountName, $_.Category) } }
  }
  $reportOnlyLoadTest = ($flagged.Keys | Where-Object { $_ -like 'hslt*' }).Count
  Write-Host ("Report rows for load-test accounts: {0} of {1} rows in the report." -f $reportOnlyLoadTest, $flagged.Count)
  Write-Host 'Hints: custom-weak is only found after hs-loadtest-custom-list.txt is in data\staging\custom and merged; rockyou-weak needs your rockyou file in staging.'
  if ($problems -eq 0) { Write-Host 'RESULT: PASS. The scan flagged exactly what it should.' -ForegroundColor Green } else { Write-Host "RESULT: $problems categor(y/ies) differ from the expectation. See above." -ForegroundColor Red; exit 1 }
  return
}

# ------------------------------------------------------------------ everything below WRITES to AD
Import-Module ActiveDirectory
$dom = Get-ADDomain
$domainDn = $dom.DistinguishedName
$dnsRoot = $dom.DNSRoot
if (-not $Server) { $Server = $dom.PDCEmulator }
$rootDn = "OU=$RootOuName,$domainDn"
if (-not $ThisIsALabOnly) { Write-Host 'This script creates or deletes thousands of AD objects. Run it again with -ThisIsALabOnly if this is a LAB domain.' -ForegroundColor Red; exit 1 }
if (-not $Force) {
  $typed = Read-Host "Type the domain name ($dnsRoot) to confirm this is your lab"
  if ($typed -ne $dnsRoot) { Write-Host 'Not confirmed. Nothing was changed.'; exit 1 }
}

function Test-OuExists([string]$dn) { [DirectoryServices.DirectoryEntry]::Exists("LDAP://$Server/$dn") }
function New-Ou([string]$parentDn, [string]$name) {
  $dn = "OU=$name,$parentDn"
  if (-not (Test-OuExists $dn)) {
    $p = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$parentDn")
    $o = $p.Children.Add("OU=$name", 'organizationalUnit')
    $o.CommitChanges()
  }
  return $dn
}

# ------------------------------------------------------------------ cleanup mode
if ($Cleanup) {
  if (-not (Test-OuExists $rootDn)) { Write-Host "$rootDn does not exist. Nothing to remove."; return }
  Write-Host "Removing everything under $rootDn (one subtree at a time) ..."
  $root = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$rootDn")
  foreach ($dept in @($root.Children | Where-Object { $_.SchemaClassName -eq 'organizationalUnit' })) {
    foreach ($team in @($dept.Children | Where-Object { $_.SchemaClassName -eq 'organizationalUnit' })) {
      Write-Host "  deleting $($team.distinguishedName)"
      $team.DeleteTree()
    }
    $dept.DeleteTree()
  }
  $root.DeleteTree()
  Write-Host 'Removed. Also delete hs-loadtest-expected.csv and the custom list from data\staging\custom, and remove the OU from the Hashslinger scope.' -ForegroundColor Green
  return
}

# ------------------------------------------------------------------ plan
$weakTotal = $PatternWeak + $RockyouWeak + $CustomWeak + $ServiceWeak + $SmartCardWeak
$fixed = $weakTotal + ($DuplicateGroups * $DuplicateSize) + $NoPassword + $ServiceStrong
if ($Total -lt $fixed) { throw "-Total $Total is smaller than the special accounts ($fixed). Raise -Total or lower the others." }
if ($RockyouWeak -gt 0 -and -not $RockyouFile) { Write-Host 'No -RockyouFile given: the rockyou-weak accounts are skipped.' -ForegroundColor Yellow; $RockyouWeak = 0 }

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rand = New-Object System.Random
function New-RandomPassword {
  $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+'
  while ($true) {
    $b = New-Object byte[] 20
    $rng.GetBytes($b)
    $s = -join ($b | ForEach-Object { $chars[$_ % $chars.Length] })
    if ($s -cmatch '[A-Z]' -and $s -cmatch '[a-z]' -and $s -match '[0-9]' -and $s -match '[!@#$%^&*\-_=+]') { return $s }
  }
}
function Test-Complex([string]$p) {
  if ($p.Length -lt 8 -or $p -notmatch '^[\x21-\x7E]+$') { return $false }
  $n = 0
  if ($p -cmatch '[A-Z]') { $n++ }
  if ($p -cmatch '[a-z]') { $n++ }
  if ($p -match '[0-9]') { $n++ }
  if ($p -match '[^A-Za-z0-9]') { $n++ }
  return ($n -ge 3)
}

# weak passwords the pattern rules catch (seasons + year, base words + common endings, keyboard waterfalls)
$patternWeakList = New-Object System.Collections.Generic.List[string]
foreach ($season in 'Summer', 'Winter', 'Spring', 'Autumn', 'Fall') { foreach ($yr in 2024, 2025, 2026) { foreach ($sfx in '', '!') { $patternWeakList.Add("$season$yr$sfx") } } }
foreach ($w in 'welcome', 'letmein', 'football', 'baseball', 'dragon', 'shadow', 'master', 'sunshine', 'princess', 'iloveyou', 'changeme', 'company', 'crossguard', 'administrator', 'waterfall', 'password', 'passw0rd') {
  $cap = $w.Substring(0, 1).ToUpperInvariant() + $w.Substring(1)
  foreach ($sfx in '1', '123', '!') { $patternWeakList.Add("$cap$sfx") }
}
foreach ($wf in '1qaz@WSX', '!QAZ2wsx', 'Zaq12wsx!', '1QAZ2WSX!', '1qaz@WSX3edc', '!QAZ@WSX#EDC', 'Qwerty123', 'Zaq1xsw2!', '1Q2w3e4r!', 'P@ssw0rd1') { $patternWeakList.Add($wf) }
$filtered = New-Object System.Collections.Generic.List[string]
foreach ($c in ($patternWeakList | Select-Object -Unique)) { if (Test-Complex ([string]$c)) { $filtered.Add([string]$c) } }
$patternWeakList = $filtered
Write-Host ("Pattern-weak passwords available: {0}" -f $patternWeakList.Count)

# passwords from the user's own rockyou file (complexity-safe lines only)
$rockyouList = New-Object System.Collections.Generic.List[string]
if ($RockyouWeak -gt 0) {
  if (-not (Test-Path -LiteralPath $RockyouFile)) { throw "Rockyou file not found: $RockyouFile" }
  $sr = New-Object IO.StreamReader($RockyouFile, [Text.Encoding]::GetEncoding(28591))
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  $lines = 0
  while ((($line = $sr.ReadLine()) -ne $null) -and $rockyouList.Count -lt $RockyouWeak -and $lines -lt 6000000) {
    $lines++
    if ((Test-Complex $line) -and $seen.Add($line)) { $rockyouList.Add($line) }
  }
  $sr.Dispose()
  Write-Host ("Rockyou passwords that satisfy the complexity rule: {0} (read {1} lines)" -f $rockyouList.Count, $lines)
  if ($rockyouList.Count -eq 0) { Write-Host 'None found: rockyou-weak accounts are skipped.' -ForegroundColor Yellow; $RockyouWeak = 0 }
}

# the rest are strong-password accounts (counted after the optional lists above are known)
$strongCount = $Total - ($PatternWeak + $RockyouWeak + $CustomWeak + $ServiceWeak + $SmartCardWeak + ($DuplicateGroups * $DuplicateSize) + $NoPassword + $ServiceStrong)

# custom list: organization-style strings the user adds to data\staging\custom
$customList = New-Object System.Collections.Generic.List[string]
for ($i = 1; $i -le [Math]::Max(1, $CustomWeak); $i++) { $customList.Add(('Falls-{0:D4}-Crimson!' -f $i)) }
$customPath = Join-Path $OutDir 'hs-loadtest-custom-list.txt'
[IO.File]::WriteAllLines($customPath, $customList)

# ------------------------------------------------------------------ OU tree
Write-Host "Creating the OU tree under $rootDn ..."
$null = New-Ou $domainDn $RootOuName
$leaves = New-Object System.Collections.Generic.List[string]
for ($d = 1; $d -le $Departments; $d++) {
  $deptDn = New-Ou $rootDn ('Dept{0:D2}' -f $d)
  foreach ($team in 'Team-A', 'Team-B') { $leaves.Add((New-Ou $deptDn $team)) }
}

# ------------------------------------------------------------------ build the account list
$specs = New-Object System.Collections.Generic.List[object]
function Add-Spec([string]$cat, $pw, [bool]$svc, [int]$uac) {
  $script:specs.Add([pscustomobject]@{ Category = $cat; Password = $pw; Service = $svc; Uac = $uac; Sam = ''; Dn = ''; Spn = '' })
}
for ($i = 0; $i -lt $PatternWeak; $i++) { Add-Spec 'pattern-weak' $patternWeakList[$i % $patternWeakList.Count] $false 512 }
for ($i = 0; $i -lt $RockyouWeak; $i++) { Add-Spec 'rockyou-weak' $rockyouList[$i % $rockyouList.Count] $false 512 }
for ($i = 0; $i -lt $CustomWeak; $i++) { Add-Spec 'custom-weak' $customList[$i % $customList.Count] $false 512 }
for ($i = 0; $i -lt $ServiceWeak; $i++) { Add-Spec 'service-weak' $patternWeakList[$i % $patternWeakList.Count] $true 512 }
for ($i = 0; $i -lt $SmartCardWeak; $i++) { Add-Spec 'smartcard-weak' $patternWeakList[$i % $patternWeakList.Count] $false 262656 }
for ($g = 0; $g -lt $DuplicateGroups; $g++) { $shared = New-RandomPassword; for ($k = 0; $k -lt $DuplicateSize; $k++) { Add-Spec 'duplicate' $shared $false 512 } }
for ($i = 0; $i -lt $NoPassword; $i++) { Add-Spec 'nopassword' $null $false 544 }
for ($i = 0; $i -lt $ServiceStrong; $i++) { Add-Spec 'service-strong' (New-RandomPassword) $true 512 }
for ($i = 0; $i -lt $strongCount; $i++) { Add-Spec 'strong' (New-RandomPassword) $false 512 }
# shuffle so categories are spread over all OUs and all connections
for ($i = $specs.Count - 1; $i -gt 0; $i--) { $j = $rand.Next($i + 1); $t = $specs[$i]; $specs[$i] = $specs[$j]; $specs[$j] = $t }
for ($i = 0; $i -lt $specs.Count; $i++) {
  $s = $specs[$i]
  $s.Sam = 'hslt{0:D6}' -f ($i + 1)
  $s.Dn = $leaves[$i % $leaves.Count]
  if ($s.Service) { $s.Spn = "HTTP/$($s.Sam).$dnsRoot" }
}
Write-Host ("Creating {0} accounts on {1} with {2} connections ..." -f $specs.Count, $Server, $Threads)

# ------------------------------------------------------------------ create them in parallel
$worker = {
  param($items, $server, $upn, $okQ, $failQ)
  $parents = @{}
  foreach ($it in $items) {
    $u = $null
    try {
      if (-not $parents.ContainsKey($it.Dn)) { $parents[$it.Dn] = New-Object DirectoryServices.DirectoryEntry("LDAP://$server/$($it.Dn)") }
      $u = $parents[$it.Dn].Children.Add("CN=$($it.Sam)", 'user')
      $u.Properties['sAMAccountName'].Value = $it.Sam
      $u.Properties['userPrincipalName'].Value = "$($it.Sam)@$upn"
      $u.Properties['displayName'].Value = "Load test $($it.Sam)"
      $u.Properties['description'].Value = 'Hashslinger load test account (safe to delete)'
      if ($it.Spn) { [void]$u.Properties['servicePrincipalName'].Add($it.Spn) }
      if ($it.Password) { $u.Properties['userAccountControl'].Value = 514 } else { $u.Properties['userAccountControl'].Value = $it.Uac }
      $u.CommitChanges()
      if ($it.Password) {
        $u.Invoke('SetPassword', @([string]$it.Password)) | Out-Null
        $u.Properties['userAccountControl'].Value = $it.Uac
        $u.CommitChanges()
      }
      $okQ.Enqueue(1)
    }
    catch {
      $msg = $_.Exception.Message
      if ($_.Exception.InnerException) { $msg += ' | ' + $_.Exception.InnerException.Message }
      try { if ($u) { $parents[$it.Dn].Children.Remove($u) } } catch { }   # do not leave half-made accounts behind
      $failQ.Enqueue("$($it.Sam)|$msg")
    }
  }
}
$chunks = @(for ($t = 0; $t -lt $Threads; $t++) { , (New-Object System.Collections.Generic.List[object]) })
for ($i = 0; $i -lt $specs.Count; $i++) { $chunks[$i % $Threads].Add($specs[$i]) }
$okQ = New-Object 'System.Collections.Concurrent.ConcurrentQueue[int]'
$failQ = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$jobs = @()
for ($t = 0; $t -lt $Threads; $t++) {
  $ps = [powershell]::Create()
  $ps.RunspacePool = $pool
  [void]$ps.AddScript($worker).AddArgument($chunks[$t].ToArray()).AddArgument($Server).AddArgument($dnsRoot).AddArgument($okQ).AddArgument($failQ)
  $jobs += [pscustomobject]@{ PS = $ps; Async = $ps.BeginInvoke() }
}
$ok = 0; $fail = 0
$failSamples = New-Object System.Collections.Generic.List[string]
$failedSams = New-Object 'System.Collections.Generic.HashSet[string]'
$sw = [Diagnostics.Stopwatch]::StartNew(); $lastPrint = -10
while ($true) {
  $x = 0
  while ($okQ.TryDequeue([ref]$x)) { $ok++ }
  $m = $null
  while ($failQ.TryDequeue([ref]$m)) { $fail++; [void]$failedSams.Add($m.Split('|')[0]); if ($failSamples.Count -lt 12) { $failSamples.Add($m) } }
  $allDone = $true
  foreach ($j in $jobs) { if (-not $j.Async.IsCompleted) { $allDone = $false } }
  $el = $sw.Elapsed.TotalSeconds
  if (($el - $lastPrint) -ge 5 -or $allDone) {
    $lastPrint = $el
    $done = $ok + $fail
    $rate = if ($el -gt 0) { $done / $el } else { 0 }
    $left = if ($rate -gt 0) { [TimeSpan]::FromSeconds([int](($specs.Count - $done) / $rate)).ToString('hh\:mm\:ss') } else { '?' }
    Write-Host ("  {0} of {1} done ({2} failed), {3}/s, elapsed {4}, about {5} left" -f $done, $specs.Count, $fail, [Math]::Round($rate, 1), ([TimeSpan]::FromSeconds([int]$el)).ToString('hh\:mm\:ss'), $left)
  }
  if ($allDone -and $okQ.IsEmpty -and $failQ.IsEmpty) { break }
  Start-Sleep -Milliseconds 300
}
foreach ($j in $jobs) { try { $j.PS.EndInvoke($j.Async) | Out-Null } catch { }; $j.PS.Dispose() }
$pool.Close(); $pool.Dispose()

# ------------------------------------------------------------------ expected results (no passwords in this file)
$rows = foreach ($s in $specs) {
  if ($failedSams.Contains($s.Sam)) { continue }
  $rule = switch ($s.Category) { 'strong' { 'N' } 'service-strong' { 'N' } 'smartcard-weak' { 'N' } 'duplicate' { 'DupOnly' } default { 'Y' } }
  [pscustomobject]@{ sAMAccountName = $s.Sam; Category = $s.Category; Expected = $rule }
}
$rows | Export-Csv -LiteralPath $ExpectedFile -NoTypeInformation -Encoding ASCII

Write-Host ''
Write-Host ("Created {0} accounts, {1} failed, in {2}." -f $ok, $fail, ([TimeSpan]::FromSeconds([int]$sw.Elapsed.TotalSeconds)).ToString('hh\:mm\:ss')) -ForegroundColor Green
if ($fail) {
  Write-Host 'First failures (a stricter password policy rejects some weak passwords; the rest of the accounts are fine):' -ForegroundColor Yellow
  $failSamples | ForEach-Object { Write-Host "  $_" }
}
Write-Host ''
Write-Host 'By category:'
$rows | Group-Object Category | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-16} {1,6}" -f $_.Name, $_.Count) }
Write-Host ''
Write-Host "OU to scan:      $rootDn"
Write-Host "Expected file:   $ExpectedFile"
Write-Host "Custom list:     $customPath   (copy it into C:\Hashslinger\data\staging\custom\ so custom-weak accounts can match)"
Write-Host 'Next: add the OU to the scan scope, run the scan, then run this script with -CompareReport <report.csv>.'
