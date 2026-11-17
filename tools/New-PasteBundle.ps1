<#
.SYNOPSIS
  Builds dist\Rebuild-Hashslinger.ps1: one paste-able PowerShell file that recreates the core Hashslinger
  files and then verifies each one (byte length, line count, SHA-256).
.DESCRIPTION
  Run:  powershell -NoProfile -ExecutionPolicy Bypass -File tools\New-PasteBundle.ps1
  Reads the files from the Hashslinger folder this script sits in (or -Source) and writes the bundle to
  <Source>\dist\Rebuild-Hashslinger.ps1 (or -Out). Line endings are normalized to LF, so a Windows copy
  with CRLF line endings gives the same hashes as the git copy.
  Only an explicit list of core files is bundled. Local configs, the built exe, CI files and the lab
  diagnostics (which change AD) are never included.
  After writing, it parses the bundle with PowerShell's own parser (without running it) and checks that
  every embedded file comes back out byte for byte.
#>
param(
  [string]$Source = (Split-Path -Parent $PSScriptRoot),
  [string]$Out
)
$ErrorActionPreference = 'Stop'
$Source = (Resolve-Path -LiteralPath $Source).Path
if (-not $Out) { $Out = Join-Path $Source 'dist\Rebuild-Hashslinger.ps1' }
if (-not (Test-Path -LiteralPath (Join-Path $Source 'powershell\Setup-Hashslinger.ps1'))) {
  throw "$Source does not look like the Hashslinger folder (no powershell\Setup-Hashslinger.ps1). Use -Source."
}

# ---------------------------------------------------------------- which files
$include = @('README.md', 'TEST-PLAN.md', '*.cmd', 'cs\*.cs', 'cs\*.csproj', 'config\*.example.json',
  'config\pattern_rules.json', 'docs\*.md', 'powershell\*.ps1')
$found = New-Object System.Collections.Generic.List[string]
foreach ($pat in $include) {
  $dir = Split-Path -Parent $pat
  $leaf = Split-Path -Leaf $pat
  $full = if ($dir) { Join-Path $Source $dir } else { $Source }
  if (-not (Test-Path -LiteralPath $full)) { continue }
  foreach ($f in @(Get-ChildItem -LiteralPath $full -Filter $leaf -File | Where-Object { $_.Name -like $leaf })) {
    $rel = if ($dir) { ($dir -replace '\\', '/') + '/' + $f.Name } else { $f.Name }
    if (-not $found.Contains($rel)) { $found.Add($rel) }
  }
}
$paths = $found.ToArray()
[Array]::Sort($paths, [StringComparer]::Ordinal)   # fixed order, so the fingerprint is the same everywhere

# ---------------------------------------------------------------- read, normalize, check
$sha = [Security.Cryptography.SHA256]::Create()
function HexOf([byte[]]$b) { [BitConverter]::ToString($sha.ComputeHash($b)).Replace('-', '') }
$entries = @()
$problems = @()
foreach ($p in $paths) {
  $raw = [IO.File]::ReadAllBytes((Join-Path $Source ($p -replace '/', '\')))
  $start = 0
  if ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF) {
    $start = 3
    Write-Warning "$p starts with a UTF-8 byte order mark; it is left out of the bundle (the git copy has none)."
  }
  $nonAscii = $false
  for ($i = $start; $i -lt $raw.Length; $i++) { if ($raw[$i] -gt 127) { $nonAscii = $true; break } }
  if ($nonAscii) { $problems += "${p}: has non-ASCII characters"; continue }
  $text = [Text.Encoding]::ASCII.GetString($raw, $start, $raw.Length - $start) -replace "`r`n", "`n"
  if ($text.Contains("`r")) { $problems += "${p}: has a stray carriage return" }
  if ($text -match "(?m)^'@") { $problems += "${p}: a line starts with '@, which would end the embedded text early" }
  if ($p.Contains("'")) { $problems += "${p}: apostrophe in the file name" }
  $bytes = [Text.Encoding]::ASCII.GetBytes($text)
  $entries += [pscustomobject]@{ Path = $p; Text = $text; Bytes = $bytes.Length; Lines = $text.Split("`n").Count - 1; Sha256 = (HexOf $bytes) }
}
if ($problems.Count) { throw ("Cannot bundle:`n  " + ($problems -join "`n  ")) }

$fpText = ($entries | ForEach-Object { "$($_.Path)`n$($_.Sha256)`n" }) -join ''
$fingerprint = HexOf ([Text.Encoding]::ASCII.GetBytes($fpText))
$total = 0; foreach ($e in $entries) { $total += $e.Bytes }
$commit = 'unknown'
try { $c = & git -C $Source rev-parse --short HEAD 2>$null; if ($LASTEXITCODE -eq 0 -and $c) { $commit = "$c" } } catch { }
$date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)

# ---------------------------------------------------------------- bundle text
$Head = @'
<#
.SYNOPSIS
  Recreates the core Hashslinger files from this one script, then checks every file's byte length,
  line count and SHA-256 against the originals.
.DESCRIPTION
  Two ways to use it:
    A. Recommended: paste this whole file into Notepad, save it as Rebuild-Hashslinger.ps1, then run
         powershell -NoProfile -ExecutionPolicy Bypass -File .\Rebuild-Hashslinger.ps1 -Destination C:\Hashslinger-src
       Add -VerifyOnly to re-check a folder without writing, or -Force to write into a folder that has files.
    B. Paste it straight into a PowerShell window. It writes to .\Hashslinger under the current folder, or
       to the folder in $HashslingerDestination if you set that first. Large pastes into a console are slow.
  Read the RESULT line at the end. Every row must say PASS.
  It only writes files under the destination. It runs nothing it creates, makes no network calls and
  does not touch Active Directory. Files are written as ASCII with LF line endings, exactly as in git.
  Everything after the next two lines is one block, so a paste that was cut short fails with a
  'Missing closing' parse error and nothing is written.
  Built from commit {COMMIT}, generated {DATE} UTC.
  {COUNT} files, {BYTES} bytes. Bundle fingerprint: {FINGERPRINT}
#>
$__hsArgs = $args
$__hsScript = $PSCommandPath
& {   # one block: a truncated paste is a parse error, never a partial run
$ErrorActionPreference = 'Stop'
$ExpectedFingerprint = '{FINGERPRINT}'

# ---- arguments (parsed by hand so the same file also works when pasted into a console)
$Destination = $null; $VerifyOnly = $false; $Force = $false
for ($i = 0; $i -lt $__hsArgs.Count; $i++) {
  $a = [string]$__hsArgs[$i]
  if ($a -match '^-Dest(ination)?:?$') {
    if ($i + 1 -ge $__hsArgs.Count) { throw '-Destination needs a folder' }
    $i++; $Destination = [string]$__hsArgs[$i]
  }
  elseif ($a -match '^-VerifyOnly$') { $VerifyOnly = $true }
  elseif ($a -match '^-Force$') { $Force = $true }
  elseif (-not $Destination -and $a -notlike '-*') { $Destination = $a }
  else { throw "Unknown argument '$a'. Use: -Destination <folder> [-VerifyOnly] [-Force]" }
}
if (-not $Destination -and $global:HashslingerDestination) { $Destination = [string]$global:HashslingerDestination }
if (-not $Destination) { $Destination = Join-Path (Get-Location).Path 'Hashslinger' }
'@

$Tail = @'
# ---- write
$dest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
Write-Host "Hashslinger rebuild: $($Manifest.Count) files -> $dest"
$missingFromBundle = @($Manifest | Where-Object { -not $Files.Contains($_.Path) })
if (-not $VerifyOnly) {
  if ((Test-Path -LiteralPath $dest) -and (Get-ChildItem -LiteralPath $dest -Force | Select-Object -First 1) -and -not $Force) {
    throw "$dest already has files in it. Pick an empty folder, or add -Force to overwrite."
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  foreach ($m in $Manifest) {
    if (-not $Files.Contains($m.Path)) { continue }
    $full = Join-Path $dest ($m.Path -replace '/', '\')
    $dir = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $text = $Files[$m.Path] -replace "`r`n", "`n"     # Notepad saves CRLF; the originals are LF
    [IO.File]::WriteAllBytes($full, $enc.GetBytes($text))
  }
}

# ---- verify
$sha = [Security.Cryptography.SHA256]::Create()
$fpText = New-Object System.Text.StringBuilder
$rows = foreach ($m in $Manifest) {
  $full = Join-Path $dest ($m.Path -replace '/', '\')
  if (-not (Test-Path -LiteralPath $full)) {
    $why = if (-not $Files.Contains($m.Path)) { 'not in the pasted bundle (paste cut short?)' } else { 'file not found' }
    [void]$fpText.Append("$($m.Path)`nMISSING`n")
    [pscustomobject]@{ Status = 'FAIL'; File = $m.Path; Bytes = "0 / $($m.Bytes)"; Lines = "0 / $($m.Lines)"; Problem = $why }
    continue
  }
  $bytes = [IO.File]::ReadAllBytes($full)
  $lines = 0; foreach ($b in $bytes) { if ($b -eq 10) { $lines++ } }
  $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')
  [void]$fpText.Append("$($m.Path)`n$hash`n")
  $problems = @()
  if ($bytes.Length -ne $m.Bytes) { $problems += "length off by $($bytes.Length - $m.Bytes) bytes" }
  if ($lines -ne $m.Lines) { $problems += "line count off by $($lines - $m.Lines)" }
  if ($hash -ne $m.Sha256) { $problems += $(if ($problems.Count) { 'content differs' } else { 'same length but content differs' }) }
  [pscustomobject]@{
    Status = $(if ($problems.Count) { 'FAIL' } else { 'PASS' }); File = $m.Path
    Bytes = "$($bytes.Length) / $($m.Bytes)"; Lines = "$lines / $($m.Lines)"; Problem = ($problems -join '; ')
  }
}
$fingerprint = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($fpText.ToString()))).Replace('-', '')

Write-Host ''
Write-Host 'Bytes and Lines are shown as actual / expected.'
$rows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
$failed = @($rows | Where-Object Status -eq 'FAIL')
foreach ($r in $failed) { Write-Host ("FAIL  {0}: {1}" -f $r.File, $r.Problem) -ForegroundColor Red }
Write-Host ("Fingerprint: {0}" -f $fingerprint)
Write-Host ("Expected:    {0}" -f $ExpectedFingerprint)
$ok = ($failed.Count -eq 0 -and $missingFromBundle.Count -eq 0 -and $fingerprint -eq $ExpectedFingerprint)
if ($ok) { Write-Host ("RESULT: PASS. All {0} files match in length, line count and SHA-256." -f $Manifest.Count) -ForegroundColor Green }
else { Write-Host ("RESULT: FAIL. {0} of {1} files do not match. Re-copy the bundle and run it again." -f $failed.Count, $Manifest.Count) -ForegroundColor Red }
if ($__hsScript) { exit $(if ($ok) { 0 } else { 1 }) }   # pasted into a console: leave the window open
}   # end of bundle
'@

$sb = New-Object System.Text.StringBuilder
function Add-Line([string]$s) { [void]$sb.Append($s).Append("`n") }
$headText = ($Head -replace "`r`n", "`n").Replace('{COMMIT}', $commit).Replace('{DATE}', $date)
$headText = $headText.Replace('{COUNT}', [string]$entries.Count).Replace('{BYTES}', [string]$total)
Add-Line $headText.Replace('{FINGERPRINT}', $fingerprint)
Add-Line ''
Add-Line '# ---- manifest: what each file must look like once written'
Add-Line '$Manifest = @('
for ($i = 0; $i -lt $entries.Count; $i++) {
  $e = $entries[$i]
  $comma = if ($i -lt $entries.Count - 1) { ',' } else { '' }
  Add-Line ('  [pscustomobject]@{{ Path = ''{0}''; Bytes = {1}; Lines = {2}; Sha256 = ''{3}'' }}{4}' -f $e.Path, $e.Bytes, $e.Lines, $e.Sha256, $comma)
}
Add-Line ')'
Add-Line ''
Add-Line '# ---- file contents, each embedded exactly as committed'
Add-Line '$Files = [ordered]@{}'
foreach ($e in $entries) {
  Add-Line ''
  Add-Line ('$Files[''{0}''] = @''' -f $e.Path)
  Add-Line ($e.Text + "`n'@")
}
Add-Line ''
Add-Line ($Tail -replace "`r`n", "`n")
$bundle = $sb.ToString()

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
[IO.File]::WriteAllText($Out, $bundle, (New-Object System.Text.ASCIIEncoding))

# ---------------------------------------------------------------- self-check: parse (never run) the bundle
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Out, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "The bundle does not parse: $($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))" }
$assigns = @($ast.FindAll({
      param($n)
      $n -is [Management.Automation.Language.AssignmentStatementAst] -and
      $n.Left -is [Management.Automation.Language.IndexExpressionAst] -and
      $n.Left.Target -is [Management.Automation.Language.VariableExpressionAst] -and
      $n.Left.Target.VariablePath.UserPath -eq 'Files'
    }, $true))
$byPath = @{}
foreach ($a in $assigns) { $byPath[$a.Left.Index.Value] = $a.Right.Expression.Value }
$bad = @($entries | Where-Object { -not $byPath.ContainsKey($_.Path) -or (($byPath[$_.Path] -replace "`r`n", "`n") -cne $_.Text) })
if ($assigns.Count -ne $entries.Count -or $bad.Count) {
  throw "Round-trip check failed for: $(($bad | ForEach-Object Path) -join ', ')"
}

Write-Host ("Wrote {0}" -f $Out)
Write-Host ("  {0} files, {1} content bytes, {2} bundle bytes" -f $entries.Count, $total, $bundle.Length)
Write-Host ("  Fingerprint: {0}" -f $fingerprint)
Write-Host '  Parser round-trip check: PASS (every file comes back out of the bundle byte for byte)' -ForegroundColor Green
