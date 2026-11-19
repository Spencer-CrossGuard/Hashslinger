<#
.SYNOPSIS
  Hashslinger Running Tool: start a scan and watch it. For analysts. There are no settings here.
.DESCRIPTION
  Pick the scope, enter your EDIPI and the reason for the scan (or the CTO number), click Start. The request is
  written to the request folder and the on-demand task, which runs as the service account, validates it and runs the
  scan. Your EDIPI, the reason and your Windows account go into the audit log.
  The window shows the current or last scan as a 7-step pipeline with a live status badge, and when a scan has finished it
  summarizes the report: how many accounts were flagged, High against Medium, and the main reasons.
  It cannot change any setting, and it never touches Active Directory or hashes.
  Open it from the Hashslinger Running Tool shortcut (desktop or Start menu). Settings are changed in the Admin tool.
#>
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\hashslinger.json'))
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'HashslingerTheme.ps1')

try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json }
catch {
  [void][Windows.Forms.MessageBox]::Show("Cannot read the Hashslinger settings:`r`n$ConfigPath`r`n`r`n$($_.Exception.Message)`r`n`r`nAsk the administrator whether you are in the analyst group.", 'Hashslinger')
  exit 1
}
$taskName = 'Hashslinger-OnDemand'
$statusPath = [string]$cfg.status_path
$outputPath = [string]$cfg.output_path
$requestDir = [string]$cfg.request_dir
$edipiLen = 11
$reasonMin = 5
try { if ($cfg.edipi_length) { $edipiLen = [int]$cfg.edipi_length } } catch { }
try { if ($cfg.reason_min_length) { $reasonMin = [int]$cfg.reason_min_length } } catch { }
$script:summaryFor = ''

$wa = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form = New-Object Windows.Forms.Form -Property @{
  Text = 'Hashslinger'; Width = [Math]::Min(800, $wa.Width - 10); Height = [Math]::Min(880, $wa.Height - 10)
  MinimumSize = New-Object Drawing.Size(640, 480); StartPosition = 'CenterScreen'; AutoScroll = $true
}
$C = $script:HsC

function Add-Lbl($parent, [string]$text, [int]$x, [int]$y, [int]$w, [int]$h = 18, [double]$size = 9, [string]$style = 'Regular', $color = $null) {
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = $x; Top = $y; Width = $w; Height = $h; AutoSize = $false }
  $l.Font = New-HsFont $size $style
  if ($color) { $l.ForeColor = $color }
  $parent.Controls.Add($l)
  return $l
}

# ---------------------------------------------------------------- header
[void](Add-HsHeader $form 'Hashslinger' 'Password exposure scan  |  run a scan, watch it, read the result' 76 $false)

# ---------------------------------------------------------------- card: start a scan
$cardA = New-HsCard 16 92 752 148 'Start a scan'
[void](Add-Lbl $cardA 'What to scan' 16 40 300)
$cmbOu = New-Object Windows.Forms.ComboBox -Property @{ Left = 16; Top = 60; Width = 320; DropDownStyle = 'DropDownList' }
foreach ($o in @($cfg.target_ous)) { [void]$cmbOu.Items.Add([string]$o) }
if ($cmbOu.Items.Count) { $cmbOu.SelectedIndex = 0 }
[void](Add-Lbl $cardA "EDIPI ($edipiLen characters)" 352 40 160)
$txtEdipi = New-Object Windows.Forms.TextBox -Property @{ Left = 352; Top = 60; Width = 150; MaxLength = $edipiLen }
[void](Add-Lbl $cardA "Reason or CTO number (at least $reasonMin characters)" 518 40 220)
$txtReason = New-Object Windows.Forms.TextBox -Property @{ Left = 518; Top = 60; Width = 218; MaxLength = 500 }
$btnStart = New-Object Windows.Forms.Button -Property @{ Text = 'Start scan'; Left = 16; Top = 98; Width = 160; Height = 34; Enabled = $false; Tag = 'primary' }
$lblSent = Add-Lbl $cardA '' 190 98 548 36 9
$cardA.Controls.AddRange(@($cmbOu, $txtEdipi, $txtReason, $btnStart))

# ---------------------------------------------------------------- card: current scan
$cardB = New-HsCard 16 252 752 322 'Current scan'
$badge = New-HsBadge 16 44 130 28
$lblRun = Add-Lbl $cardB '' 158 49 260 20 9.5 'Bold'
$lblWho = Add-Lbl $cardB '' 420 49 316 20 9 'Regular' $C.Muted
$lblWho.TextAlign = 'MiddleRight'
$stepper = New-HsStepper 8 80 736 70 @('Checks', 'Wordlists', 'Patterns', 'Pull from AD', 'Match', 'Report', 'Wipe')
$bar = New-HsProgress 16 156 720 10
$lblElapsed = Add-Lbl $cardB '' 16 174 230 20 9.5 'Bold'
$lblStepTime = Add-Lbl $cardB '' 252 174 230 20 9.5 'Regular' $C.Muted
$lblAccts = Add-Lbl $cardB '' 488 174 248 20 9.5 'Regular' $C.Muted
$lblAccts.TextAlign = 'MiddleRight'
$lblDetail = Add-Lbl $cardB '' 16 198 720 20 9
$lblNote = Add-Lbl $cardB '' 16 218 720 18 9 'Bold' $C.Red
$txtLog = New-Object Windows.Forms.TextBox -Property @{ Left = 16; Top = 240; Width = 720; Height = 70; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical' }
$txtLog.Font = New-HsFont 8.5 'Regular' 'Consolas'
$cardB.Controls.AddRange(@($badge, $stepper, $bar, $txtLog))

# ---------------------------------------------------------------- card: results
$cardC = New-HsCard 16 586 752 262 'Results of the last scan'
$btnReport = New-Object Windows.Forms.Button -Property @{ Text = 'Open newest report'; Left = 306; Top = 6; Width = 150; Height = 30 }
$btnFolder = New-Object Windows.Forms.Button -Property @{ Text = 'Reports folder'; Left = 466; Top = 6; Width = 150; Height = 30 }
$btnGuide = New-Object Windows.Forms.Button -Property @{ Text = 'Open the guide'; Left = 626; Top = 6; Width = 110; Height = 30 }
$tileA = New-HsTile 16 46 170 64 'accounts scanned' $C.Blue
$tileF = New-HsTile 198 46 170 64 'accounts flagged' $C.Amber
$tileH = New-HsTile 380 46 170 64 'High severity' $C.Red
$tileM = New-HsTile 562 46 174 64 'Medium severity' $C.Amber
$donut = New-HsDonut 16 122 130
$bars = New-HsBars 160 124 576 128
$cardC.Controls.AddRange(@($btnReport, $btnFolder, $btnGuide, $tileA, $tileF, $tileH, $tileM, $donut, $bars))

$form.Controls.AddRange(@($cardA, $cardB, $cardC))
Set-HsTheme $form
# the card titles and the drawn panels keep their own look; make sure the labels in the cards are readable
foreach ($lb in @($lblSent, $lblDetail)) { $lb.ForeColor = $C.Text }

# ---------------------------------------------------------------- start a scan
function Test-Ready {
  $ok = ($cmbOu.SelectedItem -and $txtEdipi.Text -match ('^[0-9A-Za-z]{' + $edipiLen + '}$') -and $txtReason.Text.Trim().Length -ge $reasonMin)
  $btnStart.Enabled = [bool]$ok
}
$txtEdipi.Add_TextChanged({ Test-Ready }); $txtReason.Add_TextChanged({ Test-Ready }); $cmbOu.Add_SelectedIndexChanged({ Test-Ready })

$btnStart.Add_Click({
  $btnStart.Enabled = $false
  try {
    $req = @{ ou = [string]$cmbOu.SelectedItem; output_dir = $outputPath; edipi = $txtEdipi.Text.Trim(); reason = $txtReason.Text.Trim(); requested_by = "$env:USERDOMAIN\$env:USERNAME" }
    $file = Join-Path $requestDir ("req_{0}.json" -f [guid]::NewGuid())
    $req | ConvertTo-Json | Set-Content -LiteralPath $file -Encoding UTF8
    # make the file's owner this person, so the audit log can name who started the scan
    try { $acl = Get-Acl -LiteralPath $file; $acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User); Set-Acl -LiteralPath $file -AclObject $acl } catch { }
    Start-ScheduledTask -TaskName $taskName
    $lblSent.ForeColor = $C.Green
    $lblSent.Text = 'Request sent. The scan runs as the service account; watch it below. If a scan is already running, yours starts when it finishes.'
    $txtReason.Clear()
  }
  catch {
    $lblSent.ForeColor = $C.Red
    $lblSent.Text = 'Could not send the request: ' + $_.Exception.Message + ' (ask the administrator whether manual scans are turned on and you are in the analyst group)'
  }
  Test-Ready
})

$btnReport.Add_Click({
  try {
    $f = Get-ChildItem -LiteralPath $outputPath -Filter 'report_*.csv' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($f) { Start-Process -FilePath $f.FullName } else { [void][Windows.Forms.MessageBox]::Show('There is no report yet.', 'Hashslinger') }
  } catch { [void][Windows.Forms.MessageBox]::Show('Cannot open the reports: ' + $_.Exception.Message, 'Hashslinger') }
})
$btnFolder.Add_Click({ if (Test-Path -LiteralPath $outputPath) { Start-Process explorer.exe -ArgumentList "`"$outputPath`"" } else { [void][Windows.Forms.MessageBox]::Show("Not found: $outputPath", 'Hashslinger') } })
$btnGuide.Add_Click({
  $g = Join-Path $env:ProgramData 'Hashslinger\Hashslinger-Analyst-Guide.html'
  if (Test-Path -LiteralPath $g) { Start-Process -FilePath $g } else { [void][Windows.Forms.MessageBox]::Show('The guide has not been installed on this server yet. Ask your administrator.', 'Hashslinger') }
})

function Parse-Utc([string]$s) { [DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }

# ---------------------------------------------------------------- results summary (reads the finished report)
function Get-ShortReason([string]$part) {
  $p = $part.Trim()
  if (-not $p) { return $null }
  if ($p -match 'HIBP') { return @('Breach list (HIBP)', $C.Red) }
  if ($p -match 'rockyou') { return @('Rockyou list', $C.Red) }
  if ($p -match 'custom') { return @('Organization list', $C.Red) }
  if ($p -match 'No password') { return @('No password set', $C.Red) }
  if ($p -match 'Reversible') { return @('Reversible encryption', $C.Red) }
  if ($p -match 'pattern') { return @('Weak pattern', $C.Amber) }
  if ($p -match 'Duplicate') { return @('Shared password', $C.Amber) }
  if ($p -match 'LM hash') { return @('LM hash stored', $C.Amber) }
  return @($p, $C.Muted)
}
function Clear-Results([string]$why) {
  Set-HsTile $tileF '-'; Set-HsTile $tileH '-'; Set-HsTile $tileM '-'
  Set-HsDonut $donut @() '' $why
  Set-HsBars $bars @()
}
function Show-ReportSummary([string]$path) {
  $script:summaryFor = $path
  try {
    $fi = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($fi.Length -gt 80MB) { Clear-Results 'report too big to chart'; return }
    $rows = @(Import-Csv -LiteralPath $path)
    $high = 0; $med = 0
    $counts = @{}; $colors = @{}
    foreach ($row in $rows) {
      if ([string]$row.Severity -eq 'High') { $high++ } else { $med++ }
      foreach ($part in ([string]$row.'Flag Reason' -split ';')) {
        $r = Get-ShortReason $part
        if ($r) { $counts[$r[0]] = 1 + [int]$counts[$r[0]]; $colors[$r[0]] = $r[1] }
      }
    }
    Set-HsTile $tileF ('{0:N0}' -f $rows.Count); Set-HsTile $tileH ('{0:N0}' -f $high); Set-HsTile $tileM ('{0:N0}' -f $med)
    Set-HsDonut $donut @(@{ Value = $high; Color = $C.Red }, @{ Value = $med; Color = $C.Amber }) ('{0:N0}' -f $rows.Count) 'flagged'
    $list = @($counts.Keys | Sort-Object { -[int]$counts[$_] } | Select-Object -First 5 | ForEach-Object { [pscustomobject]@{ Label = $_; Value = $counts[$_]; Color = $colors[$_] } })
    Set-HsBars $bars $list
  } catch { Clear-Results 'summary not available' }
}

# ---------------------------------------------------------------- live status (read only)
$timer = New-Object Windows.Forms.Timer -Property @{ Interval = 1500 }
$timer.Add_Tick({
  try { $s = [IO.File]::ReadAllText($statusPath) | ConvertFrom-Json }
  catch {
    Set-HsBadge $badge 'NO SCAN YET' $C.Muted; Set-HsStepper $stepper 'idle' 0; Set-HsProgress $bar 0 7
    $lblRun.Text = ''; $lblWho.Text = ''; $lblElapsed.Text = ''; $lblStepTime.Text = ''; $lblAccts.Text = ''; $lblDetail.Text = 'No scan has run on this server yet.'; $lblNote.Text = ''
    return
  }
  try {
    $now = [DateTime]::UtcNow
    $started = Parse-Utc $s.started_utc
    $updated = Parse-Utc $s.updated_utc
    $state = [string]$s.state
    $running = ($state -eq 'running')
    $end = if ($running) { $now } else { $updated }
    $stage = [int]$s.stage
    switch ($state) {
      'running' { Set-HsBadge $badge 'RUNNING' $C.Blue }
      'success' { Set-HsBadge $badge 'SUCCESS' $C.Green }
      'failed'  { Set-HsBadge $badge 'FAILED' $C.Red }
      default   { Set-HsBadge $badge $state.ToUpper() $C.Muted }
    }
    Set-HsStepper $stepper $state $stage
    Set-HsProgress $bar $(if ($state -eq 'success') { 7 } else { [Math]::Max(0, $stage - 1) + 0.5 }) 7
    $lblRun.Text = 'Run ' + [string]$s.run_id
    $by = if ($s.requested_by) { [string]$s.requested_by } else { [string]$s.run_as }
    $lblWho.Text = 'Started by ' + $by
    $lblElapsed.Text = 'Elapsed ' + ($end - $started).ToString('hh\:mm\:ss')
    $lblStepTime.Text = if ($s.stage_started_utc) { 'This step ' + ($end - (Parse-Utc $s.stage_started_utc)).ToString('hh\:mm\:ss') } else { '' }
    $lblAccts.Text = if ([int]$s.accounts_received -gt 0) { ('{0:N0} accounts received' -f [int]$s.accounts_received) } else { '' }
    $lblDetail.Text = if ($s.detail) { 'Step ' + $stage + ' of ' + $s.stages + ': ' + [string]$s.message + '  |  ' + [string]$s.detail } else { 'Step ' + $stage + ' of ' + $s.stages + ': ' + [string]$s.message }
    $stale = $running -and (($now - $updated).TotalSeconds -gt 90)
    $lblNote.Text = if ($stale) { 'No update for over 90 seconds. The scan may have stopped. Tell the administrator.' } elseif ($running) { 'A scan is running. A new request waits until it finishes.' } else { '' }
    if ($s.log) {
      $txt = (@($s.log) -join "`r`n")
      if ($txt -ne $txtLog.Text) { $txtLog.Text = $txt; $txtLog.SelectionStart = $txtLog.Text.Length; $txtLog.ScrollToCaret() }
    }
    if ($state -eq 'failed') { $lblDetail.Text = 'Failed: ' + [string]$s.error }
    if ($state -eq 'success' -and $s.output) {
      Set-HsTile $tileA ('{0:N0}' -f [int]$s.accounts_received)
      if ([string]$s.output -ne $script:summaryFor) { Show-ReportSummary ([string]$s.output) }
    }
  } catch { }
})
$timer.Start()
Clear-Results 'run a scan to see results'
Set-HsTile $tileA '-'
Test-Ready
[void]$form.ShowDialog()
