<#
.SYNOPSIS
  Hashslinger Running Tool: start a scan and watch it. For analysts. There are no settings here.
.DESCRIPTION
  Pick the scope, enter your EDIPI and the reason for the scan (or the CTO number), click Start. The request is
  written to the request folder and the on-demand task, which runs as the service account, validates it and runs the
  scan. Your EDIPI, the reason and your Windows account go into the audit log.
  The window also shows the current or last scan (step, progress, who started it) and opens the newest report.
  It cannot change any setting, and it never touches Active Directory or hashes.
  Open it from <install folder>\Hashslinger-Run.lnk (or Hashslinger-Run.ps1). Settings are changed in the Admin tool by an administrator.
#>
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\hashslinger.json'))
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json }
catch {
  [void][Windows.Forms.MessageBox]::Show("Cannot read the Hashslinger settings:`r`n$ConfigPath`r`n`r`n$($_.Exception.Message)`r`n`r`nAsk the administrator whether you are in the analyst group.", 'Hashslinger')
  exit 1
}
$taskName = 'Hashslinger-OnDemand'
$statusPath = [string]$cfg.status_path
$outputPath = [string]$cfg.output_path
$requestDir = [string]$cfg.request_dir
$script:lastOutput = $null
$edipiLen = 12
$reasonMin = 5
try { if ($cfg.edipi_length) { $edipiLen = [int]$cfg.edipi_length } } catch { }
try { if ($cfg.reason_min_length) { $reasonMin = [int]$cfg.reason_min_length } } catch { }

$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger: run a scan'; Width = 660; Height = 690; StartPosition = 'CenterScreen'; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false; Font = New-Object Drawing.Font('Segoe UI', 9) }
function Add-Label([string]$text, [int]$x, [int]$y, [int]$w = 600, [int]$h = 20, [bool]$bold = $false) {
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = $x; Top = $y; Width = $w; Height = $h }
  if ($bold) { $l.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold) }
  $form.Controls.Add($l)
  return $l
}

# ---------------------------------------------------------------- start a scan
[void](Add-Label 'Start a scan' 15 10 600 24 $true)
[void](Add-Label 'What to scan' 15 42 300)
$cmbOu = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 62; Width = 615; DropDownStyle = 'DropDownList' }
foreach ($o in @($cfg.target_ous)) { [void]$cmbOu.Items.Add([string]$o) }
if ($cmbOu.Items.Count) { $cmbOu.SelectedIndex = 0 }
[void](Add-Label ("EDIPI ($edipiLen characters)") 15 96 160)
$txtEdipi = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 116; Width = 150; MaxLength = $edipiLen }
[void](Add-Label ("Reason for this scan / CTO number (at least $reasonMin characters)") 185 96 445)
$txtReason = New-Object Windows.Forms.TextBox -Property @{ Left = 185; Top = 116; Width = 445; MaxLength = 500 }
$btnStart = New-Object Windows.Forms.Button -Property @{ Text = 'Start scan'; Left = 15; Top = 152; Width = 150; Height = 34; Enabled = $false }
$lblSent = Add-Label '' 175 160 455 40
$form.Controls.AddRange(@($cmbOu, $txtEdipi, $txtReason, $btnStart))

# ---------------------------------------------------------------- current / last scan
[void](Add-Label 'Current or last scan' 15 208 600 24 $true)
$lblState = Add-Label '' 15 234 615 22 $true
$lblStep = Add-Label '' 15 258 615
$lblDetail = Add-Label '' 15 280 615
$bar = New-Object Windows.Forms.ProgressBar -Property @{ Left = 15; Top = 306; Width = 615; Height = 20; Minimum = 0; Maximum = 7 }
$lblTime = Add-Label '' 15 332 615
$lblWho = Add-Label '' 15 354 615
$lblNote = Add-Label '' 15 376 615 20
$lblNote.ForeColor = [Drawing.Color]::Firebrick
$txtLog = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 402; Width = 615; Height = 170; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Font = New-Object Drawing.Font('Consolas', 9) }
$btnReport = New-Object Windows.Forms.Button -Property @{ Text = 'Open newest report'; Left = 15; Top = 586; Width = 170; Height = 32 }
$btnFolder = New-Object Windows.Forms.Button -Property @{ Text = 'Open reports folder'; Left = 195; Top = 586; Width = 170; Height = 32 }
$form.Controls.AddRange(@($bar, $txtLog, $btnReport, $btnFolder))

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
    $lblSent.ForeColor = [Drawing.Color]::SeaGreen
    $lblSent.Text = 'Request sent. The scan runs as the service account; watch it below. If a scan is already running, yours starts when it finishes.'
    $txtReason.Clear()
  }
  catch {
    $lblSent.ForeColor = [Drawing.Color]::Firebrick
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

function Parse-Utc([string]$s) { [DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }

# ---------------------------------------------------------------- live status (read only)
$timer = New-Object Windows.Forms.Timer -Property @{ Interval = 2000 }
$timer.Add_Tick({
  try { $s = [IO.File]::ReadAllText($statusPath) | ConvertFrom-Json }
  catch { $lblState.Text = 'No scan has run yet.'; $lblStep.Text = ''; $lblDetail.Text = ''; $lblTime.Text = ''; $lblWho.Text = ''; $lblNote.Text = ''; return }
  $now = [DateTime]::UtcNow
  $started = Parse-Utc $s.started_utc
  $updated = Parse-Utc $s.updated_utc
  $running = ($s.state -eq 'running')
  $end = if ($running) { $now } else { $updated }
  $lblState.Text = ('Run {0}: {1}' -f $s.run_id, ([string]$s.state).ToUpper())
  $lblStep.Text = ('Step {0} of {1}: {2}' -f $s.stage, $s.stages, $s.message)
  $lblDetail.Text = if ($s.detail) { [string]$s.detail } elseif ($s.accounts_received -gt 0) { "$($s.accounts_received) accounts received" } else { '' }
  $bar.Value = [Math]::Min([int]$s.stage, 7)
  $stepFor = ''
  if ($s.stage_started_utc) { $stepFor = '   |   this step ' + ($end - (Parse-Utc $s.stage_started_utc)).ToString('hh\:mm\:ss') }
  $lblTime.Text = 'Elapsed ' + ($end - $started).ToString('hh\:mm\:ss') + $stepFor
  $by = if ($s.requested_by) { [string]$s.requested_by } else { [string]$s.run_as }
  $lblWho.Text = 'Started by: ' + $by
  $stale = $running -and (($now - $updated).TotalSeconds -gt 90)
  $lblNote.Text = if ($stale) { 'No update for over 90 seconds. The scan may have stopped. Tell the administrator.' } elseif ($running) { 'A scan is running. A new request waits until it finishes.' } else { '' }
  if ($s.log) {
    $txt = (@($s.log) -join "`r`n")
    if ($txt -ne $txtLog.Text) { $txtLog.Text = $txt; $txtLog.SelectionStart = $txtLog.Text.Length; $txtLog.ScrollToCaret() }
  }
  if ($s.state -eq 'failed') { $lblDetail.Text = 'Failed: ' + [string]$s.error }
  elseif ($s.state -eq 'success' -and $s.output) { $script:lastOutput = [string]$s.output; $lblDetail.Text = 'Report: ' + [string]$s.output }
})
$timer.Start()
Test-Ready
[void]$form.ShowDialog()
