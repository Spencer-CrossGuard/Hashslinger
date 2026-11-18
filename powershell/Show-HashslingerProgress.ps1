<#
.SYNOPSIS
  Live progress viewer. Read-only; reads the status file written by Hashslinger.exe.
.DESCRIPTION
  Independent of whoever started the scan: any person with read access to the status folder can open
  this at any time, including after the starter has logged off. It cannot start, stop or change a scan.
  Heartbeat: the scan rewrites the file every ~5 seconds, so "no update for 60s+" means it likely died.
#>
param(
  [string]$StatusPath = 'C:\Hashslinger\status\status.json',
  [string]$ConfigPath
)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
if (-not $PSBoundParameters.ContainsKey('StatusPath') -and -not $ConfigPath) {
  $guess = Join-Path $PSScriptRoot '..\..\config\hashslinger.json'
  if (Test-Path $guess) { $ConfigPath = $guess }
}
if ($ConfigPath) { $StatusPath = (Get-Content $ConfigPath -Raw | ConvertFrom-Json).status_path }

$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger progress'; Width = 680; Height = 560; StartPosition = 'CenterScreen' }
function L($x, $y, $w, $h = 20, $bold = $false) {
  $l = New-Object Windows.Forms.Label -Property @{ Left = $x; Top = $y; Width = $w; Height = $h }
  if ($bold) { $l.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold) }
  $form.Controls.Add($l); $l
}
$lblState = L 15 12 570 24 $true
$lblWho = L 15 40 570
$lblStage = L 15 68 570
$lblDetail = L 15 90 570
$bar = New-Object Windows.Forms.ProgressBar -Property @{ Left = 15; Top = 118; Width = 575; Height = 22; Minimum = 0; Maximum = 7 }
$form.Controls.Add($bar)
$lblTime = L 15 148 570
$lblWarn = L 15 172 570 20
$lblWarn.ForeColor = [Drawing.Color]::Firebrick
$lblOut = L 15 198 570 36
$btnReport = New-Object Windows.Forms.Button -Property @{ Text = 'Open report'; Left = 15; Top = 245; Width = 130; Enabled = $false }
$btnFolder = New-Object Windows.Forms.Button -Property @{ Text = 'Open report folder'; Left = 155; Top = 245; Width = 150; Enabled = $false }
$form.Controls.AddRange(@($btnReport, $btnFolder))
$txtLog = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 282; Width = 635; Height = 230; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Font = (New-Object Drawing.Font('Consolas', 9)); Anchor = 'Top,Left,Right,Bottom' }
$form.Controls.Add($txtLog)
$script:out = $null
$btnReport.Add_Click({ if ($script:out -and (Test-Path $script:out)) { Start-Process $script:out } })
$btnFolder.Add_Click({ if ($script:out) { Start-Process explorer.exe (Split-Path $script:out) } })

function Parse-Utc($s) { [DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }

$timer = New-Object Windows.Forms.Timer -Property @{ Interval = 1500 }
$timer.Add_Tick({
  try { $s = [IO.File]::ReadAllText($StatusPath) | ConvertFrom-Json }
  catch { $lblState.Text = 'No scan status yet (waiting for ' + $StatusPath + ')'; return }
  $now = [DateTime]::UtcNow
  $started = Parse-Utc $s.started_utc
  $updated = Parse-Utc $s.updated_utc
  $running = ($s.state -eq 'running')
  $end = if ($running) { $now } else { $updated }
  $lblState.Text = ('Run {0}: {1}' -f $s.run_id, $s.state.ToUpper())
  $lblWho.Text = ('Started by {0}{1} on {2}' -f $s.run_as, $(if ($s.requested_by) { " (requested by $($s.requested_by))" } else { '' }), $s.host)
  $lblStage.Text = ('Step {0} of {1}: {2}' -f $s.stage, $s.stages, $s.message)
  $lblDetail.Text = if ($s.detail) { $s.detail } elseif ($s.accounts_received -gt 0) { "$($s.accounts_received) accounts received" } else { '' }
  $bar.Value = [Math]::Min([int]$s.stage, 7)
  $stepFor = ''
  if ($s.stage_started_utc) { $stepFor = '   |   this step ' + ($end - (Parse-Utc $s.stage_started_utc)).ToString('hh\:mm\:ss') }
  $msgAgo = ''
  if ($running -and $s.detail_utc) { $msgAgo = '   |   last message ' + [int]($now - (Parse-Utc $s.detail_utc)).TotalSeconds + 's ago' }
  $lblTime.Text = 'Elapsed ' + ($end - $started).ToString('hh\:mm\:ss') + $stepFor + $msgAgo
  if ($s.log) {
    $txt = ($s.log -join "`r`n")
    if ($txt -ne $txtLog.Text) { $txtLog.Text = $txt; $txtLog.SelectionStart = $txtLog.Text.Length; $txtLog.ScrollToCaret() }
  }
  $lblWarn.Text = if ($running -and ($now - $updated).TotalSeconds -gt 60) { 'No update for over 60 seconds. The scan may have stopped. Check the audit log.' } else { '' }
  if ($s.state -eq 'success') { $script:out = $s.output; $lblOut.Text = "Report: $($s.output)"; $btnReport.Enabled = [bool]$s.output; $btnFolder.Enabled = [bool]$s.output }
  elseif ($s.state -eq 'failed') { $lblOut.Text = "Failed: $($s.error)"; $btnReport.Enabled = $false; $btnFolder.Enabled = $false }
  else { $lblOut.Text = ''; $btnReport.Enabled = $false; $btnFolder.Enabled = $false }
})
$timer.Start()
[void]$form.ShowDialog()
