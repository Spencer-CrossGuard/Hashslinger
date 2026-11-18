<#
.SYNOPSIS
  Setup wizard: install Hashslinger on this server. Pick WHERE, the domain controller, WHAT to scan. Nothing else.
.DESCRIPTION
  Runs as a local administrator (no Domain Admin needed) and NEVER changes Active Directory.
  You choose one folder; everything is created inside it (app, config, data, reports, logs, status, requests,
  extras). All settings go into ONE file, <folder>\config\hashslinger.json, which the Admin tool edits later.
  You create the service account (gMSA) by hand first. Install = local install, then the service account checks
  (read-only AD checks, folder permissions, scheduled tasks, live test as the service account).
  Day-to-day changes are made in the Admin tool (<folder>\Hashslinger-Admin.cmd), not here.
#>
$ErrorActionPreference = 'Stop'
$srcRoot = Split-Path -Parent $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
  exit
}
. (Join-Path $PSScriptRoot 'HashslingerCommon.ps1')

# ---- detect (read-only)
$ad = Get-HsAdScope
$needDsOffline = -not (Get-Module -ListAvailable -Name DSInternals)
$best = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Sort-Object FreeSpace -Descending | Select-Object -First 1
$defaultRoot = if ($best) { Join-Path ($best.DeviceID + '\') 'Hashslinger' } else { 'C:\Hashslinger' }

# ---- form
$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger setup'; Width = 920; Height = 960; MinimumSize = New-Object Drawing.Size(900, 700); StartPosition = 'CenterScreen'; AutoScroll = $true; Font = New-Object Drawing.Font('Segoe UI', 9) }
function Lbl($text, $x, $y, $w = 860, $h = 20, $bold = $false) {
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = $x; Top = $y; Width = $w; Height = $h }
  if ($bold) { $l.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold) }
  $form.Controls.Add($l); $l
}
[void](Lbl 'Set up Hashslinger on this server' 15 8 860 26 $true)
[void](Lbl ("This server: {0}   |   Domain: {1}" -f $env:COMPUTERNAME, $(if ($ad.Domain) { $ad.Domain } else { '(not detected)' })) 15 36)

# 1. where
[void](Lbl '1. Where should Hashslinger be installed? Pick the drive and folder.' 15 64 860 20 $true)
$txtRoot = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 88; Width = 720; Text = $defaultRoot }
$btnRoot = New-Object Windows.Forms.Button -Property @{ Text = 'Browse...'; Left = 745; Top = 86; Width = 120; Height = 26 }
$lblPlan = Lbl '' 15 116 860 36
$form.Controls.AddRange(@($txtRoot, $btnRoot))

# 2. DC + service account
[void](Lbl '2. Domain controller to read from' 15 160 380 20 $true)
$cmbDc = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 184; Width = 380; DropDownStyle = 'DropDown' }
foreach ($d in $ad.DCs) { [void]$cmbDc.Items.Add($d) }
$cmbDc.Text = $ad.DcDefault
[void](Lbl 'Service account (gMSA) name. Create it first, by hand.' 420 160 445 20 $true)
$txtGmsa = New-Object Windows.Forms.TextBox -Property @{ Left = 420; Top = 184; Width = 445; Text = 'svc-hashslinger' }
$form.Controls.AddRange(@($cmbDc, $txtGmsa))

# 3. scope tree
[void](Lbl ('3. What should be scanned? Expand the tree, tick OUs (everything underneath is included). ' + $(if ($ad.Error) { 'AD could not be read: add DNs by hand below.' } else { '' })) 15 220 860 20 $true)
New-HsOuPicker -Parent $form -X 15 -Y 246 -Width 850 -Height 400 -Dns $ad.Dns

# 4. optional wordlists
[void](Lbl '4. Password lists (optional; you can add more later in the Admin tool)' 15 660 860 20 $true)
$txtRock = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 684; Width = 720 }
$btnRock = New-Object Windows.Forms.Button -Property @{ Text = 'rockyou...'; Left = 745; Top = 682; Width = 120; Height = 26 }
$txtHibp = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 714; Width = 720 }
$btnHibp = New-Object Windows.Forms.Button -Property @{ Text = 'HIBP...'; Left = 745; Top = 712; Width = 120; Height = 26 }
$txtDs = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 774; Width = 720; Visible = $needDsOffline }
$btnDs = New-Object Windows.Forms.Button -Property @{ Text = 'Browse...'; Left = 745; Top = 772; Width = 120; Height = 26; Visible = $needDsOffline }
$lblDs = Lbl 'DSInternals is not installed. No internet here? Pick a copied DSInternals module folder (otherwise leave blank).' 15 748 860 20
$lblDs.Visible = $needDsOffline
$form.Controls.AddRange(@($txtRock, $btnRock, $txtHibp, $btnHibp, $txtDs, $btnDs))

# actions
$btnCheck = New-Object Windows.Forms.Button -Property @{ Text = '1. Check readiness'; Left = 15; Top = 812; Width = 170; Height = 36 }
$btnGo = New-Object Windows.Forms.Button -Property @{ Text = '2. Install'; Left = 193; Top = 812; Width = 130; Height = 36 }
$btnFinish = New-Object Windows.Forms.Button -Property @{ Text = 'Re-run service account checks'; Left = 331; Top = 812; Width = 220; Height = 36; Enabled = $false }
$btnScan = New-Object Windows.Forms.Button -Property @{ Text = 'Run first scan'; Left = 559; Top = 812; Width = 150; Height = 36; Enabled = $false }
$btnAdmin = New-Object Windows.Forms.Button -Property @{ Text = 'Open Admin tool'; Left = 717; Top = 812; Width = 148; Height = 36; Enabled = $false }
$form.Controls.AddRange(@($btnCheck, $btnGo, $btnFinish, $btnScan, $btnAdmin))
$lblResult = Lbl 'Ready. Choose the options above, then click Check readiness or Install.' 15 856 860 24 $true
$bar = New-Object Windows.Forms.ProgressBar -Property @{ Left = 15; Top = 884; Width = 850; Height = 16 }
$btnLog = New-Object Windows.Forms.Button -Property @{ Text = 'Open full log'; Left = 745; Top = 904; Width = 120; Height = 24 }
$log = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 906; Width = 720; Height = 260; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; WordWrap = $true; Font = New-Object Drawing.Font('Consolas', 9.5) }
$form.Controls.AddRange(@($bar, $btnLog, $log))

function Log([string]$m) { $log.AppendText($m + "`r`n") }
function Pump { [Windows.Forms.Application]::DoEvents() }
function Resolve-Root([string]$text) {
  $t = $text.Trim().TrimEnd('\')
  if (-not $t) { return $null }
  if ((Split-Path $t -Leaf) -eq 'Hashslinger') { return $t }
  return (Join-Path $t 'Hashslinger')
}
$script:fails = @()
function Fail-Text([string]$default) {
  if ($script:fails.Count) { $t = ($script:fails[0] -replace '^\[FAIL\]\s*', ''); if ($t.Length -gt 240) { $t = $t.Substring(0, 240) + '...' }; return $t }
  return $default
}

function Update-Plan {
  $r = Resolve-Root $txtRoot.Text
  if (-not $r) { $lblPlan.Text = 'Pick a folder.'; return }
  $drv = [IO.Path]::GetPathRoot($r)
  try { $di = New-Object IO.DriveInfo($drv); $free = '{0:N0} GB free on {1}' -f ($di.AvailableFreeSpace / 1GB), $drv } catch { $free = "drive not found: $drv" }
  $lblPlan.Text = "Will install to: $r   ($free)`r`nInside: app, config, data (store + wordlists), reports, logs, status, requests, extras. Everything stays under this one folder."
}

function Load-Existing {
  $r = Resolve-Root $txtRoot.Text
  if (-not $r) { return }
  $p = Join-Path $r 'config\hashslinger.json'
  if (-not (Test-Path $p)) { return }
  try {
    $cfg = Read-HsConfig $p
    if ($cfg['target_server']) { $cmbDc.Text = [string]$cfg['target_server'] }
    $txtGmsa.Text = [string]$cfg['gmsa_name']
    Set-HsOuSelection @($cfg['target_ous'])
    $txtRock.Text = [string]$cfg['wordlists']['rockyou']; $txtHibp.Text = [string]$cfg['wordlists']['hibp']
    $btnFinish.Enabled = $true; $btnAdmin.Enabled = (Test-Path (Join-Path $r 'Hashslinger-Admin.cmd'))
    Log "Loaded the existing settings from $p"
  } catch { Log ('Could not read the existing settings: ' + $_.Exception.Message) }
}

function Save-Settings([string]$root) {
  $cfgPath = Join-Path $root 'config\hashslinger.json'
  $cfg = Read-HsConfig $cfgPath
  $cfg['install_root'] = $root
  $cfg['target_server'] = $cmbDc.Text.Trim()
  $cfg['target_ous'] = @(Get-HsOuSelection)
  $cfg['gmsa_name'] = $txtGmsa.Text.Trim()
  $cfg['run_server'] = $env:COMPUTERNAME
  $cfg['wordlists']['rockyou'] = $txtRock.Text.Trim()
  $cfg['wordlists']['hibp'] = $txtHibp.Text.Trim()
  $cfg['dsinternals_offline_path'] = $txtDs.Text.Trim()
  Save-HsConfig $cfg $cfgPath
  return $cfgPath
}

# Run Setup-Hashslinger as a child, streaming its output into the log box. Returns the exit code.
function Invoke-Setup([string]$cfgPath, [string]$phase) {
  $script:fails = @()
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = 'powershell.exe'
  $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\Setup-Hashslinger.ps1`" -Config `"$cfgPath`" -Phase $phase"
  $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
  $q = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
  $proc = New-Object Diagnostics.Process
  $proc.StartInfo = $psi
  $id1 = 'hs-out-' + [guid]::NewGuid().ToString('N'); $id2 = 'hs-err-' + [guid]::NewGuid().ToString('N')
  [void](Register-ObjectEvent $proc OutputDataReceived -SourceIdentifier $id1 -MessageData $q -Action { if ($EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) } })
  [void](Register-ObjectEvent $proc ErrorDataReceived -SourceIdentifier $id2 -MessageData $q -Action { if ($EventArgs.Data) { $Event.MessageData.Enqueue('ERR: ' + $EventArgs.Data) } })
  [void]$proc.Start(); $proc.BeginOutputReadLine(); $proc.BeginErrorReadLine()
  $line = $null
  while (-not $proc.HasExited -or -not $q.IsEmpty) {
    while ($q.TryDequeue([ref]$line)) { Log $line; if ($line -like '`[FAIL`]*') { $script:fails += $line } }
    Pump; Start-Sleep -Milliseconds 100
  }
  $proc.WaitForExit(); Start-Sleep -Milliseconds 300
  while ($q.TryDequeue([ref]$line)) { Log $line; if ($line -like '`[FAIL`]*') { $script:fails += $line } }
  Unregister-Event -SourceIdentifier $id1; Unregister-Event -SourceIdentifier $id2
  return $proc.ExitCode
}

function Test-Inputs {
  $root = Resolve-Root $txtRoot.Text
  if (-not $root -or -not $cmbDc.Text.Trim() -or -not $txtGmsa.Text.Trim() -or @(Get-HsOuSelection).Count -eq 0) {
    [void][Windows.Forms.MessageBox]::Show('Please choose an install folder, a domain controller, the service account name, and at least one thing to scan.')
    return $null
  }
  return $root
}
function Busy([bool]$on) {
  foreach ($b in $btnCheck, $btnGo, $btnFinish) { $b.Enabled = -not $on }
  $bar.Style = $(if ($on) { 'Marquee' } else { 'Continuous' })
}

$btnRoot.Add_Click({
  $d = New-Object Windows.Forms.FolderBrowserDialog
  $d.Description = 'Choose where Hashslinger should live. A folder named Hashslinger is created inside it.'
  if ($d.ShowDialog() -eq 'OK') { $txtRoot.Text = Resolve-Root $d.SelectedPath; Update-Plan; Load-Existing }
})
$txtRoot.Add_TextChanged({ Update-Plan })
$txtRoot.Add_Leave({ Load-Existing })
$btnRock.Add_Click({ $d = New-Object Windows.Forms.OpenFileDialog; if ($d.ShowDialog() -eq 'OK') { $txtRock.Text = $d.FileName } })
$btnHibp.Add_Click({ $d = New-Object Windows.Forms.OpenFileDialog; if ($d.ShowDialog() -eq 'OK') { $txtHibp.Text = $d.FileName } })
$btnDs.Add_Click({ $d = New-Object Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $txtDs.Text = $d.SelectedPath } })
$btnLog.Add_Click({
  $r = Resolve-Root $txtRoot.Text
  $l = if ($r) { Get-ChildItem (Join-Path $r 'logs') -Filter 'setup-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
  if ($l) { Start-Process notepad.exe $l.FullName } else { [void][Windows.Forms.MessageBox]::Show('No setup log yet.') }
})
$btnAdmin.Add_Click({ $r = Resolve-Root $txtRoot.Text; Start-Process (Join-Path $r 'Hashslinger-Admin.cmd') })
$btnScan.Add_Click({
  try {
    $r = Resolve-Root $txtRoot.Text
    Start-ScheduledTask -TaskName 'Hashslinger-Scheduled'
    Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $r 'app\powershell\Show-HashslingerProgress.ps1')`"", '-ConfigPath', "`"$(Join-Path $r 'config\hashslinger.json')`"")
  } catch { [void][Windows.Forms.MessageBox]::Show('Could not start the scan: ' + $_.Exception.Message) }
})

$btnCheck.Add_Click({
  try {
    $root = Test-Inputs; if (-not $root) { return }
    Busy $true; $log.Clear(); $lblResult.ForeColor = [Drawing.Color]::Black; $lblResult.Text = 'Checking this server (nothing is changed)...'
    $cfgPath = Save-Settings $root
    $rc = Invoke-Setup $cfgPath 'Check'
    if ($rc -eq 0) { $lblResult.ForeColor = [Drawing.Color]::SeaGreen; $lblResult.Text = 'Ready to install. No blocking problems found.' }
    else { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'Fix this first: ' + (Fail-Text 'see the log below.') }
  }
  catch { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'Error: ' + $_.Exception.Message; Log ('ERROR: ' + $_.Exception.Message) }
  finally { Busy $false }
})

$btnGo.Add_Click({
  try {
    $root = Test-Inputs; if (-not $root) { return }
    Busy $true; $log.Clear(); $lblResult.ForeColor = [Drawing.Color]::Black; $lblResult.Text = 'Installing on this server...'
    $cfgPath = Save-Settings $root
    $rc = Invoke-Setup $cfgPath 'Local'
    if ($rc -ne 0) { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'The install has a problem: ' + (Fail-Text 'see the log below.'); return }
    $btnAdmin.Enabled = $true
    $btnFinish.Enabled = $true
    $lblResult.Text = 'Installed. Checking the service account, permissions and scheduled tasks...'
    $rc = Invoke-Setup $cfgPath 'Finish'
    if ($rc -eq 0) { $lblResult.ForeColor = [Drawing.Color]::SeaGreen; $lblResult.Text = 'All done. You can run the first scan now.'; $btnScan.Enabled = $true }
    else { $lblResult.ForeColor = [Drawing.Color]::DarkOrange; $lblResult.Text = 'Installed, but the service account checks need attention: ' + (Fail-Text 'see the log below.') + '  Fix it, then click Re-run service account checks.' }
  }
  catch { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'Error: ' + $_.Exception.Message; Log ('ERROR: ' + $_.Exception.Message) }
  finally { $bar.Style = 'Continuous'; $btnCheck.Enabled = $true; $btnGo.Enabled = $true }
})

$btnFinish.Add_Click({
  try {
    $root = Resolve-Root $txtRoot.Text
    Busy $true; $log.Clear(); $lblResult.ForeColor = [Drawing.Color]::Black; $lblResult.Text = 'Checking the Active Directory prerequisites and finishing...'
    $cfgPath = Save-Settings $root
    $rc = Invoke-Setup $cfgPath 'Finish'
    if ($rc -eq 0) { $lblResult.ForeColor = [Drawing.Color]::SeaGreen; $lblResult.Text = 'All done. You can run the first scan now.'; $btnScan.Enabled = $true; $btnAdmin.Enabled = $true }
    else { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'Not finished: ' + (Fail-Text 'see the log below.') }
  }
  catch { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'Error: ' + $_.Exception.Message; Log ('ERROR: ' + $_.Exception.Message) }
  finally { Busy $false }
})

Update-Plan
Load-Existing
[void]$form.ShowDialog()
