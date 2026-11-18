<#
.SYNOPSIS
  One-window launcher: setup, then start the scan, then open the progress viewer. For admin/dev runs.
.DESCRIPTION
  The scan runs as a separate process and reports through the status file, so closing this window does
  not stop it and anyone can watch it with Show-HashslingerProgress.ps1. It runs under the account that
  started the launcher (needs replication rights; a Domain Admin in a dev lab) and ends if that user
  logs off. For runs that must survive logoff or run unattended, use the scheduled tasks created by
  Setup-Hashslinger.cmd -Phase Finish (service account checks, after you created the gMSA by hand). Setup steps: create folders, copy engine and rules, build the exe
  if missing, install DSInternals if missing, unblock files, write config (rewritten every run).
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$dcDefault = ''; $domainDn = ''; $ouList = @(); $adNote = ''
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $dom = Get-ADDomain
  $dcDefault = $dom.PDCEmulator
  $domainDn = $dom.DistinguishedName
  $ouList = @($domainDn, "CN=Users,$domainDn") + @(Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName | Sort-Object)
} catch { $adNote = 'Could not read AD (type DNs in the box below).' }

$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger'; Width = 700; Height = 700; StartPosition = 'CenterScreen' }
function Add-Label($text, $x, $y, $w = 300) { $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = $x; Top = $y; Width = $w }; $form.Controls.Add($l); $l }
function Add-Text($x, $y, $w, $text = '') { $t = New-Object Windows.Forms.TextBox -Property @{ Left = $x; Top = $y; Width = $w; Text = $text }; $form.Controls.Add($t); $t }

[void](Add-Label 'Domain controller' 15 12)
$txtDc = Add-Text 15 32 300 $dcDefault
[void](Add-Label 'Work folder (config, store, staging, logs, status, output)' 340 12 330)
$txtWork = Add-Text 340 32 250 'C:\Hashslinger'
$btnWork = New-Object Windows.Forms.Button -Property @{ Text = 'Browse'; Left = 600; Top = 30; Width = 70 }
$form.Controls.Add($btnWork)

[void](Add-Label 'Scope: check the OUs / containers to scan' 15 62 400)
$lst = New-Object Windows.Forms.CheckedListBox -Property @{ Left = 15; Top = 82; Width = 655; Height = 150; CheckOnClick = $true }
foreach ($o in $ouList) { [void]$lst.Items.Add($o) }
$form.Controls.Add($lst)
[void](Add-Label ('Extra DNs, one per line. ' + $adNote) 15 238 655)
$txtExtra = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 258; Width = 655; Height = 45; Multiline = $true }
$form.Controls.Add($txtExtra)

[void](Add-Label 'Replication mode' 15 312 150)
$cmbRep = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 332; Width = 150; DropDownStyle = 'DropDownList' }
[void]$cmbRep.Items.AddRange(@('bulk', 'per-account')); $cmbRep.SelectedIndex = 0
$form.Controls.Add($cmbRep)
$chkDup = New-Object Windows.Forms.CheckBox -Property @{ Text = 'Check duplicate passwords'; Left = 190; Top = 332; Width = 220 }
$form.Controls.Add($chkDup)
$btnStaging = New-Object Windows.Forms.Button -Property @{ Text = 'Open wordlist (staging) folder'; Left = 430; Top = 329; Width = 240 }
$form.Controls.Add($btnStaging)

[void](Add-Label 'EDIPI (10 digits)' 15 368 150)
$txtEdipi = Add-Text 15 388 150
$txtEdipi.MaxLength = 10
[void](Add-Label 'Reason for this scan / CTO number' 190 368 300)
$txtReason = Add-Text 190 388 480
$btnRun = New-Object Windows.Forms.Button -Property @{ Text = 'Set up and start scan'; Left = 15; Top = 424; Width = 200; Height = 32 }
$form.Controls.Add($btnRun)
$lblStage = Add-Label 'Ready.' 15 468 655
$bar = New-Object Windows.Forms.ProgressBar -Property @{ Left = 15; Top = 492; Width = 655; Height = 18; Style = 'Continuous' }
$form.Controls.Add($bar)
$log = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 518; Width = 655; Height = 110; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Font = New-Object Drawing.Font('Consolas', 9) }
$form.Controls.Add($log)

$script:statusPath = $null; $script:cfgPath = $null
function Log($m) { $log.AppendText($m + "`r`n") }
function Setup-Status($m) { $lblStage.Text = $m; Log "[setup] $m"; [Windows.Forms.Application]::DoEvents() }

$btnWork.Add_Click({ $d = New-Object Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $txtWork.Text = $d.SelectedPath } })
$btnStaging.Add_Click({ $p = Join-Path $txtWork.Text 'staging'; New-Item -ItemType Directory -Force $p | Out-Null; Start-Process explorer.exe $p })

$btnRun.Add_Click({
  try {
    $server = $txtDc.Text.Trim(); $w = $txtWork.Text.Trim()
    $ous = @()
    foreach ($i in $lst.CheckedItems) { $ous += [string]$i }
    foreach ($l in ($txtExtra.Text -split "`r?`n")) { if ($l.Trim()) { $ous += $l.Trim() } }
    $ous = @($ous | Select-Object -Unique)
    if ($txtEdipi.Text.Trim() -notmatch '^[0-9]{10}$' -or $txtReason.Text.Trim().Length -lt 10) { [void][Windows.Forms.MessageBox]::Show('Enter your 10-digit EDIPI and a reason / CTO number (at least 10 characters). They are written to the audit log.'); return }
    if (-not $server -or -not $w -or $ous.Count -eq 0) { [void][Windows.Forms.MessageBox]::Show('Enter a domain controller, a work folder, and at least one OU/DN.'); return }

    $btnRun.Enabled = $false; $bar.Style = 'Marquee'; $log.Clear()

    Setup-Status 'Creating work folders'
    foreach ($d in 'config', 'powershell', 'staging\HIBP', 'staging\rockyou', 'staging\custom', 'output', 'logs', 'store', 'status') {
      New-Item -ItemType Directory -Force (Join-Path $w $d) | Out-Null
    }
    Copy-Item (Join-Path $repo 'powershell\Get-AccountHashes.ps1') (Join-Path $w 'powershell') -Force
    if (-not (Test-Path (Join-Path $w 'config\pattern_rules.json'))) { Copy-Item (Join-Path $repo 'config\pattern_rules.json') (Join-Path $w 'config') }

    $exe = Join-Path $repo 'Hashslinger.exe'
    if (-not (Test-Path $exe)) {
      Setup-Status 'Building Hashslinger.exe with the in-box C# compiler'
      $csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
      $outF = Join-Path $env:TEMP 'hs-build.txt'
      Start-Process -FilePath $csc -WorkingDirectory $repo -Wait -NoNewWindow -RedirectStandardOutput $outF `
        -ArgumentList '/nologo', '/optimize+', '/unsafe', '/platform:x64', '/target:exe', '/out:Hashslinger.exe', '/r:System.dll', '/r:System.Core.dll', 'cs\*.cs'
      if (-not (Test-Path $exe)) { Log (Get-Content $outF -Raw); throw 'Build failed (see log).' }
    }
    if (-not (Get-Module -ListAvailable -Name DSInternals)) {
      Setup-Status 'Installing the DSInternals module (needs internet)'
      Install-Module DSInternals -Scope AllUsers -Force -AllowClobber
    }
    Setup-Status 'Unblocking downloaded files'
    Get-ChildItem $w, $repo -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

    Setup-Status 'Writing config'
    $cfg = [ordered]@{
      mode = 'live'; replication = [string]$cmbRep.SelectedItem; check_duplicates = [bool]$chkDup.Checked
      target_server = $server; target_ous = @($ous)
      uac = @{ exclude_flags = @('SMARTCARD_REQUIRED') }
      hash_store_path = "$w\store\master.ntlm"; staging_path = "$w\staging"; log_path = "$w\logs\audit.jsonl"
      output_path = "$w\output"; allowed_output_roots = @("$w\output"); status_path = "$w\status\status.json"
      pattern_rules_path = "$w\config\pattern_rules.json"; engine_script = "$w\powershell\Get-AccountHashes.ps1"
      require_encrypted_volume = $false; engine_timeout_seconds = 86400
    }
    $script:cfgPath = Join-Path $w 'config\launcher.json'
    $cfg | ConvertTo-Json -Depth 5 | Set-Content $script:cfgPath -Encoding UTF8
    $script:statusPath = "$w\status\status.json"

    Setup-Status 'Starting the scan (it keeps running if you close this window)'
    Start-Process -FilePath $exe -ArgumentList '--config', "`"$($script:cfgPath)`"", 'scan', '--edipi', $txtEdipi.Text.Trim(), '--reason', "`"$($txtReason.Text.Trim().Replace('"', "'"))`"" -WorkingDirectory $repo -WindowStyle Hidden
    $form.Close()
  }
  catch { $lblStage.Text = 'Error: ' + $_.Exception.Message; Log ('ERROR: ' + $_.Exception.Message); $btnRun.Enabled = $true }
  finally { $bar.Style = 'Continuous' }
})

[void]$form.ShowDialog()
if ($script:statusPath) { & (Join-Path $PSScriptRoot 'Show-HashslingerProgress.ps1') -StatusPath $script:statusPath }
