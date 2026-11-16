<#
.SYNOPSIS
  Guided setup. A few plain questions, everything else is chosen for you.
.DESCRIPTION
  Detects the domain, domain controllers and drives, asks you to pick: the domain controller, which
  drive holds the data, and which OUs to scan (optionally wordlist files). It then writes the init
  config, runs Setup-Hashslinger (local install, then the AD part after a plain-language confirmation),
  and shows a clear result. Safe to re-run: finished steps are skipped or refreshed.
  If you are not a Domain Admin it finishes the local part and tells you what to hand to one.
  Advanced users can still run Setup-Hashslinger.cmd with -Phase / -InitConfig directly.
#>
$ErrorActionPreference = 'Stop'
$srcRoot = Split-Path -Parent $PSScriptRoot

# ---- elevate
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
  exit
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---- detect (best effort; every field can still be typed or fixed by hand)
$domainName = ''; $domainDn = ''; $dcList = @(); $dcDefault = ''; $ouList = @(); $adNote = ''
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $dom = Get-ADDomain
  $domainName = $dom.DNSRoot; $domainDn = $dom.DistinguishedName
  $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Sort-Object)
  try { $dcDefault = (Get-ADDomainController -Discover).HostName | Select-Object -First 1 } catch { }
  $ouList = @($domainDn, "CN=Users,$domainDn") + @(Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName | Sort-Object)
} catch { $adNote = 'The Active Directory tools were not found yet. Setup will install them, then run this wizard again to pick OUs.' }
$drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Sort-Object FreeSpace -Descending |
  ForEach-Object { '{0}  ({1} GB free)' -f $_.DeviceID, [math]::Round($_.FreeSpace / 1GB) })
$needDsOffline = -not (Get-Module -ListAvailable -Name DSInternals)

# ---- form
$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger setup'; Width = 720; Height = 780; StartPosition = 'CenterScreen'; Font = New-Object Drawing.Font('Segoe UI', 9) }
function Lbl($text, $x, $y, $w = 660, $h = 20, $bold = $false) {
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = $x; Top = $y; Width = $w; Height = $h }
  if ($bold) { $l.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold) }
  $form.Controls.Add($l); $l
}
[void](Lbl 'Set up Hashslinger on this server' 15 10 660 26 $true)
[void](Lbl ("This server: {0}   |   Domain: {1}" -f $env:COMPUTERNAME, $(if ($domainName) { $domainName } else { '(not detected)' })) 15 40)

[void](Lbl '1. Domain controller to read from' 15 70)
$cmbDc = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 92; Width = 400; DropDownStyle = 'DropDown' }
foreach ($d in $dcList) { [void]$cmbDc.Items.Add($d) }
$cmbDc.Text = $dcDefault
$form.Controls.Add($cmbDc)

[void](Lbl '2. Drive for the data (needs about 60 GB if you use the HIBP list)' 15 126)
$cmbDrive = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 148; Width = 250; DropDownStyle = 'DropDownList' }
foreach ($d in $drives) { [void]$cmbDrive.Items.Add($d) }
if ($cmbDrive.Items.Count) { $cmbDrive.SelectedIndex = 0 }
$form.Controls.Add($cmbDrive)

[void](Lbl ('3. Which parts of the directory to scan (everything underneath is included). ' + $adNote) 15 182 670 34)
$lst = New-Object Windows.Forms.CheckedListBox -Property @{ Left = 15; Top = 218; Width = 670; Height = 170; CheckOnClick = $true }
foreach ($o in $ouList) { [void]$lst.Items.Add($o) }
$form.Controls.Add($lst)

[void](Lbl '4. Password lists (optional, you can add them later in the staging folder)' 15 400)
$txtRock = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 424; Width = 560 }
$btnRock = New-Object Windows.Forms.Button -Property @{ Text = 'rockyou...'; Left = 585; Top = 422; Width = 100 }
$txtHibp = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 454; Width = 560 }
$btnHibp = New-Object Windows.Forms.Button -Property @{ Text = 'HIBP...'; Left = 585; Top = 452; Width = 100 }
$form.Controls.AddRange(@($txtRock, $btnRock, $txtHibp, $btnHibp))
$btnRock.Add_Click({ $d = New-Object Windows.Forms.OpenFileDialog; if ($d.ShowDialog() -eq 'OK') { $txtRock.Text = $d.FileName } })
$btnHibp.Add_Click({ $d = New-Object Windows.Forms.OpenFileDialog; if ($d.ShowDialog() -eq 'OK') { $txtHibp.Text = $d.FileName } })

$txtDs = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 506; Width = 560; Visible = $needDsOffline }
$btnDs = New-Object Windows.Forms.Button -Property @{ Text = 'Browse...'; Left = 585; Top = 504; Width = 100; Visible = $needDsOffline }
$lblDs = Lbl 'DSInternals is not installed. If this server has no internet, pick a copied DSInternals module folder (otherwise leave blank).' 15 484 670 20
$lblDs.Visible = $needDsOffline
$form.Controls.AddRange(@($txtDs, $btnDs))
$btnDs.Add_Click({ $d = New-Object Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $txtDs.Text = $d.SelectedPath } })

$btnGo = New-Object Windows.Forms.Button -Property @{ Text = 'Install'; Left = 15; Top = 545; Width = 160; Height = 36 }
$btnSummary = New-Object Windows.Forms.Button -Property @{ Text = 'Open summary'; Left = 185; Top = 545; Width = 130; Height = 36; Enabled = $false }
$btnScan = New-Object Windows.Forms.Button -Property @{ Text = 'Run first scan now'; Left = 325; Top = 545; Width = 160; Height = 36; Enabled = $false }
$form.Controls.AddRange(@($btnGo, $btnSummary, $btnScan))
$lblResult = Lbl 'Ready. Pick the options above and click Install.' 15 590 670 24 $true
$bar = New-Object Windows.Forms.ProgressBar -Property @{ Left = 15; Top = 616; Width = 670; Height = 16 }
$form.Controls.Add($bar)
$log = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 640; Width = 670; Height = 90; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Font = New-Object Drawing.Font('Consolas', 8) }
$form.Controls.Add($log)

$script:summaryPath = $null
function Log([string]$m) { $log.AppendText($m + "`r`n") }
function Pump { [Windows.Forms.Application]::DoEvents() }

function Test-DomainAdmin {
  foreach ($g in [Security.Principal.WindowsIdentity]::GetCurrent().Groups) {
    try { if ($g.Translate([Security.Principal.NTAccount]).Value -like '*\Domain Admins') { return $true } } catch { }
  }
  return $false
}

# Run Setup-Hashslinger as a child, streaming its output into the log box. Returns the exit code.
function Invoke-Setup([string]$initPath, [string]$phase, [bool]$labKey) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = 'powershell.exe'
  $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\Setup-Hashslinger.ps1`" -InitConfig `"$initPath`" -Phase $phase"
  if ($labKey) { $a += ' -CreateKdsRootKey' }
  $psi.Arguments = $a
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
    while ($q.TryDequeue([ref]$line)) { Log $line }
    Pump; Start-Sleep -Milliseconds 100
  }
  $proc.WaitForExit(); Start-Sleep -Milliseconds 300
  while ($q.TryDequeue([ref]$line)) { Log $line }
  Unregister-Event -SourceIdentifier $id1; Unregister-Event -SourceIdentifier $id2
  return $proc.ExitCode
}

$btnSummary.Add_Click({ if ($script:summaryPath -and (Test-Path $script:summaryPath)) { Start-Process notepad.exe $script:summaryPath } })
$btnScan.Add_Click({
  try {
    Start-ScheduledTask -TaskName 'Hashslinger-Scheduled'
    $cfg = Join-Path $script:installRoot 'config\hashslinger.json'
    Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $script:installRoot 'bin\powershell\Show-HashslingerProgress.ps1')`"", '-ConfigPath', "`"$cfg`"")
  } catch { [void][Windows.Forms.MessageBox]::Show('Could not start the scan: ' + $_.Exception.Message) }
})

$btnGo.Add_Click({
  try {
    $dc = $cmbDc.Text.Trim()
    $driveSel = [string]$cmbDrive.SelectedItem
    $ous = @(); foreach ($i in $lst.CheckedItems) { $ous += [string]$i }
    if (-not $dc -or -not $driveSel -or $ous.Count -eq 0) { [void][Windows.Forms.MessageBox]::Show('Please choose a domain controller, a drive, and at least one scan location.'); return }
    $btnGo.Enabled = $false; $bar.Style = 'Marquee'; $log.Clear()
    $lblResult.ForeColor = [Drawing.Color]::Black; $lblResult.Text = 'Working...'

    $drive = $driveSel.Substring(0, 2)
    $script:installRoot = Join-Path $env:SystemDrive 'Hashslinger'
    $dataRoot = Join-Path $drive 'Hashslinger'
    $gmsaName = 'svc-hashslinger'
    $init = [ordered]@{
      install_root = $script:installRoot
      paths = [ordered]@{ store = "$dataRoot\store"; staging = "$dataRoot\staging"; logs = "$dataRoot\logs"; output = "$dataRoot\output"; status = "$($script:installRoot)\status"; requests = "$($script:installRoot)\requests" }
      ad = [ordered]@{ mode = 'live'; domain_controller = $dc; target_ous = @($ous); account_types = @('User', 'Service'); uac_exclude_flags = @('SMARTCARD_REQUIRED'); replication = 'bulk' }
      scan = [ordered]@{ check_duplicates = $false; cadence = 'Weekly'; retention_days = 90; engine_timeout_seconds = 86400 }
      security = [ordered]@{ gmsa_name = $gmsaName; run_server = $env:COMPUTERNAME; analyst_group = ''; authorized_edipis = @(); require_encrypted_volume = $false }
      wordlists = [ordered]@{ hibp = $txtHibp.Text.Trim(); rockyou = $txtRock.Text.Trim(); custom = '' }
      dsinternals_offline_path = $txtDs.Text.Trim()
      min_free_space_gb = @{ store = 60; output = 5 }
    }
    $initPath = Join-Path $srcRoot 'hashslinger.init.json'
    $init | ConvertTo-Json -Depth 6 | Set-Content $initPath -Encoding UTF8
    Log "Settings saved to $initPath"

    # ---- part 1: this server
    $lblResult.Text = 'Step 1 of 2: installing on this server...'
    $rc = Invoke-Setup $initPath 'Local' $false
    $script:summaryPath = Join-Path $script:installRoot 'SETUP-SUMMARY.txt'
    if ($rc -ne 0) { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'The local install has problems. See the log below and the summary.'; $btnSummary.Enabled = (Test-Path $script:summaryPath); return }

    # ---- part 2: Active Directory (needs a Domain Admin)
    if (-not (Test-DomainAdmin)) {
      $lblResult.ForeColor = [Drawing.Color]::DarkOrange
      $lblResult.Text = 'This server is ready. A Domain Admin must finish the AD part.'
      Log 'You are not a Domain Admin. Ask one to run Setup-Hashslinger.cmd -Phase Domain on this server (the settings are already saved).'
      $btnSummary.Enabled = $true; return
    }
    $labKey = $false
    if (-not (Get-KdsRootKey)) {
      $ans = [Windows.Forms.MessageBox]::Show("A one-time Active Directory key is missing.`r`n`r`nYES = this is a TEST lab: create it now (usable immediately).`r`nNO = this is PRODUCTION: create it now, but it only becomes usable in about 10 hours; setup will stop here and you run this wizard again later.", 'Active Directory key', 'YesNoCancel', 'Question')
      if ($ans -eq 'Cancel') { $lblResult.Text = 'Stopped before the AD changes.'; return }
      if ($ans -eq 'Yes') { $labKey = $true }
      else {
        Add-KdsRootKey -EffectiveImmediately | Out-Null
        $lblResult.ForeColor = [Drawing.Color]::DarkOrange
        $lblResult.Text = 'Key created. Run this wizard again in about 10 hours to finish.'
        $btnSummary.Enabled = $true; return
      }
    }
    $msg = "The next step changes Active Directory. It will:`r`n`r`n" +
      " - create a service account '$gmsaName' that only $env:COMPUTERNAME can use`r`n" +
      " - let that account read password data from '$domainName' (directory replication permission, domain only)`r`n" +
      " - lock the Hashslinger folders to that account and local Administrators`r`n" +
      " - create two scheduled tasks (weekly scan and on-demand scan)`r`n`r`nContinue?"
    if ([Windows.Forms.MessageBox]::Show($msg, 'Confirm Active Directory changes', 'YesNo', 'Warning') -ne 'Yes') {
      $lblResult.ForeColor = [Drawing.Color]::DarkOrange; $lblResult.Text = 'Stopped before the AD changes. This server is installed.'; $btnSummary.Enabled = $true; return
    }
    $lblResult.ForeColor = [Drawing.Color]::Black; $lblResult.Text = 'Step 2 of 2: Active Directory...'
    $rc = Invoke-Setup $initPath 'Domain' $labKey
    $btnSummary.Enabled = (Test-Path $script:summaryPath)
    if ($rc -eq 0) { $lblResult.ForeColor = [Drawing.Color]::SeaGreen; $lblResult.Text = 'All done. You can run the first scan now.'; $btnScan.Enabled = $true }
    else { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'The AD part has problems. See the log below and the summary.' }
  }
  catch { $lblResult.ForeColor = [Drawing.Color]::Firebrick; $lblResult.Text = 'Error: ' + $_.Exception.Message; Log ('ERROR: ' + $_.Exception.Message) }
  finally { $bar.Style = 'Continuous'; $btnGo.Enabled = $true }
})

[void]$form.ShowDialog()
