<#
.SYNOPSIS
  Hashslinger Admin: change ANY setting easily, see where everything is, run and watch scans, manage wordlists.
.DESCRIPTION
  Edits the ONE config file (<root>\config\hashslinger.json) that the scan program reads. Every setting is here,
  with defaults explained. A backup of the previous file is kept on every save. Changes apply to the NEXT scan
  (the schedule is applied to the scheduled task when you say so). This tool never changes Active Directory.
  Open it from <root>\Hashslinger-Admin.cmd.
#>
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\hashslinger.json'))
$ErrorActionPreference = 'Stop'
$ConfigPath = [IO.Path]::GetFullPath($ConfigPath)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-ConfigPath', "`"$ConfigPath`"")
  exit
}
. (Join-Path $PSScriptRoot 'HashslingerCommon.ps1')

if (-not (Test-Path $ConfigPath)) {
  [void][Windows.Forms.MessageBox]::Show("No settings file found at:`r`n$ConfigPath`r`n`r`nRun the Setup wizard first.", 'Hashslinger Admin')
  exit 1
}
$script:cfg = Read-HsConfig $ConfigPath
$root = [string]$script:cfg['install_root']
$exe = Join-Path $root 'app\Hashslinger.exe'
$setupScript = Join-Path $root 'app\powershell\Setup-Hashslinger.ps1'
$viewer = Join-Path $root 'app\powershell\Show-HashslingerProgress.ps1'
$ad = Get-HsAdScope

# ================================================================ window
$form = New-Object Windows.Forms.Form -Property @{ Text = "Hashslinger Admin  -  $root"; Width = 940; Height = 820; MinimumSize = New-Object Drawing.Size(900, 640); StartPosition = 'CenterScreen'; Font = New-Object Drawing.Font('Segoe UI', 9) }
$tc = New-Object Windows.Forms.TabControl -Property @{ Left = 8; Top = 8; Width = 908; Height = 700; Anchor = 'Top,Bottom,Left,Right' }
$btnSave = New-Object Windows.Forms.Button -Property @{ Text = 'Save changes'; Left = 8; Top = 718; Width = 150; Height = 34; Anchor = 'Bottom,Left' }
$btnRevert = New-Object Windows.Forms.Button -Property @{ Text = 'Discard changes'; Left = 166; Top = 718; Width = 150; Height = 34; Anchor = 'Bottom,Left' }
$lblStatus = New-Object Windows.Forms.Label -Property @{ Text = "Settings file: $ConfigPath"; Left = 326; Top = 726; Width = 590; Height = 22; Anchor = 'Bottom,Left,Right' }
$form.Controls.AddRange(@($tc, $btnSave, $btnRevert, $lblStatus))

$script:Ctl = [ordered]@{}
function Msg([string]$m, [string]$title = 'Hashslinger Admin') { [void][Windows.Forms.MessageBox]::Show($m, $title) }
function New-Tab([string]$title) {
  $tp = New-Object Windows.Forms.TabPage $title
  $tp.AutoScroll = $true
  $tp.Tag = 12
  [void]$tc.TabPages.Add($tp)
  return $tp
}
function Add-Heading($tp, [string]$text) {
  $y = [int]$tp.Tag + 6
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = 12; Top = $y; Width = 860; Height = 22; Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold) }
  $tp.Controls.Add($l); $tp.Tag = $y + 28
}
function Add-Note($tp, [string]$text) {
  $y = [int]$tp.Tag
  $h = 16 * [Math]::Max(1, [Math]::Ceiling($text.Length / 120))
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = 12; Top = $y; Width = 860; Height = $h; ForeColor = [Drawing.Color]::DimGray }
  $tp.Controls.Add($l); $tp.Tag = $y + $h + 6
}

# folder / file buttons: the target text box travels in the button's Tag (no closures needed)
$onBrowse = {
  param($s, $e)
  $t = $s.Tag
  if ($t.Kind -eq 'folder') {
    $d = New-Object Windows.Forms.FolderBrowserDialog
    if ($t.Box.Text -and (Test-Path $t.Box.Text)) { $d.SelectedPath = $t.Box.Text }
    if ($d.ShowDialog() -eq 'OK') { $t.Box.Text = $d.SelectedPath }
  } else {
    $d = New-Object Windows.Forms.OpenFileDialog
    $d.CheckFileExists = $false
    if ($d.ShowDialog() -eq 'OK') { $t.Box.Text = $d.FileName }
  }
}
$onOpen = {
  param($s, $e)
  $t = $s.Tag
  $p = $t.Box.Text.Trim()
  if (-not $p) { return }
  if ($t.Kind -eq 'folder') { if (Test-Path $p) { Start-Process explorer.exe $p } else { Msg "Not found yet: $p" } }
  elseif (Test-Path $p) { Start-Process explorer.exe "/select,`"$p`"" }
  elseif (Test-Path (Split-Path $p -Parent)) { Start-Process explorer.exe (Split-Path $p -Parent) }
  else { Msg "Not found yet: $p" }
}

# one settings row. $type: text readonly path int hours bool choice combo lines checks
function Add-Row($tp, [string]$key, [string]$label, [string]$type, $opts = $null, [string]$help = '') {
  $y = [int]$tp.Tag
  $lbl = New-Object Windows.Forms.Label -Property @{ Text = $label; Left = 12; Top = $y + 4; Width = 250; Height = 20 }
  $tp.Controls.Add($lbl)
  $h = 26
  switch ($type) {
    { $_ -in 'text', 'readonly' } {
      $c = New-Object Windows.Forms.TextBox -Property @{ Left = 270; Top = $y; Width = 440 }
      if ($type -eq 'readonly') { $c.ReadOnly = $true }
      $tp.Controls.Add($c)
    }
    'path' {
      $c = New-Object Windows.Forms.TextBox -Property @{ Left = 270; Top = $y; Width = 400 }
      $b1 = New-Object Windows.Forms.Button -Property @{ Text = 'Browse'; Left = 676; Top = $y - 1; Width = 90; Height = 26; Tag = @{ Box = $c; Kind = $opts } }
      $b2 = New-Object Windows.Forms.Button -Property @{ Text = 'Open'; Left = 772; Top = $y - 1; Width = 80; Height = 26; Tag = @{ Box = $c; Kind = $opts } }
      $b1.Add_Click($onBrowse); $b2.Add_Click($onOpen)
      $tp.Controls.AddRange(@($c, $b1, $b2))
    }
    'int' {
      $c = New-Object Windows.Forms.NumericUpDown -Property @{ Left = 270; Top = $y; Width = 130; Minimum = [decimal]$opts.Min; Maximum = [decimal]$opts.Max }
      $tp.Controls.Add($c)
    }
    'hours' {
      $c = New-Object Windows.Forms.NumericUpDown -Property @{ Left = 270; Top = $y; Width = 130; Minimum = 1; Maximum = 720 }
      $tp.Controls.Add($c)
    }
    'bool' {
      $c = New-Object Windows.Forms.CheckBox -Property @{ Left = 270; Top = $y + 2; Width = 580; Text = [string]$opts }
      $tp.Controls.Add($c)
    }
    'choice' {
      $c = New-Object Windows.Forms.ComboBox -Property @{ Left = 270; Top = $y; Width = 220; DropDownStyle = 'DropDownList' }
      foreach ($o in $opts) { [void]$c.Items.Add([string]$o) }
      $tp.Controls.Add($c)
    }
    'combo' {
      $c = New-Object Windows.Forms.ComboBox -Property @{ Left = 270; Top = $y; Width = 440; DropDownStyle = 'DropDown' }
      foreach ($o in $opts) { [void]$c.Items.Add([string]$o) }
      $tp.Controls.Add($c)
    }
    'lines' {
      $h = 76
      $c = New-Object Windows.Forms.TextBox -Property @{ Left = 270; Top = $y; Width = 580; Height = 70; Multiline = $true; ScrollBars = 'Vertical' }
      $tp.Controls.Add($c)
    }
    'checks' {
      $rows = [Math]::Ceiling(@($opts).Count / 2)
      $h = [int]($rows * 24 + 6)
      $c = New-Object Windows.Forms.FlowLayoutPanel -Property @{ Left = 270; Top = $y; Width = 580; Height = $h; WrapContents = $true }
      foreach ($o in $opts) { $cb = New-Object Windows.Forms.CheckBox -Property @{ Text = [string]$o; Width = 280; Height = 22 }; $c.Controls.Add($cb) }
      $tp.Controls.Add($c)
    }
  }
  $script:Ctl[$key] = @{ Type = $type; Control = $c }
  $tp.Tag = $y + $h + 6
  if ($help) { Add-Note $tp $help }
}

function Set-Field([string]$key, $value) {
  $f = $script:Ctl[$key]; $c = $f.Control
  switch ($f.Type) {
    { $_ -in 'text', 'readonly', 'path', 'combo' } { $c.Text = [string]$value }
    'int' { $v = if ($null -eq $value) { 0 } else { [double]$value }; $c.Value = [decimal][Math]::Min([double]$c.Maximum, [Math]::Max([double]$c.Minimum, $v)) }
    'hours' { $v = if ($null -eq $value) { 24 } else { [Math]::Round([double]$value / 3600) }; $c.Value = [decimal][Math]::Min(720, [Math]::Max(1, $v)) }
    'bool' { $c.Checked = [bool]$value }
    'choice' { $i = $c.Items.IndexOf([string]$value); if ($i -ge 0) { $c.SelectedIndex = $i } elseif ($c.Items.Count) { $c.SelectedIndex = 0 } }
    'lines' { $c.Text = (@($value) -join "`r`n") }
    'checks' { foreach ($cb in $c.Controls) { $cb.Checked = (@($value) -contains $cb.Text) } }
  }
}
function Get-Field([string]$key) {
  $f = $script:Ctl[$key]; $c = $f.Control
  switch ($f.Type) {
    { $_ -in 'text', 'readonly', 'path', 'combo' } { return $c.Text.Trim() }
    'int' { return [int]$c.Value }
    'hours' { return [int]($c.Value * 3600) }
    'bool' { return [bool]$c.Checked }
    'choice' { return [string]$c.SelectedItem }
    'lines' { return , @($c.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    'checks' { return , @($c.Controls | Where-Object { $_.Checked } | ForEach-Object { $_.Text }) }
  }
}
function Load-All {
  $script:cfg = Read-HsConfig $ConfigPath
  foreach ($k in @($script:Ctl.Keys)) { Set-Field $k (Get-HsCfgValue $script:cfg $k) }
  Set-HsOuSelection @($script:cfg['target_ous'])
  Refresh-Wordlists
  Show-LastRun
}

# ================================================================ tab: Where
$tpWhere = New-Tab 'Where everything is'
Add-Note $tpWhere 'All of Hashslinger lives under the install folder. Changing a folder here does NOT move the files already in it.'
Add-Row $tpWhere 'install_root' 'Install folder' 'readonly'
Add-Row $tpWhere 'hash_store_path' 'Hash store (file)' 'path' 'file' 'The merged, sorted list of breached/weak password hashes. Large; keep it on a fast disk.'
Add-Row $tpWhere 'staging_path' 'Wordlists (staging folder)' 'path' 'folder' 'Drop wordlist files into the HIBP, rockyou or custom folders inside this one. They are merged on the next scan.'
Add-Row $tpWhere 'output_path' 'Reports (CSV) folder' 'path' 'folder' 'Where each scan writes its report. Also used as the allowed output location.'
Add-Row $tpWhere 'log_path' 'Audit log (file)' 'path' 'file' 'Every run, who started it, how long each stage took, and whether the memory wipe was confirmed.'
Add-Row $tpWhere 'status_path' 'Live status (file)' 'path' 'file' 'What the progress viewer reads while a scan runs.'
Add-Row $tpWhere 'request_dir' 'Scan requests folder' 'path' 'folder' 'Only used if an analyst group submits scans through the request GUI.'
Add-Row $tpWhere 'pattern_rules_path' 'Pattern rules (file)' 'path' 'file' 'Keyboard walks, base words and seasons used by the pattern check.'
Add-Row $tpWhere 'allowed_output_roots' 'Allowed report locations' 'lines' $null 'One folder per line. A scan may only write reports under these. The reports folder above is added automatically.'
$btnRules = New-Object Windows.Forms.Button -Property @{ Text = 'Edit pattern rules'; Left = 270; Top = [int]$tpWhere.Tag; Width = 150; Height = 28 }
$btnRules.Add_Click({ $p = Get-Field 'pattern_rules_path'; if (Test-Path $p) { Start-Process notepad.exe $p } else { Msg "Not found: $p" } })
$btnRoot = New-Object Windows.Forms.Button -Property @{ Text = 'Open install folder'; Left = 430; Top = [int]$tpWhere.Tag; Width = 160; Height = 28 }
$btnRoot.Add_Click({ Start-Process explorer.exe $root })
$tpWhere.Controls.AddRange(@($btnRules, $btnRoot)); $tpWhere.Tag = [int]$tpWhere.Tag + 40

# ================================================================ tab: Active Directory
$tpAd = New-Tab 'Active Directory'
Add-Heading $tpAd 'Where to read from and how'
Add-Row $tpAd 'target_server' 'Domain controller' 'combo' $ad.DCs 'The DC the scan reads from (type a name if it is not in the list).'
Add-Row $tpAd 'mode' 'Mode' 'choice' @('live', 'offline') 'live = read from a DC (replication). offline = read an ntds.dit copy (set the two paths below).'
Add-Row $tpAd 'replication' 'Replication' 'choice' @('bulk', 'per-account') 'bulk = one pass over the whole domain (best for large scopes). per-account = only the accounts in scope.'
Add-Row $tpAd 'workers' 'Parallel connections' 'int' @{ Min = 1; Max = 16 } 'How many connections to the DC are used at once when replicating accounts one by one (small scopes). Higher is faster but loads the DC more. 1 turns it off.'
Add-Row $tpAd 'per_account_threshold' 'Small-scope switch' 'int' @{ Min = 0; Max = 1000000 } 'At or below this many accounts in scope, bulk automatically switches to per-account (much faster for small scans).'
Add-Row $tpAd 'account_types' 'Account types' 'checks' @('User', 'Service', 'Computer') 'Which kinds of accounts to audit.'
Add-Row $tpAd 'uac.exclude_flags' 'Skip accounts with flag' 'checks' @('SMARTCARD_REQUIRED', 'ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'DONT_EXPIRE_PASSWORD', 'ENCRYPTED_TEXT_PWD_ALLOWED') 'Accounts that have ANY ticked flag are skipped. Smart-card-required accounts have no usable password.'
Add-Row $tpAd 'uac.require_flags' 'Only accounts with flag' 'checks' @('SMARTCARD_REQUIRED', 'ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'DONT_EXPIRE_PASSWORD', 'ENCRYPTED_TEXT_PWD_ALLOWED') 'Leave empty for no restriction. If ticked, an account must have ALL of them.'
Add-Row $tpAd 'ntds_path' 'ntds.dit file (offline mode)' 'path' 'file'
Add-Row $tpAd 'system_hive_path' 'SYSTEM hive (offline mode)' 'path' 'file'
Add-Heading $tpAd 'What to scan'
Add-Note $tpAd 'Expand the tree like AD, tick what to scan. Ticking an OU includes everything underneath it. Search keeps the parents visible.'
$pickerY = [int]$tpAd.Tag
New-HsOuPicker -Parent $tpAd -X 12 -Y $pickerY -Width 850 -Height 430 -Dns $ad.Dns
$btnReload = New-Object Windows.Forms.Button -Property @{ Text = 'Reload from AD'; Left = 12; Top = $pickerY + 440; Width = 150; Height = 28 }
$btnReload.Add_Click({
  $r = Get-HsAdScope
  if ($r.Error) { Msg ('Could not read AD: ' + $r.Error) } else {
    Set-HsOuDns $r.Dns
    $f = $script:Ctl['target_server'].Control; $keep = $f.Text; $f.Items.Clear(); foreach ($d in $r.DCs) { [void]$f.Items.Add($d) }; $f.Text = $keep
    Msg "Loaded $($r.Dns.Count) containers and OUs from $($r.Domain)."
  }
})
$tpAd.Controls.Add($btnReload)
$tpAd.Tag = $pickerY + 480

# ================================================================ tab: Scan
$tpScan = New-Tab 'Scan options'
Add-Heading $tpScan 'What each scan checks'
Add-Row $tpScan 'check_duplicates' 'Duplicate passwords' 'bool' 'Flag accounts that share a password with another account. Off by default; on a large directory it can add many rows.'
Add-Heading $tpScan 'Which tasks run scans'
Add-Row $tpScan 'enable_scheduled' 'Scheduled scan' 'bool' 'Register the Hashslinger-Scheduled task (runs on the schedule below).'
Add-Row $tpScan 'enable_ondemand' 'On-demand scans' 'bool' 'Register the Hashslinger-OnDemand task (analysts request scans with their EDIPI and a reason). Needs the analyst group on the Security tab to be useful.'
Add-Heading $tpScan 'Schedule'
Add-Row $tpScan 'cadence' 'How often' 'choice' @('Daily', 'Weekly', 'Monthly') 'Daily ignores the day. Monthly runs every 4 weeks.'
Add-Row $tpScan 'schedule_day' 'Day' 'choice' @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
Add-Row $tpScan 'schedule_time' 'Start time (24h, HH:mm)' 'text' $null 'After saving, you are asked whether to apply the schedule to the scheduled task now.'
Add-Heading $tpScan 'Limits and cleanup'
Add-Row $tpScan 'retention_days' 'Keep reports for (days)' 'int' @{ Min = 0; Max = 3650 } '0 = keep forever. Older reports are securely deleted after each scan.'
Add-Row $tpScan 'engine_timeout_seconds' 'Stop a scan after (hours)' 'hours' $null 'A scan that runs longer than this is stopped and logged as failed.'

# ================================================================ tab: Security
$tpSec = New-Tab 'Security and accounts'
Add-Heading $tpSec 'Service account and access'
Add-Row $tpSec 'gmsa_name' 'Service account (gMSA) name' 'text' $null 'The account the scheduled scan runs as. Create it by hand first; it needs only the two directory replication rights on the domain root and nothing else.'
Add-Row $tpSec 'run_server' 'Scan server' 'text' $null 'The only computer allowed to use the service account.'
Add-Row $tpSec 'analyst_group' 'Analyst group (optional)' 'text' $null 'Leave empty so only the service account and local Administrators have access. A group lets analysts submit scans.'
Add-Row $tpSec 'authorized_edipis' 'Allowed EDIPIs' 'lines' $null 'One per line. Empty = any valid 10-digit EDIPI may request a scan (only used with the analyst request GUI).'
Add-Row $tpSec 'require_encrypted_volume' 'Require BitLocker' 'bool' 'Refuse to scan unless the store, wordlists and reports are on a BitLocker-protected volume.'
Add-Row $tpSec 'dsinternals_offline_path' 'DSInternals module folder' 'path' 'folder' 'Only for servers with no internet: where the DSInternals module was copied from.'
$btnFinish = New-Object Windows.Forms.Button -Property @{ Text = 'Re-apply permissions and scheduled tasks'; Left = 270; Top = [int]$tpSec.Tag; Width = 300; Height = 30 }
$btnFinish.Add_Click({
  if ([Windows.Forms.MessageBox]::Show('This re-runs the Finish step: it checks the service account in AD (read-only), then re-applies folder permissions and re-registers the scheduled tasks on this server. Save your changes first. Continue?', 'Hashslinger Admin', 'YesNo') -eq 'Yes') {
    Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$setupScript`"", '-Config', "`"$ConfigPath`"", '-Phase', 'Finish')
  }
})
$tpSec.Controls.Add($btnFinish); $tpSec.Tag = [int]$tpSec.Tag + 40
Add-Note $tpSec 'Changing the service account, analyst group or scan server needs this re-apply step to take effect.'

# ================================================================ tab: Wordlists
$tpWl = New-Tab 'Wordlists'
Add-Heading $tpWl 'Password lists the scan matches against'
Add-Note $tpWl 'Add files here (they are COPIED into the right folder so the service account can read them). Supported: plain password lists, NT hash lists (.ntlm, HASH or HASH:count) and .tsv/.csv files with a hash column and a password column (the hash type is detected and checked; passwords are never stored).'
$script:wl = @{}
foreach ($t in @(@('HIBP', 'HIBP (NTLM hashes, HASH:count)'), @('rockyou', 'rockyou (plain passwords)'), @('custom', 'Custom (your own words, TSV/CSV tables)'))) {
  $y = [int]$tpWl.Tag
  $l1 = New-Object Windows.Forms.Label -Property @{ Text = $t[1]; Left = 12; Top = $y + 4; Width = 260 }
  $info = New-Object Windows.Forms.Label -Property @{ Text = ''; Left = 276; Top = $y + 4; Width = 290 }
  $ba = New-Object Windows.Forms.Button -Property @{ Text = 'Add files...'; Left = 574; Top = $y - 1; Width = 130; Height = 26; Tag = $t[0] }
  $bo = New-Object Windows.Forms.Button -Property @{ Text = 'Open folder'; Left = 712; Top = $y - 1; Width = 130; Height = 26; Tag = $t[0] }
  $ba.Add_Click({
    param($s, $e)
    $tag = [string]$s.Tag
    $d = New-Object Windows.Forms.OpenFileDialog; $d.Multiselect = $true
    if ($d.ShowDialog() -ne 'OK') { return }
    $dest = Join-Path (Get-Field 'staging_path') $tag
    New-Item -ItemType Directory -Force $dest | Out-Null
    foreach ($f in $d.FileNames) {
      $lblStatus.Text = "Copying $(Split-Path $f -Leaf) ..."; [Windows.Forms.Application]::DoEvents()
      Copy-Item $f (Join-Path $dest (Split-Path $f -Leaf)) -Force
    }
    $lblStatus.Text = "Copied $($d.FileNames.Count) file(s) to $dest. They are merged on the next scan, or click 'Merge now'."
    Refresh-Wordlists
  })
  $bo.Add_Click({ param($s, $e) $p = Join-Path (Get-Field 'staging_path') ([string]$s.Tag); New-Item -ItemType Directory -Force $p | Out-Null; Start-Process explorer.exe $p })
  $tpWl.Controls.AddRange(@($l1, $info, $ba, $bo))
  $script:wl[$t[0]] = $info
  $tpWl.Tag = $y + 34
}
$btnMerge = New-Object Windows.Forms.Button -Property @{ Text = 'Merge new files into the store now'; Left = 12; Top = [int]$tpWl.Tag + 6; Width = 260; Height = 32 }
$btnMerge.Add_Click({ Start-Process cmd.exe -ArgumentList '/k', "`"`"$exe`" --config `"$ConfigPath`" merge`"" })
$btnInfo = New-Object Windows.Forms.Button -Property @{ Text = 'Show store size'; Left = 282; Top = [int]$tpWl.Tag + 6; Width = 160; Height = 32 }
$btnInfo.Add_Click({ Start-Process cmd.exe -ArgumentList '/k', "`"`"$exe`" --config `"$ConfigPath`" info`"" })
$tpWl.Controls.AddRange(@($btnMerge, $btnInfo))
function Refresh-Wordlists {
  foreach ($t in 'HIBP', 'rockyou', 'custom') {
    $p = Join-Path ([string]$script:cfg['staging_path']) $t
    $files = @(Get-ChildItem $p -File -ErrorAction SilentlyContinue)
    $gb = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1GB, 2)
    $script:wl[$t].Text = '{0} file(s), {1} GB' -f $files.Count, $gb
  }
}

# ================================================================ tab: Run and logs
$tpRun = New-Tab 'Run and logs'
Add-Heading $tpRun 'Scans'
$btns = @(
  @('Start a scan now', { Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $root 'app\powershell\Start-HashslingerGui.ps1')`"", '-ConfigPath', "`"$ConfigPath`""); $lblStatus.Text = 'Opened the scan request window: it asks for your EDIPI and the reason / CTO number, then runs the scan as the service account.' }),
  @('Watch progress', { Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$viewer`"", '-ConfigPath', "`"$ConfigPath`"") }),
  @('Open newest report', { $f = Get-ChildItem (Get-Field 'output_path') -Filter 'report_*.csv' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { Start-Process $f.FullName } else { Msg 'No report yet.' } }),
  @('Open reports folder', { $p = Get-Field 'output_path'; New-Item -ItemType Directory -Force $p | Out-Null; Start-Process explorer.exe $p }),
  @('Open audit log', { $p = Get-Field 'log_path'; if (Test-Path $p) { Start-Process notepad.exe $p } else { Msg 'No audit log yet.' } })
)
$x = 12; $y = [int]$tpRun.Tag
foreach ($b in $btns) {
  $bt = New-Object Windows.Forms.Button -Property @{ Text = $b[0]; Left = $x; Top = $y; Width = 165; Height = 32 }
  $bt.Add_Click($b[1]); $tpRun.Controls.Add($bt); $x += 172
}
$tpRun.Tag = $y + 44
Add-Heading $tpRun 'Checks and support'
$btns2 = @(
  @('Re-run readiness checks', { Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$setupScript`"", '-Config', "`"$ConfigPath`"", '-Phase', 'Check') }),
  @('Create support bundle', { New-SupportBundle }),
  @('Run self-test (exe)', { Start-Process cmd.exe -ArgumentList '/k', "`"`"$exe`" selftest`"" }),
  @('Open the SOP', { $p = Join-Path $root 'app\docs\Hashslinger-SOP.html'; if (Test-Path $p) { Start-Process $p } else { Msg "Not found: $p" } })
)
$x = 12; $y = [int]$tpRun.Tag
foreach ($b in $btns2) {
  $bt = New-Object Windows.Forms.Button -Property @{ Text = $b[0]; Left = $x; Top = $y; Width = 200; Height = 32 }
  $bt.Add_Click($b[1]); $tpRun.Controls.Add($bt); $x += 208
}
$tpRun.Tag = $y + 44
Add-Heading $tpRun 'Last scan'
$txtLast = New-Object Windows.Forms.TextBox -Property @{ Left = 12; Top = [int]$tpRun.Tag; Width = 850; Height = 220; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Font = New-Object Drawing.Font('Consolas', 9.5) }
$btnRefresh = New-Object Windows.Forms.Button -Property @{ Text = 'Refresh'; Left = 12; Top = [int]$tpRun.Tag + 228; Width = 110; Height = 28 }
$btnRefresh.Add_Click({ Show-LastRun })
$tpRun.Controls.AddRange(@($txtLast, $btnRefresh))

function Show-LastRun {
  $p = [string]$script:cfg['log_path']
  if (-not (Test-Path $p)) { $txtLast.Text = 'No scans have run yet.'; return }
  $end = $null
  foreach ($l in (Get-Content $p -Tail 400)) {
    try { $o = $l | ConvertFrom-Json } catch { continue }
    if ($o.event -eq 'end') { $end = $o }
  }
  if (-not $end) { $txtLast.Text = 'No finished scan found in the audit log yet.'; return }
  $names = @{ stage1 = 'Preflight'; stage2 = 'Merge wordlists'; stage3 = 'Build patterns'; stage4 = 'Pull accounts from AD'; stage5 = 'Match against store'; stage6 = 'Write report'; stage7 = 'Wipe memory + log' }
  $t = "Run $($end.run_id): $($end.status.ToUpper())  ($($end.time))`r`nAccounts processed: $($end.accounts_processed)`r`nMemory wipe confirmed: $($end.wipe_confirmed)`r`nReport: $($end.output)`r`n"
  if ($end.error) { $t += "Error: $($end.error)`r`n" }
  if ($end.timings_ms) {
    $t += "`r`nTime per stage:`r`n"
    foreach ($k in 'stage1', 'stage2', 'stage3', 'stage4', 'stage5', 'stage6', 'stage7') {
      $ms = $end.timings_ms.$k
      if ($null -ne $ms) { $t += ('  {0,-24} {1,10:N1} s' -f $names[$k], ($ms / 1000.0)) + "`r`n" }
    }
  }
  $txtLast.Text = $t
}

# support bundle: logs and settings only. No reports, no hashes, no wordlists.
function New-SupportBundle {
  try {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $tmp = Join-Path $env:TEMP "hs-support-$stamp"
    New-Item -ItemType Directory -Force $tmp | Out-Null
    Copy-Item $ConfigPath $tmp -ErrorAction SilentlyContinue
    foreach ($p in $script:cfg['log_path'], $script:cfg['status_path']) { if (Test-Path $p) { Copy-Item $p $tmp -ErrorAction SilentlyContinue } }
    $logDir = Split-Path -Parent ([string]$script:cfg['log_path'])
    Get-ChildItem $logDir -Filter 'setup-*.log' -ErrorAction SilentlyContinue | Select-Object -Last 3 | Copy-Item -Destination $tmp -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $logDir 'SETUP-SUMMARY.txt') $tmp -ErrorAction SilentlyContinue
    $fips = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction Stop).Enabled } catch { 'unknown' }
    $dsv = try { (Get-Module DSInternals -ListAvailable | Select-Object -First 1).Version.ToString() } catch { 'not installed' }
    $os = (Get-CimInstance Win32_OperatingSystem)
    @("Collected: $(Get-Date)", "Computer: $env:COMPUTERNAME", "OS: $($os.Caption) $($os.Version)", "PowerShell: $($PSVersionTable.PSVersion)", "DSInternals: $dsv", "FIPS policy enabled: $fips") | Set-Content (Join-Path $tmp 'system-info.txt')
    $zip = Join-Path ([Environment]::GetFolderPath('Desktop')) "Hashslinger-support-$stamp.zip"
    Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $zip -Force
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe "/select,`"$zip`""
    $lblStatus.Text = "Support bundle created: $zip (settings and logs only: no reports, no hashes)"
  } catch { Msg ('Could not create the bundle: ' + $_.Exception.Message) }
}

# ================================================================ save / revert
function Apply-Schedule {
  $day = [string]$script:cfg['schedule_day']
  $at = [datetime]::ParseExact([string]$script:cfg['schedule_time'], 'HH:mm', $null)
  $trigger = switch ([string]$script:cfg['cadence']) {
    'Daily'   { New-ScheduledTaskTrigger -Daily -At $at }
    'Monthly' { New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek $day -At $at }
    default   { New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $day -At $at }
  }
  Set-ScheduledTask -TaskName 'Hashslinger-Scheduled' -Trigger $trigger | Out-Null
}

$btnSave.Add_Click({
  try {
    $errs = @()
    if ((Get-Field 'mode') -eq 'live' -and -not (Get-Field 'target_server')) { $errs += 'Pick the domain controller (Active Directory tab).' }
    if (@(Get-HsOuSelection).Count -eq 0) { $errs += 'Pick at least one thing to scan (Active Directory tab).' }
    if (-not (Get-Field 'enable_scheduled') -and -not (Get-Field 'enable_ondemand')) { $errs += 'Turn on at least one of: scheduled scan, on-demand scans (Scan options tab).' }
    if ((Get-Field 'account_types').Count -eq 0) { $errs += 'Tick at least one account type.' }
    if (Get-Field 'enable_scheduled') { try { [void][datetime]::ParseExact((Get-Field 'schedule_time'), 'HH:mm', $null) } catch { $errs += 'Start time must look like 02:00.' } }
    if ($errs.Count) { Msg ("Not saved:`r`n`r`n - " + ($errs -join "`r`n - ")); return }

    $old = Read-HsConfig $ConfigPath
    $new = Read-HsConfig $ConfigPath
    foreach ($k in @($script:Ctl.Keys)) { Set-HsCfgValue $new $k (Get-Field $k) }
    $new['target_ous'] = @(Get-HsOuSelection)
    # the reports folder must always be an allowed output location, or scans would refuse to write there
    $roots = @($new['allowed_output_roots'])
    if (-not ($roots | Where-Object { $_ -ieq $new['output_path'] })) { $roots += $new['output_path']; $new['allowed_output_roots'] = $roots }
    Save-HsConfig $new $ConfigPath
    $script:cfg = $new
    $lblStatus.Text = ('Saved {0:HH:mm:ss}. Changes apply to the next scan. A backup of the previous settings was kept.' -f (Get-Date))

    $schedChanged = ($old['cadence'] -ne $new['cadence']) -or ($old['schedule_day'] -ne $new['schedule_day']) -or ($old['schedule_time'] -ne $new['schedule_time'])
    $tasksChanged = ([bool]$old['enable_scheduled'] -ne [bool]$new['enable_scheduled']) -or ([bool]$old['enable_ondemand'] -ne [bool]$new['enable_ondemand'])
    if ($tasksChanged) {
      if ([Windows.Forms.MessageBox]::Show('You changed which tasks run scans. Apply it now? This runs the Finish step (it registers or removes the scheduled tasks and re-checks the service account).', 'Hashslinger Admin', 'YesNo') -eq 'Yes') {
        Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$setupScript`"", '-Config', "`"$ConfigPath`"", '-Phase', 'Finish')
      }
    }
    elseif ($schedChanged -and [Windows.Forms.MessageBox]::Show('The schedule changed. Update the scheduled task now?', 'Hashslinger Admin', 'YesNo') -eq 'Yes') {
      try { Apply-Schedule; $lblStatus.Text = 'Saved, and the scheduled task was updated.' } catch { Msg ('Saved, but the scheduled task could not be updated (is it registered? use Re-apply on the Security tab): ' + $_.Exception.Message) }
    }
    Refresh-Wordlists
  } catch { Msg ('Could not save: ' + $_.Exception.Message) }
})
$btnRevert.Add_Click({ Load-All; $lblStatus.Text = 'Reverted to the saved settings.' })

Load-All
[void]$form.ShowDialog()
