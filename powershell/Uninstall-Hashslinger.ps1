<#
.SYNOPSIS
  Uninstall Hashslinger from this server. Local only: it never touches Active Directory.
.DESCRIPTION
  Default (no switches): stop any running scan and remove the scheduled tasks. All files stay, so a reinstall picks up
  where you left off. Add switches to delete things:
    -RemoveData      data\  (hash store, manifest, wordlists in staging)
    -RemoveReports   the reports folder (CSV files)
    -RemoveLogs      logs\ and status\ (audit log, setup logs, progress file)
    -RemoveApp       app\, app-backups\, extras\, the Admin and Uninstall launchers (config\ stays)
    -RemoveAll       the whole install folder (everything above plus config\)
    -SecureWipe      overwrite files before deleting them (slow for a large store)
    -RemoveDsInternals  also delete the DSInternals module installed for all users
    -Force           do not ask for confirmation
  The service account in AD and its replication rights are removed by hand (SOP, section "Uninstall").
.EXAMPLE
  .\Uninstall-Hashslinger.ps1                       tasks removed, files kept
  .\Uninstall-Hashslinger.ps1 -RemoveAll -SecureWipe
#>
[CmdletBinding()]
param(
  [string]$Config = (Join-Path $PSScriptRoot '..\..\config\hashslinger.json'),
  [switch]$RemoveData, [switch]$RemoveReports, [switch]$RemoveLogs, [switch]$RemoveApp, [switch]$RemoveAll,
  [switch]$SecureWipe, [switch]$RemoveDsInternals, [switch]$Force
)
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  $a = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Config', "`"$Config`"")
  foreach ($s in 'RemoveData', 'RemoveReports', 'RemoveLogs', 'RemoveApp', 'RemoveAll', 'SecureWipe', 'RemoveDsInternals', 'Force') { if ((Get-Variable $s).Value) { $a += "-$s" } }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $a
  exit
}

$Config = [IO.Path]::GetFullPath($Config)
$root = Split-Path -Parent (Split-Path -Parent $Config)
$cfg = $null
if (Test-Path $Config) { try { $cfg = Get-Content $Config -Raw | ConvertFrom-Json } catch { } }
function Cfg([string]$k, [string]$default) { if ($cfg -and $cfg.PSObject.Properties.Name -contains $k -and $cfg.$k) { return [string]$cfg.$k } return $default }
if ($cfg -and $cfg.install_root) { $root = [string]$cfg.install_root }

$store = Split-Path -Parent (Cfg 'hash_store_path' "$root\data\store\master.ntlm")
$staging = Cfg 'staging_path' "$root\data\staging"
$reports = Cfg 'output_path' "$root\reports"
$logs = Split-Path -Parent (Cfg 'log_path' "$root\logs\audit.jsonl")
$status = Split-Path -Parent (Cfg 'status_path' "$root\status\status.json")
$dataRoot = "$root\data"

if ($RemoveAll -and (($root.TrimEnd('\') -match '^[A-Za-z]:$') -or -not (Test-Path "$root\config\hashslinger.json"))) {
  Write-Host "Refusing -RemoveAll: $root does not look like a Hashslinger install folder (no config\hashslinger.json inside)." -ForegroundColor Red; exit 1
}
if ($RemoveAll) { $RemoveData = $RemoveReports = $RemoveLogs = $RemoveApp = $true }
$plan = New-Object System.Collections.ArrayList
[void]$plan.Add('Stop any running scan; remove the scheduled tasks (Hashslinger-Scheduled, Hashslinger-OnDemand)')
if ($RemoveData) { [void]$plan.Add("Delete Hashslinger's hash store files and the HIBP, rockyou and custom wordlist folders in: $store, $staging (other files in those folders are left alone)") }
if ($RemoveReports) { [void]$plan.Add("Delete Hashslinger's report_*.csv files in: $reports (other files are left alone)") }
if ($RemoveLogs) { [void]$plan.Add("Delete Hashslinger's audit log, setup logs and status file in: $logs, $status (other files are left alone)") }
if ($RemoveApp) { [void]$plan.Add("Delete the program: $root\app, $root\app-backups, $root\extras, launchers") }
if ($RemoveAll) { [void]$plan.Add("Delete the settings and the install folder itself: $root") }
if ($RemoveDsInternals) { [void]$plan.Add("Delete the DSInternals module: $env:ProgramFiles\WindowsPowerShell\Modules\DSInternals") }
if ($SecureWipe) { [void]$plan.Add('Files are overwritten before they are deleted') }
Write-Host 'This will:' -ForegroundColor Yellow
$plan | ForEach-Object { Write-Host "  - $_" }
if (-not $Force) {
  if ((Read-Host 'Type YES to continue') -ne 'YES') { Write-Host 'Cancelled.'; exit 1 }
}

function Remove-Tree([string]$path) {
  if (-not (Test-Path $path)) { return }
  # never delete a drive root or a system folder, whatever the settings file says
  $full = [IO.Path]::GetFullPath($path).TrimEnd('\')
  if ($full -match '^[A-Za-z]:$' -or $full -ieq $env:windir -or $full -ieq $env:ProgramFiles -or $full -ieq ${env:ProgramFiles(x86)} -or $full -ieq $env:SystemDrive) {
    Write-Host "  refusing to remove $path (drive root or system folder). Fix the path in the settings." -ForegroundColor Red; return
  }
  if ($SecureWipe) {
    foreach ($f in Get-ChildItem $path -Recurse -File -Force -ErrorAction SilentlyContinue) {
      try {
        $len = $f.Length
        $fs = [IO.File]::Open($f.FullName, 'Open', 'Write', 'None')
        $buf = New-Object byte[] (1MB)
        $left = $len
        while ($left -gt 0) { $n = [Math]::Min($left, $buf.Length); $fs.Write($buf, 0, $n); $left -= $n }
        $fs.Flush($true); $fs.Dispose()
      } catch { }
    }
  }
  Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
  if (Test-Path $path) { Write-Host "  could not fully remove $path (in use?)" -ForegroundColor Yellow } else { Write-Host "  removed $path" }
}

# 1. stop scans and remove tasks
foreach ($t in 'Hashslinger-Scheduled', 'Hashslinger-OnDemand', 'Hashslinger-Probe') {
  if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
    Write-Host "  removed scheduled task $t"
  }
}
Get-Process -Name Hashslinger -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'Get-AccountHashes' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Configured folders can be shared with other software (for example a common logs folder). So these remove only the
# files and subfolders Hashslinger itself creates, and the folder only if it is then empty. Whole-folder deletion is
# reserved for folders Hashslinger owns outright (the program folders and, with -RemoveAll, the install folder).
function Remove-OwnFiles([string]$dir, [string[]]$patterns, [string[]]$ownSubdirs = @(), [string[]]$ownSubdirPatterns = @()) {
  if (-not (Test-Path $dir)) { return }
  $full = [IO.Path]::GetFullPath($dir).TrimEnd('\')
  if ($full -match '^[A-Za-z]:$') { Write-Host "  refusing to touch $dir (drive root)" -ForegroundColor Red; return }
  foreach ($pat in $patterns) {
    foreach ($f in Get-ChildItem -LiteralPath $dir -File -Filter $pat -Force -ErrorAction SilentlyContinue) {
      if ($SecureWipe) {
        try {
          $fs = [IO.File]::Open($f.FullName, 'Open', 'Write', 'None'); $buf = New-Object byte[] (1MB); $left = $f.Length
          while ($left -gt 0) { $n = [Math]::Min($left, $buf.Length); $fs.Write($buf, 0, $n); $left -= $n }
          $fs.Flush($true); $fs.Dispose()
        } catch { }
      }
      Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
    }
  }
  foreach ($s in $ownSubdirs) { Remove-Tree (Join-Path $dir $s) }
  foreach ($pat in $ownSubdirPatterns) {
    foreach ($d in Get-ChildItem -LiteralPath $dir -Directory -Filter $pat -Force -ErrorAction SilentlyContinue) { Remove-Tree $d.FullName }
  }
  if (-not (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue; Write-Host "  removed $dir" }
  else { Write-Host "  cleaned Hashslinger files from $dir (other files are there, so the folder was kept)" }
}

# 2. delete what was asked
if ($RemoveData) {
  $masterName = [IO.Path]::GetFileName((Cfg 'hash_store_path' "$root\data\store\master.ntlm"))
  Remove-OwnFiles $staging @() @('HIBP', 'rockyou', 'custom')
  Remove-OwnFiles $store @("$masterName*", 'run.lock') @() @('merge-*')
  if ($dataRoot -and (Test-Path $dataRoot) -and -not (Get-ChildItem $dataRoot -Force -ErrorAction SilentlyContinue)) { Remove-Item $dataRoot -Force }
}
if ($RemoveReports) { Remove-OwnFiles $reports @('report_*.csv', 'report_*.csv.tmp') }
if ($RemoveLogs) {
  $auditName = [IO.Path]::GetFileName((Cfg 'log_path' "$root\logs\audit.jsonl"))
  Remove-OwnFiles $logs @("$auditName*", 'setup-*.log', 'SETUP-SUMMARY.txt')
  Remove-OwnFiles $status @('status.json*', 'gmsa-probe.txt')
}
if ($RemoveDsInternals) { Remove-Tree "$env:ProgramFiles\WindowsPowerShell\Modules\DSInternals" }
if ($RemoveApp) {   # also with -RemoveAll: the Start menu and desktop shortcuts must not be left pointing at nothing
  Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Hashslinger') -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Hashslinger Running Tool.lnk') -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Hashslinger SOP.lnk') -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $env:ProgramData 'Hashslinger') -Recurse -Force -ErrorAction SilentlyContinue   # the public copy of the SOP
}
if ($RemoveApp -and -not $RemoveAll) {
  Remove-Tree "$root\extras"; Remove-Tree "$root\app-backups"
  foreach ($n in 'Hashslinger-Admin', 'Hashslinger-Run', 'Hashslinger-Uninstall') { foreach ($e in '.ps1', '.lnk', '.cmd') { Remove-Item "$root\$n$e" -Force -ErrorAction SilentlyContinue } }
  Remove-Tree "$root\app"
}
if ($RemoveAll) {
  # this script lives inside the folder being deleted, so hand the final delete to a detached cmd after we exit
  $cmd = "ping -n 3 127.0.0.1 >nul & rd /s /q `"$root`""
  if ($SecureWipe) { foreach ($d in $root) { foreach ($f in Get-ChildItem $d -Recurse -File -Force -ErrorAction SilentlyContinue) { if ($f.FullName -ne $PSCommandPath) { try { $fs = [IO.File]::Open($f.FullName, 'Open', 'Write', 'None'); $b = New-Object byte[] (1MB); $l = $f.Length; while ($l -gt 0) { $n = [Math]::Min($l, $b.Length); $fs.Write($b, 0, $n); $l -= $n }; $fs.Dispose() } catch { } } } } }
  Start-Process cmd.exe -ArgumentList '/c', $cmd -WindowStyle Hidden
  Write-Host "  the install folder $root is being removed in a moment"
}

Write-Host ''
Write-Host 'Local uninstall finished. Active Directory was not touched.' -ForegroundColor Green
Write-Host 'To finish by hand: remove the service account and its two replication rights in AD (SOP, section Uninstall).'
