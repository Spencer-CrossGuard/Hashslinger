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

if ($RemoveAll) { $RemoveData = $RemoveReports = $RemoveLogs = $RemoveApp = $true }
$plan = New-Object System.Collections.ArrayList
[void]$plan.Add('Stop any running scan; remove the scheduled tasks (Hashslinger-Scheduled, Hashslinger-OnDemand)')
if ($RemoveData) { [void]$plan.Add("Delete the hash store and wordlists: $store, $staging") }
if ($RemoveReports) { [void]$plan.Add("Delete the reports: $reports") }
if ($RemoveLogs) { [void]$plan.Add("Delete logs and status: $logs, $status") }
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

# 2. delete what was asked
if ($RemoveData) { Remove-Tree $staging; Remove-Tree $store; if ($dataRoot -and (Test-Path $dataRoot) -and -not (Get-ChildItem $dataRoot -Force -ErrorAction SilentlyContinue)) { Remove-Item $dataRoot -Force } }
if ($RemoveReports) { Remove-Tree $reports }
if ($RemoveLogs) { Remove-Tree $logs; Remove-Tree $status }
if ($RemoveDsInternals) { Remove-Tree "$env:ProgramFiles\WindowsPowerShell\Modules\DSInternals" }
if ($RemoveApp -and -not $RemoveAll) {
  Remove-Tree "$root\extras"; Remove-Tree "$root\app-backups"
  foreach ($f in 'Hashslinger-Admin.cmd', 'Hashslinger-Uninstall.cmd') { Remove-Item "$root\$f" -Force -ErrorAction SilentlyContinue }
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
