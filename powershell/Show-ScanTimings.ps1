<#
.SYNOPSIS
  Shows where scan time goes: one row per recent scan from the audit log. Read only.
.DESCRIPTION
  Columns: accounts, total time, the seven stages, the three parts inside "Pull accounts from AD" (scope search, property
  test, replication), accounts per second in the AD stage, and the peak memory of the scan program. Use it to compare runs
  while tuning (for example workers, scope size, or the store size).
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Show-ScanTimings.ps1 -ConfigPath C:\Hashslinger\config\hashslinger.json -Last 10
#>
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\hashslinger.json'),
  [int]$Last = 10
)
$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$logPath = [string]$cfg.log_path
if (-not (Test-Path -LiteralPath $logPath)) { Write-Host "No audit log yet: $logPath"; return }

$starts = @{}
$runs = New-Object System.Collections.Generic.List[object]
$fs = New-Object IO.FileStream($logPath, 'Open', 'Read', 'ReadWrite')
$sr = New-Object IO.StreamReader($fs)
while (($line = $sr.ReadLine()) -ne $null) {
  if (-not $line.Trim()) { continue }
  try { $o = $line | ConvertFrom-Json } catch { continue }
  if ($o.event -eq 'start') { $starts[[string]$o.run_id] = $o }
  elseif ($o.event -eq 'end') {
    $st = $starts[[string]$o.run_id]
    $t = $o.timings_ms
    $sec = { param($v) if ($null -eq $v) { '' } else { [Math]::Round([double]$v / 1000.0, 1) } }
    $total = 0.0
    if ($t) { foreach ($k in 1..7) { $v = $t."stage$k"; if ($null -ne $v) { $total += [double]$v } } }
    $e = $o.engine_steps_ms
    $acct = [int]$o.accounts_processed
    $s4 = if ($t) { [double]$t.stage4 } else { 0.0 }
    $runs.Add([pscustomobject][ordered]@{
      Run        = [string]$o.run_id
      Status     = [string]$o.status
      Trigger    = $(if ($st) { [string]$st.trigger } else { '' })
      Accounts   = $acct
      TotalSec   = [Math]::Round($total / 1000.0, 1)
      Preflight  = (& $sec $(if ($t) { $t.stage1 }))
      Merge      = (& $sec $(if ($t) { $t.stage2 }))
      Patterns   = (& $sec $(if ($t) { $t.stage3 }))
      AdStage    = (& $sec $(if ($t) { $t.stage4 }))
      ScopeSrch  = (& $sec $(if ($e) { $e.scope_search }))
      PropTest   = (& $sec $(if ($e) { $e.property_test }))
      Replicate  = (& $sec $(if ($e) { $e.replication }))
      Match      = (& $sec $(if ($t) { $t.stage5 }))
      Report     = (& $sec $(if ($t) { $t.stage6 }))
      Wipe       = (& $sec $(if ($t) { $t.stage7 }))
      AcctPerSec = $(if ($s4 -gt 0 -and $acct -gt 0) { [Math]::Round($acct / ($s4 / 1000.0)) } else { '' })
      PeakMB     = $(if ($o.peak_working_set_mb) { [int]$o.peak_working_set_mb } else { '' })
    })
  }
}
$sr.Dispose(); $fs.Dispose()
if ($runs.Count -eq 0) { Write-Host 'No finished scans in the audit log yet.'; return }
$show = @($runs | Select-Object -Last $Last)
Write-Host 'Seconds per stage (Preflight, Merge wordlists, Patterns, AdStage = pull from AD, Match, Report, Wipe).'
Write-Host 'Inside AdStage: ScopeSrch = LDAP scope search, PropTest = one test call, Replicate = pulling the hashes.'
$show | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
$big = $show | Select-Object -Last 1
$parts = [ordered]@{ Preflight = $big.Preflight; 'Merge wordlists' = $big.Merge; Patterns = $big.Patterns; 'Pull from AD' = $big.AdStage; Match = $big.Match; Report = $big.Report; Wipe = $big.Wipe }
$tot = [double]$big.TotalSec
if ($tot -gt 0) {
  Write-Host ("Where the time went in {0} ({1} s total):" -f $big.Run, $big.TotalSec)
  foreach ($k in $parts.Keys) { $v = $parts[$k]; if ($v -ne '') { Write-Host ('  {0,-16} {1,8} s  {2,5:N1} %' -f $k, $v, (100.0 * [double]$v / $tot)) } }
}
