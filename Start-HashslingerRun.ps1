<#
.SYNOPSIS
  Lab / dev launcher: opens the one-window "set up and start a scan" tool (runs the scan as YOUR account).
  Start it with:  powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-HashslingerRun.ps1
#>
$here = Split-Path -Parent $PSCommandPath
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'powershell\Start-HashslingerRun.ps1')
