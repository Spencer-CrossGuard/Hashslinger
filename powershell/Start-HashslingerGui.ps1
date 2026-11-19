<#
.SYNOPSIS
  Kept so older shortcuts keep working: opens the Running tool (Hashslinger-Run.ps1).
#>
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\hashslinger.json'))
& (Join-Path $PSScriptRoot 'Hashslinger-Run.ps1') -ConfigPath $ConfigPath
