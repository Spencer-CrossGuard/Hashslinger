<#
.SYNOPSIS
  START HERE. Opens the Hashslinger setup wizard, or runs one setup phase.
.DESCRIPTION
  With no arguments it opens the setup wizard (recommended). With -Phase / -Config it runs that setup phase.
  Start it from PowerShell:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-Hashslinger.ps1
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-Hashslinger.ps1 -Phase Check -Config C:\Hashslinger\config\hashslinger.json
  (Right-click > Run with PowerShell also works when the execution policy allows it. The command above never depends on it.)
  Local administrator is enough. This script unblocks the package files first, then does the real work in a child
  PowerShell that has the execution policy bypassed for that process only.
#>
param(
  [ValidateSet('Check', 'Local', 'Finish', 'All')][string]$Phase,
  [Alias('InitConfig')][string]$Config,
  [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
# files from a download or a copy can carry a "blocked" mark that stops scripts from running
Get-ChildItem -LiteralPath $here -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
if (-not $Phase -and -not $Config) {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'powershell\Setup-Wizard.ps1')
  exit $LASTEXITCODE
}
$argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $here 'powershell\Setup-Hashslinger.ps1'))
if ($Config) { $argList += '-Config'; $argList += $Config }
if ($Phase) { $argList += '-Phase'; $argList += $Phase }
if ($WhatIf) { $argList += '-WhatIf' }
& powershell.exe @argList
exit $LASTEXITCODE
