<#
.SYNOPSIS
  Builds Hashslinger.exe with the C# compiler that ships with Windows (.NET Framework 4.x). No SDK or Visual Studio needed.
.DESCRIPTION
  The code is written to compile as C# 5. Run from this folder:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-Hashslinger.ps1
  then:  .\Hashslinger.exe selftest
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { Write-Host "csc.exe not found at $csc" -ForegroundColor Red; exit 1 }
Push-Location $here
try {
  & $csc /nologo /optimize+ /unsafe /platform:x64 /target:exe /out:Hashslinger.exe /r:System.dll /r:System.Core.dll 'cs\*.cs'
  if ($LASTEXITCODE -ne 0) { Write-Host 'Build failed (compiler messages above).' -ForegroundColor Red; exit 1 }
}
finally { Pop-Location }
Write-Host 'Built Hashslinger.exe. Next: .\Hashslinger.exe selftest' -ForegroundColor Green
