<#
.SYNOPSIS
  Probe run by Setup (Finish phase) AS THE gMSA: tries one directory replication and writes the outcome.
.DESCRIPTION
  Replicates a single object (the scan server's own computer account) and writes only the account name or
  the exact error text to -OutFile. It never writes a hash or any secret.
#>
param(
  [Parameter(Mandatory)][string]$Server,
  [Parameter(Mandatory)][string]$Sam,
  [Parameter(Mandatory)][string]$OutFile
)
$ErrorActionPreference = 'Stop'
$lines = @("identity: $(whoami)")
try {
  Import-Module DSInternals
  $a = Get-ADReplAccount -SamAccountName $Sam -Server $Server
  if ($a -and $a.SamAccountName) { $lines += "OK replicated $($a.SamAccountName)" } else { $lines += 'ERROR: replication returned no object' }
} catch { $lines += 'ERROR: ' + $_.Exception.Message }
Set-Content -Path $OutFile -Value $lines
