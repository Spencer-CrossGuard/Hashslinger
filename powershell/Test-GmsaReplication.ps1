<#
.SYNOPSIS
  Probe run by Setup (Finish phase) AS THE gMSA: tries one directory replication and writes the outcome.
.DESCRIPTION
  Replicates a single object (the scan server's own computer account) and writes only the account name, the
  property set that worked, or the exact error to -OutFile. It never writes a hash or any secret.
  Uses explicit -Properties sets (widest the module accepts) because DSInternals 6.3+ otherwise also needs
  replication rights on the Schema partition, which this tool deliberately does not ask for.
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
  $lines += 'dsinternals: ' + ((Get-Module DSInternals).Version)
  $ladder = @('GenericAccountInfo,NTHash,LMHash,SupplementalCredentials', 'GenericAccountInfo,NTHash,LMHash', 'GenericAccountInfo,NTHash')
  $done = $false
  foreach ($set in $ladder) {
    try {
      $a = Get-ADReplAccount -SamAccountName $Sam -Server $Server -Properties ($set -split ',')
      if ($a -and $a.SamAccountName) { $lines += "OK replicated $($a.SamAccountName) (properties: $set)"; $done = $true; break }
    }
    catch [System.Management.Automation.ParameterBindingException] { $lines += "note: property set '$set' not accepted by this DSInternals version"; continue }
    catch [System.ArgumentException] { $lines += "note: property set '$set' not accepted by this DSInternals version"; continue }
  }
  if (-not $done) {
    $a = Get-ADReplAccount -SamAccountName $Sam -Server $Server
    if ($a -and $a.SamAccountName) { $lines += "OK replicated $($a.SamAccountName) (module default properties)" } else { $lines += 'ERROR: replication returned no object' }
  }
} catch { $lines += 'ERROR: ' + $_.Exception.Message }
Set-Content -Path $OutFile -Value $lines
