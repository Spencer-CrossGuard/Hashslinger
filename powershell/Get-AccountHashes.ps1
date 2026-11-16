<#
.SYNOPSIS
  Core engine: enumerate in-scope accounts and emit NT hashes as JSON lines on stdout.
.DESCRIPTION
  Live mode: an LDAP query (SearchBase + userAccountControl bit filters) selects the
  in-scope accounts first, then ONLY those accounts are replicated with DSInternals
  Get-ADReplAccount -ObjectGuid. Out-of-scope hashes are never requested from the DC.
  Offline mode: Get-ADDBAccount over an ntds.dit copy; filters apply after load.
  Hashes go to stdout only (read by the Python process through a pipe). Never to disk,
  never to the error stream.
#>
[CmdletBinding()]
param(
  [ValidateSet('live', 'offline')][string]$Mode = 'live',
  [Parameter(Mandatory)][string]$SearchBase,
  [string]$Server,
  [string[]]$AccountTypes = @('User', 'Service'),
  [int[]]$ExcludeUacFlags = @(0x40000, 0x2),
  [int[]]$RequireUacFlags = @(),
  [string]$NtdsPath,
  [string]$SystemHivePath
)
$ErrorActionPreference = 'Stop'
Import-Module DSInternals

function ToHex([byte[]]$b) { if ($b) { ([BitConverter]::ToString($b)).Replace('-', '') } else { $null } }

function Emit($acct, [string]$type) {
  $clear = $null -ne $acct.SupplementalCredentials -and $null -ne $acct.SupplementalCredentials.ClearText
  $uac = [int]$acct.UserAccountControl
  [pscustomobject]@{
    sam        = [string]$acct.SamAccountName
    dn         = [string]$acct.DistinguishedName
    type       = $type
    nt         = ToHex $acct.NTHash
    lm         = [bool]($null -ne $acct.LMHash)
    reversible = [bool]($clear -or (($uac -band 0x80) -ne 0))
  } | ConvertTo-Json -Compress
}

# LDAP matching rule 1.2.840.113556.1.4.803 = bitwise AND.
function UacClause {
  $c = ''
  foreach ($f in $ExcludeUacFlags) { $c += "(!(userAccountControl:1.2.840.113556.1.4.803:=$f))" }
  foreach ($f in $RequireUacFlags) { $c += "(userAccountControl:1.2.840.113556.1.4.803:=$f)" }
  $c
}

function TypeClauses {
  $parts = @()
  if ($AccountTypes -contains 'User')     { $parts += '(&(objectCategory=person)(objectClass=user)(!(servicePrincipalName=*)))' }
  if ($AccountTypes -contains 'Service')  { $parts += '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' }
  if ($AccountTypes -contains 'Computer') { $parts += '(objectCategory=computer)' }
  if ($parts.Count -eq 0) { throw 'No account types selected' }
  "(|$($parts -join ''))"
}

function ClassifyType($spn, $isComputer) {
  if ($isComputer) { 'Computer' } elseif ($spn -and @($spn).Count -gt 0) { 'Service' } else { 'User' }
}

if ($Mode -eq 'live') {
  if (-not $Server) { throw '-Server is required in live mode' }
  Import-Module ActiveDirectory
  $filter = "(&$(TypeClauses)$(UacClause))"
  $objs = Get-ADObject -LDAPFilter $filter -SearchBase $SearchBase -SearchScope Subtree -Server $Server `
            -Properties objectGUID, servicePrincipalName, objectClass
  foreach ($o in $objs) {
    $acct = Get-ADReplAccount -ObjectGuid $o.ObjectGUID -Server $Server
    Emit $acct (ClassifyType $o.servicePrincipalName ($o.objectClass -eq 'computer'))
  }
}
else {
  if (-not ($NtdsPath -and $SystemHivePath)) { throw 'offline mode needs -NtdsPath and -SystemHivePath' }
  $key = Get-BootKey -SystemHivePath $SystemHivePath
  Get-ADDBAccount -All -DatabasePath $NtdsPath -BootKey $key | ForEach-Object {
    $a = $_
    if (-not $a.DistinguishedName.EndsWith($SearchBase, [StringComparison]::OrdinalIgnoreCase)) { return }
    $isComp = $a.SamAccountName.EndsWith('$')
    $type = ClassifyType $a.ServicePrincipalName $isComp
    if ($AccountTypes -notcontains $type) { return }
    $uac = [int]$a.UserAccountControl
    foreach ($f in $ExcludeUacFlags) { if (($uac -band $f) -ne 0) { return } }
    foreach ($f in $RequireUacFlags) { if (($uac -band $f) -eq 0) { return } }
    Emit $a $type
  }
}
