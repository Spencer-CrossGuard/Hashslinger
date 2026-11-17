<#
Test 1: environment facts. Run on any machine with the AD tools. Read-only.
Send the output back; it shows the DC/GW1 OS versions (for the Windows Server 2025 theory).
#>
Import-Module ActiveDirectory
"--- Domain controllers"
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, OperatingSystemVersion | Format-Table -AutoSize
"--- Functional levels"
"Domain mode: " + (Get-ADDomain).DomainMode
"Forest mode: " + (Get-ADForest).ForestMode
"--- This machine"
(Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List | Out-String).Trim()
