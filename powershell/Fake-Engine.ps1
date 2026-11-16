<#
.SYNOPSIS
  Smoke-test stand-in for Get-AccountHashes.ps1. Emits 7 fake accounts (tab separated) so the whole
  exe pipeline can be tested with no AD and no DSInternals. Hashes are of known test passwords:
  alice=password, carol=Summer2026, dave/erin share a password, frank is empty, gina has LM + reversible.
  Use with config/test.example.json (engine_command).
#>
param([string]$SearchBases)
Write-Output "alice`tCN=alice,OU=Finance,DC=contoso,DC=com`tUser`t8846F7EAEE8FB117AD06BDD830B7586C`t0`t0"
Write-Output "bob`tCN=bob,OU=Finance,DC=contoso,DC=com`tUser`t621BD3B050B3417AB43D7ADE24E09205`t0`t0"
Write-Output "carol`tCN=carol,OU=Finance,DC=contoso,DC=com`tUser`tB853AFBEBDB12E1DECB05981BEB18F74`t0`t0"
Write-Output "dave`tCN=dave,OU=Finance,DC=contoso,DC=com`tUser`t62A5843F5717E16F691B729CAAA3FBE7`t0`t0"
Write-Output "erin`tCN=erin,OU=Finance,DC=contoso,DC=com`tService`t62A5843F5717E16F691B729CAAA3FBE7`t0`t0"
Write-Output "frank`tCN=frank,OU=Finance,DC=contoso,DC=com`tUser`t31D6CFE0D16AE931B73C59D7E0C089C0`t0`t0"
Write-Output "gina`tCN=gina,OU=Finance,DC=contoso,DC=com`tUser`t319D92692CCB7557943077ACEFA6F51B`t1`t1"
