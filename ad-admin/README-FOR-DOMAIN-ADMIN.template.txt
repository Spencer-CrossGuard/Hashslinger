HASHSLINGER - ACTIVE DIRECTORY REQUEST (for a Domain Admin)
Generated {{DATE}}   Domain: {{DOMAIN}}   Scan server: {{SERVER}}   Authorization ref: ____________________

WHAT THIS IS
Hashslinger is an authorized internal tool that checks AD password hashes against breached-password lists
and reports accounts that need a reset. The tool itself only READS Active Directory and never stores or shows
plaintext passwords. The server operator is NOT a Domain Admin, so these three one-time items need to be done
by you. The scripts in this folder are the ONLY Hashslinger files that change AD, and only when you run them.

WHAT WE NEED (about 2 minutes)
1. A KDS root key must exist (required by any group Managed Service Account).
     Check:  Get-KdsRootKey
     If none: Add-KdsRootKey -EffectiveImmediately      (usable in about 10 hours; every DC must have replicated it)
2. A group Managed Service Account named '{{GMSA}}' whose password only the computer '{{SERVER}}' can retrieve.
3. That account granted two permissions on the DOMAIN root only (not forest, not schema):
     Replicating Directory Changes     (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
     Replicating Directory Changes All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
   These are the directory replication ("DCSync") rights. The tool needs them to read password hashes so it
   can compare them to the lists. Nothing else is requested.

HOW (run elevated, as a Domain Admin, on any machine with the AD PowerShell module; READ the scripts first)
   cd to this folder, then preview and apply:
     .\New-HashslingerGmsa.ps1 -Name {{GMSA}} -RunServer {{SERVER}} -WhatIf
     .\New-HashslingerGmsa.ps1 -Name {{GMSA}} -RunServer {{SERVER}} -GrantReplicationRights
   Or, for an existing gMSA, just the rights:
     .\Grant-HashslingerReplicationRights.ps1 -GmsaName {{GMSA}} -WhatIf
   Or do the same by hand in ADUC / ADSI Edit. The scripts are a convenience, not a requirement.

BEFORE THE FIRST SCAN
   * Tell the SOC: the scan server '{{SERVER}}' and account '{{GMSA}}' will trigger DCSync / replication alerts.
   * Expect replication traffic from '{{SERVER}}' to a domain controller.

TO UNDO
     Remove-ADServiceAccount {{GMSA}}
     and remove that account's two permissions from the domain root (ADSI Edit > domain root > Security).

WHEN DONE
   Tell the server operator. They finish with:  Setup-Hashslinger.cmd -Phase Finish   (or the wizard's Finish button).
