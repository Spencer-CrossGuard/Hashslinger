OPTIONAL HELPERS (not part of the install flow)

Hashslinger itself only READS Active Directory. These two scripts are conveniences for a Domain Admin who wants a
scripted way to create the service account. Read them first, run them elevated, use -WhatIf to preview.

  New-HashslingerGmsa.ps1                  creates the gMSA (needs -RunServer <scan server>), optional rights grant
  Grant-HashslingerReplicationRights.ps1   grants an EXISTING gMSA the two replication rights on the domain root

The same thing can be done by hand in ADUC / ADSI Edit; see the SOP (docs\Hashslinger-SOP.html), section "Create the
service account". Never add the account to a privileged group: it needs only the two replication rights.
