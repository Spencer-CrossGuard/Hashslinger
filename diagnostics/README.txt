Diagnostics for "Replication access was denied" when the gMSA runs a scan (lab use).
Order: 01 (facts), 02a then 02b (does a normal user with the rights work?), 03 (ask the DC why), then clean up.
Cleanup: .\02a-NonAdminControl-DC.ps1 -Cleanup ; .\03-DsAudit-DC.ps1 -Disable ;
         remove the gMSA from bhr-repl-changes / bhr-repl-all if it is still in them.
05-PowerShellLoopBench.ps1: times the PowerShell engine per-account overhead on fake accounts (no AD).
