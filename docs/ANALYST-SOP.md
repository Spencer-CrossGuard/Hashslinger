# SOP: Run an AD Credential Exposure Scan (Hashslinger)

DRAFT. Screens and wording must be checked against the real GUI once it is lab-tested.

**Who:** analysts in the approved analyst group only.
**Before you start:** you have a ticket or tasking that authorizes a scan of this network, and you know
your 10-digit EDIPI. Do not run a scan without authorization.

## Steps

1. Open **Hashslinger** from the shortcut. Do not open PowerShell.
2. **Organizational Unit:** pick the OU named in your tasking from the dropdown. You cannot type one.
   If the OU you need is not listed, stop and ask the DCO lead to add it.
3. **Output folder:** click **Browse...** and choose the output folder you were assigned. Folders
   outside the approved location will be rejected.
4. **EDIPI:** enter your own 10-digit EDIPI. Only digits are accepted.
5. **Reason:** enter the ticket number and a short justification (at least 10 characters).
   Example: `TASK-4411 quarterly credential audit, Finance OU`.
6. **Run Scan** turns on only when all fields are valid. Click it once. The message "Scan requested"
   means the request was handed off. Nothing runs under your own account.
7. Wait. Large OUs can take a long time. Do not click Run Scan again.
8. When finished, open `report_<date>.csv` in the output folder. Each row is one account to remediate.

## Reading the report

| Severity | Meaning | Action |
| --- | --- | --- |
| High | Password found in a breach or weak list, or no password, or reversible encryption | Force reset now |
| Medium | Guessable pattern, shared with another account, or LM hash present | Force reset on the standard schedule |

The report never contains passwords or hashes. If you ever see one in a report, stop and tell the DCO
lead immediately.

## If something goes wrong

- **"Could not start the scan":** tell the DCO lead. Do not retry repeatedly.
- **No report appears:** ask the DCO lead to check the audit log for your run (it records failures too).
- **Your request was rejected:** a bad EDIPI, short reason, or disallowed folder. It is logged. Correct it and resubmit.

Every run is logged with your EDIPI, your reason, the time and the number of accounts processed.
Treat the report as sensitive. Store and share it only as your tasking allows.
