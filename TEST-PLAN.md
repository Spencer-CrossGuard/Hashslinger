# Smoke test without AD (about 5 minutes)

1. `Build-Hashslinger.ps1`, then `Hashslinger.exe selftest` (expect all PASS).
2. Make `C:\HashslingerTest\` with subfolders `config`, `staging\rockyou`, `staging\custom`.
3. Copy in: `config\pattern_rules.json` -> `C:\HashslingerTest\config\`, `powershell\Fake-Engine.ps1` ->
   `C:\HashslingerTest\`, and `config\test.example.json` -> `C:\HashslingerTest\config\test.json`.
4. Put `password` on its own line in `staging\rockyou\r.txt`, and `SharedSecretXyz!9` in `staging\custom\c.txt`.
5. `Hashslinger.exe --config C:\HashslingerTest\config\test.json merge`  (expect 2 files merged)
6. `Hashslinger.exe --config C:\HashslingerTest\config\test.json scan --scheduled`
7. Check `output\report_<date>.csv`. Expected 6 flagged rows: alice (rockyou, High), carol (pattern),
   dave and erin (custom + duplicate), frank (No password set), gina (reversible + LM). bob is absent.
   No hash values anywhere in the file.
8. Check `logs\audit.jsonl` has a `start` and an `end` line with `"wipe_confirmed":true`.
9. Re-run `merge` (expect 0 merged: manifest skips unchanged files) and `scan` (run id ends in `-002`).
10. Request path: save `{"ou":"OU=Finance,DC=contoso,DC=com","output_dir":"C:\\HashslingerTest\\output","edipi":"12345678901A","reason":"smoke test run"}`
    as `req.json`, run `scan --request req.json` (file is deleted afterward, EDIPI and reason appear in the log).
    Repeat with `"edipi":"123"` (wrong length) and expect exit code 2 plus a `rejected` log line.

# Lab checks on a real domain (about an hour)

1. Setup: `Setup-Hashslinger.ps1`, Check readiness, Install. Expect no FAIL. If the server enforces FIPS, tick the FIPS box
   (needs approval) and expect the live test to say `replication works`.
2. Running tool (as a member of the analyst group, not an admin): start a scan with an EDIPI and a reason. The audit log
   `start` entry has `edipi`, `reason`, `started_by` and `started_by_sid`.
3. Load test: `diagnostics\06-LoadTest-Accounts.ps1` (lab only) creates thousands of accounts with a known mix of flagged and
   unflagged passwords; scan them, then run it with `-CompareReport`. Expect RESULT: PASS (no misses, no false positives).
   Reference run: 59,969 accounts, AD stage about 14 s, peak memory 283 MB.
4. Admin tool, Run and logs, Scan timings: check where the time goes. Change one setting at a time and compare.
5. Uninstall with no switches (tasks only), then Install again.
