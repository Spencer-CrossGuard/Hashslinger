# Smoke test without AD (about 5 minutes)

1. `build.cmd`, then `Hashslinger.exe selftest` (expect all PASS).
2. Make `C:\HashslingerTest\` with subfolders `config`, `staging\rockyou`, `staging\custom`.
3. Copy in: `config\pattern_rules.json` -> `C:\HashslingerTest\config\`, `powershell\Fake-Engine.ps1` ->
   `C:\HashslingerTest\`, and `config\test.example.json` -> `C:\HashslingerTest\config\test.json`.
4. Put `password` on its own line in `staging\rockyou\r.txt`, and `SharedSecretXyz!9` in `staging\custom\c.txt`.
5. `Hashslinger.exe --config C:\HashslingerTest\config\test.json merge`  (expect 2 files merged)
6. `Hashslinger.exe --config C:\HashslingerTest\config\test.json scan`
7. Check `output\report_<date>.csv`. Expected 6 flagged rows: alice (rockyou, High), carol (pattern),
   dave and erin (custom + duplicate), frank (No password set), gina (reversible + LM). bob is absent.
   No hash values anywhere in the file.
8. Check `logs\audit.jsonl` has a `start` and an `end` line with `"wipe_confirmed":true`.
9. Re-run `merge` (expect 0 merged: manifest skips unchanged files) and `scan` (run id ends in `-002`).
10. Request path: save `{"ou":"OU=Finance,DC=contoso,DC=com","output_dir":"C:\\HashslingerTest\\output","edipi":"1234567890","reason":"smoke test run"}`
    as `req.json`, run `scan --request req.json` (file is deleted afterward, EDIPI and reason appear in the log).
    Repeat with `"edipi":"123"` and expect exit code 2 plus a `rejected` log line.
