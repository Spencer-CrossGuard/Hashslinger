"""Stand-in for the PowerShell engine: emits JSONL accounts for a given OU."""
import json
import sys

sys.path.insert(0, "src")
from hashslinger.ntlm import nt_hash

ou = sys.argv[1]
if ou == "FAIL":
    sys.stderr.write("boom")
    sys.exit(3)
rows = [
    ("alice", "password", "User", False, False),
    ("bob", "Tr0ub4dor&3xyzzy-unique", "User", False, False),
    ("carol", "Summer2026", "User", False, False),
    ("dave", "SharedSecretXyz!9", "User", False, False),
    ("erin", "SharedSecretXyz!9", "Service", False, False),
    ("frank", "", "User", False, False),
    ("gina", "Zq8!vN3pL0wRtY5k", "User", True, True),
    ("=cmd|x", "password", "User", False, False),
]
for sam, pw, typ, lm, rev in rows:
    print(json.dumps({"sam": sam, "dn": f"CN={sam},{ou}", "type": typ,
                      "nt": nt_hash(pw).hex().upper(), "lm": lm, "reversible": rev}))
