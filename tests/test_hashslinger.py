import csv
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from hashslinger import store
from hashslinger.config import Config
from hashslinger.ntlm import EMPTY_NT, _md4_pure, nt_hash
from hashslinger.patterns import build_pattern_map
from hashslinger.runner import ScanRequestError, load_request, run_scan
from hashslinger.wipe import HashVault, secure_delete

OU = "OU=Finance,DC=contoso,DC=com"


class Ntlm(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(nt_hash("password").hex().upper(), "8846F7EAEE8FB117AD06BDD830B7586C")
        self.assertEqual(nt_hash(""), EMPTY_NT)
        self.assertEqual(_md4_pure(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")


class Store(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def test_merge_lookup_atomic_and_incremental(self):
        master = self.d / "m.ntlm"
        rock = self.d / "rock.txt"
        rock.write_text("password\nletmein\nqwerty\npassword\n")
        self.assertEqual(store.merge_source(master, rock, "rockyou", chunk=2), 3)
        hib = self.d / "h.ntlm"
        hib.write_text(nt_hash("password").hex().upper() + ":9001\n" + nt_hash("zebra99").hex() + ":5\n")
        self.assertEqual(store.merge_source(master, hib, "HIBP", "ntlm"), 4)
        raw = master.read_bytes()
        recs = [raw[i:i + 17] for i in range(0, len(raw), 17)]
        self.assertEqual(recs, sorted(recs))
        for idx in (False, True):
            with store.HashStore(master, build_index=idx) as s:
                self.assertEqual(s.lookup(nt_hash("password")), 3)  # HIBP|rockyou
                self.assertEqual(store.sources_from_mask(s.lookup(nt_hash("zebra99"))), ["HIBP"])
                self.assertEqual(s.lookup(nt_hash("nothere")), 0)
        self.assertFalse(list(self.d.glob("*.new")))

    def test_staging_manifest_and_custom(self):
        master = self.d / "m.ntlm"
        (self.d / "staging" / "custom").mkdir(parents=True)
        f = self.d / "staging" / "custom" / "terms.txt"
        f.write_text("acmecorp\n")
        self.assertEqual(store.process_staging(master, self.d / "staging"), ["custom/terms.txt"])
        self.assertEqual(store.process_staging(master, self.d / "staging"), [])  # unchanged: skipped
        with store.HashStore(master) as s:
            self.assertEqual(s.lookup(nt_hash("acmecorp")), 4)


class Patterns(unittest.TestCase):
    def test_rules(self):
        m = build_pattern_map(ROOT / "config" / "pattern_rules.json", date(2026, 11, 16))
        for pw in ("Summer2026", "P@ssw0rd"[:0] + "P@ssw0rd1", "Waterfall123", "qwerty1"):
            self.assertIn(nt_hash(pw), m, pw)
        self.assertNotIn(nt_hash("Tr0ub4dor&3xyzzy-unique"), m)


class Wipe(unittest.TestCase):
    def test_vault_and_file(self):
        v = HashVault()
        v.add(b"\x11" * 16)
        self.assertTrue(v.wipe())
        p = Path(tempfile.mkdtemp()) / "x"
        p.write_bytes(b"secret")
        self.assertTrue(secure_delete(p))


class Pipeline(unittest.TestCase):
    def make_cfg(self, engine_ou=OU):
        d = Path(tempfile.mkdtemp())
        (d / "staging" / "rockyou").mkdir(parents=True)
        (d / "staging" / "rockyou" / "r.txt").write_text("password\n")
        (d / "staging" / "custom").mkdir(parents=True)
        (d / "staging" / "custom" / "c.txt").write_text("SharedSecretXyz!9\n")
        cfg_json = {
            "target_ous": [OU, "FAIL"], "target_server": "x",
            "hash_store_path": str(d / "store" / "m.ntlm"), "staging_path": str(d / "staging"),
            "log_path": str(d / "log" / "a.jsonl"), "output_path": str(d / "out"),
            "pattern_rules_path": str(ROOT / "config" / "pattern_rules.json"),
            "require_encrypted_volume": False,
            "engine_command": [sys.executable, str(ROOT / "tests" / "fake_engine.py"), "{ou}"],
        }
        (d / "c.json").write_text(json.dumps(cfg_json))
        return d, Config.load(d / "c.json")

    def test_end_to_end(self):
        d, cfg = self.make_cfg()
        res = run_scan(cfg, [OU], trigger="test")
        self.assertEqual((res.accounts, res.wipe_confirmed), (8, True))
        text = res.output.read_text()
        rows = list(csv.DictReader(text.splitlines()))
        by = {r["Username"]: r for r in rows}
        self.assertEqual(set(by), {"alice", "carol", "dave", "erin", "frank", "gina", "'=cmd|x"})
        self.assertNotIn("bob", by)
        self.assertIn("rockyou", by["alice"]["Flag Reason"])
        self.assertEqual(by["alice"]["Severity"], "High")
        self.assertIn("Duplicate", by["alice"]["Flag Reason"] + by["'=cmd|x"]["Flag Reason"])
        self.assertIn("common-pattern", by["carol"]["Flag Reason"])
        self.assertEqual(by["carol"]["Severity"], "Medium")
        self.assertIn("custom", by["dave"]["Flag Reason"])
        self.assertEqual(by["frank"]["Flag Reason"], "No password set")
        self.assertIn("Reversible", by["gina"]["Flag Reason"])
        self.assertEqual(by["alice"]["OU / Distinguished Name"], OU)
        for pw in ("password", "Summer2026"):
            self.assertNotIn(nt_hash(pw).hex(), text.lower())
        log = [json.loads(l) for l in (d / "log" / "a.jsonl").read_text().splitlines()]
        self.assertEqual([e["event"] for e in log], ["start", "end"])
        self.assertTrue(log[1]["wipe_confirmed"])
        self.assertEqual(log[1]["accounts_processed"], 8)
        self.assertEqual(run_scan(cfg, [OU]).run_id.rsplit("-", 1)[1], "002")

    def test_failed_run_is_logged_and_wiped(self):
        d, cfg = self.make_cfg()
        with self.assertRaises(RuntimeError):
            run_scan(cfg, ["FAIL"])
        end = json.loads((d / "log" / "a.jsonl").read_text().splitlines()[-1])
        self.assertEqual(end["status"], "failed")
        self.assertTrue(end["wipe_confirmed"])
        self.assertIn("boom", end["error"])

    def test_scope_cannot_widen(self):
        d, cfg = self.make_cfg()
        with self.assertRaises(ScanRequestError):
            run_scan(cfg, ["OU=Everything,DC=contoso,DC=com"])
        req = d / "req.json"
        req.write_text(json.dumps({"ou": "OU=Other,DC=x", "output_dir": str(d / "out")}))
        with self.assertRaises(ScanRequestError):
            load_request(cfg, req)
        req.write_text(json.dumps({"ou": OU, "output_dir": str(d.parent)}))
        with self.assertRaises(Exception):
            load_request(cfg, req)
        req.write_text(json.dumps({"ou": OU, "output_dir": str(d / "out" / "sub")}))
        self.assertEqual(load_request(cfg, req)[0], OU)


if __name__ == "__main__":
    unittest.main()
