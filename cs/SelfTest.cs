using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Hashslinger
{
    /// <summary>Built-in checks. Run "Hashslinger.exe selftest" on a new build or machine; no AD required.</summary>
    public static class SelfTest
    {
        static int passed, failed;

        static void Check(string name, bool ok)
        {
            if (ok) passed++; else failed++;
            Console.WriteLine((ok ? "PASS  " : "FAIL  ") + name);
        }

        static string Hex(Hash128 h)
        {
            byte[] b = new byte[16];
            h.CopyTo(b, 0);
            return BitConverter.ToString(b).Replace("-", "");
        }

        sealed class FakeSource : IAccountSource
        {
            public void Run(Config cfg, IList<string> ous, Action<AccountRecord> sink)
            {
                if (ous[0] == "FAIL") throw new EngineException("boom");
                string ou = ous[0];
                object[][] rows =
                {
                    new object[] { "alice", "password", 0, false, false },
                    new object[] { "bob", "Tr0ub4dor&3xyzzy-unique", 0, false, false },
                    new object[] { "carol", "Summer2026", 0, false, false },
                    new object[] { "dave", "SharedSecretXyz!9", 0, false, false },
                    new object[] { "erin", "SharedSecretXyz!9", 1, false, false },
                    new object[] { "frank", "", 0, false, false },
                    new object[] { "gina", "Zq8!vN3pL0wRtY5k", 0, true, true },
                    new object[] { "=cmd|x", "password", 0, false, false },
                };
                foreach (object[] r in rows)
                {
                    AccountRecord a = new AccountRecord();
                    a.Sam = (string)r[0];
                    a.Dn = "CN=" + a.Sam + "," + ou;
                    a.Type = (int)r[2];
                    a.HasNt = true;
                    a.Nt = Ntlm.Hash((string)r[1]);
                    a.Lm = (bool)r[3];
                    a.Rev = (bool)r[4];
                    sink(a);
                }
            }
        }

        static List<string[]> ParseCsv(string text)
        {
            List<string[]> rows = new List<string[]>();
            List<string> cur = new List<string>();
            StringBuilder f = new StringBuilder();
            bool q = false;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (q)
                {
                    if (c == '"' && i + 1 < text.Length && text[i + 1] == '"') { f.Append('"'); i++; }
                    else if (c == '"') q = false;
                    else f.Append(c);
                }
                else if (c == '"') q = true;
                else if (c == ',') { cur.Add(f.ToString()); f.Length = 0; }
                else if (c == '\r') { }
                else if (c == '\n') { cur.Add(f.ToString()); f.Length = 0; rows.Add(cur.ToArray()); cur = new List<string>(); }
                else f.Append(c);
            }
            return rows;
        }

        static string NewDir()
        {
            string d = Path.Combine(Path.GetTempPath(), "hashslinger-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(d);
            return d;
        }

        const string RulesJson =
            "{\"keyboard_walks\":[\"qwerty\"],\"base_words\":[\"password\",\"waterfall\"],\"include_seasons\":true," +
            "\"years_back\":20,\"suffixes\":[\"\",\"1\",\"123\"],\"max_leet_variants\":64}";

        public static int Run()
        {
            passed = failed = 0;
            Progress.Quiet = true;
            string root = NewDir();
            try
            {
                TestNtlm();
                TestStore(root);
                TestPatterns(root);
                TestPipeline(root);
                TestRequests(root);
                TestScriptsAreReadOnly();
            }
            catch (Exception ex)
            {
                Check("selftest threw: " + ex.GetType().Name + ": " + ex.Message, false);
            }
            finally
            {
                try { Directory.Delete(root, true); } catch (IOException) { }
            }
            Console.WriteLine(passed + " passed, " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }

        /// <summary>Static check of the shipped tool scripts (powershell\\ next to the exe): no Active Directory write
        /// commands, no network commands. Scripts that change AD live in ad-admin\\ (not scanned, for a Domain Admin).</summary>
        static void TestScriptsAreReadOnly()
        {
            string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "powershell");
            if (!Directory.Exists(dir))
            {
                Console.WriteLine("SKIP  tool scripts not found next to the exe (powershell\\), AD read-only scan skipped");
                return;
            }
            string[] adWrite =
            {
                @"\b(New|Set|Add|Remove|Move|Rename|Unlock|Disable|Enable|Reset|Restore|Grant|Revoke|Install|Uninstall)-AD\w+",
                @"Add-KdsRootKey", @"Set-Acl\s+[""']?AD:", @"\bldifde\b", @"\bcsvde\b", @"\bdsacls\b", @"\bdsmod\b",
                @"Set-ADDB\w*", @"New-ADDB\w*", @"Set-ADReplAccount", @"\.CommitChanges\s*\(", @"\.DeleteTree\s*\("
            };
            string[] network =
            {
                @"Invoke-WebRequest", @"Invoke-RestMethod", @"Start-BitsTransfer", @"Net\.WebClient", @"HttpClient", @"Net\.Sockets",
                @"Send-MailMessage", @"\bwget\b", @"\bcurl\b", @"Install-PackageProvider", @"Install-Package\b"
            };
            List<string> adHits = new List<string>(), netHits = new List<string>();
            int files = 0;
            foreach (string f in Directory.GetFiles(dir, "*.ps1"))
            {
                files++;
                string text = Regex.Replace(File.ReadAllText(f), @"(?s)<#.*?#>", "");
                foreach (string line in text.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.Length == 0 || t[0] == '#') continue;
                    foreach (string p in adWrite) { Match m = Regex.Match(t, p, RegexOptions.IgnoreCase); if (m.Success) adHits.Add(Path.GetFileName(f) + ": " + m.Value); }
                    foreach (string p in network) { Match m = Regex.Match(t, p, RegexOptions.IgnoreCase); if (m.Success) netHits.Add(Path.GetFileName(f) + ": " + m.Value); }
                    // the only permitted download: the DSInternals module (offline copy supported via dsinternals_offline_path)
                    foreach (Match m in Regex.Matches(t, @"Install-Module\s+(\S+)", RegexOptions.IgnoreCase))
                        if (!string.Equals(m.Groups[1].Value.Trim('\'', '"'), "DSInternals", StringComparison.OrdinalIgnoreCase)) netHits.Add(Path.GetFileName(f) + ": " + m.Value);
                }
            }
            foreach (string h in adHits) Console.WriteLine("      AD-write command found: " + h);
            foreach (string h in netHits) Console.WriteLine("      network command found: " + h);
            Check("Scanned " + files + " tool scripts: no Active Directory write commands", files > 0 && adHits.Count == 0);
            Check("Tool scripts: no network commands (only Install-Module DSInternals, optional)", netHits.Count == 0);
        }

        static void TestNtlm()
        {
            Check("NT(password)", Hex(Ntlm.Hash("password")) == "8846F7EAEE8FB117AD06BDD830B7586C");
            Check("NT(empty)", Ntlm.Hash("").Equals(Ntlm.Empty));
            Check("MD4(abc)", BitConverter.ToString(Ntlm.Md4(Encoding.ASCII.GetBytes("abc"))).Replace("-", "").ToLowerInvariant() == "a448017aaf21d8525fc10ae87aa6729d");
        }

        static void TestStore(string root)
        {
            string d = Path.Combine(root, "s");
            Directory.CreateDirectory(d);
            using (HashStore none = new HashStore(Path.Combine(d, "does-not-exist.ntlm"), false))
                Check("A missing store file reads as an empty store", none.Count == 0 && none.Lookup(Ntlm.Hash("x")) == 0);
            string master = Path.Combine(d, "m.ntlm");
            string rock = Path.Combine(d, "rock.txt");
            File.WriteAllText(rock, "password\nletmein\nqwerty\npassword\n");
            Check("merge rockyou -> 3 unique", StoreMerge.MergeSource(master, rock, "rockyou", null, 2) == 3);
            string hib = Path.Combine(d, "h.ntlm");
            File.WriteAllText(hib, Hex(Ntlm.Hash("password")) + ":9001\n" + Hex(Ntlm.Hash("zebra99")).ToLowerInvariant() + ":5\n");
            Check("merge HIBP -> 4 unique", StoreMerge.MergeSource(master, hib, "HIBP", "ntlm", 1000) == 4);

            byte[] raw = File.ReadAllBytes(master);
            bool sorted = true;
            for (int i = 17; i < raw.Length; i += 17)
            {
                Hash128 a = Hash128.FromBytes(raw, i - 17), b = Hash128.FromBytes(raw, i);
                if (a.CompareTo(b) >= 0) sorted = false;
            }
            Check("master sorted ascending", sorted && raw.Length == 4 * 17);
            foreach (bool idx in new[] { false, true })
            {
                using (HashStore s = new HashStore(master, idx))
                {
                    Check("lookup password = HIBP|rockyou (index=" + idx + ")", s.Lookup(Ntlm.Hash("password")) == 3);
                    Check("lookup zebra99 = HIBP", s.Lookup(Ntlm.Hash("zebra99")) == 1);
                    Check("lookup absent = 0", s.Lookup(Ntlm.Hash("nothere")) == 0);
                }
            }
            Check("no leftover .new file", !File.Exists(master + ".new"));

            string stg = Path.Combine(d, "staging");
            Directory.CreateDirectory(Path.Combine(stg, "custom"));
            File.WriteAllText(Path.Combine(stg, "custom", "terms.txt"), "acmecorp\n");
            string m2 = Path.Combine(d, "m2.ntlm");
            Check("staging merges new file", StoreMerge.ProcessStaging(m2, stg, null).Count == 1);
            Check("staging skips unchanged file", StoreMerge.ProcessStaging(m2, stg, null).Count == 0);
            using (HashStore s = new HashStore(m2, false))
                Check("custom term has custom bit", s.Lookup(Ntlm.Hash("acmecorp")) == 4);

            // table files: TSV with a hash column + password column, several files merged in ONE pass
            string stg2 = Path.Combine(d, "stg2");
            Directory.CreateDirectory(Path.Combine(stg2, "custom"));
            File.WriteAllText(Path.Combine(stg2, "custom", "a.tsv"), "hash\tpassword\n" + Hex(Ntlm.Hash("tsvpass1")) + "\ttsvpass1\n" +
                Hex(Ntlm.Hash("tsvpass1b")).ToLowerInvariant() + "\ttsvpass1b\n");
            File.WriteAllText(Path.Combine(stg2, "custom", "b.tsv"), "00112233445566778899AABBCCDDEEFF\ttsvpass2\n");
            File.WriteAllText(Path.Combine(stg2, "custom", "c.csv"), "tsvpass3," + Hex(Ntlm.Hash("tsvpass3")) + "\n");
            string m3 = Path.Combine(d, "m3.ntlm");
            Check("three table files merged in one pass", StoreMerge.ProcessStaging(m3, stg2, null).Count == 3);
            using (HashStore s = new HashStore(m3, false))
            {
                Check("TSV with header, NT hash column verified and used", s.Lookup(Ntlm.Hash("tsvpass1")) == 4 && s.Lookup(Ntlm.Hash("tsvpass1b")) == 4);
                Check("TSV with a non-NT hash column: NT computed from the password", s.Lookup(Ntlm.Hash("tsvpass2")) == 4);
                Check("non-NT hash column value is not stored", s.Lookup(Hash128.FromHex("00112233445566778899AABBCCDDEEFF")) == 0);
                Check("CSV with the hash in the last column", s.Lookup(Ntlm.Hash("tsvpass3")) == 4);
            }
        }

        static void TestPatterns(string root)
        {
            string p = Path.Combine(root, "rules.json");
            File.WriteAllText(p, RulesJson);
            Dictionary<Hash128, string> m = Patterns.Build(p, new DateTime(2026, 11, 16));
            foreach (string pw in new[] { "Summer2026", "P@ssw0rd1", "Waterfall123", "qwerty1" })
                Check("pattern hits " + pw, m.ContainsKey(Ntlm.Hash(pw)));
            Check("pattern misses unique", !m.ContainsKey(Ntlm.Hash("Tr0ub4dor&3xyzzy-unique")));
        }

        const string Ou = "OU=Finance,DC=contoso,DC=com";

        static Config MakeConfig(string root)
        {
            string d = Path.Combine(root, "p" + Guid.NewGuid().ToString("N").Substring(0, 6));
            Directory.CreateDirectory(Path.Combine(d, "staging", "rockyou"));
            Directory.CreateDirectory(Path.Combine(d, "staging", "custom"));
            File.WriteAllText(Path.Combine(d, "staging", "rockyou", "r.txt"), "password\n");
            File.WriteAllText(Path.Combine(d, "staging", "custom", "c.txt"), "SharedSecretXyz!9\n");
            File.WriteAllText(Path.Combine(d, "rules.json"), RulesJson);
            Config c = new Config();
            c.TargetOus = new List<string> { Ou, "FAIL" };
            c.HashStorePath = Path.Combine(d, "store", "m.ntlm");
            c.StagingPath = Path.Combine(d, "staging");
            c.LogPath = Path.Combine(d, "log", "a.jsonl");
            c.OutputPath = Path.Combine(d, "out");
            c.PatternRulesPath = Path.Combine(d, "rules.json");
            c.CheckDuplicates = true;
            c.StatusPath = Path.Combine(d, "status", "status.json");
            return c;
        }

        static void TestPipeline(string root)
        {
            Config cfg = MakeConfig(root);
            RunResult res = Runner.Run(cfg, new FakeSource(), new List<string> { Ou }, null, "test", null, null, null, false);
            Check("8 accounts processed, wipe confirmed", res.Accounts == 8 && res.WipeConfirmed);
            string text = File.ReadAllText(res.Output);
            List<string[]> rows = ParseCsv(text);
            Dictionary<string, string[]> by = new Dictionary<string, string[]>();
            for (int i = 1; i < rows.Count; i++) by[rows[i][0]] = rows[i];
            Check("flagged set is exactly expected", by.Count == 7 && !by.ContainsKey("bob") &&
                by.ContainsKey("alice") && by.ContainsKey("carol") && by.ContainsKey("dave") && by.ContainsKey("erin") &&
                by.ContainsKey("frank") && by.ContainsKey("gina") && by.ContainsKey("'=cmd|x"));
            Check("alice: rockyou, High", by["alice"][3].Contains("rockyou") && by["alice"][4] == "High");
            Check("alice and =cmd share a hash: duplicate", by["alice"][3].Contains("Duplicate"));
            Check("carol: pattern, Medium", by["carol"][3].Contains("common-pattern") && by["carol"][4] == "Medium");
            Check("dave: custom list + duplicate", by["dave"][3].Contains("custom") && by["dave"][3].Contains("Duplicate"));
            Check("erin typed Service", by["erin"][2] == "Service");
            Check("frank: no password", by["frank"][3] == "No password set");
            Check("gina: reversible + LM", by["gina"][3].Contains("Reversible") && by["gina"][3].Contains("LM"));
            Check("OU column is parent container", by["alice"][1] == Ou);
            bool allNamed = rows.Count > 1;
            for (int i = 1; i < rows.Count; i++) if (rows[i][0].Length == 0) allNamed = false;
            Check("report column 1 is sAMAccountName and no name is blank", rows[0][0] == "sAMAccountName" && allNamed);
            Check("no hashes in report", !text.ToLowerInvariant().Contains(Hex(Ntlm.Hash("password")).ToLowerInvariant()));
            string[] log = File.ReadAllLines(cfg.LogPath);
            Check("audit log has start+end", log.Length == 2 && log[0].Contains("\"start\"") && log[1].Contains("\"wipe_confirmed\":true"));
            Dictionary<string, object> stt = (Dictionary<string, object>)Json.Parse(File.ReadAllText(cfg.StatusPath));
            Check("status file shows success at stage 7", Json.Str(stt, "state", "") == "success" && Json.Str(stt, "stage", "") == "7" && Json.Str(stt, "output", "") == res.Output);
            RunResult res2 = Runner.Run(cfg, new FakeSource(), new List<string> { Ou }, null, "test", null, null, null, false);
            Check("second run id is 002", res2.RunId.EndsWith("-002"));

            using (FileStream held = new FileStream(Path.Combine(Path.GetDirectoryName(cfg.StatusPath), "run.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                bool refused = false;
                try { Runner.Run(cfg, new FakeSource(), new List<string> { Ou }, null, "test", null, null, null, false); }
                catch (InvalidOperationException) { refused = true; }
                string[] lg = File.ReadAllLines(cfg.LogPath);
                Check("second concurrent scan refused and logged", refused && lg[lg.Length - 1].Contains("scan already running"));
            }
            cfg.CheckDuplicates = false;
            RunResult res3 = Runner.Run(cfg, new FakeSource(), new List<string> { Ou }, null, "test", null, null, null, false);
            string text3 = File.ReadAllText(res3.Output);
            Check("duplicates off: no duplicate reasons", !text3.Contains("Duplicate") && text3.Contains("dave"));

            bool threw = false;
            try { Runner.Run(cfg, new FakeSource(), new List<string> { "FAIL" }, null, "test", null, null, null, false); }
            catch (InvalidOperationException) { threw = true; }
            string[] log2 = File.ReadAllLines(cfg.LogPath);
            string last = log2[log2.Length - 1];
            Check("failed run raises and is logged + wiped", threw && last.Contains("\"failed\"") && last.Contains("boom") && last.Contains("\"wipe_confirmed\":true"));
        }

        static void TestRequests(string root)
        {
            Config cfg = MakeConfig(root);
            string req = Path.Combine(root, "req.json");
            string outOk = Path.Combine(cfg.OutputPath, "sub").Replace("\\", "\\\\");
            string good = "{\"ou\":\"" + Ou + "\",\"output_dir\":\"" + outOk + "\",\"edipi\":\"1234567890\",\"reason\":\"Quarterly audit ticket 4411\"}";
            File.WriteAllText(req, good);
            Check("valid request accepted", Request.Load(cfg, req).Ou == Ou);
            string[][] bad =
            {
                new[] { "\"ou\":\"" + Ou + "\"", "\"ou\":\"OU=Other,DC=x\"" },
                new[] { "\"edipi\":\"1234567890\"", "\"edipi\":\"12345\"" },
                new[] { "\"edipi\":\"1234567890\"", "\"edipi\":\"12345678ab\"" },
                new[] { "\"reason\":\"Quarterly audit ticket 4411\"", "\"reason\":\"short\"" },
                new[] { "\"reason\":\"Quarterly audit ticket 4411\"", "\"reason\":\"\"" },
                new[] { "\"output_dir\":\"" + outOk + "\"", "\"output_dir\":\"" + Path.GetTempPath().Replace("\\", "\\\\") + "\"" },
            };
            int rejected = 0;
            foreach (string[] b in bad)
            {
                File.WriteAllText(req, good.Replace(b[0], b[1]));
                try { Request.Load(cfg, req); } catch (RequestException) { rejected++; }
            }
            Check("6 bad requests all rejected", rejected == 6);
            cfg.AuthorizedEdipis = new List<string> { "1111111111" };
            File.WriteAllText(req, good);
            bool denied = false;
            try { Request.Load(cfg, req); } catch (RequestException) { denied = true; }
            Check("EDIPI allowlist enforced", denied);
        }
    }
}
