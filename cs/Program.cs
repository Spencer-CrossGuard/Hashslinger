using System;
using System.Collections.Generic;
using System.IO;

namespace Hashslinger
{
    public static class Program
    {
        const string Usage =
            "Hashslinger <command>\n" +
            "  selftest                              run built-in checks (no AD needed)\n" +
            "  bench [accounts] [storeRecords]       time the C# side at scale with synthetic data (no AD)\n" +
            "  --config <file> merge                 merge staging/<HIBP|rockyou|custom>/* into the hash store\n" +
            "  --config <file> info                  show hash store record count\n" +
            "  --config <file> scan [--ou <dn>] [--output-dir <dir>] [--trigger <t>] [--request <file> | --request-dir <dir>]\n";

        public static int Main(string[] args)
        {
            try
            {
                return Dispatch(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("error: " + ex.Message);
                return 2;
            }
        }

        static int Dispatch(string[] args)
        {
            if (args.Length == 1 && args[0] == "selftest") return SelfTest.Run();
            if (args.Length >= 1 && args[0] == "bench") return Bench.Run(args);
            if (args.Length < 3 || args[0] != "--config") { Console.Error.Write(Usage); return 1; }
            Config cfg = Config.Load(args[1]);
            string cmd = args[2];

            if (cmd == "merge")
            {
                List<string> done = StoreMerge.ProcessStaging(cfg.HashStorePath, cfg.StagingPath, Console.WriteLine);
                Console.WriteLine("merged " + done.Count + " source file(s)");
                return 0;
            }
            if (cmd == "info")
            {
                using (HashStore s = new HashStore(cfg.HashStorePath, false))
                    Console.WriteLine(s.Count + " records");
                return 0;
            }
            if (cmd != "scan") { Console.Error.Write(Usage); return 1; }

            string ou = null, outDir = null, trigger = "scheduled", requestFile = null, requestDir = null;
            for (int i = 3; i < args.Length; i++)
            {
                if (i + 1 >= args.Length) { Console.Error.Write(Usage); return 1; }
                string a = args[i];
                if (a == "--ou") ou = args[++i];
                else if (a == "--output-dir") outDir = args[++i];
                else if (a == "--trigger") trigger = args[++i];
                else if (a == "--request") requestFile = args[++i];
                else if (a == "--request-dir") requestDir = args[++i];
                else { Console.Error.Write(Usage); return 1; }
            }

            if (requestDir != null && requestFile == null)
            {
                string[] cands = Directory.Exists(requestDir) ? Directory.GetFiles(requestDir, "req_*.json") : new string[0];
                if (cands.Length == 0) { Console.WriteLine("no pending requests"); return 0; }
                Array.Sort(cands, delegate(string x, string y) { return File.GetLastWriteTimeUtc(x).CompareTo(File.GetLastWriteTimeUtc(y)); });
                requestFile = cands[0]; // oldest first
            }

            IList<string> ous = ou != null ? new List<string> { ou } : null;
            string by = null, edipi = null, reason = null;
            if (requestFile != null)
            {
                ScanRequest rq = null;
                try
                {
                    rq = Request.Load(cfg, requestFile);
                }
                catch (RequestException e)
                {
                    new AuditLog(cfg.LogPath).Rejected(e.Message, e.Edipi, e.Reason, e.RequestedBy);
                    Console.Error.WriteLine("scan failed: " + e.Message);
                    return 2;
                }
                catch (FormatException)
                {
                    new AuditLog(cfg.LogPath).Rejected("malformed request file", null, null, null);
                    Console.Error.WriteLine("scan failed: malformed request file");
                    return 2;
                }
                finally
                {
                    try { File.Delete(requestFile); } catch (IOException) { } // content now lives only in the audit log
                }
                ous = new List<string> { rq.Ou };
                outDir = rq.OutputDir;
                trigger = "on-demand";
                by = rq.RequestedBy; edipi = rq.Edipi; reason = rq.Reason;
            }

            try
            {
                RunResult res = Runner.Run(cfg, new PowerShellSource(), ous, outDir, trigger, by, edipi, reason, false);
                Console.WriteLine(res.RunId + ": " + res.Accounts + " accounts, " + res.Flagged + " flagged -> " + res.Output);
                return 0;
            }
            catch (RequestException e)
            {
                Console.Error.WriteLine("scan failed: " + e.Message);
                return 2;
            }
            catch (InvalidOperationException e)
            {
                Console.Error.WriteLine("scan failed: " + e.Message);
                return 2;
            }
        }
    }
}
