using System;
using System.Collections.Generic;
using System.IO;

namespace Hashslinger
{
    public static class Program
    {
        static bool busy;   // the last attempt was refused because another scan or merge holds the lock
        const string Usage =
            "Hashslinger <command>\n" +
            "  selftest                              run built-in checks (no AD needed)\n" +
            "  bench [accounts] [storeRecords]       time the C# side at scale with synthetic data (no AD)\n" +
            "  --config <file> merge                 merge staging/<HIBP|rockyou|custom>/* into the hash store\n" +
            "  --config <file> info                  show hash store record count\n" +
            "  --config <file> scan [--ou <dn>] [--output-dir <dir>] [--trigger <t>] [--request <file> | --request-dir <dir>]\n" +
            "                                        [--scheduled] [--edipi <digits> --reason <text>]\n" +
            "      A scan started by a person asks for an EDIPI and a reason / CTO number (or take them from --edipi/--reason).\n" +
            "      --scheduled is for the unattended scheduled task only: no person, logged as scheduled.\n";

        public static int Main(string[] args)
        {
            try
            {
                // Requests that arrive while a scan is running cannot start a second task instance, so keep going
                // through the queue here until it is empty (or no progress is being made).
                string queue = null;
                if (args.Length >= 3 && args[0] == "--config" && args[2] == "scan")
                    for (int i = 3; i + 1 < args.Length; i++) if (args[i] == "--request-dir") queue = args[i + 1];
                if (queue == null) return Dispatch(args);
                int rc;
                int waits = 0;
                for (int n = 0; n < 5000; n++)
                {
                    string before = OldestRequest(queue);
                    rc = Dispatch(args);
                    string after = OldestRequest(queue);
                    if (after == null) return rc;
                    if (busy)
                    {
                        // a scheduled scan or merge is running: wait for it instead of leaving the request stranded
                        if (waits++ >= 2880) return rc;   // about 24 hours at 30 seconds a try
                        if (waits == 1) Console.WriteLine("another scan or merge is running; the request is kept and will run when it finishes");
                        System.Threading.Thread.Sleep(30000);
                        continue;
                    }
                    if (after == before) return rc;      // the request could not be removed: do not loop on it
                }
                return 2;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("error: " + ex.Message);
                return 2;
            }
        }

        static int Dispatch(string[] args)
        {
            busy = false;
            if (args.Length == 1 && args[0] == "selftest") return SelfTest.Run();
            if (args.Length >= 1 && args[0] == "bench") return Bench.Run(args);
            if (args.Length < 3 || args[0] != "--config") { Console.Error.Write(Usage); return 1; }
            Config cfg = Config.Load(args[1]);
            string cmd = args[2];

            if (cmd == "merge")
            {
                using (FileStream mergeLock = Runner.TryLock(cfg))
                {
                    if (mergeLock == null) { Console.Error.WriteLine("a scan or merge is already running; try again when it has finished"); return 2; }
                    List<string> done = StoreMerge.ProcessStaging(cfg.HashStorePath, cfg.StagingPath, Console.WriteLine);
                    Console.WriteLine("merged " + done.Count + " source file(s)");
                    return 0;
                }
            }
            if (cmd == "info")
            {
                using (HashStore s = new HashStore(cfg.HashStorePath, false))
                    Console.WriteLine(s.Count + " records");
                return 0;
            }
            if (cmd != "scan") { Console.Error.Write(Usage); return 1; }

            string ou = null, outDir = null, trigger = "scheduled", requestFile = null, requestDir = null;
            string edipiArg = null, reasonArg = null;
            bool scheduledFlag = false;
            for (int i = 3; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--scheduled") { scheduledFlag = true; continue; }
                if (i + 1 >= args.Length) { Console.Error.Write(Usage); return 1; }
                if (a == "--edipi") edipiArg = args[++i];
                else if (a == "--reason") reasonArg = args[++i];
                else if (a == "--ou") ou = args[++i];
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
            string by = null, edipi = null, reason = null, startedBy = null, startedBySid = null;
            if (requestFile != null)
            {
                ScanRequest rq = null;
                try
                {
                    rq = Request.Load(cfg, requestFile);
                }
                catch (RequestException e)
                {
                    new AuditLog(cfg.LogPath).Rejected(e.Message, e.Edipi, e.Reason, e.RequestedBy, Request.FileOwnerOf(requestFile), Request.FileOwnerSidOf(requestFile));
                    TryDelete(requestFile);
                    Console.Error.WriteLine("scan failed: " + e.Message);
                    return 2;
                }
                catch (Exception ex)   // malformed, wrong shape, too deeply nested, unreadable: refuse and log, never crash
                {
                    new AuditLog(cfg.LogPath).Rejected("malformed request file (" + ex.GetType().Name + ")", null, null, null, Request.FileOwnerOf(requestFile), Request.FileOwnerSidOf(requestFile));
                    TryDelete(requestFile);
                    Console.Error.WriteLine("scan failed: malformed request file");
                    return 2;
                }
                ous = new List<string> { rq.Ou };
                outDir = rq.OutputDir;
                trigger = "on-demand";
                by = (rq.RequestedBy ?? "(not given)") + " | request file created by: " + (rq.FileOwner ?? "unknown"); edipi = rq.Edipi; reason = rq.Reason; startedBy = rq.FileOwner; startedBySid = rq.FileOwnerSid;
                // an elevated admin's new files are owned by the Administrators group, which names no person
                if (startedBy == null || startedBy.StartsWith("BUILTIN\\", StringComparison.OrdinalIgnoreCase) || startedBy.StartsWith("NT AUTHORITY\\", StringComparison.OrdinalIgnoreCase))
                    startedBy = (rq.RequestedBy ?? "unknown") + " (as stated in the request; file owner is " + (rq.FileOwner ?? "unknown") + ")";
            }

            if (requestFile == null)
            {
                // a person at the console (or passing --edipi/--reason) must identify themselves; the unattended
                // scheduled task (--scheduled, or any non-interactive start) is logged as scheduled with no person
                bool interactive = Environment.UserInteractive && !Console.IsInputRedirected;
                if (edipiArg != null || reasonArg != null || (!scheduledFlag && interactive))
                {
                    string who = Environment.UserDomainName + "\\" + Environment.UserName;
                    try { Request.AskPerson(cfg, ref edipiArg, ref reasonArg, interactive, who); }
                    catch (RequestException e)
                    {
                        new AuditLog(cfg.LogPath).Rejected(e.Message, e.Edipi, e.Reason, who);
                        Console.Error.WriteLine("scan not started: " + e.Message);
                        return 2;
                    }
                    edipi = edipiArg; reason = reasonArg; by = who; startedBy = who; trigger = "manual";
                }
            }

            bool keepRequest = false;
            try
            {
                RunResult res = Runner.Run(cfg, new PowerShellSource(), ous, outDir, trigger, by, edipi, reason, false, startedBy, startedBySid);
                Console.WriteLine(res.RunId + ": " + res.Accounts + " accounts, " + res.Flagged + " flagged -> " + res.Output);
                return 0;
            }
            catch (ScanBusyException e)
            {
                keepRequest = true;   // another scan holds the lock: keep the request; Main waits and tries again
                busy = true;
                Console.Error.WriteLine("scan not started: " + e.Message);
                return 2;
            }
            catch (RequestException e)
            {
                new AuditLog(cfg.LogPath).Rejected(e.Message, e.Edipi, e.Reason, e.RequestedBy ?? by, startedBy, startedBySid);   // for example a bad --ou
                Console.Error.WriteLine("scan failed: " + e.Message);
                return 2;
            }
            catch (InvalidOperationException e)
            {
                Console.Error.WriteLine("scan failed: " + e.Message);
                return 2;
            }
            finally
            {
                if (requestFile != null && !keepRequest) TryDelete(requestFile);   // content now lives only in the audit log
            }
        }

        static void TryDelete(string path)
        {
            try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        static string OldestRequest(string dir)
        {
            string[] c = Directory.Exists(dir) ? Directory.GetFiles(dir, "req_*.json") : new string[0];
            if (c.Length == 0) return null;
            Array.Sort(c, delegate(string x, string y) { return File.GetLastWriteTimeUtc(x).CompareTo(File.GetLastWriteTimeUtc(y)); });
            return c[0];
        }
    }
}
