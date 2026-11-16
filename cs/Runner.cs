using System;
using System.Collections.Generic;
using System.IO;

namespace Hashslinger
{
    public sealed class RunResult
    {
        public string RunId;
        public int Accounts;
        public int Flagged;
        public string Output;
        public bool WipeConfirmed;
    }

    public static class Runner
    {
        /// <summary>Lookups, pattern matching and duplicate detection run over hashes sorted ascending,
        /// so reads of the mmap'd store move forward through the file instead of jumping around.</summary>
        static HashIdx[] Analyze(AccountTable t, HashStore store, Dictionary<Hash128, string> patterns, bool checkDuplicates)
        {
            int n = 0;
            for (int i = 0; i < t.Count; i++)
                if (t.HasNt(i) && !t.Hash(i).Equals(Ntlm.Empty)) n++;
            HashIdx[] arr = new HashIdx[n];
            int k = 0;
            for (int i = 0; i < t.Count; i++)
            {
                if (!t.HasNt(i)) continue;
                Hash128 h = t.Hash(i);
                if (h.Equals(Ntlm.Empty)) { t.AddReasons(i, Reason.Empty); continue; }
                arr[k].H = h;
                arr[k].Idx = i;
                k++;
            }
            Array.Sort(arr);
            int s = 0;
            while (s < arr.Length)
            {
                int e = s + 1;
                while (e < arr.Length && arr[e].H.Equals(arr[s].H)) e++;
                byte bits = store.Lookup(arr[s].H);
                if (patterns.ContainsKey(arr[s].H)) bits |= Reason.Pattern;
                if (checkDuplicates && e - s > 1) bits |= Reason.Duplicate;
                if (bits != 0)
                    for (int j = s; j < e; j++) t.AddReasons(arr[j].Idx, bits);
                s = e;
            }
            return arr;
        }

        public static RunResult Run(Config cfg, IAccountSource source, IList<string> ous, string outputDir,
            string trigger, string requestedBy, string edipi, string reason, bool skipPreflight)
        {
            if (ous == null || ous.Count == 0) ous = cfg.TargetOus;
            foreach (string ou in ous)
                if (!cfg.TargetOus.Contains(ou)) throw new RequestException("OU not in configured list: " + ou, edipi, reason, requestedBy);
            string outDir = outputDir ?? cfg.OutputPath;
            AuditLog log = new AuditLog(cfg.LogPath);
            string runId = log.NextRunId();
            log.Start(runId, trigger, ous, requestedBy, edipi, reason);

            AccountTable table = new AccountTable();
            string status = "failed", error = null, outPath = null;
            int flagged = 0, accounts = 0;
            bool wipeOk = false;
            try
            {
                if (!skipPreflight) Preflight.Run(cfg, outDir);
                StoreMerge.ProcessStaging(cfg.HashStorePath, cfg.StagingPath, null);
                Dictionary<Hash128, string> patterns = Patterns.Build(cfg.PatternRulesPath, DateTime.Now);
                source.Run(cfg, ous, delegate(AccountRecord a)
                {
                    int idx = table.Add(a);
                    byte r = 0;
                    if (a.Rev) r |= Reason.Reversible;
                    if (a.Lm) r |= Reason.Lm;
                    if (r != 0) table.AddReasons(idx, r);
                });
                accounts = table.Count;
                HashIdx[] sorted;
                using (HashStore store = new HashStore(cfg.HashStorePath, ShouldIndex(cfg)))
                    sorted = Analyze(table, store, patterns, cfg.CheckDuplicates);
                outPath = Report.Write(table, runId, outDir, sorted, out flagged);
                Report.PurgeOld(outDir, cfg.RetentionDays);
                status = "success";
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
            }
            finally
            {
                accounts = table.Count > accounts ? table.Count : accounts;
                wipeOk = table.Wipe();
                bool tmpOk = true;
                string dir = Path.GetDirectoryName(Path.GetFullPath(cfg.HashStorePath));
                if (Directory.Exists(dir))
                    foreach (string d in Directory.GetDirectories(dir, "merge-*"))
                        tmpOk &= Wipe.SecureDeleteDir(d);
                log.End(runId, status, accounts, outPath, wipeOk && tmpOk, error);
                wipeOk = wipeOk && tmpOk;
            }
            if (status != "success") throw new InvalidOperationException(error);
            RunResult res = new RunResult();
            res.RunId = runId; res.Accounts = accounts; res.Flagged = flagged; res.Output = outPath; res.WipeConfirmed = wipeOk;
            return res;
        }

        static bool ShouldIndex(Config cfg)
        {
            return new FileInfo(cfg.HashStorePath).Length / HashStore.Record > 1000000;
        }
    }
}
