using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace Hashslinger
{
    /// <summary>"Hashslinger.exe bench [accounts] [storeRecords]": times the C# side (ingest, sort + lookup,
    /// report) with synthetic random data. No AD, no PowerShell. The AD replication pull is NOT measured here.</summary>
    public static class Bench
    {
        static string Rate(long n, Stopwatch sw)
        {
            return n + " in " + sw.Elapsed.TotalSeconds.ToString("F1") + "s (" + (long)(n / Math.Max(0.001, sw.Elapsed.TotalSeconds)) + "/s)";
        }

        public static int Run(string[] args)
        {
            int accounts = args.Length > 1 ? int.Parse(args[1]) : 1000000;
            long storeRecords = args.Length > 2 ? long.Parse(args[2]) : 20000000L;
            string dir = Path.Combine(Path.GetTempPath(), "hashslinger-bench-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string storePath = Path.Combine(dir, "master.ntlm");
            Console.WriteLine("bench: " + accounts + " accounts, " + storeRecords + " store records, temp dir " + dir);
            try
            {
                Random rng = new Random(12345);
                List<Hash128> hits = new List<Hash128>();
                double keep = Math.Min(1.0, (accounts / 10.0) / storeRecords);

                Stopwatch sw = Stopwatch.StartNew();
                using (FileStream fs = new FileStream(storePath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
                {
                    byte[] buf = new byte[HashStore.Record * 65536];
                    int o = 0;
                    ulong hi = 0;
                    ulong step = ulong.MaxValue / (ulong)storeRecords;
                    for (long i = 0; i < storeRecords; i++)
                    {
                        hi += (ulong)(rng.NextDouble() * (double)(step - 1)) + 1UL;
                        ulong lo = ((ulong)(uint)rng.Next() << 32) | (uint)rng.Next();
                        Hash128 h = new Hash128(hi, lo);
                        h.CopyTo(buf, o);
                        buf[o + 16] = Sources.HIBP;
                        o += HashStore.Record;
                        if (o == buf.Length) { fs.Write(buf, 0, o); o = 0; }
                        if (hits.Count < accounts / 10 && rng.NextDouble() < keep) hits.Add(h);
                    }
                    if (o > 0) fs.Write(buf, 0, o);
                }
                Console.WriteLine("generate store (not timed as part of a scan): " + Rate(storeRecords, sw));

                AccountTable t = new AccountTable();
                sw.Restart();
                for (int i = 0; i < accounts; i++)
                {
                    AccountRecord a = new AccountRecord();
                    a.Sam = "user" + i;
                    a.Dn = "CN=user" + i + ",OU=Bench,DC=corp,DC=contoso,DC=com";
                    a.HasNt = true;
                    a.Nt = (i % 10 == 0 && hits.Count > 0) ? hits[(i / 10) % hits.Count]
                         : new Hash128(((ulong)(uint)rng.Next() << 32) | (uint)rng.Next(), ((ulong)(uint)rng.Next() << 32) | (uint)rng.Next());
                    t.Add(a);
                }
                Console.WriteLine("ingest into AccountTable: " + Rate(accounts, sw));

                HashIdx[] sorted;
                sw.Restart();
                using (HashStore store = new HashStore(storePath, storeRecords > 1000000))
                {
                    Console.WriteLine("open store + prefix index: " + sw.Elapsed.TotalSeconds.ToString("F1") + "s");
                    sw.Restart();
                    sorted = Runner.Analyze(t, store, new Dictionary<Hash128, string>(), false);
                }
                Console.WriteLine("sort + lookup: " + Rate(accounts, sw));

                int flagged;
                sw.Restart();
                Report.Write(t, "2000-01-01-001", dir, sorted, out flagged);
                Console.WriteLine("write report (" + flagged + " flagged rows): " + Rate(flagged, sw));

                Console.WriteLine("peak memory: " + (Process.GetCurrentProcess().PeakWorkingSet64 / (1024 * 1024)) + " MB");
                t.Wipe();
                Console.WriteLine("Note: the AD replication pull (PowerShell + DSInternals) is not included. Measure it with a real scan.");
                return 0;
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch (IOException) { }
            }
        }
    }
}
