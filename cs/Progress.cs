using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace Hashslinger
{
    /// <summary>Progress for a run: console lines plus a status file that anyone with read access can watch
    /// (the viewer never depends on who started the run). A heartbeat rewrites the file every few seconds so
    /// a viewer can tell "quiet but alive" from "stopped". Never write hashes or credentials here.</summary>
    public static class Progress
    {
        public static bool Quiet = false;
        public const int Stages = 7;

        static readonly object gate = new object();
        static string statusPath;
        static Dictionary<string, object> st;
        static Timer heartbeat;
        static System.Diagnostics.Stopwatch stageClock = new System.Diagnostics.Stopwatch();
        static int curStage;
        static long[] stageMs = new long[Stages + 1];

        static string Now()
        {
            return DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }

        public static void Begin(string path, string runId, string runAs, string requestedBy, IList<string> scope)
        {
            lock (gate)
            {
                statusPath = path;
                stageMs = new long[Stages + 1];
                curStage = 0;
                stageClock.Restart();
                st = new Dictionary<string, object>();
                st["state"] = "running";
                st["run_id"] = runId;
                st["started_utc"] = Now();
                st["updated_utc"] = Now();
                st["stage"] = 0;
                st["stages"] = Stages;
                st["message"] = "Starting";
                st["detail"] = "";
                st["accounts_received"] = 0;
                st["run_as"] = runAs;
                st["requested_by"] = requestedBy;
                st["host"] = Environment.MachineName;
                st["scope"] = new List<string>(scope);
                st["output"] = null;
                st["error"] = null;
                WriteLocked();
                if (heartbeat != null) heartbeat.Dispose();
                heartbeat = new Timer(delegate(object o) { Beat(); }, null, 5000, 5000);
            }
        }

        static void Beat()
        {
            lock (gate)
            {
                if (st != null && (string)st["state"] == "running") WriteLocked();
            }
        }

        /// <summary>Status must never break a scan, so write failures are swallowed.</summary>
        static void WriteLocked()
        {
            if (statusPath == null || st == null) return;
            try
            {
                st["updated_utc"] = Now();
                string dir = Path.GetDirectoryName(Path.GetFullPath(statusPath));
                Directory.CreateDirectory(dir);
                string tmp = statusPath + ".tmp";
                File.WriteAllText(tmp, Json.Write(st), new UTF8Encoding(false));
                if (File.Exists(statusPath)) File.Replace(tmp, statusPath, null);
                else File.Move(tmp, statusPath);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        public static void Stage(int n, string msg)
        {
            lock (gate)
            {
                stageMs[curStage] += stageClock.ElapsedMilliseconds;
                stageClock.Restart();
                curStage = n;
                if (st != null) { st["stage"] = n; st["message"] = msg; st["detail"] = ""; WriteLocked(); }
            }
            if (Quiet) return;
            Console.WriteLine("[" + n + "/" + Stages + "] " + msg);
            Console.Out.Flush();
        }

        public static void Info(string msg)
        {
            lock (gate)
            {
                if (st != null) { st["detail"] = msg; WriteLocked(); }
            }
            if (Quiet) return;
            Console.WriteLine("      " + msg);
            Console.Out.Flush();
        }

        /// <summary>Milliseconds spent per stage so far (the current stage included).</summary>
        public static Dictionary<string, object> Timings()
        {
            lock (gate)
            {
                long[] copy = (long[])stageMs.Clone();
                copy[curStage] += stageClock.ElapsedMilliseconds;
                Dictionary<string, object> d = new Dictionary<string, object>();
                for (int i = 1; i <= Stages; i++) d["stage" + i] = copy[i];
                return d;
            }
        }

        public static void Count(int accounts)
        {
            lock (gate)
            {
                if (st != null) st["accounts_received"] = accounts;
            }
        }

        public static void Finish(string state, string output, string error)
        {
            lock (gate)
            {
                if (heartbeat != null) { heartbeat.Dispose(); heartbeat = null; }
                if (st == null) return;
                st["state"] = state;
                st["output"] = output;
                st["error"] = error;
                if (state == "success") { st["stage"] = Stages; st["message"] = "Done"; st["detail"] = ""; }
                WriteLocked();
                st = null;
            }
        }
    }
}
