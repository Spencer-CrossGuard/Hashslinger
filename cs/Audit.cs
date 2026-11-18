using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Hashslinger
{
    /// <summary>Append-only JSONL audit log. Every run writes a start and an end entry, failures included.</summary>
    public sealed class AuditLog
    {
        readonly string path;

        public AuditLog(string path)
        {
            this.path = path;
            string dir = Path.GetDirectoryName(Path.GetFullPath(path));
            Directory.CreateDirectory(dir);
        }

        static string Now()
        {
            return DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }

        static string Who()
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }

        void Append(Dictionary<string, object> e)
        {
            byte[] b = new UTF8Encoding(false).GetBytes(Json.Write(e) + "\n");
            using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                fs.Write(b, 0, b.Length);
                fs.Flush(true);
            }
        }

        public string NextRunId()
        {
            string today = DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            int n = 0;
            if (File.Exists(path))
            {
                string[] lines;
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    lines = sr.ReadToEnd().Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    try
                    {
                        Dictionary<string, object> e = Json.Parse(line) as Dictionary<string, object>;
                        if (e != null && Json.Str(e, "event", "") == "start" && Json.Str(e, "run_id", "").StartsWith(today + "-", StringComparison.Ordinal)) n++;
                    }
                    catch (FormatException) { }
                }
            }
            return today + "-" + (n + 1).ToString("D3", CultureInfo.InvariantCulture);
        }

        public void Start(string runId, string trigger, IList<string> scope, string requestedBy, string edipi, string reason, string startedBy = null)
        {
            Dictionary<string, object> e = new Dictionary<string, object>();
            e["event"] = "start";
            e["run_id"] = runId;
            e["time"] = Now();
            e["trigger"] = trigger;
            e["run_as"] = Who();
            e["started_by"] = startedBy ?? Who();   // taken from Windows automatically, never typed in
            e["host"] = Environment.MachineName;
            e["requested_by"] = requestedBy;
            e["edipi"] = edipi;
            e["reason"] = reason;
            e["scope"] = new List<string>(scope);
            Append(e);
        }

        public void Rejected(string why, string edipi, string reason, string requestedBy, string startedBy = null)
        {
            Dictionary<string, object> e = new Dictionary<string, object>();
            e["event"] = "rejected";
            e["time"] = Now();
            e["run_as"] = Who();
            e["started_by"] = startedBy ?? Who();
            e["host"] = Environment.MachineName;
            e["why"] = why;
            e["edipi"] = edipi;
            e["reason"] = reason;
            e["requested_by"] = requestedBy;
            Append(e);
        }

        public void End(string runId, string status, int accounts, string output, bool wipeConfirmed, string error, Dictionary<string, object> timingsMs)
        {
            Dictionary<string, object> e = new Dictionary<string, object>();
            e["event"] = "end";
            e["run_id"] = runId;
            e["time"] = Now();
            e["status"] = status;
            e["accounts_processed"] = accounts;
            e["output"] = output;
            e["wipe_confirmed"] = wipeConfirmed;
            e["error"] = error;
            e["timings_ms"] = timingsMs;
            Append(e);
        }
    }
}
