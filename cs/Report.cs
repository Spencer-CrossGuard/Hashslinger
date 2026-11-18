using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Hashslinger
{
    public class ReportLeakException : Exception
    {
        public ReportLeakException(string m) : base(m) { }
    }

    /// <summary>Reason bits stored per account. Bits 1,2,4 are the store source bits (HIBP, rockyou, custom).</summary>
    public static class Reason
    {
        public const byte Pattern = 8;
        public const byte Duplicate = 16;
        public const byte Empty = 32;
        public const byte Reversible = 64;
        public const byte Lm = 128;

        public static string Text(byte r)
        {
            List<string> t = new List<string>();
            if ((r & Sources.HIBP) != 0) t.Add("Found in HIBP breach corpus");
            if ((r & Sources.Rockyou) != 0) t.Add("Found in rockyou list");
            if ((r & Sources.Custom) != 0) t.Add("Found in custom/organization term list");
            if ((r & Pattern) != 0) t.Add("Matched common-pattern rule (keyboard walk / dictionary base word)");
            if ((r & Duplicate) != 0) t.Add("Duplicate password shared with another account");
            if ((r & Empty) != 0) t.Add("No password set");
            if ((r & Reversible) != 0) t.Add("Reversible encryption enabled");
            if ((r & Lm) != 0) t.Add("LM hash present");
            return string.Join("; ", t.ToArray());
        }

        public static string Severity(byte r)
        {
            if ((r & (Sources.HIBP | Sources.Rockyou | Sources.Custom | Empty | Reversible)) != 0) return "High";
            return "Medium"; // pattern, duplicate, LM
        }
    }

    public static class Report
    {
        static readonly string[] Columns = { "sAMAccountName", "OU / Distinguished Name", "Account Type", "Flag Reason", "Severity", "Scan Run ID / Date" };

        static int FirstUnescapedComma(string dn)
        {
            for (int i = 0; i < dn.Length; i++)
            {
                if (dn[i] == '\\') { i++; continue; }
                if (dn[i] == ',') return i;
            }
            return -1;
        }

        /// <summary>The CN from a DN: only a last-resort stand-in so the sAMAccountName column is never blank.</summary>
        public static string CnFromDn(string dn)
        {
            int i = FirstUnescapedComma(dn);
            string first = i >= 0 ? dn.Substring(0, i) : dn;
            if (first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) first = first.Substring(3);
            return first.Replace("\\,", ",");
        }

        /// <summary>Strip the leading CN= RDN so the column routes remediation to an OU.</summary>
        public static string ParentContainer(string dn)
        {
            int i = FirstUnescapedComma(dn);
            if (i >= 0 && dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) return dn.Substring(i + 1);
            return dn;
        }

        static string Safe(string v)
        {
            if (v.Length > 0 && (v[0] == '=' || v[0] == '+' || v[0] == '-' || v[0] == '@' || v[0] == '\t' || v[0] == '\r')) return "'" + v;
            return v;
        }

        static string Csv(string v)
        {
            if (v.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0) return "\"" + v.Replace("\"", "\"\"") + "\"";
            return v;
        }

        static bool IsHex(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        /// <summary>Refuse to write a cell that contains any account's NT hash.</summary>
        static void LeakGuard(string cell, HashIdx[] sorted)
        {
            for (int i = 0; i + 32 <= cell.Length; i++)
            {
                if (!IsHex(cell[i])) continue;
                if (i > 0 && IsHex(cell[i - 1])) continue;
                Hash128 h;
                if (!Hash128.TryParseHex(cell, i, out h)) continue;
                if (i + 32 < cell.Length && IsHex(cell[i + 32])) continue;
                int lo = 0, hi = sorted.Length - 1;
                while (lo <= hi)
                {
                    int mid = (lo + hi) >> 1;
                    int c = sorted[mid].H.CompareTo(h);
                    if (c == 0) throw new ReportLeakException("a hash value would be written to the report");
                    if (c < 0) lo = mid + 1; else hi = mid - 1;
                }
            }
        }

        public static string Write(AccountTable t, string runId, string outDir, HashIdx[] sortedHashes, out int flagged)
        {
            Directory.CreateDirectory(outDir);
            string datePart = runId.Substring(0, runId.LastIndexOf('-'));
            string final = Path.Combine(outDir, "report_" + datePart + ".csv");
            if (File.Exists(final)) final = Path.Combine(outDir, "report_" + runId + ".csv");
            string tmp = final + ".tmp";
            int rows = 0;
            using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
            using (StreamWriter w = new StreamWriter(fs, new UTF8Encoding(false), 1 << 16))
            {
                w.Write(string.Join(",", Columns) + "\r\n");
                for (int i = 0; i < t.Count; i++)
                {
                    byte r = t.Reasons(i);
                    if (r == 0) continue;
                    string sam, dn;
                    t.GetNames(i, out sam, out dn);
                    if (string.IsNullOrEmpty(sam) || sam == "(unknown)") sam = CnFromDn(dn);
                    string[] cells =
                    {
                        Safe(sam), Safe(ParentContainer(dn)), AccountTable.TypeNames[t.Type(i)],
                        Reason.Text(r), Reason.Severity(r), runId
                    };
                    for (int c = 0; c < cells.Length; c++)
                    {
                        LeakGuard(cells[c], sortedHashes);
                        cells[c] = Csv(cells[c]);
                    }
                    w.Write(string.Join(",", cells) + "\r\n");
                    rows++;
                }
                w.Flush();
                fs.Flush(true);
            }
            if (File.Exists(final)) File.Delete(final);
            File.Move(tmp, final);
            int lines = 0;   // CSV records: a line break inside a quoted cell does not start a new record
            bool inQuotes = false, any = false;
            using (StreamReader sr = new StreamReader(final, Encoding.UTF8))
            {
                int ch;
                while ((ch = sr.Read()) >= 0)
                {
                    any = true;
                    if (ch == '"') inQuotes = !inQuotes;
                    else if (ch == '\n' && !inQuotes) any = false;
                    if (ch == '\n' && !inQuotes) lines++;
                }
            }
            if (any) lines++;
            if (lines - 1 != rows) throw new InvalidOperationException("Report verification failed: row count mismatch");
            flagged = rows;
            return final;
        }

        public static int PurgeOld(string outDir, int retentionDays)
        {
            if (retentionDays <= 0 || !Directory.Exists(outDir)) return 0;
            int n = 0;
            DateTime cutoff = DateTime.UtcNow.AddDays(-retentionDays);
            foreach (string f in Directory.GetFiles(outDir, "report_*.csv"))
                if (File.GetLastWriteTimeUtc(f) < cutoff && Wipe.SecureDelete(f)) n++;
            return n;
        }
    }
}
