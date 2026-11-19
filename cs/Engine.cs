using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace Hashslinger
{
    public class EngineException : Exception
    {
        public EngineException(string m) : base(m) { }
    }

    /// <summary>Anything that can stream accounts (the PowerShell engine, or a fake in tests).</summary>
    public interface IAccountSource
    {
        void Run(Config cfg, IList<string> ous, Action<AccountRecord> sink);
    }

    /// <summary>Runs the PowerShell engine and reads accounts from its stdout pipe.
    /// Line format (tab separated): sam, dn, type, nt-hex-or-empty, lm(0/1), reversible(0/1).
    /// Hashes live only on the pipe and in the zeroable AccountTable. Never on disk.</summary>
    public sealed class PowerShellSource : IAccountSource
    {
        public static string Quote(string a)
        {
            if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
            StringBuilder sb = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char c in a)
            {
                if (c == '\\') { backslashes++; continue; }
                if (c == '"') { sb.Append('\\', backslashes * 2 + 1); sb.Append('"'); }
                else { sb.Append('\\', backslashes); sb.Append(c); }
                backslashes = 0;
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }

        public static List<string> BuildCommand(Config cfg, IList<string> ous)
        {
            string joined = string.Join("|", new List<string>(ous).ToArray());
            List<string> cmd = new List<string>();
            if (cfg.EngineCommand != null)
            {
                foreach (string a in cfg.EngineCommand) cmd.Add(a.Replace("{ous}", joined));
                return cmd;
            }
            cmd.Add(cfg.PowerShellPath);
            cmd.AddRange(new[] { "-NoProfile", "-NonInteractive", "-File", cfg.EngineScript,
                "-Mode", cfg.Mode, "-Replication", cfg.Replication, "-SearchBases", joined,
                "-PerAccountThreshold", cfg.PerAccountThreshold.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "-Workers", cfg.Workers.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "-ReplProperties", cfg.ReplProperties,
                "-AccountTypes", string.Join(",", cfg.AccountTypes.ToArray()) });
            if (cfg.UacExclude.Count > 0) { cmd.Add("-ExcludeUacFlags"); cmd.Add(JoinInts(cfg.UacExclude)); }
            if (cfg.UacRequire.Count > 0) { cmd.Add("-RequireUacFlags"); cmd.Add(JoinInts(cfg.UacRequire)); }
            if (cfg.Mode == "live") { cmd.Add("-Server"); cmd.Add(cfg.TargetServer); }
            else { cmd.Add("-NtdsPath"); cmd.Add(cfg.NtdsPath); cmd.Add("-SystemHivePath"); cmd.Add(cfg.SystemHivePath); }
            return cmd;
        }

        static string JoinInts(List<int> l)
        {
            string[] s = new string[l.Count];
            for (int i = 0; i < s.Length; i++) s[i] = l[i].ToString();
            return string.Join(",", s);
        }

        public void Run(Config cfg, IList<string> ous, Action<AccountRecord> sink)
        {
            List<string> cmd = BuildCommand(cfg, ous);
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = Config.ResolvePowerShell(cmd[0]);
            StringBuilder args = new StringBuilder();
            for (int i = 1; i < cmd.Count; i++)
            {
                if (i > 1) args.Append(' ');
                args.Append(Quote(cmd[i]));
            }
            psi.Arguments = args.ToString();
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            psi.StandardOutputEncoding = Encoding.UTF8;

            StringBuilder err = new StringBuilder();
            bool timedOut = false;
            using (Process p = new Process())
            {
                p.StartInfo = psi;
                p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null && err.Length < 4000) err.AppendLine(e.Data);
                };
                p.Start();
                p.BeginErrorReadLine();
                Timer killer = null;
                try
                {
                    // 64-bit milliseconds: seconds * 1000 overflows 32 bits above about 596 hours. Created inside the try so a
                    // failure here still ends the PowerShell child in the cleanup below.
                    long ms = Math.Min((long)cfg.EngineTimeoutSeconds * 1000L, 4294967294L);
                    killer = new Timer(delegate(object o)
                    {
                        timedOut = true;
                        try { p.Kill(); } catch (InvalidOperationException) { }
                    }, null, ms, (long)Timeout.Infinite);
                    string line;
                    while ((line = p.StandardOutput.ReadLine()) != null)
                    {
                        if (line.Length == 0) continue;
                        if (line.StartsWith("##HS## ", StringComparison.Ordinal)) { Progress.Info(line.Substring(7)); Progress.Mark(line.Substring(7)); continue; }
                        sink(Parse(line));
                    }
                    p.WaitForExit();
                }
                finally
                {
                    if (killer != null) killer.Dispose();
                    try { if (!p.HasExited) p.Kill(); } catch (InvalidOperationException) { }
                }
                if (timedOut) throw new EngineException("the engine ran longer than engine_timeout_seconds (" + cfg.EngineTimeoutSeconds + ") and was stopped");
                if (p.ExitCode != 0)
                {
                    string msg = err.ToString().Trim();
                    if (msg.Length > 500) msg = msg.Substring(0, 500);
                    throw new EngineException("engine exited " + p.ExitCode + ": " + msg);
                }
            }
        }

        /// <summary>Parse one engine line. Error messages never echo the line (it may hold a hash).</summary>
        public static AccountRecord Parse(string line)
        {
            string[] f = line.Split('\t');
            if (f.Length != 6 && f.Length != 7) throw new EngineException("engine produced a malformed line");
            AccountRecord a = new AccountRecord();
            a.Sam = f[0];
            a.Dn = f[1];
            a.Type = f[2] == "Service" ? 1 : (f[2] == "Computer" ? 2 : 0);
            if (f[3].Length > 0)
            {
                Hash128 h;
                if (!Hash128.TryParseHex(f[3], 0, out h) || f[3].Length != 32)
                    throw new EngineException("engine produced a malformed hash field");
                a.HasNt = true;
                a.Nt = h;
            }
            a.Lm = f[4] == "1";
            a.Rev = f[5] == "1";
            a.NoPw = f.Length == 7 && f[6] == "1";
            return a;
        }
    }
}
