using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Hashslinger
{
    public class ConfigException : Exception
    {
        public ConfigException(string m) : base(m) { }
    }

    public sealed class Config
    {
        public string Mode = "live";                 // live (DRS replication) | offline (ntds.dit)
        public string Replication = "bulk";          // bulk (stream all, filter) | per-account
        public string TargetServer = "";
        public List<string> TargetOus = new List<string>();
        public List<string> AccountTypes = new List<string> { "User", "Service" };
        public List<string> ServiceNamePrefixes = new List<string> { "svc.", "$svc." };   // accounts whose name starts with one of these count as Service even without an SPN (service_name_prefixes)
        public List<int> UacRequire = new List<int>();
        public List<int> UacExclude = new List<int> { 0x40000 }; // smart-card-required
        public string HashStorePath = "store\\master.ntlm";
        public string StagingPath = "staging";
        public string LogPath = "logs\\audit.jsonl";
        public string OutputPath = "output";
        public List<string> AllowedOutputRoots = new List<string>();
        public string RequestDir = "requests";
        public string PatternRulesPath = "config\\pattern_rules.json";
        public bool RequireEncryptedVolume = false;
        public int RetentionDays = 0;                // 0 = keep forever
        /// <summary>The system PowerShell by FULL path. A bare "powershell.exe" would be looked up in the exe's own folder
        /// first, so anyone who could write there could run code as the scan account.</summary>
        public static readonly string DefaultPowerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        public static string ResolvePowerShell(string p)
        {
            if (string.Equals(p, "powershell.exe", StringComparison.OrdinalIgnoreCase)) return DefaultPowerShell;
            return p;
        }
        public string PowerShellPath = DefaultPowerShell;
        public string EngineScript = "powershell\\Get-AccountHashes.ps1";
        public List<string> EngineCommand = null;    // test hook; {ous} is replaced by the '|' joined OU list
        public int EngineTimeoutSeconds = 6 * 3600;
        public string NtdsPath = "";
        public string SystemHivePath = "";
        public List<string> AuthorizedEdipis = new List<string>();
        public string StatusPath = "status\\status.json";
        public int Workers = 1;                      // parallel DC connections for per-account replication
        public int PerAccountThreshold = 5000;       // at or below this many in-scope accounts, bulk mode switches to per-account
        public string ReplProperties = "GenericAccountInfo,NTHash,LMHash";   // password data pulled from AD; SupplementalCredentials is slower and only adds clear-text detection
        public int EdipiLength = 11;                 // how many characters an EDIPI has, letters and digits (edipi_length)
        public int ReasonMinLength = 5;              // shortest accepted reason or CTO number (reason_min_length)
        public bool FipsExemptEngine = false;       // OFF by default: .NET FIPS enforcement is switched off for the scan engine process ONLY (needs security approval)
        public bool CheckDuplicates = false;         // off unless explicitly enabled

        static int Flag(string name)
        {
            switch (name)
            {
                case "ACCOUNTDISABLE": return 0x2;
                case "PASSWD_NOTREQD": return 0x20;
                case "ENCRYPTED_TEXT_PWD_ALLOWED": return 0x80;
                case "DONT_EXPIRE_PASSWORD": return 0x10000;
                case "SMARTCARD_REQUIRED": return 0x40000;
            }
            int n;
            if (int.TryParse(name, out n)) return n;
            throw new ConfigException("Unknown UAC flag " + name);
        }

        static string Resolve(string baseDir, string p)
        {
            return Path.IsPathRooted(p) ? p : Path.Combine(baseDir, p);
        }

        public static Config Load(string path)
        {
            // the Admin tool may be replacing the file at this very moment: retry briefly on a sharing violation
            string text = null;
            for (int attempt = 0; ; attempt++)
            {
                try { text = File.ReadAllText(path, Encoding.UTF8); break; }
                catch (IOException) { if (attempt >= 10) throw; System.Threading.Thread.Sleep(300); }
            }
            Dictionary<string, object> raw = Json.Parse(text) as Dictionary<string, object>;
            if (raw == null) throw new ConfigException("the settings file must be a JSON object");
            string baseDir = Path.GetDirectoryName(Path.GetFullPath(path));
            Config c = new Config();
            c.Mode = Json.Str(raw, "mode", c.Mode);
            c.Replication = Json.Str(raw, "replication", c.Replication);
            c.TargetServer = Json.Str(raw, "target_server", "");
            c.TargetOus = Json.StrList(raw, "target_ous");
            if (raw.ContainsKey("account_types")) c.AccountTypes = Json.StrList(raw, "account_types");
            if (raw.ContainsKey("service_name_prefixes")) c.ServiceNamePrefixes = Json.StrList(raw, "service_name_prefixes");
            object uo;
            if (raw.TryGetValue("uac", out uo))
            {
                Dictionary<string, object> uac = uo as Dictionary<string, object>;
                if (uac != null)
                {
                    if (uac.ContainsKey("require_flags")) { c.UacRequire = new List<int>(); foreach (string s in Json.StrList(uac, "require_flags")) c.UacRequire.Add(Flag(s)); }
                    if (uac.ContainsKey("exclude_flags")) { c.UacExclude = new List<int>(); foreach (string s in Json.StrList(uac, "exclude_flags")) c.UacExclude.Add(Flag(s)); }
                }
            }
            c.HashStorePath = Resolve(baseDir, Json.Str(raw, "hash_store_path", c.HashStorePath));
            c.StagingPath = Resolve(baseDir, Json.Str(raw, "staging_path", c.StagingPath));
            c.LogPath = Resolve(baseDir, Json.Str(raw, "log_path", c.LogPath));
            c.OutputPath = Resolve(baseDir, Json.Str(raw, "output_path", c.OutputPath));
            c.RequestDir = Resolve(baseDir, Json.Str(raw, "request_dir", c.RequestDir));
            c.PatternRulesPath = Resolve(baseDir, Json.Str(raw, "pattern_rules_path", c.PatternRulesPath));
            c.StatusPath = Resolve(baseDir, Json.Str(raw, "status_path", c.StatusPath));
            c.EngineScript = Resolve(baseDir, Json.Str(raw, "engine_script", c.EngineScript));
            c.AllowedOutputRoots = Json.StrList(raw, "allowed_output_roots");
            c.RequireEncryptedVolume = Json.Str(raw, "require_encrypted_volume", "false").ToLowerInvariant() == "true";
            c.RetentionDays = (int)Convert.ToDouble(Json.Str(raw, "retention_days", "0"), System.Globalization.CultureInfo.InvariantCulture);
            c.PowerShellPath = ResolvePowerShell(Json.Str(raw, "powershell_path", c.PowerShellPath));
            if (!Path.IsPathRooted(c.PowerShellPath)) throw new ConfigException("powershell_path must be a full path");
            if (raw.ContainsKey("engine_command")) c.EngineCommand = Json.StrList(raw, "engine_command");
            c.EngineTimeoutSeconds = (int)Convert.ToDouble(Json.Str(raw, "engine_timeout_seconds", c.EngineTimeoutSeconds.ToString()), System.Globalization.CultureInfo.InvariantCulture);
            c.NtdsPath = Json.Str(raw, "ntds_path", "");
            c.SystemHivePath = Json.Str(raw, "system_hive_path", "");
            c.AuthorizedEdipis = Json.StrList(raw, "authorized_edipis");
            c.Workers = Math.Max(1, Math.Min(16, (int)Convert.ToDouble(Json.Str(raw, "workers", "1"), System.Globalization.CultureInfo.InvariantCulture)));
            c.PerAccountThreshold = (int)Convert.ToDouble(Json.Str(raw, "per_account_threshold", "5000"), System.Globalization.CultureInfo.InvariantCulture);
            c.CheckDuplicates = Json.Str(raw, "check_duplicates", "false").ToLowerInvariant() == "true";
            c.ReplProperties = Json.Str(raw, "repl_properties", c.ReplProperties).Trim();
            if (!System.Text.RegularExpressions.Regex.IsMatch(c.ReplProperties, "^[A-Za-z]+(,[A-Za-z]+)*$")) throw new ConfigException("repl_properties must be a comma separated list of property names");
            c.EdipiLength = Math.Max(4, Math.Min(30, (int)Convert.ToDouble(Json.Str(raw, "edipi_length", "11"), System.Globalization.CultureInfo.InvariantCulture)));
            c.ReasonMinLength = Math.Max(1, Math.Min(100, (int)Convert.ToDouble(Json.Str(raw, "reason_min_length", "5"), System.Globalization.CultureInfo.InvariantCulture)));
            c.FipsExemptEngine = Json.Str(raw, "engine_fips_exempt", "false").ToLowerInvariant() == "true";
            if (c.FipsExemptEngine)
            {
                // a copy of powershell.exe in the (admin-only) app folder with its own .config that turns FIPS enforcement
                // off for THAT process only. Windows FIPS mode stays on for everything else.
                string ex = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hs-engine.exe");
                if (!File.Exists(ex)) throw new ConfigException("engine_fips_exempt is on but " + ex + " does not exist. Re-run the Finish step (Admin tool, Security and accounts, Re-apply).");
                c.PowerShellPath = ex;
            }
            if (c.EngineTimeoutSeconds < 60) c.EngineTimeoutSeconds = 60;
            if (c.EngineTimeoutSeconds > 4000000) c.EngineTimeoutSeconds = 4000000;   // about 46 days
            c.Validate();
            return c;
        }

        public void Validate()
        {
            if (Mode != "live" && Mode != "offline") throw new ConfigException("mode must be 'live' or 'offline'");
            if (Replication != "bulk" && Replication != "per-account") throw new ConfigException("replication must be 'bulk' or 'per-account'");
            if (TargetOus.Count == 0) throw new ConfigException("target_ous must list at least one OU distinguished name");
            foreach (string t in AccountTypes)
                if (t != "User" && t != "Service" && t != "Computer") throw new ConfigException("bad account type " + t);
            foreach (string sp in ServiceNamePrefixes)
                if (sp.Length == 0 || sp.IndexOfAny(new[] { ',', '*', '(', ')', '\\', '\0', '"', '\'' }) >= 0)
                    throw new ConfigException("service_name_prefixes entries must be non-empty and must not contain , * ( ) \\ quotes: " + sp);
            foreach (string lp in new[] { HashStorePath, StagingPath, LogPath, OutputPath, StatusPath, RequestDir })
                if (lp.StartsWith("\\\\", StringComparison.Ordinal)) throw new ConfigException("paths must be on a local drive, not a network share: " + lp);
            foreach (string ar in AllowedOutputRoots)
                if (ar.StartsWith("\\\\", StringComparison.Ordinal)) throw new ConfigException("allowed_output_roots must be local drives, not a network share: " + ar);
            if (Mode == "offline" && (NtdsPath.Length == 0 || SystemHivePath.Length == 0))
                throw new ConfigException("offline mode needs ntds_path and system_hive_path");
        }
    }
}
