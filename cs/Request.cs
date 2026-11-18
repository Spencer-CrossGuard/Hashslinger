using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace Hashslinger
{
    public sealed class ScanRequest
    {
        public string Ou;
        public string OutputDir;
        public string Edipi;
        public string Reason;
        public string RequestedBy;
        public string FileOwner; // NTFS owner of the request file = the account that really created it
    }

    public class RequestException : Exception
    {
        public string Edipi;
        public string Reason;
        public string RequestedBy;

        public RequestException(string m, string edipi, string reason, string by) : base(m)
        {
            Edipi = edipi;
            Reason = reason;
            RequestedBy = by;
        }
    }

    public static class Request
    {
        /// <summary>Every scan started by a person needs a 10-digit EDIPI (on the allowed list, if one is set) and a
        /// reason or CTO number of 10 to 500 characters. Both go into the audit log.</summary>
        public static void CheckPerson(Config cfg, string edipi, string reason, string by)
        {
            edipi = (edipi ?? "").Trim();
            reason = (reason ?? "").Trim();
            if (!Regex.IsMatch(edipi, "^[0-9]{10}$"))
                throw new RequestException("EDIPI must be exactly 10 digits", edipi, reason, by);
            if (cfg.AuthorizedEdipis.Count > 0 && !cfg.AuthorizedEdipis.Contains(edipi))
                throw new RequestException("EDIPI is not authorized to request scans", edipi, reason, by);
            if (reason.Length < 10 || reason.Length > 500)
                throw new RequestException("a reason or CTO number of 10 to 500 characters is required", edipi, reason, by);
        }

        /// <summary>Ask the person at the console for their EDIPI and the reason / CTO number (three tries).
        /// Values already supplied on the command line are checked, not asked for again.</summary>
        public static void AskPerson(Config cfg, ref string edipi, ref string reason, bool interactive, string who)
        {
            if (!interactive)
            {
                CheckPerson(cfg, edipi, reason, who);
                return;
            }
            Console.WriteLine("This scan is attributed to a person and logged. Windows account: " + who);
            for (int tries = 0; ; tries++)
            {
                if (string.IsNullOrEmpty(edipi)) { Console.Write("EDIPI (10 digits): "); edipi = (Console.ReadLine() ?? "").Trim(); }
                if (string.IsNullOrEmpty(reason)) { Console.Write("Reason for this scan / CTO number: "); reason = (Console.ReadLine() ?? "").Trim(); }
                try { CheckPerson(cfg, edipi, reason, who); return; }
                catch (RequestException e)
                {
                    if (tries >= 2) throw;
                    Console.WriteLine("  " + e.Message);
                    edipi = null;
                    reason = null;
                }
            }
        }

        /// <summary>Validate an analyst request. Only config-listed OUs and allowed output roots are accepted;
        /// an EDIPI (10 digits) and a reason (10-500 chars) are mandatory and end up in the audit log.</summary>
        public static ScanRequest Load(Config cfg, string path)
        {
            Dictionary<string, object> req = (Dictionary<string, object>)Json.Parse(File.ReadAllText(path, Encoding.UTF8));
            string edipi = Json.Str(req, "edipi", "").Trim();
            string reason = Json.Str(req, "reason", "").Trim();
            string by = Json.Str(req, "requested_by", null);
            CheckPerson(cfg, edipi, reason, by);
            string ou = Json.Str(req, "ou", "");
            if (!cfg.TargetOus.Contains(ou))
                throw new RequestException("requested OU is not in the configured list", edipi, reason, by);
            string outDir;
            try { outDir = Preflight.CheckOutputAllowed(cfg, Json.Str(req, "output_dir", "")); }
            catch (Exception e)
            {
                if (e is PreflightException || e is ArgumentException || e is NotSupportedException)
                    throw new RequestException(e.Message, edipi, reason, by);
                throw;
            }
            string owner = null;
            try { owner = File.GetAccessControl(path).GetOwner(typeof(NTAccount)).Value; } catch (Exception) { }
            ScanRequest r = new ScanRequest();
            r.FileOwner = owner;
            r.Ou = ou; r.OutputDir = outDir; r.Edipi = edipi; r.Reason = reason; r.RequestedBy = by;
            return r;
        }
    }
}
