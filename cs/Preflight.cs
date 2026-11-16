using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace Hashslinger
{
    public class PreflightException : Exception
    {
        public PreflightException(string m) : base(m) { }
    }

    public static class Preflight
    {
        static string Norm(string p)
        {
            return Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        /// <summary>Output must sit under an allowed root so a request cannot redirect it elsewhere.</summary>
        public static string CheckOutputAllowed(Config cfg, string outDir)
        {
            string o = Norm(outDir);
            List<string> roots = cfg.AllowedOutputRoots.Count > 0 ? cfg.AllowedOutputRoots : new List<string> { cfg.OutputPath };
            foreach (string r in roots)
            {
                string rr = Norm(r);
                if (string.Equals(o, rr, StringComparison.OrdinalIgnoreCase) ||
                    o.StartsWith(rr + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    return o;
            }
            throw new PreflightException("output folder " + o + " is outside the allowed roots");
        }

        static bool BitLockerProtected(string path)
        {
            string drive = Path.GetPathRoot(Path.GetFullPath(path)).Substring(0, 1);
            ProcessStartInfo psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"(Get-BitLockerVolume -MountPoint '" + drive + ":').ProtectionStatus -eq 'On'\"");
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            using (Process p = Process.Start(psi))
            {
                string o = p.StandardOutput.ReadToEnd().Trim();
                p.WaitForExit();
                return string.Equals(o, "True", StringComparison.OrdinalIgnoreCase);
            }
        }

        public static void Run(Config cfg, string outDir)
        {
            CheckOutputAllowed(cfg, outDir);
            if (!cfg.RequireEncryptedVolume) return;
            string[][] checks =
            {
                new[] { "hash store", cfg.HashStorePath },
                new[] { "staging", cfg.StagingPath },
                new[] { "output", outDir }
            };
            foreach (string[] c in checks)
                if (!BitLockerProtected(c[1]))
                    throw new PreflightException(c[0] + " path " + c[1] + " is not on a BitLocker-protected volume");
        }
    }
}
