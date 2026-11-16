using System;
using System.IO;
using System.Security.Cryptography;

namespace Hashslinger
{
    /// <summary>Best-effort secure deletion. Volume encryption is the real control (SSD / CoW caveat).</summary>
    public static class Wipe
    {
        public static bool SecureDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    long size = new FileInfo(path).Length;
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
                    {
                        byte[] zeros = new byte[1 << 20];
                        byte[] rnd = new byte[1 << 20];
                        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                        {
                            for (int pass = 0; pass < 2; pass++)
                            {
                                fs.Position = 0;
                                long left = size;
                                while (left > 0)
                                {
                                    int n = (int)Math.Min(left, (long)zeros.Length);
                                    if (pass == 0) fs.Write(zeros, 0, n);
                                    else { rng.GetBytes(rnd); fs.Write(rnd, 0, n); }
                                    left -= n;
                                }
                                fs.Flush(true);
                            }
                        }
                    }
                    File.Delete(path);
                }
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            return !File.Exists(path);
        }

        public static bool SecureDeleteDir(string dir)
        {
            if (!Directory.Exists(dir)) return true;
            bool ok = true;
            foreach (string f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                ok &= SecureDelete(f);
            try { Directory.Delete(dir, true); }
            catch (IOException) { ok = false; }
            catch (UnauthorizedAccessException) { ok = false; }
            return ok && !Directory.Exists(dir);
        }
    }
}
