using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Hashslinger
{
    public static class Sources
    {
        public const byte HIBP = 1;
        public const byte Rockyou = 2;
        public const byte Custom = 4;

        public static readonly string[] Tags = { "HIBP", "rockyou", "custom" };

        public static byte Bit(string tag)
        {
            if (tag == "HIBP") return HIBP;
            if (tag == "rockyou") return Rockyou;
            if (tag == "custom") return Custom;
            throw new StoreException("Unknown source tag " + tag);
        }

        public static string DefaultFormat(string tag)
        {
            return tag == "HIBP" ? "ntlm" : "plaintext";
        }
    }

    interface IHashStream
    {
        bool Next(out Hash128 h);
    }

    /// <summary>Reads 16-byte records sequentially from a run file.</summary>
    sealed class RunReader : IDisposable
    {
        FileStream fs;
        byte[] buf = new byte[16 * 65536];
        int pos, len;
        public Hash128 Current;

        public RunReader(string path)
        {
            fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
        }

        public bool Advance()
        {
            if (pos >= len)
            {
                int got = 0;
                while (got < buf.Length)
                {
                    int n = fs.Read(buf, got, buf.Length - got);
                    if (n <= 0) break;
                    got += n;
                }
                len = got;
                pos = 0;
                if (len == 0) return false;
            }
            Current = Hash128.FromBytes(buf, pos);
            pos += 16;
            return true;
        }

        public void Dispose()
        {
            fs.Dispose();
        }
    }

    /// <summary>Consumes any hash sequence, sorts it in memory-bounded chunks (spilling runs to disk),
    /// and yields the globally sorted, de-duplicated sequence.</summary>
    sealed class SortedUniqueStream : IHashStream, IDisposable
    {
        readonly List<string> runFiles = new List<string>();
        readonly List<RunReader> readers = new List<RunReader>();
        int[] heap;
        int heapSize;
        Hash128[] mem; // used when everything fit in a single chunk
        int memPos, memLen;
        bool havePrev;
        Hash128 prev;

        public SortedUniqueStream(IEnumerable<Hash128> input, string workDir, int chunk)
        {
            Hash128[] buf = new Hash128[Math.Min(chunk, 65536)];
            int n = 0;
            foreach (Hash128 h in input)
            {
                if (n == buf.Length)
                {
                    if (buf.Length < chunk)
                    {
                        Array.Resize(ref buf, Math.Min(buf.Length * 2, chunk));
                    }
                    else
                    {
                        Spill(buf, n, workDir);
                        n = 0;
                    }
                }
                buf[n++] = h;
            }
            if (runFiles.Count == 0)
            {
                Array.Sort(buf, 0, n);
                mem = buf;
                memLen = n;
                return;
            }
            if (n > 0) Spill(buf, n, workDir);
            foreach (string f in runFiles)
            {
                RunReader r = new RunReader(f);
                if (r.Advance()) readers.Add(r); else r.Dispose();
            }
            heap = new int[readers.Count];
            for (int i = 0; i < readers.Count; i++) heap[heapSize++] = i;
            for (int i = heapSize / 2 - 1; i >= 0; i--) SiftDown(i);
        }

        void Spill(Hash128[] buf, int n, string workDir)
        {
            Array.Sort(buf, 0, n);
            string p = Path.Combine(workDir, "run" + runFiles.Count.ToString("D5", CultureInfo.InvariantCulture) + ".bin");
            using (FileStream fs = new FileStream(p, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
            {
                byte[] outBuf = new byte[16 * 65536];
                int o = 0;
                Hash128 last = new Hash128();
                bool have = false;
                for (int i = 0; i < n; i++)
                {
                    if (have && buf[i].Equals(last)) continue;
                    buf[i].CopyTo(outBuf, o);
                    o += 16;
                    last = buf[i];
                    have = true;
                    if (o == outBuf.Length) { fs.Write(outBuf, 0, o); o = 0; }
                }
                if (o > 0) fs.Write(outBuf, 0, o);
            }
            runFiles.Add(p);
        }

        bool Less(int a, int b)
        {
            return readers[heap[a]].Current.CompareTo(readers[heap[b]].Current) < 0;
        }

        void SiftDown(int i)
        {
            while (true)
            {
                int l = 2 * i + 1, r = l + 1, m = i;
                if (l < heapSize && Less(l, m)) m = l;
                if (r < heapSize && Less(r, m)) m = r;
                if (m == i) return;
                int t = heap[i]; heap[i] = heap[m]; heap[m] = t;
                i = m;
            }
        }

        bool NextRaw(out Hash128 h)
        {
            if (mem != null)
            {
                if (memPos < memLen) { h = mem[memPos++]; return true; }
                h = new Hash128();
                return false;
            }
            if (heapSize == 0) { h = new Hash128(); return false; }
            RunReader top = readers[heap[0]];
            h = top.Current;
            if (!top.Advance())
            {
                heap[0] = heap[--heapSize];
            }
            if (heapSize > 0) SiftDown(0);
            return true;
        }

        public bool Next(out Hash128 h)
        {
            while (NextRaw(out h))
            {
                if (havePrev && h.Equals(prev)) continue;
                prev = h;
                havePrev = true;
                return true;
            }
            return false;
        }

        public void Dispose()
        {
            foreach (RunReader r in readers) r.Dispose();
            readers.Clear();
        }
    }

    sealed class MasterReader : IDisposable
    {
        FileStream fs;
        byte[] buf = new byte[HashStore.Record * 65536];
        int pos, len;

        public MasterReader(string path)
        {
            if (File.Exists(path))
                fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
        }

        public bool Next(out Hash128 h, out byte mask)
        {
            h = new Hash128();
            mask = 0;
            if (fs == null) return false;
            if (pos >= len)
            {
                int got = 0;
                while (got < buf.Length)
                {
                    int n = fs.Read(buf, got, buf.Length - got);
                    if (n <= 0) break;
                    got += n;
                }
                if (got % HashStore.Record != 0) throw new StoreException("Truncated master file");
                len = got;
                pos = 0;
                if (len == 0) return false;
            }
            h = Hash128.FromBytes(buf, pos);
            mask = buf[pos + 16];
            pos += HashStore.Record;
            return true;
        }

        public void Dispose()
        {
            if (fs != null) fs.Dispose();
        }
    }

    public static class StoreMerge
    {
        /// <summary>Yield raw hashes from a source file. fmt 'ntlm': 32-hex lines, optional ":count" (HIBP).
        /// fmt 'plaintext': one candidate password per line, hashed here.</summary>
        public static IEnumerable<Hash128> IterSource(string path, string fmt)
        {
            using (StreamReader sr = new StreamReader(path, new UTF8Encoding(false), true, 1 << 20))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (line.Length == 0) continue;
                    if (fmt == "ntlm")
                    {
                        if (line.Length != 32 && !(line.Length > 32 && line[32] == ':')) continue;
                        Hash128 h;
                        if (Hash128.TryParseHex(line, 0, out h)) yield return h;
                    }
                    else if (fmt == "plaintext")
                    {
                        yield return Ntlm.Hash(line);
                    }
                    else
                    {
                        throw new StoreException("Unknown source format " + fmt);
                    }
                }
            }
        }

        /// <summary>Merge one source into the master in a single linear pass and swap it in atomically.
        /// Returns the new record count.</summary>
        public static long MergeSource(string master, string source, string tag, string fmt, int chunk)
        {
            byte bit = Sources.Bit(tag);
            if (fmt == null) fmt = Sources.DefaultFormat(tag);
            string dir = Path.GetDirectoryName(Path.GetFullPath(master));
            Directory.CreateDirectory(dir);
            string work = Path.Combine(dir, "merge-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            string tmp = master + ".new";
            long count = 0;
            try
            {
                using (SortedUniqueStream ns = new SortedUniqueStream(IterSource(source, fmt), work, chunk))
                using (MasterReader mr = new MasterReader(master))
                using (FileStream outFs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                {
                    byte[] ob = new byte[HashStore.Record * 65536];
                    int o = 0;
                    Hash128 mh, nh;
                    byte mm;
                    bool haveM = mr.Next(out mh, out mm);
                    bool haveN = ns.Next(out nh);
                    while (haveM || haveN)
                    {
                        Hash128 w;
                        byte wm;
                        if (haveM && (!haveN || mh.CompareTo(nh) < 0))
                        {
                            w = mh; wm = mm;
                            haveM = mr.Next(out mh, out mm);
                        }
                        else if (haveN && (!haveM || nh.CompareTo(mh) < 0))
                        {
                            w = nh; wm = bit;
                            haveN = ns.Next(out nh);
                        }
                        else
                        {
                            w = mh; wm = (byte)(mm | bit);
                            haveM = mr.Next(out mh, out mm);
                            haveN = ns.Next(out nh);
                        }
                        w.CopyTo(ob, o);
                        ob[o + 16] = wm;
                        o += HashStore.Record;
                        count++;
                        if (o == ob.Length) { outFs.Write(ob, 0, o); o = 0; }
                    }
                    if (o > 0) outFs.Write(ob, 0, o);
                    outFs.Flush(true);
                }
                if (File.Exists(master)) File.Replace(tmp, master, null);
                else File.Move(tmp, master);
            }
            finally
            {
                Wipe.SecureDeleteDir(work);
                if (File.Exists(tmp)) File.Delete(tmp);
            }
            return count;
        }

        // ------------------------------------------------------------ staging pipeline

        static string FingerPrint(string p)
        {
            FileInfo fi = new FileInfo(p);
            long secs = (long)(fi.LastWriteTimeUtc - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            return fi.Length.ToString(CultureInfo.InvariantCulture) + ":" + secs.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>Merge any new or changed file under staging/HIBP|rockyou|custom into the master.
        /// A manifest skips unchanged files, so an edited custom list takes effect on the next run.</summary>
        public static List<string> ProcessStaging(string master, string staging, Action<string> log)
        {
            List<string> merged = new List<string>();
            string manPath = master + ".manifest.json";
            Dictionary<string, object> manifest = new Dictionary<string, object>();
            if (File.Exists(manPath))
                manifest = (Dictionary<string, object>)Json.Parse(File.ReadAllText(manPath, Encoding.UTF8));
            foreach (string tag in Sources.Tags)
            {
                string d = Path.Combine(staging, tag);
                if (!Directory.Exists(d)) continue;
                string[] files = Directory.GetFiles(d);
                Array.Sort(files, StringComparer.Ordinal);
                foreach (string f in files)
                {
                    string key = tag + "/" + Path.GetFileName(f);
                    string fp = FingerPrint(f);
                    object old;
                    if (manifest.TryGetValue(key, out old) && (old as string) == fp) continue;
                    string fmt = f.EndsWith(".ntlm", StringComparison.OrdinalIgnoreCase) ? "ntlm" : Sources.DefaultFormat(tag);
                    if (log != null) log("merging " + key + " (" + fmt + ")");
                    MergeSource(master, f, tag, fmt, 16000000);
                    manifest[key] = fp;
                    File.WriteAllText(manPath, Json.Write(manifest), Encoding.UTF8);
                    merged.Add(key);
                }
            }
            return merged;
        }
    }
}
