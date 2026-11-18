using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;

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
            return IterSource(path, fmt, null);
        }

        /// <summary>fmt 'table' = TSV/CSV-style file with a hash column and a password column (see IterTable).</summary>
        public static IEnumerable<Hash128> IterSource(string path, string fmt, Action<string> log)
        {
            if (fmt == "table") return IterTable(path, log);
            return IterLines(path, fmt);
        }

        static IEnumerable<Hash128> IterLines(string path, string fmt)
        {
            foreach (string line in ReadLinesSmart(path))
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

        /// <summary>Decode one line: UTF-8 when it is valid UTF-8, otherwise Windows-1252. Old lists such as rockyou hold
        /// Latin-1 bytes; reading those as UTF-8 would turn them into U+FFFD and hash the wrong password.</summary>
        static string DecodeLine(byte[] b, int start, int len, Encoding strict, Encoding legacy)
        {
            try { return strict.GetString(b, start, len); }
            catch (DecoderFallbackException) { return legacy.GetString(b, start, len); }
        }

        public static IEnumerable<string> ReadLinesSmart(string path)
        {
            Encoding strict = new UTF8Encoding(false, true);
            Encoding legacy = Encoding.GetEncoding(1252);
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
            {
                byte[] buf = new byte[1 << 20];
                byte[] line = new byte[4096];
                int len = 0, n;
                bool atStart = true;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++)
                    {
                        byte c = buf[i];
                        if (c != 10)
                        {
                            if (len == line.Length) Array.Resize(ref line, len * 2);
                            line[len++] = c;
                            continue;
                        }
                        int start = 0, end = len;
                        if (atStart && end >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF) start = 3;
                        atStart = false;
                        if (end > start && line[end - 1] == 13) end--;
                        len = 0;
                        yield return DecodeLine(line, start, end - start, strict, legacy);
                    }
                }
                if (len > 0)
                {
                    int start = 0, end = len;
                    if (atStart && end >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF) start = 3;
                    if (end > start && line[end - 1] == 13) end--;
                    yield return DecodeLine(line, start, end - start, strict, legacy);
                }
            }
        }

        /// <summary>Merge one source into the master in a single linear pass and swap it in atomically.
        /// Returns the new record count.</summary>
        public static long MergeSource(string master, string source, string tag, string fmt, int chunk)
        {
            byte bit = Sources.Bit(tag);
            if (fmt == null) fmt = Sources.DefaultFormat(tag);
            return MergeStream(master, IterSource(source, fmt, null), bit, chunk);
        }

        public static long MergeStream(string master, IEnumerable<Hash128> input, byte bit, int chunk)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(master));
            Directory.CreateDirectory(dir);
            string work = Path.Combine(dir, "merge-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            string tmp = master + ".new";
            long count = 0;
            try
            {
                using (SortedUniqueStream ns = new SortedUniqueStream(input, work, chunk))
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


        // ---------------------------------------------------------------- table files (hash column + password column)

        static bool IsHex32(string s)
        {
            Hash128 h;
            return s.Length == 32 && Hash128.TryParseHex(s, 0, out h);
        }

        /// <summary>Split one row into its hash and password pieces. Tab files use the first two columns (extra columns
        /// are ignored). For ':' and ',' files the password is the remainder (it may contain the delimiter).</summary>
        static bool Pieces(string line, char delim, bool hashFirst, out string hash, out string pw)
        {
            bool ok = PiecesRaw(line, delim, hashFirst, out hash, out pw);
            if (ok && delim == ',')
            {
                hash = hash.Trim().Trim('"');
                if (pw.Length >= 2 && pw[0] == '"' && pw[pw.Length - 1] == '"') pw = pw.Substring(1, pw.Length - 2).Replace("\"\"", "\"");
            }
            return ok;
        }

        static bool PiecesRaw(string line, char delim, bool hashFirst, out string hash, out string pw)
        {
            hash = null;
            pw = null;
            if (hashFirst)
            {
                int i = line.IndexOf(delim);
                if (i < 0) return false;
                hash = line.Substring(0, i);
                int j = delim == '\t' ? line.IndexOf('\t', i + 1) : -1;
                pw = j < 0 ? line.Substring(i + 1) : line.Substring(i + 1, j - i - 1);
                return true;
            }
            if (delim == '\t')
            {
                int i = line.IndexOf('\t');
                if (i < 0) return false;
                int j = line.IndexOf('\t', i + 1);
                pw = line.Substring(0, i);
                hash = j < 0 ? line.Substring(i + 1) : line.Substring(i + 1, j - i - 1);
                return true;
            }
            int k = line.LastIndexOf(delim);
            if (k < 0) return false;
            pw = line.Substring(0, k);
            hash = line.Substring(k + 1);
            return true;
        }

        /// <summary>Read a file with a hash column next to a password column (TSV, or ':' / ',' separated).
        /// Detects the layout from a sample: delimiter, which column holds the hash, and an optional header row.
        /// Then it TESTS the first rows: if NT(password) equals the hash column, the hash column is NT and is used
        /// directly. Otherwise the hash column is some other algorithm (it would never match AD), so the NT hash is
        /// computed from the password column instead. Passwords exist only transiently in memory and are never stored.
        /// A file with a single column is treated as a list of NT hashes.</summary>
        static IEnumerable<Hash128> IterTable(string path, Action<string> log)
        {
            string name = Path.GetFileName(path);
            List<string> sample = new List<string>();
            foreach (string sl in ReadLinesSmart(path))
            {
                if (sl.Length > 0) sample.Add(sl);
                if (sample.Count >= 2000) break;
            }
            if (sample.Count == 0)
            {
                if (log != null) log(name + ": empty file, skipped");
                yield break;
            }

            // try each delimiter present in the sample and keep the one that yields the most 32-hex hash columns
            char delim = '\0';
            int bestHits = 0;
            foreach (char cand in new[] { '\t', ':', ',' })
            {
                int hits = 0;
                foreach (string l in sample)
                {
                    string ch, cp;
                    if (Pieces(l, cand, true, out ch, out cp) && IsHex32(ch.Trim())) hits++;
                    else if (Pieces(l, cand, false, out ch, out cp) && IsHex32(ch.Trim())) hits++;
                }
                if (hits > bestHits) { bestHits = hits; delim = cand; }
            }
            if (delim == '\0' && (sample[0].IndexOf('\t') >= 0 || sample[0].IndexOf(':') >= 0 || sample[0].IndexOf(',') >= 0))
                delim = sample[0].IndexOf('\t') >= 0 ? '\t' : (sample[0].IndexOf(':') >= 0 ? ':' : ',');   // no hash column found: report below
            if (delim == '\0')
            {
                if (log != null) log(name + ": single column, treated as a list of NT hashes");
                foreach (Hash128 one in IterLines(path, "ntlm")) yield return one;
                yield break;
            }

            int first = 0, last = 0;
            foreach (string l in sample)
            {
                string h, p;
                if (Pieces(l, delim, true, out h, out p) && IsHex32(h.Trim())) first++;
                if (Pieces(l, delim, false, out h, out p) && IsHex32(h.Trim())) last++;
            }
            if (first == 0 && last == 0)
            {
                if (log != null) log(name + ": no 32-character hex hash column found, skipped");
                yield break;
            }
            bool hashFirst = first >= last;

            string h0, p0;
            bool hasHeader = !(Pieces(sample[0], delim, hashFirst, out h0, out p0) && IsHex32(h0.Trim()));

            int tested = 0, matched = 0;
            for (int i = hasHeader ? 1 : 0; i < sample.Count && tested < 1000; i++)
            {
                string h, p;
                if (!Pieces(sample[i], delim, hashFirst, out h, out p)) continue;
                h = h.Trim();
                Hash128 hh;
                if (h.Length != 32 || !Hash128.TryParseHex(h, 0, out hh)) continue;
                tested++;
                if (p.Length > 0 && Ntlm.Hash(p).Equals(hh)) matched++;
            }
            bool useHashColumn = tested > 0 && matched >= tested * 0.9;
            if (log != null)
            {
                string layout = (delim == '\t' ? "tab" : delim.ToString()) + " separated, hash in " + (hashFirst ? "first" : "last") + " column" + (hasHeader ? ", header row" : "");
                if (useHashColumn) log(name + ": " + layout + "; hash column verified as NT (" + matched + "/" + tested + " sample rows match); using the hash column");
                else log(name + ": " + layout + "; hash column is NOT NT (" + matched + "/" + tested + " sample rows match); computing NT from the password column and ignoring the hash column");
            }

            long used = 0, skipped = 0;
            {
                bool firstLine = true;
                foreach (string line in ReadLinesSmart(path))
                {
                    if (line.Length == 0) continue;
                    if (firstLine) { firstLine = false; if (hasHeader) continue; }
                    string h, p;
                    if (!Pieces(line, delim, hashFirst, out h, out p)) { skipped++; continue; }
                    if (useHashColumn)
                    {
                        h = h.Trim();
                        Hash128 hh;
                        if (h.Length == 32 && Hash128.TryParseHex(h, 0, out hh)) { used++; yield return hh; }
                        else skipped++;
                    }
                    else
                    {
                        if (p.Length == 0) { skipped++; continue; }
                        used++;
                        yield return Ntlm.Hash(p);
                    }
                }
            }
            if (log != null) log(name + ": " + used + " rows used, " + skipped + " skipped");
        }

        static string FormatFor(string tag, string file)
        {
            string ext = Path.GetExtension(file).ToLowerInvariant();
            if (ext == ".ntlm") return "ntlm";
            if (ext == ".tsv" || ext == ".csv") return "table";
            return Sources.DefaultFormat(tag);
        }

        /// <summary>Parse several source files at the same time (one producer per core, up to half the cores) into
        /// batches that the single sorter/merger consumes. Fewer than two files: plain sequential read.</summary>
        static IEnumerable<Hash128> ParallelSources(IList<string> files, string tag, Action<string> log)
        {
            if (files.Count == 1)
            {
                foreach (Hash128 h in IterSource(files[0], FormatFor(tag, files[0]), log)) yield return h;
                yield break;
            }
            BlockingCollection<Hash128[]> q = new BlockingCollection<Hash128[]>(64);
            Exception error = null;
            ParallelOptions opts = new ParallelOptions();
            opts.MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2);
            Task producer = Task.Factory.StartNew(delegate
            {
                try
                {
                    Parallel.ForEach(files, opts, delegate(string f)
                    {
                        Hash128[] batch = new Hash128[65536];
                        int n = 0;
                        foreach (Hash128 h in IterSource(f, FormatFor(tag, f), log))
                        {
                            batch[n++] = h;
                            if (n == batch.Length) { q.Add(batch); batch = new Hash128[65536]; n = 0; }
                        }
                        if (n > 0)
                        {
                            Hash128[] tail = new Hash128[n];
                            Array.Copy(batch, tail, n);
                            q.Add(tail);
                        }
                    });
                }
                catch (Exception ex) { error = ex; }
                finally { q.CompleteAdding(); }
            }, TaskCreationOptions.LongRunning);
            foreach (Hash128[] b in q.GetConsumingEnumerable())
                foreach (Hash128 h in b) yield return h;
            producer.Wait();
            if (error != null) throw new StoreException("reading the source files failed: " + error.Message);
        }

        /// <summary>Merge several files of one source tag into the master in ONE pass (one rewrite of the master,
        /// however many files).</summary>
        public static long MergeFiles(string master, string tag, IList<string> files, int chunk, Action<string> log)
        {
            return MergeStream(master, ParallelSources(files, tag, log), Sources.Bit(tag), chunk);
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
            if (File.Exists(manPath) && File.Exists(master))   // a manifest without its store would wrongly skip every file
                manifest = (Dictionary<string, object>)Json.Parse(File.ReadAllText(manPath, Encoding.UTF8));
            foreach (string tag in Sources.Tags)
            {
                string d = Path.Combine(staging, tag);
                if (!Directory.Exists(d)) continue;
                string[] files = Directory.GetFiles(d);
                Array.Sort(files, StringComparer.Ordinal);
                List<string> changed = new List<string>();
                Dictionary<string, string> prints = new Dictionary<string, string>();
                foreach (string f in files)
                {
                    string key = tag + "/" + Path.GetFileName(f);
                    string fp = FingerPrint(f);
                    object old;
                    if (manifest.TryGetValue(key, out old) && (old as string) == fp) continue;
                    changed.Add(f);
                    prints[f] = fp;
                }
                if (changed.Count == 0) continue;
                if (log != null)
                {
                    List<string> names = new List<string>();
                    foreach (string f in changed) names.Add(Path.GetFileName(f) + " (" + FormatFor(tag, f) + ")");
                    log("merging " + changed.Count + " file(s) into " + tag + " in one pass: " + string.Join(", ", names.ToArray()));
                }
                MergeFiles(master, tag, changed, 16000000, log);
                foreach (string f in changed)
                {
                    string key = tag + "/" + Path.GetFileName(f);
                    manifest[key] = prints[f];
                    merged.Add(key);
                }
                File.WriteAllText(manPath, Json.Write(manifest), Encoding.UTF8);
            }
            return merged;
        }
    }
}
