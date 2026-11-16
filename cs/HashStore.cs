using System;
using System.IO;
using System.IO.MemoryMappedFiles;

namespace Hashslinger
{
    public class StoreException : Exception
    {
        public StoreException(string m) : base(m) { }
    }

    /// <summary>Read-only, memory-mapped view of the sorted 17-byte-record master file
    /// (16-byte NT hash + 1-byte source bitmask). Binary search plus a 2-byte prefix index.</summary>
    public sealed unsafe class HashStore : IDisposable
    {
        public const int Record = 17;
        FileStream fs;
        MemoryMappedFile mmf;
        MemoryMappedViewAccessor view;
        byte* basePtr;
        readonly long count;
        long[] prefix;

        public long Count { get { return count; } }

        public HashStore(string path, bool buildIndex)
        {
            long size = new FileInfo(path).Length;
            if (size % Record != 0) throw new StoreException(path + ": size is not a multiple of 17");
            count = size / Record;
            if (count == 0) return;
            fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            mmf = MemoryMappedFile.CreateFromFile(fs, null, 0, MemoryMappedFileAccess.Read,
                null, HandleInheritability.None, false);
            view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            byte* p = null;
            view.SafeMemoryMappedViewHandle.AcquirePointer(ref p);
            basePtr = p + view.PointerOffset;
            if (buildIndex) BuildPrefixIndex();
        }

        public void Dispose()
        {
            if (view != null)
            {
                view.SafeMemoryMappedViewHandle.ReleasePointer();
                view.Dispose();
                view = null;
            }
            if (mmf != null) { mmf.Dispose(); mmf = null; }
            if (fs != null) { fs.Dispose(); fs = null; }
            basePtr = null;
        }

        static ulong BE(byte* p)
        {
            return ((ulong)p[0] << 56) | ((ulong)p[1] << 48) | ((ulong)p[2] << 40) | ((ulong)p[3] << 32) |
                   ((ulong)p[4] << 24) | ((ulong)p[5] << 16) | ((ulong)p[6] << 8) | (ulong)p[7];
        }

        /// <summary>First record index in [lo,hi) whose hash is &gt;= key.</summary>
        long LowerBound(ulong khi, ulong klo, long lo, long hi)
        {
            while (lo < hi)
            {
                long mid = lo + ((hi - lo) >> 1);
                byte* r = basePtr + mid * Record;
                ulong rhi = BE(r);
                bool less = rhi < khi || (rhi == khi && BE(r + 8) < klo);
                if (less) lo = mid + 1; else hi = mid;
            }
            return lo;
        }

        void BuildPrefixIndex()
        {
            prefix = new long[65537];
            long lo = 0;
            for (int p = 0; p < 65536; p++)
            {
                lo = LowerBound((ulong)p << 48, 0UL, lo, count);
                prefix[p] = lo;
            }
            prefix[65536] = count;
        }

        /// <summary>Source bitmask for the hash, 0 when absent.</summary>
        public byte Lookup(Hash128 h)
        {
            if (count == 0) return 0;
            long lo = 0, hi = count;
            if (prefix != null)
            {
                int p = (int)(h.Hi >> 48);
                lo = prefix[p];
                hi = prefix[p + 1];
            }
            long i = LowerBound(h.Hi, h.Lo, lo, hi);
            if (i < count)
            {
                byte* r = basePtr + i * Record;
                if (BE(r) == h.Hi && BE(r + 8) == h.Lo) return r[16];
            }
            return 0;
        }
    }
}
