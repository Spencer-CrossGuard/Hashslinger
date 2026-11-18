using System;
using System.Collections.Generic;
using System.Text;

namespace Hashslinger
{
    public sealed class AccountRecord
    {
        public string Sam;
        public string Dn;
        public int Type; // 0 User, 1 Service, 2 Computer
        public bool HasNt;
        public Hash128 Nt;
        public bool Lm;
        public bool Rev;
    }

    /// <summary>Compact, zeroable storage for millions of accounts: hashes in one byte[], names in
    /// UTF-8 pages, per-account flag/reason bytes. No per-account objects are retained.</summary>
    public sealed class AccountTable
    {
        public static readonly string[] TypeNames = { "User", "Service", "Computer" };
        const int PageBits = 26; // 64 MB pages
        const int PageSize = 1 << PageBits;

        byte[] hashes = new byte[16 * 1024];
        byte[] flags = new byte[1024];
        byte[] reasons = new byte[1024];
        long[] metaPos = new long[1024];
        List<byte[]> pages = new List<byte[]>();
        int pagePos = PageSize; // forces first page allocation
        int count;

        public int Count { get { return count; } }

        static void Grow<T>(ref T[] arr, int needed)
        {
            if (needed <= arr.Length) return;
            long n = (long)arr.Length * 2;
            if (n < needed) n = needed;
            if (n > int.MaxValue) n = int.MaxValue;
            Array.Resize(ref arr, (int)n);
        }

        public int Add(AccountRecord a)
        {
            int i = count;
            Grow(ref flags, i + 1);
            Grow(ref reasons, i + 1);
            Grow(ref metaPos, i + 1);
            if (hashes.Length < (long)(i + 1) * 16)
            {
                long n = (long)hashes.Length * 2;
                if (n < (long)(i + 1) * 16) n = (long)(i + 1) * 16;
                if (n > int.MaxValue) n = int.MaxValue;
                byte[] bigger = new byte[(int)n];
                Buffer.BlockCopy(hashes, 0, bigger, 0, hashes.Length);
                Array.Clear(hashes, 0, hashes.Length);   // the old copy of every hash so far must not linger in memory
                hashes = bigger;
            }
            byte f = (byte)(a.Type << 4);
            if (a.HasNt) { f |= 1; a.Nt.CopyTo(hashes, i * 16); }
            if (a.Lm) f |= 2;
            if (a.Rev) f |= 4;
            flags[i] = f;
            byte[] sam = Encoding.UTF8.GetBytes(a.Sam ?? "");
            byte[] dn = Encoding.UTF8.GetBytes(a.Dn ?? "");
            int need = 8 + sam.Length + dn.Length;
            if (need > PageSize) throw new InvalidOperationException("Account record too large");
            if (pagePos + need > PageSize)
            {
                pages.Add(new byte[PageSize]);
                pagePos = 0;
            }
            byte[] page = pages[pages.Count - 1];
            metaPos[i] = ((long)(pages.Count - 1) << 32) | (uint)pagePos;
            WriteInt(page, pagePos, sam.Length); pagePos += 4;
            Buffer.BlockCopy(sam, 0, page, pagePos, sam.Length); pagePos += sam.Length;
            WriteInt(page, pagePos, dn.Length); pagePos += 4;
            Buffer.BlockCopy(dn, 0, page, pagePos, dn.Length); pagePos += dn.Length;
            count++;
            return i;
        }

        static void WriteInt(byte[] b, int o, int v)
        {
            b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
        }

        static int ReadInt(byte[] b, int o)
        {
            return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
        }

        public bool HasNt(int i) { return (flags[i] & 1) != 0; }
        public bool Lm(int i) { return (flags[i] & 2) != 0; }
        public bool Rev(int i) { return (flags[i] & 4) != 0; }
        public int Type(int i) { return flags[i] >> 4; }
        public Hash128 Hash(int i) { return Hash128.FromBytes(hashes, i * 16); }
        public byte Reasons(int i) { return reasons[i]; }
        public void AddReasons(int i, byte bits) { reasons[i] |= bits; }

        public void GetNames(int i, out string sam, out string dn)
        {
            long p = metaPos[i];
            byte[] page = pages[(int)(p >> 32)];
            int o = (int)(p & 0xFFFFFFFFL);
            int n = ReadInt(page, o); o += 4;
            sam = Encoding.UTF8.GetString(page, o, n); o += n;
            n = ReadInt(page, o); o += 4;
            dn = Encoding.UTF8.GetString(page, o, n);
        }

        /// <summary>Zero every buffer and release it. Returns true when the hash buffer reads back all zero.</summary>
        public bool Wipe()
        {
            Array.Clear(hashes, 0, hashes.Length);
            bool clean = true;
            for (int i = 0; i < hashes.Length; i++)
                if (hashes[i] != 0) { clean = false; break; }
            foreach (byte[] p in pages) Array.Clear(p, 0, p.Length);
            Array.Clear(flags, 0, flags.Length);
            Array.Clear(reasons, 0, reasons.Length);
            Array.Clear(metaPos, 0, metaPos.Length);
            pages.Clear();
            hashes = new byte[0];
            flags = new byte[0];
            reasons = new byte[0];
            metaPos = new long[0];
            count = 0;
            return clean;
        }
    }
}
