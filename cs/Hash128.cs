using System;

namespace Hashslinger
{
    /// <summary>A 16-byte hash held as two big-endian ulongs, so numeric order equals byte order.</summary>
    public struct Hash128 : IComparable<Hash128>, IEquatable<Hash128>
    {
        public ulong Hi;
        public ulong Lo;

        public Hash128(ulong hi, ulong lo)
        {
            Hi = hi;
            Lo = lo;
        }

        public static Hash128 FromBytes(byte[] b, int off)
        {
            ulong hi = 0, lo = 0;
            for (int i = 0; i < 8; i++)
            {
                hi = (hi << 8) | b[off + i];
                lo = (lo << 8) | b[off + 8 + i];
            }
            return new Hash128(hi, lo);
        }

        public void CopyTo(byte[] b, int off)
        {
            for (int i = 0; i < 8; i++)
            {
                b[off + i] = (byte)(Hi >> (56 - 8 * i));
                b[off + 8 + i] = (byte)(Lo >> (56 - 8 * i));
            }
        }

        static int Nibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        /// <summary>Parse 32 hex chars starting at s[start].</summary>
        public static bool TryParseHex(string s, int start, out Hash128 h)
        {
            h = new Hash128();
            if (start < 0 || start + 32 > s.Length) return false;
            ulong hi = 0, lo = 0;
            for (int i = 0; i < 16; i++)
            {
                int n = Nibble(s[start + i]);
                if (n < 0) return false;
                hi = (hi << 4) | (uint)n;
            }
            for (int i = 16; i < 32; i++)
            {
                int n = Nibble(s[start + i]);
                if (n < 0) return false;
                lo = (lo << 4) | (uint)n;
            }
            h = new Hash128(hi, lo);
            return true;
        }

        public static Hash128 FromHex(string s)
        {
            Hash128 h;
            if (s.Length != 32 || !TryParseHex(s, 0, out h)) throw new FormatException("Bad hash hex");
            return h;
        }

        public int CompareTo(Hash128 o)
        {
            if (Hi != o.Hi) return Hi < o.Hi ? -1 : 1;
            if (Lo != o.Lo) return Lo < o.Lo ? -1 : 1;
            return 0;
        }

        public bool Equals(Hash128 o)
        {
            return Hi == o.Hi && Lo == o.Lo;
        }

        public override bool Equals(object obj)
        {
            return obj is Hash128 && Equals((Hash128)obj);
        }

        public override int GetHashCode()
        {
            unchecked { return (int)(Lo ^ (Lo >> 32) ^ Hi ^ (Hi >> 32)); }
        }
    }

    /// <summary>Hash plus the account index it came from; sortable for duplicate detection and batched lookups.</summary>
    public struct HashIdx : IComparable<HashIdx>
    {
        public Hash128 H;
        public int Idx;

        public int CompareTo(HashIdx o)
        {
            int c = H.CompareTo(o.H);
            if (c != 0) return c;
            return Idx < o.Idx ? -1 : (Idx > o.Idx ? 1 : 0);
        }
    }
}
