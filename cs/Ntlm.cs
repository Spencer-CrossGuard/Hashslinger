using System;
using System.Text;

namespace Hashslinger
{
    /// <summary>NT hash = MD4(UTF-16LE(password)). .NET has no MD4, so it is implemented here.</summary>
    public static class Ntlm
    {
        public static readonly Hash128 Empty = Hash128.FromHex("31D6CFE0D16AE931B73C59D7E0C089C0");

        static readonly int[] R2 = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
        static readonly int[] R3 = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
        static readonly int[] S1 = { 3, 7, 11, 19 };
        static readonly int[] S2 = { 3, 5, 9, 13 };
        static readonly int[] S3 = { 3, 9, 11, 15 };

        public static Hash128 Hash(string password)
        {
            return Hash128.FromBytes(Md4(Encoding.Unicode.GetBytes(password)), 0);
        }

        static uint Rol(uint x, int n)
        {
            return (x << n) | (x >> (32 - n));
        }

        public static byte[] Md4(byte[] data)
        {
            int padLen = ((data.Length + 8) / 64 + 1) * 64;
            byte[] msg = new byte[padLen];
            Buffer.BlockCopy(data, 0, msg, 0, data.Length);
            msg[data.Length] = 0x80;
            ulong bits = (ulong)data.Length * 8UL;
            for (int i = 0; i < 8; i++) msg[padLen - 8 + i] = (byte)(bits >> (8 * i));

            uint a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
            uint[] x = new uint[16];
            unchecked
            {
                for (int off = 0; off < padLen; off += 64)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        int o = off + 4 * i;
                        x[i] = (uint)msg[o] | ((uint)msg[o + 1] << 8) | ((uint)msg[o + 2] << 16) | ((uint)msg[o + 3] << 24);
                    }
                    uint aa = a, bb = b, cc = c, dd = d;
                    for (int i = 0; i < 16; i++)
                    {
                        uint t = Rol(a + ((b & c) | (~b & d)) + x[i], S1[i % 4]);
                        a = d; d = c; c = b; b = t;
                    }
                    for (int i = 0; i < 16; i++)
                    {
                        uint t = Rol(a + ((b & c) | (b & d) | (c & d)) + x[R2[i]] + 0x5A827999u, S2[i % 4]);
                        a = d; d = c; c = b; b = t;
                    }
                    for (int i = 0; i < 16; i++)
                    {
                        uint t = Rol(a + (b ^ c ^ d) + x[R3[i]] + 0x6ED9EBA1u, S3[i % 4]);
                        a = d; d = c; c = b; b = t;
                    }
                    a += aa; b += bb; c += cc; d += dd;
                }
            }
            byte[] r = new byte[16];
            uint[] w = { a, b, c, d };
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    r[4 * i + j] = (byte)(w[i] >> (8 * j));
            return r;
        }
    }
}
