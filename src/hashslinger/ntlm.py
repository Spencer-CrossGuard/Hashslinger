"""NT hash (MD4 over UTF-16LE) with a pure-Python fallback.

OpenSSL 3 builds often drop MD4, so we try hashlib first and fall back.
"""
from __future__ import annotations

import hashlib

EMPTY_NT = bytes.fromhex("31D6CFE0D16AE931B73C59D7E0C089C0")

_M = 0xFFFFFFFF


def _rol(x: int, n: int) -> int:
    x &= _M
    return ((x << n) | (x >> (32 - n))) & _M


def _md4_pure(data: bytes) -> bytes:
    msg = bytearray(data)
    bitlen = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bitlen.to_bytes(8, "little")
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    r2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    r3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i : off + 4 * i + 4], "little") for i in range(16)]
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            s = (3, 7, 11, 19)[i % 4]
            a = _rol(a + ((b & c) | (~b & d)) + x[i], s)
            a, b, c, d = d, a, b, c
        for i in range(16):
            s = (3, 5, 9, 13)[i % 4]
            a = _rol(a + ((b & c) | (b & d) | (c & d)) + x[r2[i]] + 0x5A827999, s)
            a, b, c, d = d, a, b, c
        for i in range(16):
            s = (3, 9, 11, 15)[i % 4]
            a = _rol(a + (b ^ c ^ d) + x[r3[i]] + 0x6ED9EBA1, s)
            a, b, c, d = d, a, b, c
        a, b, c, d = (a + aa) & _M, (b + bb) & _M, (c + cc) & _M, (d + dd) & _M
    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


try:
    hashlib.new("md4")

    def _md4(data: bytes) -> bytes:
        return hashlib.new("md4", data).digest()

except ValueError:
    _md4 = _md4_pure


def nt_hash(password: str) -> bytes:
    """Raw 16-byte NT hash of a password."""
    return _md4(password.encode("utf-16-le"))
