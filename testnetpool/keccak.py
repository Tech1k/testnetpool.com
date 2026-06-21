# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Keccak-256 (the original, pre-NIST padding), pure stdlib.

Monero (and Ethereum) use original Keccak with 0x01 domain padding, which differs
from FIPS-202 SHA3-256 (0x06 padding) that ``hashlib`` provides. This is only used
for Monero address checksums and block-id hashing - never per-share (RandomX, the
share PoW, is verified by monerod, not here), so pure Python is fast enough.

Verified against the well-known empty / "abc" / "fox" Keccak-256 vectors in
tests/monero.py.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1

# Iota round constants and rho rotation offsets (lane index = x + 5*y).
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
        41, 45, 15, 21, 8, 18, 2, 61, 56, 14]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a: list) -> None:
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            a[i] ^= d[i % 5]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x + 5 * y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
        a[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest (32 bytes) of ``data``."""
    rate = 136  # (1600 - 512) / 8
    msg = bytearray(data) + b"\x01"
    while len(msg) % rate != 0:
        msg.append(0)
    msg[-1] ^= 0x80
    a = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        _keccak_f(a)
    return b"".join(a[i].to_bytes(8, "little") for i in range(25))[:32]
