# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""A tiny, dependency-free QR Code (Model 2) encoder - byte mode, error-correction
level M, versions 1-13 (enough for any coin address or BIP21 URI). Pure stdlib, in
the same hand-rolled spirit as the rest of the project, so the donate page can render
a QR for whatever address is configured instead of shipping baked-in images.

Verified module-for-module against the reference `qrcode` library across every
version/mask in tests/qr.py - it is NOT a dependency, only the test oracle.

Reference: ISO/IEC 18004. Returns a square matrix of 0/1 (no quiet zone); the caller
adds the quiet zone + renders.
"""

from __future__ import annotations

import functools

# --- GF(256) arithmetic for Reed-Solomon (primitive polynomial 0x11d) ----------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11d
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_generator(n: int) -> list[int]:
    g = [1]
    for i in range(n):
        ng = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            ng[j] ^= c
            ng[j + 1] ^= _gf_mul(c, _EXP[i])
        g = ng
    return g


def _rs_encode(data: list[int], n: int) -> list[int]:
    gen = _rs_generator(n)
    rem = [0] * n
    for d in data:
        factor = d ^ rem[0]
        rem = rem[1:] + [0]
        if factor:
            for i in range(n):
                rem[i] ^= _gf_mul(gen[i + 1], factor)
    return rem


# --- capacity / block structure, error-correction level M, versions 1-13 -------
# (data_codewords_total, ec_per_block, [(num_blocks, data_per_block), ...])
_ECC_M = {
    1: (16, 10, [(1, 16)]),
    2: (28, 16, [(1, 28)]),
    3: (44, 26, [(1, 44)]),
    4: (64, 18, [(2, 32)]),
    5: (86, 24, [(2, 43)]),
    6: (108, 16, [(4, 27)]),
    7: (124, 18, [(4, 31)]),
    8: (154, 22, [(2, 38), (2, 39)]),
    9: (182, 22, [(3, 36), (2, 37)]),
    10: (216, 26, [(4, 43), (1, 44)]),
    11: (254, 30, [(1, 50), (4, 51)]),
    12: (290, 22, [(6, 36), (2, 37)]),
    13: (334, 22, [(8, 37), (1, 38)]),
}

# Alignment-pattern centre coordinates per version (empty for version 1).
_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
    11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62],
}


def _format_bits(mask: int) -> list[int]:
    # ECC level M = 0b00; 5 data bits = (ecc<<3)|mask, BCH(15,5), XOR 0x5412.
    data = (0b00 << 3) | mask
    rem = data << 10
    g = 0b10100110111
    for i in range(4, -1, -1):
        if rem & (1 << (i + 10)):
            rem ^= g << i
    bits = ((data << 10) | rem) ^ 0b101010000010010
    return [(bits >> (14 - i)) & 1 for i in range(15)]


def _version_bits(version: int) -> list[int]:
    rem = version << 12
    g = 0b1111100100101
    for i in range(5, -1, -1):
        if rem & (1 << (i + 12)):
            rem ^= g << i
    bits = (version << 12) | rem
    return [(bits >> (17 - i)) & 1 for i in range(18)]


def _bitstream(data: bytes, version: int, total_data: int) -> list[int]:
    bits: list[int] = []
    bits += [0, 1, 0, 0]                          # byte mode indicator
    count_len = 8 if version <= 9 else 16          # char-count bits
    for i in range(count_len - 1, -1, -1):
        bits.append((len(data) >> i) & 1)
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    cap = total_data * 8
    bits += [0] * min(4, cap - len(bits))          # terminator
    while len(bits) % 8:                            # pad to a byte boundary
        bits.append(0)
    pad = [0xEC, 0x11]
    i = 0
    while len(bits) < cap:                          # pad codewords
        for b in range(7, -1, -1):
            bits.append((pad[i % 2] >> b) & 1)
        i += 1
    return bits


def _codewords(data: bytes, version: int):
    total_data, ec_per_block, groups = _ECC_M[version]
    bits = _bitstream(data, version, total_data)
    allcw = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
    blocks, pos = [], 0
    for num, dpb in groups:
        for _ in range(num):
            d = allcw[pos:pos + dpb]
            pos += dpb
            blocks.append((d, _rs_encode(d, ec_per_block)))
    # Interleave data codewords, then ec codewords.
    out: list[int] = []
    maxd = max(len(d) for d, _ in blocks)
    for i in range(maxd):
        for d, _ in blocks:
            if i < len(d):
                out.append(d[i])
    for i in range(ec_per_block):
        for _, e in blocks:
            out.append(e[i])
    return out


def _new_matrix(size: int):
    return [[None] * size for _ in range(size)]


def _place_function_patterns(m, version: int):
    size = len(m)

    def finder(r, c):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if 0 <= rr < size and 0 <= cc < size:
                    inring = dr in (0, 6) or dc in (0, 6)
                    incore = 2 <= dr <= 4 and 2 <= dc <= 4
                    edge = dr in (-1, 7) or dc in (-1, 7)
                    m[rr][cc] = 0 if edge else (1 if (inring or incore) else 0)
    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    # Timing patterns.
    for i in range(8, size - 8):
        v = (i + 1) % 2
        if m[6][i] is None:
            m[6][i] = v
        if m[i][6] is None:
            m[i][6] = v
    # Alignment patterns.
    centers = _ALIGN[version]
    for r in centers:
        for c in centers:
            if (r, c) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    ring = dr in (-2, 2) or dc in (-2, 2)
                    m[r + dr][c + dc] = 1 if (ring or (dr == 0 and dc == 0)) else 0
    m[size - 8][8] = 1  # dark module


def _reserved(m, version: int):
    """A boolean grid of cells that hold function patterns / format / version info
    (so data placement and masking skip them)."""
    size = len(m)
    res = [[False] * size for _ in range(size)]
    for r in range(size):
        for c in range(size):
            if m[r][c] is not None:
                res[r][c] = True
    for i in range(9):                       # format-info areas
        if i != 6:
            res[8][i] = res[i][8] = True
    res[8][8] = True
    for i in range(8):
        res[8][size - 1 - i] = True
        res[size - 1 - i][8] = True
    if version >= 7:                          # version-info areas
        for i in range(6):
            for j in range(3):
                res[size - 11 + j][i] = True
                res[i][size - 11 + j] = True
    return res


def _place_data(m, res, codewords):
    size = len(m)
    bits = []
    for cw in codewords:
        for b in range(7, -1, -1):
            bits.append((cw >> b) & 1)
    idx, col = 0, size - 1
    up = True
    while col > 0:
        if col == 6:                          # skip the vertical timing column
            col -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for c in (col, col - 1):
                if not res[r][c]:
                    m[r][c] = bits[idx] if idx < len(bits) else 0
                    idx += 1
        up = not up
        col -= 2


_MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _apply_mask(m, res, mask: int):
    size = len(m)
    out = [row[:] for row in m]
    fn = _MASKS[mask]
    for r in range(size):
        for c in range(size):
            if not res[r][c] and fn(r, c):
                out[r][c] ^= 1
    return out


def _place_format(m, mask: int):
    size = len(m)
    bits = _format_bits(mask)
    coords1 = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
               (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    coords2 = [(size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8),
               (size - 5, 8), (size - 6, 8), (size - 7, 8),
               (8, size - 8), (8, size - 7), (8, size - 6), (8, size - 5),
               (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1)]
    for b, (r, c) in zip(bits, coords1):
        m[r][c] = b
    for b, (r, c) in zip(bits, coords2):
        m[r][c] = b


def _place_version(m, version: int):
    if version < 7:
        return
    size = len(m)
    bits = _version_bits(version)
    for i in range(6):
        for j in range(3):
            b = bits[17 - (i * 3 + j)]
            m[size - 11 + j][i] = b
            m[i][size - 11 + j] = b


def _penalty(m) -> int:
    size = len(m)
    score = 0
    for line in list(m) + [list(col) for col in zip(*m)]:    # rule 1
        run, prev = 1, line[0]
        for v in line[1:]:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run, prev = 1, v
        if run >= 5:
            score += 3 + (run - 5)
    for r in range(size - 1):                                 # rule 2
        for c in range(size - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for line in list(m) + [list(col) for col in zip(*m)]:    # rule 3
        for i in range(size - 10):
            seg = line[i:i + 11]
            if seg == pat1 or seg == pat2:
                score += 40
    dark = sum(sum(row) for row in m)                         # rule 4
    pct = dark * 100.0 / (size * size)
    score += int(abs(pct - 50) / 5) * 10
    return score


def _overhead(n: int, version: int) -> int:
    """Data codewords needed to hold ``n`` bytes in byte mode at this version."""
    count_len = 8 if version <= 9 else 16
    return (4 + count_len + n * 8 + 7) // 8


def _pick_version(n: int) -> int:
    for v in sorted(_ECC_M):
        if _ECC_M[v][0] >= _overhead(n, v):
            return v
    raise ValueError("data too long for a version-13 QR")


def _prep(data: bytes, version: int):
    base = _new_matrix(version * 4 + 17)
    _place_function_patterns(base, version)
    res = _reserved(base, version)
    _place_data(base, res, _codewords(data, version))
    return base, res


def _compose(base, res, version: int, mask: int):
    cand = _apply_mask(base, res, mask)
    _place_format(cand, mask)
    _place_version(cand, version)
    return cand


def _forced(data: bytes, version: int, mask: int):
    """One specific version+mask (test hook for the reference cross-check)."""
    base, res = _prep(data, version)
    return _compose(base, res, version, mask)


@functools.lru_cache(maxsize=64)
def matrix(data: bytes) -> list[list[int]]:
    """Encode ``data`` (raw bytes) as a QR matrix of 0/1 rows (no quiet zone).
    Smallest fitting version, ECC level M, lowest-penalty mask. Cached (read-only)."""
    version = _pick_version(len(data))
    base, res = _prep(data, version)
    best, best_score = None, None
    for mask in range(8):
        cand = _compose(base, res, version, mask)
        s = _penalty(cand)
        if best_score is None or s < best_score:
            best, best_score = cand, s
    return best
