# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Unit test for the pure-Python QR encoder (testnetpool.qr) that draws the
donate-page address codes - no third-party dependency ships with the pool.

Correctness was established by encoding the same inputs with the `qrcode`
reference library (a scanner-verified encoder, present only in the dev env) and
confirming the matrices are *byte-identical* for every fitting version and all
eight masks. This test freezes that result two ways so it runs with nothing but
the stdlib:

  * structural invariants every valid QR must hold (size, finder/timing patterns,
    0/1 cells, quiet-zone-free output);
  * Reed-Solomon / GF(256) algebra sanity;
  * min-penalty mask selection (the spec's rule, and what `matrix()` must pick);
  * frozen SHA-256 digests of outputs that were byte-identical to `qrcode` when
    captured - a regression lock that fails loudly if encoding ever drifts.

If `qrcode` happens to be importable it is *also* used as a live oracle (extra
checks, auto-skipped otherwise).

Run:  python3 tests/qr.py
"""

from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool import qr  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


# Real-ish addresses across several versions (byte mode, ECC level M).
BTC = b"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
LTC = b"tltc1qabcdefghijklmnopqrstuvwxyz0234567890abcd"
XMR = b"9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzfAsrWcMqXNyNqz1ZbtrFP9b1qHbcz1"
ADDRS = [b"abc", BTC, LTC, XMR]

# Digests of outputs that were byte-identical to the `qrcode` reference library
# when captured (verified for every version + all 8 masks).  (version, mask, digest).
FROZEN_AUTO = {
    b"abc": (1, 2, "9c98978a088141d5281b56c9878a39ee"),
    BTC: (3, 2, "325bc921c606e8d446dbf8b12f761166"),
    LTC: (4, 2, "9f5efa2ac0872546ff7ab88641d4397c"),
    XMR: (6, 2, "33c0bf7ab9cad1cc99caf7e3deb1385c"),
}
FROZEN_FORCED = {
    (b"abc", 1, 0): "39fe177187ef2dc357da25091426022d",
    (b"abc", 1, 5): "740f28f9c941068046a783ecc80c191c",
    (BTC, 3, 7): "afff3bf85400ba7186f704f0504896dc",
}

# Canonical 7x7 finder pattern (placed at all three corners of every QR).
FINDER = [
    [1, 1, 1, 1, 1, 1, 1],
    [1, 0, 0, 0, 0, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 0, 0, 0, 0, 1],
    [1, 1, 1, 1, 1, 1, 1],
]


def digest(m):
    return hashlib.sha256(
        ("".join("".join(map(str, r)) for r in m)).encode()
    ).hexdigest()[:32]


def block(m, r0, c0):
    return [row[c0:c0 + 7] for row in m[r0:r0 + 7]]


def best_mask(data, version):
    """The spec's mask rule: lowest penalty wins (ties to the lower index)."""
    res = qr._prep(data, version)
    best, score = 0, None
    for k in range(8):
        p = qr._penalty(qr._compose(res[0], res[1], version, k))
        if score is None or p < score:
            best, score = k, p
    return best


def main():
    # --- public API shape ---------------------------------------------------
    for d in ADDRS:
        m = qr.matrix(d)
        size = len(m)
        chk(f"matrix is square ({len(d)}B)", all(len(r) == size for r in m))
        chk(f"cells are strictly 0/1 ({len(d)}B)",
            all(c in (0, 1) for r in m for c in r))
        # size must be 4*version + 17 for the smallest fitting version
        v = qr._pick_version(len(d))
        chk(f"size matches version {v} ({len(d)}B)", size == 4 * v + 17)

    # --- structural invariants every valid QR holds -------------------------
    for d in ADDRS:
        m = qr.matrix(d)
        size = len(m)
        chk(f"top-left finder ({len(d)}B)", block(m, 0, 0) == FINDER)
        chk(f"top-right finder ({len(d)}B)", block(m, 0, size - 7) == FINDER)
        chk(f"bottom-left finder ({len(d)}B)", block(m, size - 7, 0) == FINDER)
        # timing patterns: row/col 6 alternate 1,0,1,0... between the finders
        trow = all(m[6][c] == (1 - (c & 1)) for c in range(8, size - 8))
        tcol = all(m[r][6] == (1 - (r & 1)) for r in range(8, size - 8))
        chk(f"horizontal timing pattern ({len(d)}B)", trow)
        chk(f"vertical timing pattern ({len(d)}B)", tcol)
        # the fixed dark module just above the bottom-left finder
        chk(f"dark module present ({len(d)}B)", m[size - 8][8] == 1)

    # --- determinism + min-penalty mask selection ---------------------------
    for d in ADDRS:
        chk(f"deterministic ({len(d)}B)", qr.matrix(d) == qr.matrix(d))
        v = qr._pick_version(len(d))
        k = best_mask(d, v)
        chk(f"matrix() uses the min-penalty mask {k} ({len(d)}B)",
            qr.matrix(d) == qr._forced(d, v, k))

    # --- Reed-Solomon / GF(256) algebra -------------------------------------
    chk("gf_mul identity (x*1 == x)", all(qr._gf_mul(x, 1) == x for x in range(256)))
    chk("gf_mul zero (x*0 == 0)", all(qr._gf_mul(x, 0) == 0 for x in range(256)))
    chk("gf_mul commutes", all(qr._gf_mul(a, b) == qr._gf_mul(b, a)
                               for a in (2, 7, 100, 255) for b in (3, 9, 200)))
    ec = qr._rs_encode([0x10, 0x20, 0x0C, 0x56], 10)
    chk("rs_encode emits n parity bytes", len(ec) == 10)
    chk("rs_encode parity is byte-valued", all(0 <= b < 256 for b in ec))

    # --- frozen regression locks (were byte-identical to `qrcode`) ----------
    for d, (ev, ek, dg) in FROZEN_AUTO.items():
        v = qr._pick_version(len(d))
        chk(f"frozen version pick ({len(d)}B)", v == ev)
        chk(f"frozen auto digest ({len(d)}B)", digest(qr.matrix(d)) == dg)
    for (d, v, k), dg in FROZEN_FORCED.items():
        chk(f"frozen forced digest v{v} mask {k}", digest(qr._forced(d, v, k)) == dg)

    # --- optional live oracle: byte-identity with `qrcode`, all masks -------
    try:
        import qrcode  # noqa: E402  (dev-only; never a shipped dependency)
        from qrcode.constants import ERROR_CORRECT_M

        def ref(d, v, k):
            q = qrcode.QRCode(version=v, error_correction=ERROR_CORRECT_M,
                              box_size=1, border=0, mask_pattern=k)
            q.add_data(d)
            q.make(fit=False)
            return [[1 if x else 0 for x in r] for r in q.get_matrix()]

        miss = 0
        for d in ADDRS:
            v = qr._pick_version(len(d))
            for k in range(8):
                if qr._forced(d, v, k) != ref(d, v, k):
                    miss += 1
        chk("byte-identical to qrcode (all addrs x all masks)", miss == 0)
    except ImportError:
        print("  [skip] qrcode not installed - live oracle skipped "
              "(frozen digests still enforce byte-identity)")

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} qr checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
