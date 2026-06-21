# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Vectors for the pure-Python Monero/CryptoNote primitives (no node needed).

Covers Keccak-256, CryptoNote base58, Monero address validation (against a real
mainnet address + self-constructed per-network addresses), the difficulty/target
math, and block-template nonce handling.

Run:  python3 tests/monero.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.keccak import keccak256  # noqa: E402
from testnetpool.cryptonote import (  # noqa: E402
    NETWORKS, CryptoNoteError, b58_decode, b58_encode, block_nonce_offset,
    difficulty_to_target, hash_meets_difficulty, is_valid_address, read_varint,
    set_block_nonce, validate_address, write_varint,
)

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def _make_address(network: str, kind: str) -> str:
    prefix = NETWORKS[network][kind]
    spend, view = bytes(range(32)), bytes(range(32, 64))
    body = write_varint(prefix) + spend + view + (b"\x11" * 8 if kind == "integrated" else b"")
    return b58_encode(body + keccak256(body)[:4])


def main() -> int:
    # 1) Keccak-256 vectors (original Keccak, not NIST SHA3)
    kv = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"The quick brown fox jumps over the lazy dog":
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    }
    for msg, exp in kv.items():
        chk(f"keccak256({msg[:12]!r})", keccak256(msg).hex() == exp)

    # 2) CryptoNote base58: anchors + round-trip
    chk("b58 empty", b58_encode(b"") == "")
    chk("b58 eight zeros", b58_encode(bytes(8)) == "11111111111")
    chk("b58 decode ones", b58_decode("11111111111") == bytes(8))
    rt = all(b58_decode(b58_encode(bytes(range(n)))) == bytes(range(n)) for n in range(1, 17))
    chk("b58 round-trip 1..16 bytes", rt)
    try:
        b58_decode("0OIl")  # chars not in the alphabet
        chk("b58 rejects bad chars", False)
    except CryptoNoteError:
        chk("b58 rejects bad chars", True)

    # 3) Monero address validation
    # Real mainnet address (the long-published Monero project donation address).
    DONATION = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7"
                "SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
    info = validate_address(DONATION, "mainnet")
    chk("real mainnet address valid", info["kind"] == "standard" and info["prefix"] == 18)
    chk("mainnet addr is 95 chars", len(DONATION) == 95)
    chk("mainnet addr wrong network rejected", not is_valid_address(DONATION, "stagenet"))

    for net in ("mainnet", "testnet", "stagenet"):
        for kind in ("standard", "subaddress", "integrated"):
            a = _make_address(net, kind)
            got = validate_address(a, net)
            chk(f"{net}/{kind} self-addr validates", got["kind"] == kind)
        # a one-char corruption breaks the checksum
        good = _make_address(net, "standard")
        bad = good[:-2] + ("X" if good[-2] != "X" else "Y") + good[-1]
        chk(f"{net} corrupted addr rejected", not is_valid_address(bad, net))
        # right shape, wrong network
        chk(f"{net} addr rejected on other network",
            not is_valid_address(good, "testnet" if net != "testnet" else "mainnet"))

    # 4) difficulty / target math
    chk("target diff=1", difficulty_to_target(1) == "ffffffffffffffff")
    chk("target diff=2", difficulty_to_target(2) == (1 << 63).to_bytes(8, "little").hex())
    chk("hash 0x00 meets any diff", hash_meets_difficulty(b"\x00" * 32, 10 ** 18))
    chk("hash 0xff meets diff 1", hash_meets_difficulty(b"\xff" * 32, 1))
    chk("hash 0xff fails diff 2", not hash_meets_difficulty(b"\xff" * 32, 2))

    # 5) block-template nonce: locate + set
    header = (write_varint(16) + write_varint(0) + write_varint(1_700_000_000)
              + bytes(range(32)) + b"\xaa\xbb\xcc\xdd" + b"the rest of the block")
    exp_off = (len(write_varint(16)) + len(write_varint(0))
               + len(write_varint(1_700_000_000)) + 32)
    off = block_nonce_offset(header)
    chk("nonce offset correct", off == exp_off and header[off:off + 4] == b"\xaa\xbb\xcc\xdd")
    nb = set_block_nonce(header, 0x12345678)
    chk("set_nonce writes LE + preserves length",
        nb[off:off + 4] == (0x12345678).to_bytes(4, "little") and len(nb) == len(header))
    chk("set_nonce leaves the rest intact",
        nb[:off] == header[:off] and nb[off + 4:] == header[off + 4:])
    v, p = read_varint(write_varint(1_700_000_000))
    chk("varint round-trip", v == 1_700_000_000 and p == len(write_varint(1_700_000_000)))

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} monero primitive checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
