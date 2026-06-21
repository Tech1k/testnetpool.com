# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Decode a Litecoin payout address into its scriptPubKey, network-aware.

Supports the address types a coinbase output can pay to:

* P2PKH  (legacy, base58check, ``L...`` / ``m`` / ``n``)
* P2SH   (base58check, ``M...`` / ``3...`` / ``Q...`` / ``2...``)
* P2WPKH / P2WSH (bech32 segwit v0, ``ltc1q...`` / ``tltc1q...`` / ``rltc1...``)
* P2TR   (bech32m segwit v1, ``ltc1p...``)

MWEB addresses (``ltcmweb1.../ltc1mweb...``) are intentionally NOT supported:
a coinbase output cannot pay directly into MWEB, so the payout address must be a
normal on-chain address. The block subsidy lands on-chain; move it to MWEB
afterwards from your wallet if you want privacy.

Address parameters come from a coin :class:`~testnetpool.coin.Network` (passed in
duck-typed: anything with ``.bech32_hrp``, ``.pubkey_version`` and
``.script_versions``), so this module stays coin-agnostic.
"""

from __future__ import annotations

import hashlib

# Opcodes used when building scriptPubKeys.
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC


class AddressError(ValueError):
    pass


# ---------------------------------------------------------------------------
# base58check
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    # Bound the input first: `num = num*58 + idx` is O(n^2) in len(s), so an
    # unbounded string (e.g. a ~64 KB stratum username) would stall the event loop.
    # The longest real base58check address is ~35 chars; 64 is generous headroom.
    if len(s) > 64:
        raise AddressError("base58 string too long")
    num = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx == -1:
            raise AddressError(f"invalid base58 character {ch!r}")
        num = num * 58 + idx
    # Convert to bytes, then restore leading zero bytes (encoded as '1').
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + full


def _b58check_decode(s: str) -> bytes:
    raw = _b58decode(s)
    if len(raw) < 5:
        raise AddressError("base58 payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise AddressError("bad base58 checksum")
    return payload


# ---------------------------------------------------------------------------
# bech32 / bech32m  (BIP173 / BIP350)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= generator[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_decode(addr: str) -> tuple[str, list[int], int]:
    # BIP173/BIP350 cap the whole address at 90 chars. Enforcing it up front also
    # bounds the O(n) polymod against a pathologically long worker-name input.
    if len(addr) > 90:
        raise AddressError("bech32 address too long")
    if addr != addr.lower() and addr != addr.upper():
        raise AddressError("mixed-case bech32 address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise AddressError("invalid bech32 separator position")
    hrp = addr[:pos]
    data = []
    for ch in addr[pos + 1 :]:
        d = _BECH32_CHARSET.find(ch)
        if d == -1:
            raise AddressError(f"invalid bech32 character {ch!r}")
        data.append(d)
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    return hrp, data[:-6], const


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise AddressError("invalid value in bech32 payload")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise AddressError("invalid padding in bech32 payload")
    return ret


def _decode_segwit(hrp_expected: str, addr: str) -> tuple[int, bytes]:
    hrp, data, const = _bech32_decode(addr)
    if hrp != hrp_expected:
        raise AddressError(f"wrong bech32 hrp {hrp!r} (expected {hrp_expected!r})")
    if not data:
        raise AddressError("empty bech32 payload")
    witver = data[0]
    decoded = _convertbits(data[1:], 5, 8, False)
    if len(decoded) < 2 or len(decoded) > 40:
        raise AddressError("invalid witness program length")
    # Only v0 (P2WPKH/P2WSH) and v1 (P2TR) are spendable today; v2-v16 are
    # currently-unspendable future programs. Reject them as payout targets - fail
    # closed so neither an operator config nor a miner-supplied username can route
    # the subsidy/credits to a script no wallet can spend.
    if witver > 1:
        raise AddressError("unsupported witness version (only v0/v1)")
    expected_const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    if const != expected_const:
        raise AddressError("bad bech32 checksum")
    if witver == 0 and len(decoded) not in (20, 32):
        raise AddressError("v0 witness program must be 20 or 32 bytes")
    if witver == 1 and len(decoded) != 32:
        raise AddressError("v1 (P2TR) witness program must be 32 bytes")
    return witver, bytes(decoded)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def address_to_script(addr: str, net) -> bytes:
    """Return the scriptPubKey bytes a coinbase output should use to pay ``addr``.

    ``net`` is a coin Network (duck-typed: ``.bech32_hrp``, ``.pubkey_version``,
    ``.script_versions``).  Raises :class:`AddressError` for malformed addresses
    or a network/coin mismatch.
    """
    hrp = net.bech32_hrp

    # Native segwit (bech32 / bech32m) first - they carry their own hrp.
    if addr.lower().startswith(hrp + "1"):
        witver, program = _decode_segwit(hrp, addr)
        op = 0x00 if witver == 0 else (0x50 + witver)  # OP_0 / OP_1..OP_16
        return bytes([op, len(program)]) + program

    # Otherwise base58check (legacy P2PKH / P2SH).
    payload = _b58check_decode(addr)
    version, h160 = payload[0], payload[1:]
    if len(h160) != 20:
        raise AddressError("base58 hash160 must be 20 bytes")
    if version == net.pubkey_version:
        # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        return bytes([OP_DUP, OP_HASH160, 20]) + h160 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    if version in net.script_versions:
        # OP_HASH160 <20> OP_EQUAL
        return bytes([OP_HASH160, 20]) + h160 + bytes([OP_EQUAL])
    raise AddressError(
        f"address version byte 0x{version:02x} not valid for {net.bech32_hrp} network"
    )
