# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""CryptoNote / Monero protocol primitives, pure stdlib.

The pieces a Monero pool needs that are NOT RandomX (which monerod verifies for us
on block submission):

* CryptoNote base58 (block-wise, distinct from Bitcoin base58) - encode/decode.
* Monero address validation (network prefix + Keccak-256 checksum).
* difficulty <-> share/network target, and the trust-based hash check.
* block-template nonce handling (locate + set the 4-byte nonce in a block blob).

This is the testnet, trust-based path: shares are accepted on the miner's submitted
result (testnet coins are worthless, so share-weighting fraud is pointless), and the
node is the final arbiter for real blocks. None of this touches RandomX.
"""

from __future__ import annotations

from .keccak import keccak256


class CryptoNoteError(ValueError):
    """Invalid CryptoNote/Monero data (address, base58, blob)."""


# --- CryptoNote base58 (8-byte blocks -> 11 chars; partial blocks per table) ---

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_FULL_BLOCK = 8
_FULL_ENCODED = 11
# encoded length for a decoded block of 0..8 bytes
_ENC_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]


def _encode_block(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ["1"] * _ENC_SIZES[len(data)]
    i = len(out) - 1
    while num > 0:
        num, rem = divmod(num, 58)
        out[i] = _ALPHABET[rem]
        i -= 1
    return "".join(out)


def _decode_block(s: str) -> bytes:
    try:
        size = _ENC_SIZES.index(len(s))
    except ValueError:
        raise CryptoNoteError("bad base58 block length")
    num = 0
    for ch in s:
        idx = _ALPHABET.find(ch)
        if idx < 0:
            raise CryptoNoteError(f"bad base58 character {ch!r}")
        num = num * 58 + idx
    if num >> (size * 8):
        raise CryptoNoteError("base58 block overflow")
    return num.to_bytes(size, "big")


def b58_encode(data: bytes) -> str:
    return "".join(_encode_block(data[off:off + _FULL_BLOCK])
                   for off in range(0, len(data), _FULL_BLOCK))


def b58_decode(s: str) -> bytes:
    out = bytearray()
    for off in range(0, len(s), _FULL_ENCODED):
        out += _decode_block(s[off:off + _FULL_ENCODED])
    return bytes(out)


# --- Monero address validation -------------------------------------------------

# network -> {address kind: 1-byte prefix}.  All Monero prefixes are < 128, so the
# leading varint is a single byte.
NETWORKS = {
    "mainnet": {"standard": 18, "integrated": 19, "subaddress": 42},
    "testnet": {"standard": 53, "integrated": 54, "subaddress": 63},
    "stagenet": {"standard": 24, "integrated": 25, "subaddress": 36},
}
# decoded byte length: prefix(1) + spend(32) + view(32) [+ payment_id(8)] + checksum(4)
_LEN_STANDARD = 69
_LEN_INTEGRATED = 77


def validate_address(addr: str, network: str) -> dict:
    """Validate a Monero address for ``network`` (mainnet/testnet/stagenet).

    Checks the CryptoNote base58, the Keccak-256 checksum, and that the network
    prefix matches.  Returns ``{"kind", "prefix", "network"}`` or raises
    CryptoNoteError.  Integrated addresses are accepted but a plain standard or
    subaddress is the usual payout target.
    """
    nets = NETWORKS.get(network)
    if nets is None:
        raise CryptoNoteError(f"unknown network {network!r}")
    # Cap before the base58/keccak work: real Monero addresses are <=106 chars, so a longer
    # input is invalid by definition. Without this, a crafted oversized login address would
    # drive keccak over a large body and stall the event loop. (Don't truncate - that could
    # turn a valid integrated address into a mismatched one; reject outright.)
    if len(addr) > 128:
        raise CryptoNoteError("address too long")
    raw = b58_decode(addr)
    if len(raw) < 5:
        raise CryptoNoteError("address too short")
    body, checksum = raw[:-4], raw[-4:]
    if keccak256(body)[:4] != checksum:
        raise CryptoNoteError("bad address checksum")
    prefix = body[0]
    kind = next((k for k, v in nets.items() if v == prefix), None)
    if kind is None:
        raise CryptoNoteError(f"prefix {prefix} is not a {network} address")
    expected = _LEN_INTEGRATED if kind == "integrated" else _LEN_STANDARD
    if len(raw) != expected:
        raise CryptoNoteError(f"address length {len(raw)} != {expected} for {kind}")
    return {"kind": kind, "prefix": prefix, "network": network}


def is_valid_address(addr: str, network: str) -> bool:
    try:
        validate_address(addr, network)
        return True
    except CryptoNoteError:
        return False


# --- difficulty / target -------------------------------------------------------

_2_256 = 1 << 256


def hash_meets_difficulty(hash_le: bytes, difficulty: int) -> bool:
    """True if a 32-byte result hash (little-endian) satisfies ``difficulty``.

    Monero's check: hash_int * difficulty < 2^256 (i.e. hash < 2^256/difficulty).
    Exact, no rounding.  Used trust-based on the miner's submitted result.  The
    difficulty is floored at 1 (consistent with difficulty_to_target) so a sub-1
    vardiff value can't collapse int(difficulty) to 0 and accept every hash.
    """
    d = max(1, int(difficulty))
    return int.from_bytes(hash_le, "little") * d < _2_256


def difficulty_to_target(difficulty: int) -> str:
    """xmrig-compatible Stratum job target: floor(2^64 / difficulty) as 8-byte
    little-endian hex (the top 64 bits of the 256-bit target)."""
    d = max(1, int(difficulty))
    t = max(1, min((1 << 64) - 1, (1 << 64) // d))  # floor at 1: never an all-zero target
    return t.to_bytes(8, "little").hex()


# --- block-template nonce ------------------------------------------------------

def read_varint(data: bytes, pos: int = 0) -> tuple:
    """Read a CryptoNote varint; return (value, next_pos)."""
    result = shift = 0
    while True:
        if pos >= len(data):
            raise CryptoNoteError("truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def block_nonce_offset(blob: bytes) -> int:
    """Byte offset of the 4-byte nonce in a Monero block (hashing or template blob).

    Header layout: major_version varint, minor_version varint, timestamp varint,
    prev_id 32 bytes, then the nonce (uint32 LE).
    """
    pos = 0
    for _ in range(3):  # major, minor, timestamp
        _, pos = read_varint(blob, pos)
    pos += 32  # prev_id
    if pos + 4 > len(blob):
        raise CryptoNoteError("blob too short for nonce")
    return pos


def set_block_nonce(blob: bytes, nonce: int) -> bytes:
    """Return ``blob`` with its 4-byte nonce replaced (for block submission)."""
    off = block_nonce_offset(blob)
    return blob[:off] + (nonce & 0xFFFFFFFF).to_bytes(4, "little") + blob[off + 4:]


def write_varint(value: int) -> bytes:
    """Encode a non-negative int as a CryptoNote varint (used by tests/builders)."""
    if value < 0:
        raise CryptoNoteError("varint must be non-negative")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        out.append(b | (0x80 if value else 0))
        if not value:
            return bytes(out)
