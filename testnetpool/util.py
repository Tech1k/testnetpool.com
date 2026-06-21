# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Low-level Bitcoin/Litecoin serialization, hashing and difficulty helpers.

Hashes are handled in two byte orders that recur throughout the codebase:

* **internal** order  - the raw bytes produced by ``sha256d`` / scrypt, i.e. the
  order they appear in when a block/transaction is serialized on the wire.  A
  256-bit value in internal order is interpreted little-endian.
* **display** order   - the big-endian hex you see in block explorers and in
  ``getblocktemplate`` output (``previousblockhash``, ``txid`` ...).  It is the
  byte-reverse of internal order.

Functions are named with the order they expect/return to keep this straight.
"""

from __future__ import annotations

import hashlib
import socket
import struct


def enable_tcp_nodelay(writer) -> None:
    """Disable Nagle's algorithm on an asyncio stream's socket.

    Stratum is a chatty, latency-sensitive protocol: a single handshake sends several
    tiny messages back-to-back (subscribe reply, then mining.set_difficulty, then
    mining.notify - each its own write). With Nagle ON (asyncio's default) the kernel
    coalesces small segments and holds each one waiting for the previous segment's ACK
    (or the ~40-200ms delayed-ACK timer), so the multi-message handshake can take tenths
    of a second instead of well under a millisecond. A normal long-lived miner never
    notices, but a proxy that reaps each connection on a tight timer (e.g.
    MiningRigRentals advertises "ttl": 2) can tear the socket down before the handshake
    lands. Every serious stratum server sets TCP_NODELAY for exactly this reason; ckpool
    does it in keep_sockalive(). Best-effort: a closed/non-TCP transport is harmless."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def sha256d(data: bytes) -> bytes:
    """Double SHA-256. Returns 32 bytes in *internal* order."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# scrypt(N=1024, r=1, p=1) over the 80-byte header, with the header used as both
# password and salt.  128 * N * r = 128 KiB of working memory; give OpenSSL a
# generous maxmem so it never refuses.
_SCRYPT_MAXMEM = 128 * 1024 * 1024


def scrypt_pow(header80: bytes) -> bytes:
    """Litecoin proof-of-work hash of an 80-byte header.

    Returns 32 bytes in *internal* (little-endian) order. Verified against the
    block-29255 test vector in the test-suite.
    """
    return hashlib.scrypt(
        header80, salt=header80, n=1024, r=1, p=1, dklen=32, maxmem=_SCRYPT_MAXMEM
    )


# ---------------------------------------------------------------------------
# Serialization primitives
# ---------------------------------------------------------------------------


def ser_compactsize(n: int) -> bytes:
    """Bitcoin CompactSize / varint encoding."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_string(data: bytes) -> bytes:
    """A length-prefixed byte string (CompactSize length + payload)."""
    return ser_compactsize(len(data)) + data


def pack_u32le(n: int) -> bytes:
    return struct.pack("<I", n & 0xFFFFFFFF)


def pack_u64le(n: int) -> bytes:
    return struct.pack("<Q", n & 0xFFFFFFFFFFFFFFFF)


def script_push_height(height: int) -> bytes:
    """BIP34 coinbase height prefix, replicating Litecoin's ``CScript() << n``.

    The node only checks that the coinbase scriptSig *begins* with this, so the
    encoding must match exactly: OP_0 for 0, OP_1..OP_16 for 1..16, otherwise a
    minimally-encoded little-endian CScriptNum data push.
    """
    if height == 0:
        return b"\x00"
    if 1 <= height <= 16:
        return bytes([0x50 + height])  # OP_1 .. OP_16
    out = bytearray()
    n = height
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:  # high bit set -> CScriptNum would read it as negative
        out.append(0x00)
    return bytes([len(out)]) + bytes(out)


# ---------------------------------------------------------------------------
# Byte-order helpers
# ---------------------------------------------------------------------------


def display_to_internal(hex_display: str) -> bytes:
    """Big-endian display hex -> internal-order bytes (full reverse)."""
    return bytes.fromhex(hex_display)[::-1]


def internal_to_display(data: bytes) -> str:
    """Internal-order bytes -> big-endian display hex (full reverse)."""
    return data[::-1].hex()


def stratum_prevhash(previousblockhash_display: str) -> str:
    """Encode ``previousblockhash`` for the ``mining.notify`` prevhash field.

    The de-facto Stratum convention (cgminer/sgminer, NOMP) takes the big-endian
    display hash, splits it into eight 4-byte words and reverses the *order* of
    the words while leaving the bytes inside each word untouched.
    """
    b = bytes.fromhex(previousblockhash_display)
    if len(b) != 32:
        raise ValueError("previousblockhash must be 32 bytes")
    words = [b[i : i + 4] for i in range(0, 32, 4)]
    return b"".join(reversed(words)).hex()


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


def coinbase_merkle_branch(txids_internal: list[bytes]) -> list[bytes]:
    """Merkle branch that combines with the (left-most) coinbase txid.

    ``txids_internal`` is the list of *non-coinbase* txids in internal order, in
    block order.  Returns the list of sibling hashes (internal order) a miner
    folds against the coinbase txid to reach the merkle root.  The coinbase sits
    at leaf index 0, so its sibling is always on the right and the branch never
    depends on the (still-unknown) coinbase value; we use a placeholder for it.
    """
    branch: list[bytes] = []
    index = 0
    hashes: list[bytes] = [b"\x00" * 32] + list(txids_internal)
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes = hashes + [hashes[-1]]  # duplicate the last on odd levels
        branch.append(hashes[index ^ 1])
        index >>= 1
        hashes = [sha256d(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return branch


def merkle_root_from_branch(coinbase_txid_internal: bytes, branch: list[bytes]) -> bytes:
    """Fold a coinbase txid through a merkle branch to the root (internal order)."""
    h = coinbase_txid_internal
    for sibling in branch:
        h = sha256d(h + sibling)
    return h


def merkle_root_full(txids_internal: list[bytes]) -> bytes:
    """Reference merkle root over a full ordered txid list (internal order)."""
    if not txids_internal:
        raise ValueError("empty tx list")
    layer = list(txids_internal)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


# ---------------------------------------------------------------------------
# Difficulty / target
# ---------------------------------------------------------------------------

# Default Stratum "difficulty 1" target (scrypt pools).  A share of difficulty D
# must hash (as a little-endian 256-bit int) to <= diff1 / D.  Each coin supplies
# its own diff1 (see coin.py); this default keeps scrypt-oriented call sites and
# tests working without passing it explicitly.
POOL_DIFF1_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000

MAX_TARGET = (1 << 256) - 1


def bits_to_target(nbits: int) -> int:
    """Compact ``nBits`` -> full 256-bit target integer."""
    exponent = nbits >> 24
    mantissa = nbits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def difficulty_to_target(difficulty: float, diff1: int = POOL_DIFF1_TARGET) -> int:
    """Pool difficulty -> 256-bit target int (hash must be <= this)."""
    if difficulty <= 0:
        return MAX_TARGET
    return min(int(diff1 / difficulty), MAX_TARGET)


def hash_to_difficulty(hash_internal: bytes, diff1: int = POOL_DIFF1_TARGET) -> float:
    """Pool difficulty represented by a PoW hash (internal order)."""
    h = int.from_bytes(hash_internal, "little")
    if h == 0:
        return float("inf")
    return diff1 / h


def hash_int_le(hash_internal: bytes) -> int:
    """PoW hash (internal order) as a little-endian integer for target compares."""
    return int.from_bytes(hash_internal, "little")


def numfmt(n) -> str:
    """Compact human number for logs and UI: 16384 -> '16.4 K', 1.88e6 -> '1.88 M'.

    Full SI table (through Y) with a magnitude-aware fixed mantissa, so it NEVER
    falls back to scientific notation, and carries to the next unit at the 1000
    boundary (999 999 -> '1.00 M'). Shared by the dashboard and the loggers so a
    difficulty reads the same everywhere.
    """
    n = float(n)
    for unit in ("", "K", "M", "G", "T", "P", "E", "Z", "Y"):
        if abs(n) < 999.5:
            if unit == "":
                return f"{n:,.0f}" if n == int(n) else f"{n:,.2f}"
            prec = 0 if abs(n) >= 100 else (1 if abs(n) >= 10 else 2)
            return f"{n:.{prec}f} {unit}"
        n /= 1000
    return f"{n:,.2f} Y"
