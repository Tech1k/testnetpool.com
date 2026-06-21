# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Coin + network definitions.

Litecoin and Bitcoin share ~all of the Stratum/GBT/coinbase machinery (Litecoin
forked from Bitcoin).  The only per-coin differences are:

* the proof-of-work hash (scrypt vs double-SHA256),
* the Stratum "difficulty 1" target (scrypt bakes in a 2^16 factor),
* the expected hashes per difficulty-1 share (for hashrate estimates),
* the address parameters (bech32 hrp + base58 version bytes),
* the `getblocktemplate` rules (Litecoin requires `mweb`, Bitcoin must not send it),
* default RPC ports.

Everything coin-specific lives here so the rest of the pool stays generic.  A
future CryptoNote/RandomX coin (Monero) would not slot in here; it needs a
separate engine.  Bitcoin-family coins do.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import util

# Stratum difficulty-1 targets.  A share of difficulty D must hash (as a
# little-endian 256-bit int) to <= diff1_target / D.
SCRYPT_DIFF1 = 0x0000FFFF00000000000000000000000000000000000000000000000000000000
SHA256_DIFF1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

# Both Bitcoin and Litecoin use 1e8 base units (satoshis / litoshis) and a
# 100-block coinbase maturity.
COIN = 100_000_000
COINBASE_MATURITY = 100


@dataclass(frozen=True)
class Network:
    name: str
    rpc_port: int
    bech32_hrp: str
    pubkey_version: int          # base58 P2PKH version byte
    script_versions: tuple       # accepted base58 P2SH version byte(s)
    node_chain: str              # value getblockchaininfo reports in "chain"


@dataclass(frozen=True)
class Coin:
    name: str
    algo: str                    # "scrypt" | "sha256d"
    diff1_target: int
    hashes_per_diff1: int
    block_time: int              # target block spacing, seconds (for network-hashrate est.)
    gbt_rules: tuple
    networks: dict

    def network(self, name: str) -> Network:
        try:
            return self.networks[name]
        except KeyError:
            raise ValueError(
                f"{self.name} has no network {name!r}; choose from {tuple(self.networks)}"
            )

    def pow_hash(self, header80: bytes) -> bytes:
        """Proof-of-work hash of an 80-byte header (internal/LE byte order)."""
        if self.algo == "scrypt":
            return util.scrypt_pow(header80)
        return util.sha256d(header80)

    def difficulty_to_target(self, difficulty: float) -> int:
        return util.difficulty_to_target(difficulty, self.diff1_target)

    def hash_to_difficulty(self, hash_internal: bytes) -> float:
        return util.hash_to_difficulty(hash_internal, self.diff1_target)


LITECOIN = Coin(
    name="litecoin",
    algo="scrypt",
    diff1_target=SCRYPT_DIFF1,
    hashes_per_diff1=1 << 16,
    block_time=150,              # 2.5-minute target spacing
    gbt_rules=("segwit", "mweb"),
    networks={
        "main": Network("main", 9332, "ltc", 0x30, (0x32, 0x05), "main"),
        "test": Network("test", 19332, "tltc", 0x6F, (0x3A, 0xC4), "test"),
        "regtest": Network("regtest", 19443, "rltc", 0x6F, (0x3A, 0xC4), "regtest"),
    },
)

BITCOIN = Coin(
    name="bitcoin",
    algo="sha256d",
    diff1_target=SHA256_DIFF1,
    hashes_per_diff1=1 << 32,
    block_time=600,              # 10-minute target spacing
    gbt_rules=("segwit",),
    networks={
        "main": Network("main", 8332, "bc", 0x00, (0x05,), "main"),
        "test": Network("test", 18332, "tb", 0x6F, (0xC4,), "test"),          # testnet3
        "testnet4": Network("testnet4", 48332, "tb", 0x6F, (0xC4,), "testnet4"),
        "signet": Network("signet", 38332, "tb", 0x6F, (0xC4,), "signet"),
        "regtest": Network("regtest", 18443, "bcrt", 0x6F, (0xC4,), "regtest"),
    },
)

from .monero_coin import MONERO  # noqa: E402  (avoids a cycle: monero_coin needs nothing here)

# Monero is a parallel engine (CryptoNote + RandomX) that reuses Stats/dashboard/
# hub but NOT the Bitcoin Pool/template/stratum.  It's registered here so config
# accepts coin = "monero"; the actual engine is MoneroPool, dispatched by coin.
COINS = {"litecoin": LITECOIN, "bitcoin": BITCOIN, "monero": MONERO}
