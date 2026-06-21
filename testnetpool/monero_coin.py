# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""The Monero "coin": just enough to slot into the shared Stats/dashboard/hub.

Monero is modelled to fit the same abstraction the Bitcoin/Litecoin engine uses,
so it reuses Stats, the dashboard, accounting and the hub unchanged:

* ``hashes_per_diff1 = 1`` - a Monero share of difficulty D represents D hashes
  (RandomX difficulty is absolute, not relative to a diff-1), so the windowed
  hashrate math (sum(difficulty) * hashes_per_diff1 / window) is correct.
* ``diff1_target = 2**256`` and a job's ``network_target = 2**256 // difficulty``,
  so Stats' ``net_diff = diff1_target / network_target`` recovers the real
  network difficulty and ``eta`` is difficulty / hashrate.

Amounts are kept on the internal 1e8 "coin" scale used everywhere; the Monero RPC
boundary converts to/from piconero (1e12) with ``unit_scale`` (1e4 piconero per
internal unit). Sub-1e-8 XMR dust is below a testnet faucet's min payout anyway.
"""

from __future__ import annotations

MONERO_MATURITY = 60  # Monero coinbase unlock window (blocks)


class _MoneroNetwork:
    def __init__(self, name: str, rpc_port: int):
        self.name = name        # cryptonote network: mainnet | testnet | stagenet
        self.node_chain = name  # what get_info's nettype maps to
        self.rpc_port = rpc_port


class MoneroCoin:
    name = "monero"
    algo = "randomx"
    hashes_per_diff1 = 1
    diff1_target = 1 << 256
    block_time = 120        # 2-minute target spacing (network-hashrate = difficulty / 120)
    maturity = MONERO_MATURITY
    atomic = 10 ** 12       # piconero per XMR
    unit_scale = 10 ** 4    # piconero per internal accounting unit (1e8 scale)

    def __init__(self):
        # NO mainnet: the Monero engine credits shares TRUST-BASED (no RandomX
        # verification), which is only safe where coins are worthless. Omitting
        # mainnet here makes `chain = "mainnet"` fail closed at config load.
        self.networks = {
            "testnet": _MoneroNetwork("testnet", 28081),
            "stagenet": _MoneroNetwork("stagenet", 38081),
        }

    def network(self, name: str) -> _MoneroNetwork:
        if name not in self.networks:
            raise KeyError(f"unknown monero network {name!r} "
                           f"(expected one of {', '.join(self.networks)})")
        return self.networks[name]


MONERO = MoneroCoin()
