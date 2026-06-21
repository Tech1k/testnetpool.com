# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Hub: run several per-coin pools in one process under one shared dashboard.

Each coin still needs its own node and its own Stratum port (a mining connection
mines one coin/algo), but they share a single process and a single dashboard /
JSON API.  One coin's node being down doesn't take the others down.
"""

from __future__ import annotations

import asyncio
import logging

from .config import HubConfig
from .pool import Pool
from .stats import StatsServer

log = logging.getLogger("testnetpool.hub")


def make_pool(cfg, serve_stats: bool = True):
    """Build the engine for a coin: MoneroPool for monero, Pool otherwise."""
    if cfg.coin == "monero":
        from .monero_pool import MoneroPool  # lazy: only load the Monero engine if used
        return MoneroPool(cfg, serve_stats=serve_stats)
    return Pool(cfg, serve_stats=serve_stats)


class Hub:
    def __init__(self, cfg: HubConfig):
        self.cfg = cfg
        # Each pool runs its own stratum/node/loops with its stats server off;
        # the hub owns the one shared dashboard over all of them.
        self.pools = [make_pool(c, serve_stats=False) for c in cfg.coins]
        self.stats_server = StatsServer(self.pools, cfg.stats, donate=cfg.donate)
        self._tasks: list[asyncio.Task] = []

    async def _run_pool(self, pool: Pool) -> None:
        try:
            await pool.run()
        except asyncio.CancelledError:
            raise
        except Exception:
            # One coin failing must never take the hub (or the other coins) down.
            #
            # Transient node trouble is already self-healed *inside* pool.run(): the
            # startup probe retries with backoff (rpc.await_node_ready) and the RPC layer
            # wraps every transport/parse failure as a retryable RPCError that the poll/
            # payout/maturity loops swallow-and-retry. So reaching here means an
            # UNEXPECTED, non-transient exit (e.g. a bug or a hard misconfig) - we log it
            # loudly and leave that one coin stopped on purpose. We deliberately do NOT
            # auto-restart it: re-invoking run() on the same Pool would hit an already-
            # closed sqlite Accounting connection and a stratum port still in TIME_WAIT.
            # A supervised restart would have to rebuild the pool instance; that's a
            # future enhancement, not a transient-recovery path.
            log.exception("coin %s/%s stopped", pool.cfg.coin, pool.cfg.chain)

    async def run(self) -> None:
        await self.stats_server.start()
        log.info(
            "hub: %d coin(s) | %s",
            len(self.pools),
            "  ".join(f"{p.cfg.coin}/{p.cfg.chain}@:{p.cfg.stratum_port}" for p in self.pools),
        )
        self._tasks = [asyncio.create_task(self._run_pool(p)) for p in self.pools]
        try:
            await asyncio.gather(*self._tasks)
        finally:
            await self.stats_server.close()

    def stop(self) -> None:
        for p in self.pools:
            p.stop()
