# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Job-id scheme + workbase retention (ckpool-parity).

The MRR/whatsminer failure was "job not found (stale)": our job_ids reset to 0 on restart
and we kept only 8 jobs, wiping all on every block change - so a proxy lagging a few minutes
(or holding a pre-restart id) found its job gone. ckpool uses non-resetting time-seeded ids
and retains workbases by age (600s) across block changes. These tests pin that behaviour.

Run:  python3 tests/jobs.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool import util  # noqa: E402
from testnetpool.config import Config, RPCConfig, StatsConfig, VardiffConfig  # noqa: E402
from testnetpool.pool import (  # noqa: E402
    JOB_RETENTION_SECONDS, MIN_RETAINED_JOBS, Pool,
)

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


class FakeRPC:
    """Minimal node: only the best-effort calls _apply_template makes."""

    async def get_mempool_info(self, timeout=None):
        return {"size": 0, "bytes": 0, "total_fee": 0.0}

    async def get_blockchain_info(self, timeout=None):
        return {"chain": "regtest", "blocks": 200, "headers": 200, "time": 1_700_000_000}

    async def get_connection_count(self, timeout=None):
        return 1

    async def get_network_hashps(self, nblocks=120, timeout=None):
        return 1.0


def _gbt(prevhash: str, height: int = 200) -> dict:
    bits = "207fffff"
    return {
        "height": height,
        "previousblockhash": prevhash,
        "version": 0x20000000,
        "bits": bits,
        "curtime": 1_700_000_123,
        "mintime": 1_700_000_000,
        "target": f"{util.bits_to_target(int(bits, 16)):064x}",
        "coinbasevalue": 2_500_000_000,
        "transactions": [],
    }


async def main() -> int:
    cfg = Config(
        chain="regtest",
        address="rltc1qw508d6qejxtdg4y5r3zarvary0c5xw7k693xs3",
        stratum_port=13340,
        include_transactions=False,
        rpc=RPCConfig(host="127.0.0.1", port=19443, user="x", password="y"),
        vardiff=VardiffConfig(enabled=False),
        stats=StatsConfig(enabled=False),
    )
    pool = Pool(cfg)
    pool.rpc = FakeRPC()  # type: ignore[assignment]

    # Fix 1: the job-id counter is seeded from the wall clock in the high bits (never 0),
    # so a restart always jumps the id space forward (ckpool's randomiser<<32).
    chk("job_id counter seeded from time, not reset to 0", pool._job_counter > (1 << 32))

    P1 = "11" * 32
    P2 = "22" * 32

    await pool._ingest_template(_gbt(P1))           # first job (clean=True)
    job_a = pool.current_job_id
    chk("job_id is 16 lowercase hex (ckpool %016lx width)",
        isinstance(job_a, str) and len(job_a) == 16
        and all(c in "0123456789abcdef" for c in job_a))

    await pool._ingest_template(_gbt(P1))           # same-block refresh (clean=False)
    job_a2 = pool.current_job_id
    chk("ids strictly increase", int(job_a2, 16) > int(job_a, 16))
    chk("same-block jobs both retained",
        pool.get_job(job_a) is not None and pool.get_job(job_a2) is not None)

    # Fix 2 (the core fix): a NEW BLOCK (clean=True) must NOT wipe prior jobs - an in-flight
    # share crossing the block boundary, or a slightly-lagging proxy, still resolves its job.
    await pool._ingest_template(_gbt(P2, height=201))
    job_b = pool.current_job_id
    chk("new block does NOT clear prior jobs (retained across block change)",
        pool.get_job(job_a) is not None and pool.get_job(job_b) is not None)
    chk("best_hash advanced to the new tip", pool._best_hash == P2)
    chk("prior-block job carries the old prevhash (for the stale gate)",
        pool.get_job(job_a).prevhash_display == P1
        and pool.get_job(job_b).prevhash_display == P2)

    # Fix 2: age-based eviction keeps a floor (ckpool: free past 600s, keep >=3).
    n_before = len(pool.jobs)
    chk("jobs accumulate (not capped at the old 8) without aging", n_before >= 3)
    for j in pool.jobs.values():                    # age every retained job past the horizon
        j.created -= (JOB_RETENTION_SECONDS + 60)
    await pool._ingest_template(_gbt(P2, height=201))  # one fresh job triggers eviction
    chk("ages out jobs past the 600s horizon but keeps the floor",
        len(pool.jobs) == MIN_RETAINED_JOBS)

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} job checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
