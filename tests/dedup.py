# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Regression: per-connection duplicate-share detection keys on PARSED values.

A miner that submits one solution re-encoded ("00000001" / "1" / "0x1" / "0X01")
must NOT be able to inflate its PPLNS weight by having each spelling counted as a
distinct share.  The fix keys the dedup set on the parsed (extranonce2, ntime,
nonce, version) tuple rather than the raw hex strings; this test drives
MinerConnection._on_submit directly and asserts every re-encoding of an accepted
share is rejected as a duplicate, while a genuinely different nonce still passes.

Run:  python3 tests/dedup.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.config import (  # noqa: E402
    Config, PublicConfig, RPCConfig, StatsConfig, VardiffConfig,
)
from testnetpool.pool import Pool  # noqa: E402
from testnetpool.selftest import _bech32_encode  # noqa: E402
from testnetpool.stratum import ERR_DUPLICATE, ERR_STALE, MinerConnection  # noqa: E402

from integration import FakeRPC  # noqa: E402

MINER_ADDR = _bech32_encode("rltc", 0, b"\x11" * 20)
POOL_ADDR = _bech32_encode("rltc", 0, b"\x22" * 20)
FAUCET_ADDR = _bech32_encode("rltc", 0, b"\x33" * 20)


class FakeWriter:
    """Captures the JSON-RPC lines a connection writes back."""

    def __init__(self):
        self.lines: list[dict] = []
        self._buf = b""

    def get_extra_info(self, _key):
        return ("127.0.0.1", 0)

    def write(self, data: bytes):
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            if line.strip():
                self.lines.append(json.loads(line))

    async def drain(self):
        pass

    def close(self):
        pass

    def last(self) -> dict:
        return self.lines[-1]


async def main() -> int:
    ok = []
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    cfg = Config(
        coin="litecoin", chain="regtest", mode="public",
        stratum_host="127.0.0.1", stratum_port=13355,
        rpc=RPCConfig(host="127.0.0.1", port=19443, user="x", password="y"),
        vardiff=VardiffConfig(enabled=False, start_difficulty=0.0001),
        stats=StatsConfig(enabled=False, host="127.0.0.1", port=18086),
        public=PublicConfig(db_path=db_path, pool_address=POOL_ADDR, faucet_address=FAUCET_ADDR),
    )
    pool = Pool(cfg)
    pool.rpc = FakeRPC()  # type: ignore[assignment]

    run_task = asyncio.create_task(pool.run())
    for _ in range(50):
        if pool.current_job() is not None:
            break
        await asyncio.sleep(0.1)
    job = pool.current_job()
    assert job is not None, "pool never built a job"
    # Make sure NO share can be a block, so the job never rotates mid-test and we
    # isolate exactly the dedup path (a block would also be an accepted share).
    job.network_target = 0

    conn = MinerConnection(None, FakeWriter(), pool)
    conn.subscribed = True
    conn.authorized = True
    conn.worker = MINER_ADDR
    conn.payout_address = MINER_ADDR
    conn.worker_name = ""
    # accept_diff = min(difficulty, previous_difficulty) = 0, so EVERY share is
    # accepted regardless of the (random) scrypt hash - this test is about dedup,
    # not difficulty, and with network_target=0 nothing is ever a block.
    conn.vardiff.difficulty = 0.0
    conn.vardiff.previous_difficulty = 0.0
    writer = conn.writer

    en2_hex = "00" * cfg.extranonce2_size
    ntime_hex = f"{job.curtime:08x}"

    async def submit(msg_id, nonce_hex):
        await conn._on_submit(msg_id, [MINER_ADDR, job.job_id, en2_hex, ntime_hex, nonce_hex])
        return writer.last()

    # First submission of the solution: accepted.
    r1 = await submit(1, "00000001")
    ok.append(("first submit accepted", r1.get("result") is True and r1.get("error") is None))

    # Every re-encoding of the SAME (en2, ntime, nonce, version) must be a duplicate.
    for spelling in ("1", "0x1", "0X00000001", "00000001"):
        r = await submit(2, spelling)
        err = r.get("error")
        ok.append((f"re-encoded nonce {spelling!r} rejected as duplicate",
                   r.get("result") is False and isinstance(err, list) and err[0] == ERR_DUPLICATE))

    # High-WORD nonce variants (nonce + k*2^32) mask to the SAME on-wire 32-bit nonce
    # build_header serializes, so they produce the identical header + PoW and MUST be
    # duplicates - else one valid share inflates PPLNS weight (payout theft).
    for spelling in ("100000001", "200000001", "ffffffff00000001"):
        r = await submit(4, spelling)
        err = r.get("error")
        ok.append((f"high-word nonce {spelling!r} rejected as duplicate",
                   r.get("result") is False and isinstance(err, list) and err[0] == ERR_DUPLICATE))

    # A genuinely different nonce is NOT a duplicate (dedup didn't over-reject).
    r3 = await submit(3, "00000002")
    ok.append(("distinct nonce still accepted", r3.get("result") is True and r3.get("error") is None))

    # Accounting recorded exactly the two distinct shares (not the re-encodings).
    await asyncio.sleep(0.05)
    n_shares = pool.accounting.conn.execute(
        "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.address=?",
        (MINER_ADDR,),
    ).fetchone()[0]
    ok.append(("only 2 distinct shares credited", n_shares == 2))

    # --- H-1 regression: job retention must NOT re-open the per-connection dedup window ---
    # With many same-tip jobs live at once, the dedup set must NOT be cleared when a
    # connection submits to a DIFFERENT job_id. Otherwise a miner re-credits one already-
    # counted valid share by ping-ponging job_ids: submit S on A, any share on B (which used
    # to clear _seen), then re-submit S on A - now forgotten, so credited twice. Mint a second
    # same-tip job B (same prevhash => passes the stale gate) and drive A -> B -> A.
    gbt2 = await pool.rpc.get_block_template()
    await pool._ingest_template(gbt2)
    job_b_id = pool.current_job_id            # capture synchronously (poll loop may add more)
    job_b = pool.get_job(job_b_id)
    job_b.network_target = 0                   # keep B's shares non-blocks, like A
    ntime_b = f"{job_b.curtime:08x}"
    ok.append(("job B is a distinct retained job_id", job_b_id != job.job_id))
    ok.append(("job B is same-tip (passes the stale gate)",
               job_b.prevhash_display == pool._best_hash))

    n_before = pool.accounting.conn.execute(
        "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.address=?",
        (MINER_ADDR,)).fetchone()[0]

    async def submit_job(msg_id, job_id, ntime_h, nonce_hex):
        await conn._on_submit(msg_id, [MINER_ADDR, job_id, en2_hex, ntime_h, nonce_hex])
        return writer.last()

    S = "00000007"                             # a nonce not yet seen on job A
    rA = await submit_job(10, job.job_id, ntime_hex, S)
    ok.append(("replay setup: share S on job A accepted", rA.get("result") is True))
    rB = await submit_job(11, job_b_id, ntime_b, S)   # switch job_id (the old clear() trigger)
    ok.append(("share on job B accepted (distinct key)", rB.get("result") is True))
    rA2 = await submit_job(12, job.job_id, ntime_hex, S)   # replay S on A
    errA2 = rA2.get("error")
    ok.append(("A->B->A replay of S on job A rejected as duplicate",
               rA2.get("result") is False and isinstance(errA2, list)
               and errA2[0] == ERR_DUPLICATE))

    await asyncio.sleep(0.05)
    n_after = pool.accounting.conn.execute(
        "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.address=?",
        (MINER_ADDR,)).fetchone()[0]
    ok.append(("replay credited exactly 2 shares (S on A + S on B), not 3",
               n_after - n_before == 2))

    # --- B1 regression: a non-block share for a SUPERSEDED (lower-height) tip is rejected as
    # stale - even while pool._best_hash is transiently blank (the post-solve refetch window).
    # The gate is HEIGHT-based, so the blank sentinel can't leak dead-tip shares into PPLNS.
    old = pool.get_job(job.job_id)             # job A, at the original height
    old.network_target = 0                     # its shares are non-blocks (so the gate applies)
    old_ntime = f"{old.curtime:08x}"
    base_gbt = await pool.rpc.get_block_template()
    higher = {**base_gbt, "height": old.height + 1, "previousblockhash": "ab" * 32}

    async def _gbt_higher(*a, **k):            # poll loop now also sees the advanced tip (no race)
        return dict(higher)
    pool.rpc.get_block_template = _gbt_higher  # type: ignore[assignment]
    await pool._ingest_template(higher)
    ok.append(("tip advanced; old job retained below current_height",
               pool.current_height == old.height + 1 and pool.get_job(old.job_id) is not None))

    rS = await submit_job(20, old.job_id, old_ntime, "0000aa01")
    eS = rS.get("error")
    ok.append(("superseded-tip share rejected as stale",
               rS.get("result") is False and isinstance(eS, list) and eS[0] == ERR_STALE))

    pool._best_hash = ""                       # the old falsy-sentinel hole: gate must still fire
    rS2 = await submit_job(21, old.job_id, old_ntime, "0000aa02")
    eS2 = rS2.get("error")
    ok.append(("dead-tip share STILL rejected while _best_hash is blank (B1)",
               rS2.get("result") is False and isinstance(eS2, list) and eS2[0] == ERR_STALE))

    pool.stop()
    try:
        await asyncio.wait_for(run_task, timeout=3)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        run_task.cancel()
    for p in (db_path, db_path + "-wal", db_path + "-shm"):
        try:
            os.unlink(p)
        except OSError:
            pass

    passed = sum(1 for _, c in ok if c)
    for name, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(ok)} dedup checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
