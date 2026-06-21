# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Scaling/perf regressions: the changes that let the pool absorb many miners,
rigs, blocks and shares without stalling the event loop.

Covers:
  * shares.coin denormalization + backfill, so the hot pool-wide aggregates
    (hashrate windows, round effort, active counts) are a single (coin, ts) range
    scan instead of a per-miner fan-out through the miners join;
  * the short-TTL snapshot cache (one rebuild per window, not per request);
  * the public miners[] array cap (connected_miners stays exact);
  * prune_shares chunked draining (bounded DELETEs on the event loop).

Run:  python3 tests/scaling.py
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.accounting import Accounting  # noqa: E402
import testnetpool.stats as S  # noqa: E402

ok: list[tuple[str, bool]] = []


def chk(name, cond, extra=""):
    ok.append((name, bool(cond)))
    if not cond and extra:
        print(f"    -> {extra}")


def _tmpdb():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _cleanup(path):
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.unlink(p)
        except OSError:
            pass


def test_coin_aggregates():
    db = _tmpdb()
    try:
        acc = Accounting(db, coin="litecoin")
        now = int(time.time())
        # 3 miners, 9 shares of difficulty 100 each, all within the last minute.
        for i in range(9):
            acc.record_share(f"addr{i % 3}", 100.0, now - i, share_diff=500.0, worker="w")
        win = acc.pool_hashrate_windows(now)
        chk("aggregate: window sum across all miners", win[60] == 900.0, f"got {win[60]}")
        chk("aggregate: longer windows include the same shares", win[86400] == 900.0)
        rd, start = acc.round_share_diff(now)
        chk("aggregate: round diff sums shares since last block", rd == 900.0 and start == 0)
        counts = acc.active_counts(now)
        chk("aggregate: active distinct-miner count", counts["active_miners"] == 3,
            f"got {counts['active_miners']}")
        # every share row carries this coin, and the planner uses the (coin, ts) index.
        coins = acc.conn.execute("SELECT DISTINCT coin FROM shares").fetchall()
        chk("aggregate: shares.coin populated on insert", coins == [("litecoin",)], f"got {coins}")
        plan = " ".join(r[-1] for r in acc.conn.execute(
            "EXPLAIN QUERY PLAN SELECT SUM(difficulty) FROM shares WHERE coin=? AND ts>=?",
            ("litecoin", now - 60)).fetchall())
        chk("aggregate: hot query uses idx_shares_coin_ts (no miners fan-out)",
            "idx_shares_coin_ts" in plan, f"plan: {plan}")
    finally:
        _cleanup(db)


def test_coin_backfill():
    db = _tmpdb()
    try:
        # An OLD DB: shares table with no coin column, one miner, two shares.
        c = sqlite3.connect(db)
        c.executescript(
            "CREATE TABLE miners (id INTEGER PRIMARY KEY, coin TEXT, address TEXT,"
            " last_seen INTEGER DEFAULT 0, UNIQUE(coin,address));"
            "CREATE TABLE shares (id INTEGER PRIMARY KEY, miner_id INTEGER, difficulty REAL,"
            " ts INTEGER, worker TEXT);"
            "INSERT INTO miners(id,coin,address) VALUES (1,'litecoin','addr');"
            f"INSERT INTO shares(miner_id,difficulty,ts,worker) VALUES"
            f" (1,250.0,{int(time.time())},''),(1,250.0,{int(time.time())},'');"
        )
        c.commit()
        c.close()
        acc = Accounting(db, coin="litecoin")  # _migrate adds coin + back-fills from miners
        rows = acc.conn.execute("SELECT coin, COUNT(*) FROM shares GROUP BY coin").fetchall()
        chk("backfill: existing shares get coin from miners", rows == [("litecoin", 2)], f"got {rows}")
        chk("backfill: aggregates see back-filled rows",
            acc.pool_hashrate_windows(int(time.time()))[300] == 500.0)
    finally:
        _cleanup(db)


def test_prune_chunked_drain():
    db = _tmpdb()
    try:
        acc = Accounting(db, coin="litecoin")
        old = int(time.time()) - 90 * 86400          # well past any retention horizon
        for i in range(120):
            acc.record_share("addr", 1.0, old + i)
        for i in range(10):                           # 10 recent rows we must always keep
            acc.record_share("addr", 1.0, int(time.time()) - i)
        before = acc.conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
        cutoff = int(time.time()) - 35 * 86400
        # Drain in tiny chunks; a short read (< chunk) signals the backlog is gone.
        total, rounds = 0, 0
        while True:
            n = acc.prune_shares(cutoff, keep_recent=10, chunk=25)
            total += n
            rounds += 1
            if n < 25:
                break
            if rounds > 50:
                break
        after = acc.conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
        chk("prune: chunked loop drains the old backlog", total == 120 and after == before - 120,
            f"total={total} before={before} after={after}")
        chk("prune: never deletes the kept-recent window", after == 10, f"after={after}")
        chk("prune: took multiple chunks (chunk cap honored)", rounds > 1, f"rounds={rounds}")
    finally:
        _cleanup(db)


def _fake_pool(n_conns):
    class FakeVardiff:
        difficulty = 16.0

    class FakeConn:
        def __init__(self, i):
            self.id = i
            self.worker = f"w{i}"
            self.vardiff = FakeVardiff()
            self.accepted = 1
            self.rejected = 0
            self.best = 0.0
            self.last_share = 0
            self.user_agent = "cpuminer/1.0"

    class FakeCoin:
        algo = "scrypt"
        diff1_target = 1
        hashes_per_diff1 = 65536
        block_time = 150

    pool = types.SimpleNamespace(
        connections=set(FakeConn(i) for i in range(n_conns)),
        cfg=types.SimpleNamespace(
            coin="litecoin", chain="test", mode="public", explorer_url="",
            explorer_tx_url="", include_transactions=False,
            public=types.SimpleNamespace(faucet_address="")),
        coin=FakeCoin(), accounting=None, current_height=1, last_template_ts=0,
        mempool=None, node_health={}, bans=None, network_hashps=None)
    pool.current_job = lambda: None
    return pool


def test_snapshot_cache_and_cap():
    pool = _fake_pool(5000)
    st = S.Stats(pool)
    a = st.snapshot()
    b = st.snapshot()
    chk("cache: returns the same object within the TTL", a is b)
    chk("cap: miners[] capped to MAX_SNAPSHOT_MINERS",
        len(a["miners"]) == S.MAX_SNAPSHOT_MINERS, f"got {len(a['miners'])}")
    chk("cap: connected_miners stays exact", a["connected_miners"] == 5000)
    # Expire the cache -> a fresh object is built.
    st._snap_cache = (time.monotonic() - S.SNAPSHOT_TTL - 0.1, a)
    c = st.snapshot()
    chk("cache: rebuilds after the TTL lapses", c is not a)
    # No miner IPs ever leak through the per-connection array.
    chk("cap: no peer/IP field in serialized miners[]", all("peer" not in m for m in a["miners"]))


def main() -> int:
    test_coin_aggregates()
    test_coin_backfill()
    test_prune_chunked_drain()
    test_snapshot_cache_and_cap()
    passed = sum(1 for _, c in ok if c)
    for name, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(ok)} scaling checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
