# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""SQLite-backed accounting for public (multi-miner, PPLNS) mode.

Layer 1 records *who mined what*: a row per accepted share, weighted by its
difficulty, keyed to the miner's payout address. Later layers add the PPLNS
split on block maturity, balance carry-forward, and the payout loop; the schema
for those tables is created up front so it stays stable.

Design notes:
- One database file per pool instance (BTC and LTC run separately).  Every query
  is scoped by ``coin`` (the ``shares`` table has no coin column, so reads join
  ``miners`` and filter on ``m.coin``), which keeps a shared DB safe, though the
  intended deployment is still one DB file per coin.
- WAL + ``synchronous=NORMAL``: commits are cheap (no fsync per share), and a
  crash loses at most the last checkpoint's shares, fine for a PPLNS window.
- Calls are synchronous SQLite (sub-millisecond local inserts); at testnet share
  rates that's negligible on the event loop. Can move to a writer thread/queue
  later if a single instance ever gets busy.

Money is stored as integer base units (satoshis / litoshis) everywhere to avoid
float rounding.
"""

from __future__ import annotations

import json
import logging
import sqlite3

log = logging.getLogger("testnetpool.accounting")

SCHEMA = """
CREATE TABLE IF NOT EXISTS miners (
    id         INTEGER PRIMARY KEY,
    coin       TEXT    NOT NULL,
    address    TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    UNIQUE(coin, address)
);
CREATE TABLE IF NOT EXISTS shares (
    id         INTEGER PRIMARY KEY,
    miner_id   INTEGER NOT NULL,
    difficulty REAL    NOT NULL,
    ts         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_id    ON shares(id);
CREATE INDEX IF NOT EXISTS idx_shares_miner ON shares(miner_id);

-- Populated by later layers (PPLNS split, maturity, payouts):
CREATE TABLE IF NOT EXISTS blocks (
    id       INTEGER PRIMARY KEY,
    coin     TEXT    NOT NULL,
    height   INTEGER NOT NULL,
    hash     TEXT    NOT NULL,
    reward   INTEGER NOT NULL,
    found_ts INTEGER NOT NULL,
    status   TEXT    NOT NULL DEFAULT 'immature',  -- immature|matured|orphaned
    UNIQUE(coin, hash)
);
CREATE TABLE IF NOT EXISTS balances (
    miner_id INTEGER PRIMARY KEY,
    owed     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS payouts (
    id       INTEGER PRIMARY KEY,
    miner_id INTEGER NOT NULL,
    amount   INTEGER NOT NULL,
    txid     TEXT,
    ts       INTEGER NOT NULL
);
-- Per-block PPLNS split, applied to balances only when the block matures.
CREATE TABLE IF NOT EXISTS credits (
    id       INTEGER PRIMARY KEY,
    block_id INTEGER NOT NULL,
    miner_id INTEGER NOT NULL,
    amount   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credits_block ON credits(block_id);
-- A payout batch is recorded here BEFORE the wallet send, then cleared atomically
-- with the balance debit. If the process crashes after the send broadcast but before
-- the debit, this row survives so startup can reconcile (find the tx, debit once)
-- instead of re-paying. `items` is the JSON [{miner_id, amount}] of the batch.
CREATE TABLE IF NOT EXISTS pending_payouts (
    comment TEXT PRIMARY KEY,
    items   TEXT    NOT NULL,
    ts      INTEGER NOT NULL,
    txid    TEXT             -- set the instant the wallet send returns a txid (proof it
                             -- broadcast); reconcile uses it directly so it never depends
                             -- on scanning a bounded recent-tx window.
);
"""


class Accounting:
    def __init__(self, db_path: str, coin: str):
        self.coin = coin
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        # Block briefly instead of erroring out when another writer (e.g. the admin CLI
        # racing the live pool) holds the write lock; WAL lets readers through regardless.
        self.conn.execute("PRAGMA busy_timeout=2000")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()
        self._ids: dict[str, int] = {}  # address -> miner_id cache

    def _migrate(self) -> None:
        """Additive, idempotent schema upgrades for existing DBs (ALTER can't be
        IF NOT EXISTS). Adds dashboard columns + indexes; safe to run every start."""
        def cols(table):
            return {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
        if "worker" not in cols("shares"):
            self.conn.execute("ALTER TABLE shares ADD COLUMN worker TEXT")
            # ALTER back-fills existing rows with NULL; normalize to '' so the
            # default worker groups as a single bucket (NULL != '' in SQLite).
            self.conn.execute("UPDATE shares SET worker='' WHERE worker IS NULL")
        # Denormalize coin onto shares so the hot pool-wide aggregates (hashrate windows,
        # round effort, active counts) are a single range scan over idx_shares_coin_ts
        # instead of a per-miner fan-out through the miners join - the difference between
        # ~one indexed scan and O(active_miners x shares) on the event loop. One-time
        # back-fill from miners (PK lookup per row); runs at startup before serving.
        if "coin" not in cols("shares"):
            self.conn.execute("ALTER TABLE shares ADD COLUMN coin TEXT")
            self.conn.execute(
                "UPDATE shares SET coin=(SELECT m.coin FROM miners m WHERE m.id=shares.miner_id) "
                "WHERE coin IS NULL")
        if "best_share" not in cols("miners"):
            self.conn.execute("ALTER TABLE miners ADD COLUMN best_share REAL NOT NULL DEFAULT 0")
        if "net_diff" not in cols("blocks"):
            self.conn.execute("ALTER TABLE blocks ADD COLUMN net_diff REAL")
        if "finder" not in cols("blocks"):
            self.conn.execute("ALTER TABLE blocks ADD COLUMN finder TEXT")
        if "txid" not in cols("pending_payouts"):
            self.conn.execute("ALTER TABLE pending_payouts ADD COLUMN txid TEXT")
        # Per-worker best difficulty (public-pool style): the highest actual share
        # difficulty each rig has reached. Keyed (miner_id, worker); CREATE ... IF
        # NOT EXISTS is itself idempotent, no cols() guard needed.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS workers ("
            "miner_id INTEGER NOT NULL, worker TEXT NOT NULL, "
            "best_share REAL NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY(miner_id, worker))"
        )
        # Indexes that need the new columns must come after the ALTERs.
        for ddl in (
            "CREATE INDEX IF NOT EXISTS idx_shares_ts       ON shares(ts)",
            "CREATE INDEX IF NOT EXISTS idx_shares_miner_ts ON shares(miner_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_shares_worker   ON shares(miner_id, worker, ts)",
            # Pool-wide aggregates filter (coin, ts) directly - one range scan, no miners join.
            "CREATE INDEX IF NOT EXISTS idx_shares_coin_ts  ON shares(coin, ts)",
            "CREATE INDEX IF NOT EXISTS idx_blocks_found_ts ON blocks(coin, found_ts)",
            # payouts/credits are read per-miner (miners_overview's correlated SUM, miner_detail,
            # miner_block_credits). Without these the public dashboard does a full-table scan
            # PER miner row as those (never-pruned) tables grow - an event-loop stall that also
            # blocks share validation. Back-built idempotently on existing DBs at startup.
            "CREATE INDEX IF NOT EXISTS idx_payouts_miner   ON payouts(miner_id)",
            "CREATE INDEX IF NOT EXISTS idx_credits_miner   ON credits(miner_id)",
        ):
            self.conn.execute(ddl)

    def _miner_id(self, address: str, ts: int, bump: bool = True) -> int:
        mid = self._ids.get(address)
        if mid is not None:
            return mid
        if bump:
            self.conn.execute(
                "INSERT INTO miners(coin, address, first_seen, last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(coin, address) DO UPDATE SET last_seen=excluded.last_seen",
                (self.coin, address, ts, ts),
            )
        else:
            # Operator/correction path: create the row if missing, but NEVER bump an existing
            # miner's last_seen - that would defer the idle-sweep and falsely show them active.
            self.conn.execute(
                "INSERT INTO miners(coin, address, first_seen, last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(coin, address) DO NOTHING",
                (self.coin, address, ts, ts),
            )
        row = self.conn.execute(
            "SELECT id FROM miners WHERE coin=? AND address=?", (self.coin, address)
        ).fetchone()
        self._ids[address] = row[0]
        return row[0]

    def record_share(
        self, address: str, difficulty: float, ts: float,
        share_diff: float | None = None, worker: str | None = None,
    ) -> None:
        """Persist one accepted share, weighted by its (pool) difficulty.

        ``share_diff`` is the share's *actual* difficulty (for the best-share
        record); ``worker`` is the optional worker name (suffix after the dot in
        the Stratum username). Both default off for backward compatibility.
        """
        ts = int(ts)
        mid = self._miner_id(address, ts)
        if share_diff is None:
            self.conn.execute("UPDATE miners SET last_seen=? WHERE id=?", (ts, mid))
        else:
            self.conn.execute(
                "UPDATE miners SET last_seen=?, best_share=MAX(best_share, ?) WHERE id=?",
                (ts, float(share_diff), mid),
            )
            # Same write-only-if-higher semantics, but per worker (rig).
            self.conn.execute(
                "INSERT INTO workers(miner_id, worker, best_share, last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(miner_id, worker) DO UPDATE SET "
                "best_share=MAX(best_share, excluded.best_share), last_seen=excluded.last_seen",
                (mid, worker or "", float(share_diff), ts),
            )
        self.conn.execute(
            "INSERT INTO shares(miner_id, difficulty, ts, worker, coin) VALUES(?,?,?,?,?)",
            (mid, difficulty, ts, worker or "", self.coin),
        )
        self.conn.commit()

    # -- Layer 2: PPLNS distribution + maturity ------------------------------

    def credit_block(
        self,
        height: int,
        block_hash: str,
        reward: int,
        fee_percent: float,
        window: int,
        faucet_address: str,
        ts: float,
        net_diff: float | None = None,
        finder: str | None = None,
    ) -> dict:
        """Record a found block and snapshot its PPLNS split into ``credits``.

        Credits are NOT applied to balances yet; that happens in
        :meth:`mature_block` once the block has enough confirmations. ``net_diff``
        is the network difficulty at the time (stored for per-block luck, which
        must use the difficulty of *that* round, not the current one). Returns a
        summary, or ``{"duplicate": True}`` if this block was already recorded.
        """
        ts = int(ts)
        # One transaction: the block row + every credit + the faucet remainder commit
        # together or not at all. A bare commit (the old way) could leave a PARTIAL split
        # on a mid-loop exception, which the status-aware dedup guard then refuses to
        # repair (it sees credits exist) - stranding the rest of the reward.
        with self.conn:
            cur = self.conn
            cur.execute(
                "INSERT OR IGNORE INTO blocks(coin, height, hash, reward, found_ts, status, net_diff, finder) "
                "VALUES(?,?,?,?,?, 'immature', ?, ?)",
                (self.coin, height, block_hash, reward, ts, net_diff, finder),
            )
            block_id, status = cur.execute(
                "SELECT id, status FROM blocks WHERE coin=? AND hash=?", (self.coin, block_hash)
            ).fetchone()
            # Idempotency, STATUS-aware: refuse to re-credit a block that already has credits
            # OR that has left 'immature' (matured / orphaned / stale). Keying only on the
            # credit-row count would let a re-credit after orphan_block() - which DELETEs the
            # credit rows but leaves status='orphaned' - strand fresh credits against a block
            # that can never mature (the maturity loop only scans 'immature' blocks).
            if status != "immature" or cur.execute(
                    "SELECT COUNT(*) FROM credits WHERE block_id=?", (block_id,)).fetchone()[0]:
                return {"duplicate": True, "block_id": block_id}

            rows = cur.execute(
                "SELECT miner_id, SUM(difficulty) FROM "
                "(SELECT s.miner_id, s.difficulty FROM shares s JOIN miners m ON m.id=s.miner_id "
                " WHERE m.coin=? ORDER BY s.id DESC LIMIT ?) GROUP BY miner_id",
                (self.coin, window),
            ).fetchall()
            total_w = sum(w for _, w in rows) or 0.0
            payable = int(reward * (1 - fee_percent / 100.0))
            credited = 0
            if total_w > 0:
                for miner_id, w in rows:
                    amt = int(payable * w / total_w)
                    if amt > 0:
                        cur.execute(
                            "INSERT INTO credits(block_id, miner_id, amount) VALUES(?,?,?)",
                            (block_id, miner_id, amt),
                        )
                        credited += amt
            # Fee + integer rounding remainder -> faucet (paid out like any miner). bump=False:
            # receiving the fee is NOT mining activity, so it must not refresh the faucet's
            # last_seen and make it show "online" in the live view when it isn't mining.
            faucet_id = self._miner_id(faucet_address, ts, bump=False)
            faucet_amt = reward - credited
            cur.execute(
                "INSERT INTO credits(block_id, miner_id, amount) VALUES(?,?,?)",
                (block_id, faucet_id, faucet_amt),
            )
        return {
            "block_id": block_id, "miners": len(rows),
            "to_miners": credited, "to_faucet": faucet_amt,
        }

    def immature_blocks(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, height, hash FROM blocks WHERE coin=? AND status='immature'",
            (self.coin,),
        ).fetchall()
        return [{"id": r[0], "height": r[1], "hash": r[2]} for r in rows]

    def mature_block(self, block_id: int) -> None:
        """Apply a matured block's credits to balances (atomic, idempotent)."""
        with self.conn:
            cur = self.conn
            if not cur.execute(
                "SELECT 1 FROM blocks WHERE id=? AND status='immature'", (block_id,)
            ).fetchone():
                return  # already matured/orphaned; don't double-apply
            for miner_id, amount in cur.execute(
                "SELECT miner_id, amount FROM credits WHERE block_id=?", (block_id,)
            ).fetchall():
                cur.execute(
                    "INSERT INTO balances(miner_id, owed) VALUES(?,?) "
                    "ON CONFLICT(miner_id) DO UPDATE SET owed=owed+excluded.owed",
                    (miner_id, amount),
                )
            cur.execute("UPDATE blocks SET status='matured' WHERE id=?", (block_id,))

    def orphan_block(self, block_id: int) -> None:
        """Drop an orphaned block's credits (never applied, nothing to reverse)."""
        with self.conn:
            self.conn.execute("DELETE FROM credits WHERE block_id=?", (block_id,))
            self.conn.execute(
                "UPDATE blocks SET status='orphaned' WHERE id=? AND status='immature'",
                (block_id,),
            )

    def record_stale_block(self, height: int, block_hash: str, reward: int, ts: float,
                           net_diff: float | None = None, finder: str | None = None) -> None:
        """Record a block we solved but that lost the propagation race (submitblock
        'inconclusive'/'duplicate' - a stale/orphan). Persisted for transparency, but
        NEVER credited: status='stale' creates no PPLNS round, so it pays nobody."""
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO blocks(coin, height, hash, reward, found_ts, status, "
                "net_diff, finder) VALUES(?,?,?,?,?, 'stale', ?, ?)",
                (self.coin, height, block_hash, reward, int(ts), net_diff, finder),
            )

    def block_counts(self) -> dict:
        """Block tallies for the dashboard: won (matured+immature) vs lost
        (orphaned+stale), and the orphan rate over everything we solved."""
        rows = dict(self.conn.execute(
            "SELECT status, COUNT(*) FROM blocks WHERE coin=? GROUP BY status",
            (self.coin,)).fetchall())
        matured, immature = rows.get("matured", 0), rows.get("immature", 0)
        orphaned, stale = rows.get("orphaned", 0), rows.get("stale", 0)
        won, lost = matured + immature, orphaned + stale
        solved = won + lost
        return {
            "won": won, "matured": matured, "immature": immature,
            "orphaned": orphaned, "stale": stale, "solved": solved,
            "orphan_rate": round(lost / solved * 100, 1) if solved else None,
        }

    # -- Layer 3: payouts + sweep -------------------------------------------

    def payable(self, min_amount: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT b.miner_id, m.address, b.owed FROM balances b "
            "JOIN miners m ON m.id=b.miner_id WHERE b.owed >= ? ORDER BY b.owed DESC",
            (min_amount,),
        ).fetchall()
        return [{"miner_id": r[0], "address": r[1], "owed": r[2]} for r in rows]

    def _fsync_durable(self) -> None:
        """Force the WAL to the main db file and fsync it. synchronous=NORMAL (chosen for
        the high-rate shares table) does NOT fsync on COMMIT, so a payout intent/txid would
        survive an application crash but not an OS/power loss before the next checkpoint -
        and losing it AFTER the broadcast double-pays. A FULL checkpoint under NORMAL fsyncs
        the db file, making these low-rate, money-critical rows durable before the send."""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(FULL)")
        except sqlite3.Error:
            log.warning("payout-intent checkpoint failed; intent is committed but may not be "
                        "fsynced until the next checkpoint", exc_info=True)

    def begin_payout(self, comment: str, items: list[dict], ts: float) -> None:
        """Persist a payout batch's intent BEFORE the wallet send, so a crash between
        the broadcast and the balance debit is recoverable (vs. silently re-paying)."""
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO pending_payouts(comment, items, ts) VALUES(?,?,?)",
                (comment, json.dumps(items), int(ts)),
            )
        self._fsync_durable()  # intent must be on disk before the caller broadcasts

    def set_payout_txid(self, comment: str, txid: str) -> None:
        """Record the wallet txid the instant the send returns it - PROOF the batch
        broadcast. Reconcile uses this to debit-once without scanning the wallet."""
        with self.conn:
            self.conn.execute("UPDATE pending_payouts SET txid=? WHERE comment=?",
                              (txid, comment))
        self._fsync_durable()  # the broadcast proof must outlive a power loss

    def clear_payout(self, comment: str) -> None:
        """Drop a pending intent that DEFINITELY never broadcast (retried next round)."""
        with self.conn:
            self.conn.execute("DELETE FROM pending_payouts WHERE comment=?", (comment,))

    def pending_payouts(self) -> list[dict]:
        """Payout batches recorded but not yet confirmed-and-debited (for reconcile).
        Returns [{comment, items, ts, txid}] - txid is None until the send returns one."""
        rows = self.conn.execute(
            "SELECT comment, items, ts, txid FROM pending_payouts ORDER BY ts"
        ).fetchall()
        return [{"comment": r[0], "items": json.loads(r[1]), "ts": r[2], "txid": r[3]}
                for r in rows]

    def pending_payout_miner_ids(self) -> set:
        """Every miner_id named in an unresolved pending intent. The live payout loop
        excludes these so an in-flight (not-yet-reconciled) batch can't be paid twice.
        Handles both intent shapes: a bare list (BTC/LTC) and {items, before} (Monero)."""
        out: set = set()
        for r in self.conn.execute("SELECT items FROM pending_payouts").fetchall():
            data = json.loads(r[0])
            rows = data.get("items", []) if isinstance(data, dict) else data
            for it in rows:
                if isinstance(it, dict) and "miner_id" in it:
                    out.add(it["miner_id"])
        return out

    def record_payouts(self, items: list[dict], txid: str, ts: float,
                       comment: str | None = None) -> None:
        """Decrement balances + log payouts, and clear the batch's pending intent -
        all in ONE transaction so the debit and the intent-clear are exactly-once
        (a crash mid-way rolls both back; startup reconcile then re-does it)."""
        ts = int(ts)
        with self.conn:
            if comment is not None:
                # Idempotency gate: a payout intent must be debited EXACTLY once. Delete the
                # pending intent FIRST and gate the debit on having actually removed it. If
                # it's already gone - the live reconciler raced the admin CLI, or this is a
                # double-call - the debit is skipped. Without this, two writers each running
                # the unconditional UPDATE below would debit one on-chain payout twice
                # (WAL serializes the writes but neither would gate on the intent). Every
                # comment-bearing call is preceded by begin_payout, so the first writer always
                # finds rowcount==1 and debits; only a redundant second writer is skipped.
                cur = self.conn.execute(
                    "DELETE FROM pending_payouts WHERE comment=?", (comment,))
                if cur.rowcount != 1:
                    return
            for it in items:
                # Clamp at 0 so a stale/oversized item can't drive a balance
                # negative (which would become a phantom credit at next maturity).
                self.conn.execute(
                    "UPDATE balances SET owed=MAX(0, owed-?) WHERE miner_id=?",
                    (it["amount"], it["miner_id"]),
                )
                self.conn.execute(
                    "INSERT INTO payouts(miner_id, amount, txid, ts) VALUES(?,?,?,?)",
                    (it["miner_id"], it["amount"], txid, ts),
                )

    def adjust_balance(self, address: str, delta: int, ts: float) -> int:
        """Operator correction: credit (delta>0) or debit (delta<0) a miner's owed balance.
        Clamps at 0 (never negative), creates the miner row if needed, atomic. Returns the
        new owed balance. Used by the admin CLI, never by the mining/payout paths."""
        mid = self._miner_id(address, int(ts), bump=False)
        with self.conn:
            self.conn.execute(
                "INSERT INTO balances(miner_id, owed) VALUES(?, MAX(0, ?)) "
                "ON CONFLICT(miner_id) DO UPDATE SET owed = MAX(0, owed + ?)",
                (mid, delta, delta),
            )
            row = self.conn.execute(
                "SELECT owed FROM balances WHERE miner_id=?", (mid,)).fetchone()
        return row[0] if row else 0

    def sweep_stale(self, idle_cutoff_ts: int, faucet_address: str, ts: float) -> int:
        """Move balances of miners idle since ``idle_cutoff_ts`` to the faucet."""
        faucet_id = self._miner_id(faucet_address, int(ts), bump=False)  # not mining -> no last_seen bump
        # Never sweep a balance that is named in an unresolved payout intent. The live
        # payout loop already excludes these; the sweep must too, or a balance that was
        # broadcast-but-left-pending (the indeterminate reconcile branch) could be both
        # paid on-chain AND credited to the faucet - an unreconcilable over-credit.
        pending = self.pending_payout_miner_ids()
        with self.conn:
            rows = self.conn.execute(
                "SELECT b.miner_id, b.owed FROM balances b JOIN miners m ON m.id=b.miner_id "
                "WHERE m.last_seen < ? AND b.owed > 0 AND b.miner_id != ?",
                (idle_cutoff_ts, faucet_id),
            ).fetchall()
            rows = [(mid, owed) for mid, owed in rows if mid not in pending]
            swept = sum(owed for _, owed in rows)
            for miner_id, _ in rows:
                self.conn.execute("UPDATE balances SET owed=0 WHERE miner_id=?", (miner_id,))
            if swept:
                self.conn.execute(
                    "INSERT INTO balances(miner_id, owed) VALUES(?,?) "
                    "ON CONFLICT(miner_id) DO UPDATE SET owed=owed+excluded.owed",
                    (faucet_id, swept),
                )
        return swept

    def prune_shares(self, before_ts: int, keep_recent: int, chunk: int = 20000) -> int:
        """Bound the otherwise insert-only shares table. Deletes shares older than
        ``before_ts`` but ALWAYS keeps the ``keep_recent`` most-recent rows (one full
        PPLNS window) regardless of age, and never touches anything newer than
        before_ts. The caller sets before_ts past the longest dashboard chart window
        (~30 days) so pruning can't blank a chart. Returns the number of rows deleted.

        Deletes at most ``chunk`` (oldest-first) rows per call: this is synchronous SQLite on
        the event loop, so one unbounded DELETE of a large first-prune backlog could stall the
        whole pool. A return of exactly ``chunk`` means more remain; the maintenance loop drains
        the rest on later cycles (or in a yielding loop)."""
        with self.conn:
            # The id of the keep_recent-th most-recent share: everything with a smaller
            # id is beyond the retained window and eligible (if also old enough).
            row = self.conn.execute(
                "SELECT id FROM shares ORDER BY id DESC LIMIT 1 OFFSET ?", (keep_recent,)
            ).fetchone()
            if row is None:
                return 0  # fewer than keep_recent rows total - keep everything
            cur = self.conn.execute(
                "DELETE FROM shares WHERE id IN ("
                "  SELECT id FROM shares WHERE ts < ? AND id <= ? ORDER BY id LIMIT ?)",
                (int(before_ts), row[0], int(chunk)))
            return cur.rowcount

    # -- Layer 4: read queries for the JSON API -----------------------------

    def miners_overview(self, limit: int = 500, exclude: str = "",
                        exclude_active_since: int | None = None) -> list[dict]:
        # ``exclude`` drops one address (the faucet) from the miners leaderboard - it's
        # the pool's fee sink, not a miner, so it shouldn't sit in "Top miners" with 0
        # shares. ('' excludes nothing, since no real address is empty.)
        # EXCEPTION for transparency: if ``exclude_active_since`` is given and the excluded
        # address has LIVE hashrate (last_seen >= that cutoff - e.g. the operator topping the
        # faucet up), show it after all (it's badged "faucet" in the UI). None => always
        # exclude (an impossibly-future cutoff the OR can never satisfy).
        cutoff = exclude_active_since if exclude_active_since is not None else (1 << 62)
        rows = self.conn.execute(
            "SELECT m.address, COALESCE(b.owed,0), "
            "(SELECT COALESCE(SUM(p.amount),0) FROM payouts p WHERE p.miner_id=m.id), "
            "m.last_seen, "
            "(SELECT COUNT(*) FROM shares s WHERE s.miner_id=m.id), "
            "m.best_share "
            "FROM miners m LEFT JOIN balances b ON b.miner_id=m.id "
            "WHERE m.coin=? AND (m.address != ? OR m.last_seen >= ?) ORDER BY m.last_seen DESC LIMIT ?",
            (self.coin, exclude, cutoff, limit),
        ).fetchall()
        return [
            {"address": r[0], "owed": r[1], "paid": r[2], "last_seen": r[3],
             "shares": r[4], "best_share": r[5]}
            for r in rows
        ]

    def best_shares(self, limit: int = 10) -> list[dict]:
        """High-score leaderboard: addresses ranked by their best-ever share
        difficulty (public-pool style). Keyed on public addresses only."""
        rows = self.conn.execute(
            "SELECT address, best_share FROM miners "
            "WHERE coin=? AND best_share > 0 ORDER BY best_share DESC LIMIT ?",
            (self.coin, limit),
        ).fetchall()
        return [{"address": r[0], "best_share": r[1]} for r in rows]

    def miner_detail(self, address: str) -> dict | None:
        row = self.conn.execute(
            "SELECT id, first_seen, last_seen, best_share FROM miners WHERE coin=? AND address=?",
            (self.coin, address),
        ).fetchone()
        if not row:
            return None
        mid, first, last, best = row
        owed_row = self.conn.execute(
            "SELECT owed FROM balances WHERE miner_id=?", (mid,)
        ).fetchone()
        paid = self.conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM payouts WHERE miner_id=?", (mid,)
        ).fetchone()[0]
        shares = self.conn.execute(
            "SELECT COUNT(*) FROM shares WHERE miner_id=?", (mid,)
        ).fetchone()[0]
        payouts = [
            {"amount": a, "txid": t, "ts": ts}
            for a, t, ts in self.conn.execute(
                "SELECT amount, txid, ts FROM payouts WHERE miner_id=? ORDER BY id DESC LIMIT 25",
                (mid,),
            ).fetchall()
        ]
        return {
            "address": address, "first_seen": first, "last_seen": last,
            "owed": owed_row[0] if owed_row else 0, "paid": paid,
            "shares": shares, "best_share": best or 0.0, "recent_payouts": payouts,
        }

    # -- Dashboard reads: hashrate windows, luck/effort, worker breakdown -----

    def pool_hashrate_windows(self, now: int, windows=(60, 300, 3600, 86400)) -> dict:
        """{window_seconds: sum(difficulty)} across all miners of this coin.

        The caller multiplies by ``coin.hashes_per_diff1 / window`` to get H/s;
        accounting stays coin-agnostic and never imports the multiplier.
        """
        out = {}
        for w in windows:
            # coin denormalized onto shares -> single range scan on idx_shares_coin_ts,
            # not a per-miner fan-out through the miners join (see _migrate).
            out[w] = self.conn.execute(
                "SELECT COALESCE(SUM(difficulty),0.0) FROM shares WHERE coin=? AND ts>=?",
                (self.coin, now - w),
            ).fetchone()[0]
        return out

    def miner_hashrate_windows(self, address: str, now: int, windows=(300, 3600, 86400)) -> dict:
        """{window_seconds: sum(difficulty)} for one miner (caller multiplies)."""
        out = {}
        for w in windows:
            out[w] = self.conn.execute(
                "SELECT COALESCE(SUM(s.difficulty),0.0) FROM shares s "
                "JOIN miners m ON m.id=s.miner_id WHERE m.coin=? AND m.address=? AND s.ts>=?",
                (self.coin, address, now - w),
            ).fetchone()[0]
        return out

    def round_share_diff(self, now: int) -> tuple[float, int]:
        """(sum of share difficulty since the last non-orphaned block, round_start_ts).

        round_start is 0 when no block has ever been found (counts all shares).
        """
        start = self.conn.execute(
            "SELECT COALESCE(MAX(found_ts),0) FROM blocks WHERE coin=? AND status!='orphaned'",
            (self.coin,),
        ).fetchone()[0]
        diff = self.conn.execute(
            "SELECT COALESCE(SUM(difficulty),0.0) FROM shares WHERE coin=? AND ts>?",
            (self.coin, start),
        ).fetchone()[0]
        return diff, start

    def active_counts(self, now: int, window: int = 600) -> dict:
        """Miners with a share in the last ``window`` s, plus total known."""
        active = self.conn.execute(
            "SELECT COUNT(DISTINCT miner_id) FROM shares WHERE coin=? AND ts>=?",
            (self.coin, now - window),
        ).fetchone()[0]
        known = self.conn.execute(
            "SELECT COUNT(*) FROM miners WHERE coin=?", (self.coin,)
        ).fetchone()[0]
        return {"active_miners": active, "known_miners": known, "window": window}

    def pool_best_share(self) -> float:
        return self.conn.execute(
            "SELECT COALESCE(MAX(best_share),0.0) FROM miners WHERE coin=?", (self.coin,)
        ).fetchone()[0]

    def block_luck(self, limit: int = 50) -> list[dict]:
        """Per found-block round difficulty + luck%.  A window-function LAG over
        ``found_ts`` bounds each block's round; orphans are excluded.

        luck% = round_share_diff / net_diff * 100 (using the block's *own* net_diff).
        """
        # Round boundaries (LAG) are computed over WON blocks only (matured/immature),
        # so an orphaned/stale block can't split a neighbour's round. Every block is
        # still returned for the dashboard; lost ones get round_diff/luck = NULL.
        rows = self.conn.execute(
            "WITH won AS (SELECT id, found_ts, "
            "  LAG(found_ts, 1, 0) OVER (ORDER BY found_ts, id) AS prev_ts "
            "  FROM blocks WHERE coin=? AND status IN ('matured','immature')) "
            "SELECT b.height, b.hash, b.reward, b.found_ts, b.status, b.net_diff, "
            "  CASE WHEN w.id IS NOT NULL THEN "
            "    (SELECT COALESCE(SUM(s.difficulty),0.0) FROM shares s "
            "     JOIN miners m ON m.id=s.miner_id "
            "     WHERE m.coin=? AND s.ts>w.prev_ts AND s.ts<=b.found_ts) "
            "  ELSE NULL END AS round_diff "
            "FROM blocks b LEFT JOIN won w ON w.id=b.id "
            "WHERE b.coin=? ORDER BY b.found_ts DESC, b.id DESC LIMIT ?",
            (self.coin, self.coin, self.coin, limit),
        ).fetchall()
        out = []
        for h, hsh, rew, fts, st, nd, rd in rows:
            luck = round(rd / nd * 100, 2) if (rd is not None and nd) else None
            out.append({
                "height": h, "hash": hsh, "reward": rew, "found_ts": fts,
                "status": st, "net_diff": nd, "round_diff": rd, "luck_percent": luck,
            })
        return out

    def block_detail(self, height: int) -> dict | None:
        """Full detail for one found block: round difficulty, luck, finder, and how
        many miners its PPLNS split credited.  ``height`` may have been re-found
        after an orphan, so the most recent row at that height wins."""
        row = self.conn.execute(
            "SELECT id, height, hash, reward, found_ts, status, net_diff, finder "
            "FROM blocks WHERE coin=? AND height=? ORDER BY id DESC LIMIT 1",
            (self.coin, height),
        ).fetchone()
        if not row:
            return None
        bid, h, hsh, rew, fts, st, nd, finder = row
        # The round this block closed runs from the previous non-orphaned block's
        # found_ts (0 if none) up to and including this block's found_ts.
        prev = self.conn.execute(
            "SELECT COALESCE(MAX(found_ts),0) FROM blocks WHERE coin=? AND status!='orphaned' "
            "AND (found_ts<? OR (found_ts=? AND id<?))",
            (self.coin, fts, fts, bid),
        ).fetchone()[0]
        rd = self.conn.execute(
            "SELECT COALESCE(SUM(s.difficulty),0.0) FROM shares s JOIN miners m ON m.id=s.miner_id "
            "WHERE m.coin=? AND s.ts>? AND s.ts<=?",
            (self.coin, prev, fts),
        ).fetchone()[0]
        # The per-miner PPLNS split for this block (address + amount), biggest first.
        # Orphaned blocks have had their credits deleted, so this is empty for them.
        creds = self.conn.execute(
            "SELECT m.address, c.amount FROM credits c JOIN miners m ON m.id=c.miner_id "
            "WHERE c.block_id=? ORDER BY c.amount DESC", (bid,)
        ).fetchall()
        return {
            "height": h, "hash": hsh, "reward": rew, "found_ts": fts, "status": st,
            "net_diff": nd, "finder": finder, "round_diff": rd,
            "luck_percent": round(rd / nd * 100, 2) if nd else None,
            "credited_miners": len(creds),
            "credits": [{"address": a, "amount": amt} for a, amt in creds],
        }

    def miner_block_credits(self, address: str, limit: int = 50) -> list[dict]:
        """Per-block credits this miner earned (its PPLNS slice of each block), newest
        first, with the block's status so the miner can see PENDING (immature, not-yet-
        paid) earnings distinctly from matured ones. Orphaned blocks drop out (their
        credits are deleted)."""
        rows = self.conn.execute(
            "SELECT b.height, b.hash, b.status, b.found_ts, c.amount "
            "FROM credits c JOIN blocks b ON b.id=c.block_id JOIN miners m ON m.id=c.miner_id "
            "WHERE m.coin=? AND m.address=? ORDER BY b.id DESC LIMIT ?",
            (self.coin, address, limit),
        ).fetchall()
        return [{"height": h, "hash": hsh, "status": st, "found_ts": fts, "amount": amt}
                for h, hsh, st, fts, amt in rows]

    def hashrate_series(self, now: int, span: int = 86400, buckets: int = 48,
                        address: str | None = None, worker: str | None = None) -> dict:
        """Time-bucketed share-difficulty sums for a hashrate chart.

        Splits the last ``span`` seconds into ``buckets`` equal buckets and sums
        share difficulty in each (optionally for one ``address``, and within it one
        ``worker``). Empty buckets are 0. The caller turns each ``diff`` into H/s via
        ``diff * hashes_per_diff1 / bucket_width``. Derived live from ``shares``,
        no separate time-series table to keep.
        """
        now = int(now)
        bw = max(span // buckets, 1)
        start = now - bw * buckets
        sql = (
            "SELECT CAST((s.ts - :start) / :bw AS INTEGER) AS b, "
            "       COALESCE(SUM(s.difficulty),0.0) "
            "FROM shares s JOIN miners m ON m.id=s.miner_id "
            "WHERE m.coin=:coin AND s.ts>=:start AND s.ts<:now "
            + ("AND m.address=:addr " if address is not None else "")
            + ("AND COALESCE(s.worker,'')=:worker " if worker is not None else "")
            + "GROUP BY b"
        )
        params = {"start": start, "bw": bw, "coin": self.coin, "now": now}
        if address is not None:
            params["addr"] = address
        if worker is not None:
            params["worker"] = worker
        by_bucket = {int(b): d for b, d in self.conn.execute(sql, params).fetchall()}
        points = [{"ts": start + i * bw + bw // 2, "diff": by_bucket.get(i, 0.0)}
                  for i in range(buckets)]
        return {"bucket_width": bw, "span": span, "points": points}

    def worker_breakdown(self, address: str, now: int, windows=(300, 3600, 86400),
                         limit: int = 100) -> list[dict]:
        """Per-worker rolling diff sums + last_seen + share count for one address.

        Caller multiplies the diff sums by ``hashes_per_diff1 / window`` for H/s.
        ``COALESCE(worker,'')`` merges legacy-NULL and '' into one default bucket;
        ``limit`` bounds the result (worker names are caller-supplied).
        """
        w5, w1h, w24 = windows
        rows = self.conn.execute(
            "SELECT COALESCE(s.worker,''), "
            " SUM(CASE WHEN s.ts>=? THEN s.difficulty ELSE 0 END), "
            " SUM(CASE WHEN s.ts>=? THEN s.difficulty ELSE 0 END), "
            " SUM(CASE WHEN s.ts>=? THEN s.difficulty ELSE 0 END), "
            " MAX(s.ts), COUNT(*), "
            " COALESCE(MAX(wk.best_share), 0.0) "
            "FROM shares s JOIN miners m ON m.id=s.miner_id "
            "LEFT JOIN workers wk ON wk.miner_id=s.miner_id AND wk.worker=COALESCE(s.worker,'') "
            "WHERE m.coin=? AND m.address=? GROUP BY COALESCE(s.worker,'') "
            "ORDER BY 2 DESC LIMIT ?",
            (now - w5, now - w1h, now - w24, self.coin, address, limit),
        ).fetchall()
        return [
            {"worker": (w or "(default)"), "diff": {w5: d5, w1h: d1h, w24: d24},
             "last_seen": ls, "shares": n, "best_share": best}
            for w, d5, d1h, d24, ls, n, best in rows
        ]

    def worker_detail(self, address: str, worker: str, now: int,
                      windows=(300, 3600, 86400)) -> dict | None:
        """One rig's stats: best share, share count, first/last seen, and rolling
        diff sums (for hashrate). ``worker`` is the raw key ('' = default rig).
        None if that rig has no shares on record."""
        w5, w1h, w24 = windows
        row = self.conn.execute(
            "SELECT COUNT(*), MIN(s.ts), MAX(s.ts), COALESCE(MAX(wk.best_share),0.0), "
            " SUM(CASE WHEN s.ts>=? THEN s.difficulty ELSE 0 END), "
            " SUM(CASE WHEN s.ts>=? THEN s.difficulty ELSE 0 END), "
            " SUM(CASE WHEN s.ts>=? THEN s.difficulty ELSE 0 END) "
            "FROM shares s JOIN miners m ON m.id=s.miner_id "
            "LEFT JOIN workers wk ON wk.miner_id=s.miner_id AND wk.worker=COALESCE(s.worker,'') "
            "WHERE m.coin=? AND m.address=? AND COALESCE(s.worker,'')=?",
            (now - w5, now - w1h, now - w24, self.coin, address, worker),
        ).fetchone()
        n, first, last, best, d5, d1h, d24 = row
        if not n:
            return None
        return {"address": address, "worker": worker, "shares": n,
                "first_seen": first, "last_seen": last, "best_share": best,
                "diff": {w5: d5 or 0.0, w1h: d1h or 0.0, w24: d24 or 0.0}}

    def recent_blocks(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT height, hash, reward, found_ts, status FROM blocks WHERE coin=? "
            "ORDER BY height DESC LIMIT ?",
            (self.coin, limit),
        ).fetchall()
        return [
            {"height": r[0], "hash": r[1], "reward": r[2], "found_ts": r[3], "status": r[4]}
            for r in rows
        ]

    def blocks_found(self) -> int:
        """Won blocks (matured + immature) - the count that actually pays, persisted
        so it survives restarts. Orphaned/stale are excluded here; see block_counts()
        for the orphan rate."""
        return self.conn.execute(
            "SELECT COUNT(*) FROM blocks WHERE coin=? AND status IN ('matured','immature')",
            (self.coin,),
        ).fetchone()[0]

    def recent_payouts(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT m.address, p.amount, p.txid, p.ts FROM payouts p "
            "JOIN miners m ON m.id=p.miner_id WHERE m.coin=? ORDER BY p.id DESC LIMIT ?",
            (self.coin, limit),
        ).fetchall()
        return [{"address": r[0], "amount": r[1], "txid": r[2], "ts": r[3]} for r in rows]

    def summary(self) -> dict:
        miners = self.conn.execute(
            "SELECT COUNT(*) FROM miners WHERE coin=?", (self.coin,)
        ).fetchone()[0]
        shares = self.conn.execute(
            "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.coin=?",
            (self.coin,),
        ).fetchone()[0]
        blocks = self.conn.execute(
            "SELECT status, COUNT(*) FROM blocks WHERE coin=? GROUP BY status", (self.coin,)
        ).fetchall()
        return {
            "miners_known": miners,
            "shares_recorded": shares,
            "blocks": {status: n for status, n in blocks},
        }

    def close(self) -> None:
        try:
            self.conn.commit()
            self.conn.close()
        except sqlite3.Error:
            pass
