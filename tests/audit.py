# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Regression tests for the 2026-06-13 final-audit fixes (deterministic subset).

Covers the release-gating + payout-correctness fixes that are unit-testable without a
live node: the Monero mainnet fail-closed guard, the status-aware credit_block dedup
(so a re-credit after an orphan can't strand credits), orphan removal from the maturity
set, and config validation of non-positive intervals.

Run:  python3 tests/audit.py
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.accounting import Accounting  # noqa: E402
from testnetpool.coin import COINS  # noqa: E402
from testnetpool.config import Config, _validate  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def raises(fn, needle=""):
    try:
        fn()
        return False
    except Exception as e:
        return needle.lower() in str(e).lower()


def main():
    # --- CRITICAL: Monero mainnet is fail-closed -----------------------------
    chk("monero has no mainnet network", "mainnet" not in COINS["monero"].networks
        and set(COINS["monero"].networks) == {"testnet", "stagenet"})
    chk("validate refuses monero+mainnet",
        raises(lambda: _validate(Config(coin="monero", chain="mainnet")), "mainnet"))
    # a testnet monero config is NOT refused by the mainnet guard (reaches later checks)
    chk("validate allows monero+testnet past the mainnet guard",
        not raises(lambda: _validate(Config(coin="monero", chain="testnet")), "refusing mainnet"))

    # --- config: non-positive intervals/timeouts are rejected ----------------
    chk("rejects negative block_poll_interval",
        raises(lambda: _validate(Config(coin="bitcoin", chain="testnet4",
                                        rpc=__import__("testnetpool.config", fromlist=["RPCConfig"]).RPCConfig(user="u", password="p"),
                                        block_poll_interval=-1)), "block_poll_interval"))
    from testnetpool.config import RPCConfig, PublicConfig
    good_rpc = RPCConfig(user="u", password="p")
    chk("rejects zero payout_interval",
        raises(lambda: _validate(Config(coin="bitcoin", chain="testnet4", rpc=good_rpc,
                                        public=PublicConfig(payout_interval=0))), "payout_interval"))
    chk("rejects negative rpc.timeout",
        raises(lambda: _validate(Config(coin="bitcoin", chain="testnet4",
                                        rpc=RPCConfig(user="u", password="p", timeout=-5))), "timeout"))
    chk("rejects negative sweep_after_days",
        raises(lambda: _validate(Config(coin="bitcoin", chain="testnet4", rpc=good_rpc,
                                        public=PublicConfig(sweep_after_days=-1))), "sweep_after_days"))
    chk("sane positive intervals don't trip the interval/timeout guard",
        not raises(lambda: _validate(Config(coin="bitcoin", chain="testnet4", rpc=good_rpc)), "interval")
        and not raises(lambda: _validate(Config(coin="bitcoin", chain="testnet4", rpc=good_rpc)), "must be > 0"))

    # --- accounting: status-aware credit guard + orphan removal --------------
    db = tempfile.mktemp(suffix=".db")
    acc = Accounting(db, "bitcoin")
    NOW = 1_700_000_000
    M, F = "tb1qminer", "tb1qfaucet"
    acc.record_share(M, 1.0, NOW)
    info = acc.credit_block(100, "ab" * 32, 5_000_000_000, 1.0, 1000, F, NOW)
    bid = info["block_id"]
    chk("credit_block credits an immature block", not info.get("duplicate")
        and bid is not None)
    chk("re-crediting an immature block with credits -> duplicate",
        acc.credit_block(100, "ab" * 32, 5_000_000_000, 1.0, 1000, F, NOW).get("duplicate"))
    chk("block is in the immature set", bid in [b["id"] for b in acc.immature_blocks()])

    # orphan it -> credits deleted, status='orphaned', dropped from the maturity set
    acc.orphan_block(bid)
    chk("orphaned block leaves the immature set", bid not in [b["id"] for b in acc.immature_blocks()])
    # THE FIX: re-crediting the SAME (coin,hash) after an orphan must NOT strand new
    # credits against the orphaned block (which could never mature) - it must dedup.
    reinfo = acc.credit_block(100, "ab" * 32, 5_000_000_000, 1.0, 1000, F, NOW)
    chk("re-credit after orphan is refused (status-aware guard)", reinfo.get("duplicate"))
    chk("no credits resurrected against the orphaned block",
        acc.conn.execute("SELECT COUNT(*) FROM credits WHERE block_id=?", (bid,)).fetchone()[0] == 0)
    acc.close()
    try:
        os.unlink(db)
    except OSError:
        pass

    # --- #16: shares pruning keeps recent + young, drops old-beyond-window ----
    db2 = tempfile.mktemp(suffix=".db")
    acc2 = Accounting(db2, "bitcoin")
    OLD, YOUNG = NOW - 40 * 86400, NOW - 86400
    for _ in range(5):
        acc2.record_share("tb1qa", 1.0, OLD)     # ids 1-5 (old, > retention)
    for _ in range(3):
        acc2.record_share("tb1qa", 1.0, YOUNG)   # ids 6-8 (young, within retention)
    deleted = acc2.prune_shares(NOW - 35 * 86400, keep_recent=4)
    remaining = acc2.conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
    chk("prune drops only old shares beyond the keep-recent window",
        deleted == 4 and remaining == 4)
    chk("prune never touches young (within-retention) shares",
        acc2.conn.execute("SELECT COUNT(*) FROM shares WHERE ts=?", (YOUNG,)).fetchone()[0] == 3)
    chk("prune is a no-op when fewer than keep_recent rows",
        acc2.prune_shares(NOW, keep_recent=100) == 0)
    acc2.close()
    try:
        os.unlink(db2)
    except OSError:
        pass

    # --- #10: pending-payout intent lifecycle (crash-window reconcile parts) --
    db3 = tempfile.mktemp(suffix=".db")
    acc3 = Accounting(db3, "bitcoin")
    mid = acc3._miner_id("tb1qx", NOW)
    acc3.conn.execute("INSERT INTO balances(miner_id, owed) VALUES(?,?)", (mid, 1000))
    acc3.conn.commit()
    items = [{"miner_id": mid, "amount": 1000}]
    acc3.begin_payout("c1", items, NOW)
    chk("begin_payout persists a pending intent",
        [p["comment"] for p in acc3.pending_payouts()] == ["c1"]
        and acc3.pending_payouts()[0]["items"] == items)
    acc3.record_payouts(items, "txid1", NOW, comment="c1")
    chk("record_payouts(comment) debits AND clears the intent atomically",
        not acc3.pending_payouts()
        and acc3.conn.execute("SELECT owed FROM balances WHERE miner_id=?", (mid,)).fetchone()[0] == 0)
    acc3.begin_payout("c2", items, NOW)
    acc3.clear_payout("c2")
    chk("clear_payout drops an un-broadcast intent (no debit)", not acc3.pending_payouts())
    acc3.close()
    try:
        os.unlink(db3)
    except OSError:
        pass

    # --- pre-launch fixes: pending-payout txid proof + miner-id gate ----------
    db4 = tempfile.mktemp(suffix=".db")
    acc4 = Accounting(db4, "bitcoin")
    m1, m2 = acc4._miner_id("tb1qa", NOW), acc4._miner_id("tb1qb", NOW)
    acc4.begin_payout("p1", [{"miner_id": m1, "amount": 500}], NOW)
    chk("pending intent has no txid until the send returns one",
        acc4.pending_payouts()[0]["txid"] is None)
    acc4.set_payout_txid("p1", "TXPROOF")
    chk("set_payout_txid records broadcast proof", acc4.pending_payouts()[0]["txid"] == "TXPROOF")
    chk("pending miner-id gate (BTC list intent)", acc4.pending_payout_miner_ids() == {m1})
    # Monero stores {items, before}; the gate must still find its miner_ids
    acc4.begin_payout("p2", {"items": [{"miner_id": m2, "amount": 9}], "before": None}, NOW)
    chk("pending miner-id gate (Monero dict intent)", acc4.pending_payout_miner_ids() == {m1, m2})
    acc4.close()
    try:
        os.unlink(db4)
    except OSError:
        pass

    # --- credit_block is one transaction (the full reward splits or nothing) --
    db5 = tempfile.mktemp(suffix=".db")
    acc5 = Accounting(db5, "bitcoin")
    acc5.record_share("tb1qm", 1.0, NOW)
    cinfo = acc5.credit_block(10, "ee" * 32, 1_000_000_000, 2.0, 1000, "tb1qf", NOW)
    tot = acc5.conn.execute("SELECT COALESCE(SUM(amount),0) FROM credits WHERE block_id=?",
                            (cinfo["block_id"],)).fetchone()[0]
    chk("credit_block splits the FULL reward atomically (miners + faucet remainder)",
        tot == 1_000_000_000)
    acc5.close()
    try:
        os.unlink(db5)
    except OSError:
        pass

    # --- HTTP rate limiting (per-IP sliding window, proxy-aware client IP) ----
    from testnetpool.stats import HttpRateLimiter, client_ip
    rl = HttpRateLimiter(limit=3, window=60.0)
    chk("rate limit: allows up to the limit, then 429s",
        [rl.allow("1.2.3.4", 1000.0) for _ in range(5)] == [True, True, True, False, False])
    chk("rate limit: other IPs are independent", rl.allow("9.9.9.9", 1000.0) is True)
    chk("rate limit: the window slides", rl.allow("1.2.3.4", 1061.0) is True)
    chk("rate limit: 0 disables it", all(HttpRateLimiter(0).allow("x", 1.0) for _ in range(50)))
    chk("client ip: XFF trusted from loopback by default, private only when opted in",
        client_ip("127.0.0.1", "8.8.8.8") == "8.8.8.8"             # loopback proxy -> XFF
        and client_ip("8.8.4.4", "10.0.0.1") == "8.8.4.4"          # direct public -> ignore XFF
        and client_ip("10.0.0.1", "1.1.1.1, 8.8.8.8") == "10.0.0.1"   # private peer -> NOT trusted by default
        and client_ip("10.0.0.1", "1.1.1.1, 8.8.8.8", True) == "8.8.8.8")  # opt-in -> last hop

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} audit-fix checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
