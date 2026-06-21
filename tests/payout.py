# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Payout-verify regression: a sendmany whose RPC reply times out must NOT cause a
double-pay.

The block-submit path already verifies an ambiguous (timed-out) submit against the
chain before deciding win/loss. This test asserts the payout path now mirrors that:
Pool._do_payouts tags each batch with a unique comment and, when sendmany raises
RPCTimeout, looks the batch up via listtransactions (find_wallet_tx) before deciding
whether to debit balances.

  * normal send         -> balances debited, payout recorded with the real txid
  * timeout + tx found  -> recovered: balances debited exactly once (no re-send)
  * timeout + not found  -> NOT debited: the batch is retried next round, not lost twice

Run:  python3 tests/payout.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.config import (  # noqa: E402
    Config, PublicConfig, RPCConfig, StatsConfig, VardiffConfig,
)
from testnetpool.pool import COIN, Pool  # noqa: E402
from testnetpool.rpc import RPCTimeout  # noqa: E402
from testnetpool.selftest import _bech32_encode  # noqa: E402

MINER_ADDR = _bech32_encode("rltc", 0, b"\x11" * 20)
POOL_ADDR = _bech32_encode("rltc", 0, b"\x22" * 20)
FAUCET_ADDR = _bech32_encode("rltc", 0, b"\x33" * 20)

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


class PayoutRPC:
    """Wallet RPC stub with switchable sendmany behaviour."""

    def __init__(self):
        self.mode = "ok"          # "ok" | "timeout_sent" | "timeout_unsent"
        self.balance = 100.0
        self.sent = []            # comments that actually broadcast
        self.calls = 0

    async def get_balance(self):
        return self.balance

    async def send_many(self, outputs, comment=""):
        self.calls += 1
        if self.mode == "ok":
            self.sent.append(comment)
            return "tx_ok_" + comment
        if self.mode == "timeout_sent":
            self.sent.append(comment)        # broadcast, but the reply is lost
            raise RPCTimeout("sendmany timed out")
        raise RPCTimeout("sendmany timed out")  # timeout_unsent: never broadcast

    async def find_wallet_tx(self, comment, count=100):
        return ("tx_recovered_" + comment) if comment in self.sent else ""


def _owed(acc, address):
    row = acc.conn.execute(
        "SELECT b.owed FROM balances b JOIN miners m ON m.id=b.miner_id WHERE m.address=?",
        (address,),
    ).fetchone()
    return row[0] if row else 0


def _seed_balance(acc, address, owed):
    mid = acc._miner_id(address, int(time.time()))
    acc.conn.execute(
        "INSERT INTO balances(miner_id, owed) VALUES(?,?) "
        "ON CONFLICT(miner_id) DO UPDATE SET owed=excluded.owed",
        (mid, owed),
    )
    acc.conn.commit()


async def main() -> int:
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    cfg = Config(
        coin="litecoin", chain="regtest", mode="public",
        rpc=RPCConfig(host="127.0.0.1", port=19443, user="x", password="y"),
        vardiff=VardiffConfig(enabled=False),
        stats=StatsConfig(enabled=False),
        public=PublicConfig(db_path=db_path, pool_address=POOL_ADDR,
                            faucet_address=FAUCET_ADDR, min_payout=0.001),
    )
    pool = Pool(cfg, serve_stats=False)
    rpc = PayoutRPC()
    pool.rpc = rpc  # type: ignore[assignment]
    acc = pool.accounting
    owed = int(1.0 * COIN)  # 1 whole coin owed

    # 1) Normal send: balance is debited and the payout is recorded.
    _seed_balance(acc, MINER_ADDR, owed)
    rpc.mode = "ok"
    await pool._do_payouts(int(cfg.public.min_payout * COIN))
    chk("normal: balance debited to 0", _owed(acc, MINER_ADDR) == 0)
    chk("normal: payout row recorded", acc.recent_payouts()[0]["amount"] == owed)
    payouts_after_normal = len(acc.recent_payouts())

    # 2) Timeout but the tx DID broadcast: recovered via find_wallet_tx, debited once.
    _seed_balance(acc, MINER_ADDR, owed)
    rpc.mode = "timeout_sent"
    before_calls = rpc.calls
    await pool._do_payouts(int(cfg.public.min_payout * COIN))
    chk("timeout+found: balance debited exactly once", _owed(acc, MINER_ADDR) == 0)
    chk("timeout+found: recorded the recovered txid",
        acc.recent_payouts()[0]["txid"].startswith("tx_recovered_"))
    chk("timeout+found: only one sendmany attempt", rpc.calls - before_calls == 1)

    # 3) Timeout and the tx did NOT broadcast: balance preserved, nothing recorded.
    _seed_balance(acc, MINER_ADDR, owed)
    rpc.mode = "timeout_unsent"
    payouts_before = len(acc.recent_payouts())
    await pool._do_payouts(int(cfg.public.min_payout * COIN))
    chk("timeout+unsent: balance NOT debited (retried next round)",
        _owed(acc, MINER_ADDR) == owed)
    chk("timeout+unsent: no payout row recorded",
        len(acc.recent_payouts()) == payouts_before)

    # 3b) Stranded pending intent (broadcast-but-not-debited before a crash) must NOT be
    #     re-paid by the live loop: _do_payouts skips any miner with an unresolved intent.
    _seed_balance(acc, MINER_ADDR, owed)
    mid = acc._miner_id(MINER_ADDR, int(time.time()))
    acc.begin_payout("stranded-1", [{"miner_id": mid, "amount": owed}], time.time())
    rpc.mode = "ok"
    calls_before = rpc.calls
    await pool._do_payouts(int(cfg.public.min_payout * COIN))
    chk("stranded: in-flight miner is NOT paid again (no double-pay)",
        rpc.calls == calls_before and _owed(acc, MINER_ADDR) == owed)

    # 3c) Reconcile resolves it via the persisted txid (proof of broadcast): debits ONCE,
    #     no wallet scan (this is the fix for the 100-tx-window blind spot).
    acc.set_payout_txid("stranded-1", "tx_proof_stranded")
    await pool._reconcile_pending_payouts()
    chk("reconcile(txid): debits once + clears the intent",
        _owed(acc, MINER_ADDR) == 0 and not acc.pending_payouts())
    chk("reconcile(txid): recorded the persisted txid",
        acc.recent_payouts()[0]["txid"] == "tx_proof_stranded")

    # 3d) Indeterminate reconcile (no txid AND tx not in the wallet) must LEAVE it pending,
    #     never clear-and-risk-a-double-pay.
    _seed_balance(acc, MINER_ADDR, owed)
    mid = acc._miner_id(MINER_ADDR, int(time.time()))
    acc.begin_payout("indeterminate-1", [{"miner_id": mid, "amount": owed}], time.time())
    await pool._reconcile_pending_payouts()  # find_wallet_tx('indeterminate-1') -> '' (never sent)
    chk("reconcile(indeterminate): left pending, NOT debited or cleared",
        _owed(acc, MINER_ADDR) == owed
        and any(p["comment"] == "indeterminate-1" for p in acc.pending_payouts()))
    acc.clear_payout("indeterminate-1")

    # 3e) sweep_stale must EXCLUDE a miner named in an unresolved payout intent. Otherwise a
    #     balance that broadcast-but-stayed-pending (the indeterminate branch) and then went
    #     idle could be both paid on-chain AND swept to the faucet. [M-Payout-2]
    idle_addr = _bech32_encode("rltc", 0, b"\x44" * 20)
    _seed_balance(acc, MINER_ADDR, owed)
    _seed_balance(acc, idle_addr, owed)
    mid_pending = acc._miner_id(MINER_ADDR, int(time.time()))
    mid_plain = acc._miner_id(idle_addr, int(time.time()))
    old = int(time.time()) - 10 * 86400  # both idle for 10 days
    acc.conn.execute("UPDATE miners SET last_seen=? WHERE id IN (?,?)", (old, mid_pending, mid_plain))
    acc.conn.commit()
    acc.begin_payout("sweep-pending-1", [{"miner_id": mid_pending, "amount": owed}], time.time())
    swept = acc.sweep_stale(int(time.time()) - 7 * 86400, FAUCET_ADDR, time.time())
    chk("sweep_stale: skips a miner with an unresolved payout intent [M-Payout-2]",
        _owed(acc, MINER_ADDR) == owed)
    chk("sweep_stale: still sweeps a non-pending idle miner",
        _owed(acc, idle_addr) == 0 and swept == owed)
    acc.clear_payout("sweep-pending-1")

    # 4) A brace-bomb explorer_url must NOT crash _notify_block - otherwise the
    #    exception would unwind before credit_block and a won block goes uncredited.
    pool.cfg.block_webhook_url = "http://127.0.0.1:1/hook"
    pool.cfg.explorer_url = "https://x/block/{hash}?ref={partner}#{"  # would break str.format
    raised = False
    try:
        pool._notify_block(123, "ab" * 32, int(0.5 * COIN))
    except Exception:
        raised = True
    chk("notify_block survives a brace-bomb explorer_url", not raised)
    await asyncio.gather(*pool._webhook_tasks, return_exceptions=True)

    os.unlink(db_path)
    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} payout checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
