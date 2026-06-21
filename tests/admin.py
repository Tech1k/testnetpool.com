# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Operator admin CLI: resolving a stranded pending payout (--paid / --unpaid).

The crash-safe reconciler deliberately leaves an unverifiable payout PENDING (never auto-
debits, never auto-re-pays). The operator resolves it: --unpaid clears it so its miners are
re-paid next round; --paid debits the balances and marks it done. These must do exactly
that, and never touch the wrong intent.

Run:  python3 tests/admin.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.accounting import Accounting  # noqa: E402
from testnetpool.admin import (  # noqa: E402
    _adjust_balance, _list_blocks, _list_miners, _list_pending, _miner_info, _resolve,
)

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def _owed(acc, mid):
    row = acc.conn.execute("SELECT owed FROM balances WHERE miner_id=?", (mid,)).fetchone()
    return row[0] if row else 0


def _has_pending(acc, comment):
    return any(p["comment"] == comment for p in acc.pending_payouts())


def main() -> int:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        acc = Accounting(path, "bitcoin")
        now = int(time.time())
        mid = acc._miner_id("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", now)
        acc.conn.execute("INSERT INTO balances(miner_id, owed) VALUES(?,?)", (mid, 1000))
        acc.conn.commit()

        # --- --unpaid: clears the intent, balance stays owed (re-paid next round) ---
        acc.begin_payout("payout-unpaid", [{"miner_id": mid, "amount": 1000}], now)
        chk("intent present before resolve", _has_pending(acc, "payout-unpaid"))
        rc = _resolve([("bitcoin/test", acc)], "payout-unpaid", paid=False)
        chk("resolve --unpaid returns 0", rc == 0)
        chk("--unpaid clears the intent", not _has_pending(acc, "payout-unpaid"))
        chk("--unpaid leaves the balance owed (will be re-paid)", _owed(acc, mid) == 1000)

        # --- --paid: debits the balance + clears the intent ---
        acc.begin_payout("payout-paid", [{"miner_id": mid, "amount": 1000}], now)
        rc = _resolve([("bitcoin/test", acc)], "payout-paid", paid=True, txid="deadbeef")
        chk("resolve --paid returns 0", rc == 0)
        chk("--paid clears the intent", not _has_pending(acc, "payout-paid"))
        chk("--paid debits the balance to 0", _owed(acc, mid) == 0)
        chk("--paid records the payout with the txid",
            any(r[0] == "deadbeef" for r in acc.conn.execute("SELECT txid FROM payouts").fetchall()))

        # --- Monero {items, before} shape resolves too ---
        macc = Accounting(path + ".m", "monero")
        mmid = macc._miner_id("9zmonero", now)
        macc.conn.execute("INSERT INTO balances(miner_id, owed) VALUES(?,?)", (mmid, 500))
        macc.conn.commit()
        macc.begin_payout("monero-payout-1", {"items": [{"miner_id": mmid, "amount": 500}],
                                              "before": None}, now)
        rc = _resolve([("monero/testnet", macc)], "monero-payout-1", paid=False)
        chk("resolves the Monero {items, before} intent shape",
            rc == 0 and not _has_pending(macc, "monero-payout-1") and _owed(macc, mmid) == 500)

        # --- unknown comment -> error, touches nothing ---
        acc.begin_payout("payout-keep", [{"miner_id": mid, "amount": 7}], now)
        rc = _resolve([("bitcoin/test", acc)], "no-such-comment", paid=False)
        chk("unknown comment returns non-zero", rc == 1)
        chk("unknown comment leaves other intents intact", _has_pending(acc, "payout-keep"))

        chk("_list_pending runs cleanly", _list_pending([("bitcoin/test", acc)]) == 0)

        # --- balance adjust (credit/debit corrections) ---
        accs = [("bitcoin/test", acc)]
        chk("balance starts at 0 after --paid debit", _owed(acc, mid) == 0)
        rc = _adjust_balance(accs, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 100, "", apply=False)  # dry run
        chk("adjust dry-run returns 0 and does NOT change the balance",
            rc == 0 and _owed(acc, mid) == 0)
        rc = _adjust_balance(accs, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 500, "", apply=True)   # credit
        chk("adjust --yes credits the balance", rc == 0 and _owed(acc, mid) == 500)
        _adjust_balance(accs, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", -9999, "", apply=True)      # over-debit
        chk("adjust clamps a debit at 0 (never negative)", _owed(acc, mid) == 0)
        rc = _adjust_balance(accs, "tb1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnl25zw8", 250, "bitcoin", apply=True)  # create via --coin
        chk("adjust creates a new address under --coin",
            rc == 0 and (acc.miner_detail("tb1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnl25zw8") or {}).get("owed") == 250)
        rc = _adjust_balance(accs, "tb1qUNKNOWN", 5, "", apply=True)   # ambiguous/none -> error
        chk("adjust on an unknown address (no --coin) errors, no create",
            rc == 1 and acc.miner_detail("tb1qUNKNOWN") is None)

        # --- M-3: --adjust-balance validates the address against coin+network ---
        bad = "tb1qnotavalidaddressxxxxxxxxxxxxxxxx"
        rc = _adjust_balance(accs, bad, 100, "bitcoin", apply=True)
        chk("adjust refuses an invalid address (would stall the payout batch); no row created",
            rc == 1 and acc.miner_detail(bad) is None)

        # --- H-3: --unpaid must REFUSE to clear a txid-bearing (already-broadcast) intent ---
        # A recorded txid is proof the batch broadcast; clearing it as UNPAID re-pays those
        # miners next round - a real on-chain double-spend.
        acc.begin_payout("payout-sent", [{"miner_id": mid, "amount": 100}], now)
        acc.set_payout_txid("payout-sent", "abc123")
        rc = _resolve([("bitcoin/test", acc)], "payout-sent", paid=False)            # --unpaid
        chk("--unpaid on a txid-bearing intent is refused", rc == 1)
        chk("--unpaid refusal leaves the intent intact", _has_pending(acc, "payout-sent"))
        rc = _resolve([("bitcoin/test", acc)], "payout-sent", paid=False, force_unpaid=True)
        chk("--force-unpaid overrides and clears it",
            rc == 0 and not _has_pending(acc, "payout-sent"))

        # --- H-4: record_payouts is idempotent on the intent (no double-debit) ---
        # The admin CLI can run while the pool's reconciler resolves the same comment; the
        # debit must happen exactly once even if record_payouts is called twice.
        acc.conn.execute("UPDATE balances SET owed=? WHERE miner_id=?", (1000, mid))
        acc.conn.commit()
        acc.begin_payout("idem-1", [{"miner_id": mid, "amount": 600}], now)
        acc.record_payouts([{"miner_id": mid, "amount": 600}], "tx-idem", now, comment="idem-1")
        chk("record_payouts debits once (1000 -> 400)", _owed(acc, mid) == 400)
        chk("record_payouts cleared the intent", not _has_pending(acc, "idem-1"))
        acc.record_payouts([{"miner_id": mid, "amount": 600}], "tx-idem", now, comment="idem-1")
        chk("a second record_payouts on the same comment does NOT double-debit",
            _owed(acc, mid) == 400)

        # --- read commands run cleanly ---
        chk("--miner on a known address returns 0", _miner_info(accs, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0)
        chk("--miner on an unknown address returns 1", _miner_info(accs, "tb1qZZZ") == 1)
        chk("--list-miners runs cleanly", _list_miners(accs, 50) == 0)
        chk("--blocks runs cleanly", _list_blocks(accs, 50) == 0)

        acc.close()
        macc.close()
    finally:
        for p in (path, path + ".m"):
            try:
                os.unlink(p)
            except OSError:
                pass

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} admin checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
