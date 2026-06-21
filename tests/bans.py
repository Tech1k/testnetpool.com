# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Unit test for BanManager - the per-IP abuse control shared by every coin's
Stratum listener (connection caps + temp-ban for reject-flood-dropped IPs).

Time is injected so ban expiry is deterministic (no sleeping). We assert: a clean
IP is allowed; strikes below the threshold do not ban; the threshold ban refuses
new connections; the ban lifts once it expires; stale strikes age out of the
window; and the per-IP / global connection caps refuse over-limit connects while
unregister frees the slot again.

Run:  python3 tests/bans.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.stratum import BanManager  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def main() -> int:
    # --- temp-ban on repeated reject-flood drops ---------------------------
    bm = BanManager(ban_threshold=3, ban_seconds=100.0, strike_window=600.0)
    t = 1000.0
    chk("clean IP is allowed", bm.allow("1.2.3.4", t)[0] is True)
    chk("strike 1 does not ban", bm.strike("1.2.3.4", t) is False)
    chk("strike 2 does not ban", bm.strike("1.2.3.4", t + 1) is False)
    chk("still allowed below threshold", bm.allow("1.2.3.4", t + 1)[0] is True)
    chk("strike 3 triggers the ban", bm.strike("1.2.3.4", t + 2) is True)
    allowed, reason = bm.allow("1.2.3.4", t + 3)
    chk("banned IP is refused", allowed is False)
    chk("refusal reason mentions the ban", "ban" in reason.lower())
    chk("a different IP is unaffected", bm.allow("9.9.9.9", t + 3)[0] is True)
    chk("snapshot counts one banned IP", bm.snapshot(t + 3)["banned_ips"] == 1)

    # --- ban expires on its own --------------------------------------------
    chk("still banned just before expiry", bm.allow("1.2.3.4", t + 101)[0] is False)
    chk("allowed once the ban expires", bm.allow("1.2.3.4", t + 103)[0] is True)
    chk("snapshot clears the expired ban", bm.snapshot(t + 103)["banned_ips"] == 0)

    # --- strikes outside the window age out (never reach the threshold) ----
    bw = BanManager(ban_threshold=3, ban_seconds=100.0, strike_window=10.0)
    bw.strike("5.5.5.5", 0.0)
    bw.strike("5.5.5.5", 5.0)
    banned = bw.strike("5.5.5.5", 100.0)  # first two are now stale -> count is 1
    chk("stale strikes age out of the window", banned is False)
    chk("aged-out IP stays allowed", bw.allow("5.5.5.5", 100.0)[0] is True)

    # --- ban_threshold = 0 disables temp-banning ---------------------------
    bo = BanManager(ban_threshold=0)
    for i in range(20):
        bo.strike("7.7.7.7", float(i))
    chk("threshold 0 never bans", bo.allow("7.7.7.7", 100.0)[0] is True)

    # --- per-IP connection cap ---------------------------------------------
    bp = BanManager(max_per_ip=2)
    bp.register("8.8.8.8")
    bp.register("8.8.8.8")
    chk("third connection from one IP is refused", bp.allow("8.8.8.8", 0.0)[0] is False)
    # The cap refusal reason must be DISTINCT from a ban: the server logs cap hits at a
    # visible (throttled) level - so an operator sees a rental proxy (e.g. MiningRigRentals,
    # all rigs behind one IP) exceeding max_conns_per_ip - while keeping scanner bans at debug.
    cap_allowed, cap_reason = bp.allow("8.8.8.8", 0.0)
    chk("per-IP cap refusal reason is distinct from a ban (drives visible cap logging)",
        cap_allowed is False and cap_reason != "temporarily banned" and "connection" in cap_reason.lower())
    chk("another IP still has room", bp.allow("8.8.8.0", 0.0)[0] is True)
    bp.unregister("8.8.8.8")
    chk("unregister frees a per-IP slot", bp.allow("8.8.8.8", 0.0)[0] is True)

    # --- global connection cap ---------------------------------------------
    bg = BanManager(max_total=2)
    bg.register("1.1.1.1")
    bg.register("2.2.2.2")
    chk("global cap refuses past the total", bg.allow("3.3.3.3", 0.0)[0] is False)
    bg.unregister("1.1.1.1")
    chk("unregister frees a global slot", bg.allow("3.3.3.3", 0.0)[0] is True)
    chk("snapshot reports the live connection count", bg.snapshot(0.0)["connections"] == 1)

    # --- unlimited by default ----------------------------------------------
    bd = BanManager()  # max_per_ip=0, max_total=0
    for _ in range(500):
        bd.register("4.4.4.4")
    chk("defaults impose no connection cap", bd.allow("4.4.4.4", 0.0)[0] is True)

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} ban checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
