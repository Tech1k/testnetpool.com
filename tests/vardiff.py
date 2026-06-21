# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Unit tests for the self-tuning vardiff controller.

Vardiff needs no operator configuration: it ramps difficulty up for a fast miner
(share-count retarget) and down for one that has gone quiet (idle_retarget).

Run:  python3 tests/vardiff.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.config import VardiffConfig  # noqa: E402
from testnetpool.stratum import (  # noqa: E402
    FAST_RETARGET_SHARES, IDLE_RETARGET_FACTOR, RELAX_PIN_GRACE_SHARES, Vardiff,
)

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def main() -> int:
    cfg = VardiffConfig(enabled=True, start_difficulty=16, min_difficulty=1,
                        max_difficulty=65536, target_time=15, retarget_time=90,
                        variance_percent=30)

    # 1) fast UP retarget: many shares in a tiny window retarget before retarget_time
    v = Vardiff(cfg, now=1000.0)
    new = None
    for i in range(FAST_RETARGET_SHARES):
        new = v.record_share(1000.0 + i * 0.001)  # ~1ms apart, far under target_time
    chk("fast up-retarget fires before retarget_time", new is not None and new > 16)
    chk("up-retarget bounded to <= 4x", new is not None and new <= 16 * 4 + 1e-6)

    # 2) idle DOWN adjust: a connection that never submits gets halved after the window
    v = Vardiff(cfg, now=2000.0)
    window = IDLE_RETARGET_FACTOR * cfg.target_time
    chk("no idle adjust before the window", v.idle_retarget(2000.0 + window - 1) is None)
    nd = v.idle_retarget(2000.0 + window + 1)
    chk("idle halves difficulty", nd == 8.0)
    t = 2000.0 + window + 1
    for _ in range(20):  # repeated idleness floors at min_difficulty
        t += window + 1
        v.idle_retarget(t)
    chk("idle floors at min_difficulty", v.difficulty == cfg.min_difficulty)
    chk("idle is a no-op at min", v.idle_retarget(t + 10 * window) is None)

    # 3) a miner-pinned (fixed) difficulty that IS producing shares is never auto-adjusted
    v = Vardiff(cfg, now=3000.0)
    v.set_fixed(1024)
    chk("fixed ignores record_share", all(v.record_share(3000.0 + i) is None for i in range(50)))
    chk("producing fixed worker ignores idle", v.idle_retarget(3000.0 + 100000) is None)
    chk("fixed stays put", v.difficulty == 1024)

    # 3b) RELAX safety net: a pin that produces ~nothing for a full idle window is too high for
    # the rig (MRR-style d=8M onto a tiny rig) -> relax it, re-open vardiff from start_difficulty.
    window = IDLE_RETARGET_FACTOR * cfg.target_time
    v = Vardiff(cfg, now=6000.0)
    v.set_fixed(8000000, floor=True)
    chk("absurd pin clamps to max, stays fixed", v.fixed and v.difficulty == cfg.max_difficulty)
    chk("dead pin not relaxed before the idle window", v.idle_retarget(6000.0 + window - 1) is None)
    nd = v.idle_retarget(6000.0 + window + 1)
    chk("dead pin relaxes to start_difficulty + un-fixes",
        nd == 16 and not v.fixed and v.difficulty == 16)
    chk("relaxed worker is back under vardiff (record_share now retargets)",
        v.record_share(6000.0 + window + 2) is None and not v.fixed)

    # 3c) but a pin PRODUCING shares keeps its floor across a quiet spell (A1/A2 must hold)
    v = Vardiff(cfg, now=7000.0)
    v.set_fixed(8192, floor=True)
    for i in range(RELAX_PIN_GRACE_SHARES + 1):    # produce more than the grace count
        v.record_share(7000.0 + i)
    chk("producing pin holds its floor when idle (A1/A2)",
        v.idle_retarget(7000.0 + 100000) is None and v.fixed and v.difficulty == 8192)

    # 4) set_fixed clamps to max_difficulty (audit fix)
    v = Vardiff(cfg, now=4000.0)
    v.set_fixed(10 ** 9)
    chk("set_fixed clamps to max", v.difficulty == cfg.max_difficulty)

    # 4b) set_fixed must pin previous_difficulty to the NEW value. Acceptance is
    # min(difficulty, previous_difficulty) and fixed disables retargeting, so a stale
    # previous_difficulty would leave a permanent accept-low/credit-high window (pin
    # d=8192 yet have diff-16 shares accepted + credited at 8192). [C2]
    v = Vardiff(cfg, now=4100.0)   # opens at start_difficulty 16
    v.set_fixed(4096)
    chk("set_fixed pins previous_difficulty to the pinned value (no accept-low window)",
        v.previous_difficulty == 4096 and v.difficulty == 4096)

    # 4c) start_difficulty is clamped into [min, max] at construction. [L5]
    v = Vardiff(VardiffConfig(enabled=True, start_difficulty=10 ** 9, min_difficulty=1,
                              max_difficulty=65536, target_time=15, retarget_time=90,
                              variance_percent=30), now=4200.0)
    chk("start_difficulty clamped into [min,max] at open", v.difficulty == 65536)

    # 4d) a password "d=" pin (floor=True) is a FLOOR a later suggest_difficulty can't
    # undercut - a rental proxy pins high, the rig then suggests its low firmware default,
    # and letting that win drags the worker below the proxy's target ("Low Worker
    # Difficulty"). A suggest may RAISE above the floor but never drop below it. [MRR]
    v = Vardiff(cfg, now=4300.0)
    v.set_fixed(8192, floor=True)               # proxy password pin
    v.set_fixed(16)                             # rig's low suggest_difficulty
    chk("password pin is a floor a lower suggest can't undercut", v.difficulty == 8192)
    v.set_fixed(16384)                          # a HIGHER suggest may still raise it
    chk("a suggest above the floor still raises difficulty", v.difficulty == 16384)

    # 5) disabled vardiff never moves
    v = Vardiff(VardiffConfig(enabled=False, start_difficulty=16), now=5000.0)
    chk("disabled: record_share no-op", v.record_share(5000.0) is None and v.record_share(9999.0) is None)
    chk("disabled: idle no-op", v.idle_retarget(99999.0) is None)

    # 6) per-algo starting-difficulty floor (config). A SHA-256 ASIC can't mine at the
    # CPU-tuned default of 16 (it would flood ~millions of shares/sec, so its firmware /
    # a rental proxy refuses and disconnects) - so bitcoin (sha256d) defaults to an
    # ASIC-sane start, while scrypt/randomx stay low for CPU miners. Explicit wins.
    from testnetpool.config import _config_from_sections  # noqa: E402
    from testnetpool.selftest import _bech32_encode  # noqa: E402

    def _vd(coin, hrp, vdiff=None):
        addr = _bech32_encode(hrp, 0, b"\x11" * 20)
        c = _config_from_sections(
            {"coin": coin, "chain": "regtest"},
            {"mode": "solo", "address": addr, "stratum_port": 3333},
            {"user": "x", "password": "y"}, vdiff or {}, {"enabled": False}, {})
        return c.vardiff

    chk("sha256d (bitcoin) defaults to an ASIC-sane start difficulty", _vd("bitcoin", "bcrt").start_difficulty == 16384.0)
    chk("scrypt (litecoin) keeps the low CPU-friendly start difficulty", _vd("litecoin", "rltc").start_difficulty == 16.0)
    # max must be high enough for a big rented ASIC (optimal in the MILLIONS) - the 65536
    # class default would trap vardiff / suggest_difficulty / "d=" well below where it mines.
    chk("sha256d max ceiling is raised into the millions", _vd("bitcoin", "bcrt").max_difficulty >= 2 ** 28)
    chk("an explicit [vardiff].start_difficulty overrides the algo default",
        _vd("bitcoin", "bcrt", {"start_difficulty": 42}).start_difficulty == 42.0)

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} vardiff checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
