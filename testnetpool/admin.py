# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Operator admin commands - the local control surface, ckpmsg-style.

ckpool has no web admin; its operator commands go over a LOCAL Unix socket (ckpmsg), and
the security boundary is just "you're on the box." These commands follow the same model:
they run locally and operate directly on the pool's accounting databases - no auth, no
network. They work whether or not the pool is running (SQLite WAL allows concurrent
access), though running them with the pool stopped is cleanest.

Today this covers the one operator action with no other escape hatch: resolving a stranded
pending payout that the crash-safe reconciler deliberately left pending (e.g. the wallet
was unreachable when the batch was first attempted, so it can't be auto-verified). Live
controls (drop a connection, force-reconnect) would need a control channel into the running
pool process - a separate, larger piece.
"""

from __future__ import annotations

import sys
import time

from .accounting import Accounting
from .address import address_to_script
from .coin import COINS
from .config import HubConfig
from .cryptonote import validate_address


def _accountings(cfg) -> list[tuple[str, Accounting]]:
    """Open an Accounting handle for every PUBLIC-mode coin in the config (solo mode keeps
    no balances/payouts). Returns [(label, accounting), ...]; caller closes them."""
    coins = cfg.coins if isinstance(cfg, HubConfig) else [cfg]
    out: list[tuple[str, Accounting]] = []
    for c in coins:
        if getattr(c, "mode", "") == "public":
            out.append((f"{c.coin}/{c.chain}", Accounting(c.public.db_path, c.coin)))
    return out


def _items(intent) -> list:
    """Pull the [{miner_id, amount}, ...] list out of a stored intent, handling both
    shapes: a bare list (BTC/LTC) and {"items": [...], "before": ...} (Monero)."""
    if isinstance(intent, dict):
        return intent.get("items") or []
    return intent or []


# -- core (testable: take an explicit [(label, accounting)] list) -----------

def _list_pending(accs) -> int:
    n = 0
    for label, acc in accs:
        for p in acc.pending_payouts():
            n += 1
            items = _items(p["items"])
            total = sum(it.get("amount", 0) for it in items if isinstance(it, dict))
            state = "BROADCAST (txid recorded)" if p.get("txid") else "NO txid - unverified"
            print(f"[{label}] {p['comment']}")
            print(f"    {state} | {len(items)} recipient(s) | {total} base units | ts={p['ts']}"
                  + (f" | txid={p['txid']}" if p.get("txid") else ""))
    print(f"\n{n} pending payout intent(s)." if n else "no pending payout intents.")
    return 0


def _resolve(accs, comment: str, paid: bool, txid: str = "", coin: str = "",
             force_unpaid: bool = False) -> int:
    matches = []
    for label, acc in accs:
        if coin and label.split("/")[0] != coin:
            continue
        m = next((p for p in acc.pending_payouts() if p["comment"] == comment), None)
        if m is not None:
            matches.append((label, acc, m))
    if not matches:
        print(f"no pending payout with comment {comment!r} in any coin database"
              + (f" for coin {coin!r}" if coin else "") + ".", file=sys.stderr)
        return 1
    # A comment matching more than one coin (only possible on a same-second seq collision
    # across coins) must be disambiguated: resolving the wrong coin - especially recording a
    # txid into another coin's DB on --paid - would be incorrect.
    if len(matches) > 1 and not coin:
        labels = ", ".join(label for label, _, _ in matches)
        print(f"comment {comment!r} matches {len(matches)} coins ({labels}); disambiguate "
              f"with --coin <coin> so exactly one coin's database is resolved.", file=sys.stderr)
        return 1

    if paid:
        # The batch DID broadcast: debit the balances and clear the intent so its miners are
        # not re-paid. record_payouts does both atomically and is idempotent on the intent.
        for label, acc, match in matches:
            items = _items(match["items"])
            tx = txid or match.get("txid") or "manual-resolved"
            acc.record_payouts(items, tx, time.time(), comment=comment)
            print(f"[{label}] {comment}: marked PAID (txid={tx}) - debited {len(items)} "
                  f"balance(s) and cleared the intent.")
        return 0

    # --unpaid: a recorded txid is proof the batch broadcast on-chain. Clearing it as UNPAID
    # leaves the balances owed and re-pays those miners next round - a real on-chain
    # double-spend. Refuse outright (before touching anything) unless explicitly overridden.
    broadcast = [(label, m) for label, _, m in matches if m.get("txid")]
    if broadcast and not force_unpaid:
        label, m = broadcast[0]
        print(f"[{label}] {comment}: REFUSING --unpaid - this intent has a recorded txid "
              f"({m['txid']}), meaning it DID broadcast. Use --paid to debit it, or "
              f"--force-unpaid only if you are certain it never sent.", file=sys.stderr)
        return 1
    for label, acc, match in matches:
        # It did NOT broadcast: just clear it; the balances stay owed and are re-paid next round.
        acc.clear_payout(comment)
        print(f"[{label}] {comment}: cleared as UNPAID - its miners will be re-paid on "
              f"the next payout round.")
    return 0


def _fmt_ts(ts) -> str:
    if not ts:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(ts)))


def _miner_info(accs, address: str) -> int:
    hits = 0
    for label, acc in accs:
        d = acc.miner_detail(address)
        if d is None:
            continue
        hits += 1
        print(f"[{label}] {address}")
        print(f"    owed={d['owed']}  paid={d['paid']}  shares={d['shares']}  "
              f"best={d['best_share']:.0f}")
        print(f"    first_seen={_fmt_ts(d['first_seen'])}  last_seen={_fmt_ts(d['last_seen'])}")
        for p in d["recent_payouts"][:10]:
            print(f"    paid {p['amount']} @ {_fmt_ts(p['ts'])}  txid={p['txid']}")
    if not hits:
        print(f"no miner {address!r} found in any coin database.", file=sys.stderr)
        return 1
    return 0


def _list_miners(accs, limit: int) -> int:
    for label, acc in accs:
        rows = acc.miners_overview(limit)
        print(f"[{label}] {len(rows)} miner(s):")
        for m in rows:
            print(f"    {m['address']}  owed={m['owed']}  paid={m['paid']}  "
                  f"shares={m['shares']}  last_seen={_fmt_ts(m['last_seen'])}")
    return 0


def _list_blocks(accs, limit: int) -> int:
    for label, acc in accs:
        rows = acc.recent_blocks(limit)
        counts = acc.block_counts()
        print(f"[{label}] blocks: {counts}  (showing last {len(rows)})")
        for b in rows:
            print(f"    height={b.get('height')}  status={b.get('status')}  "
                  f"reward={b.get('reward')}  finder={b.get('finder') or '-'}  "
                  f"{_fmt_ts(b.get('ts'))}")
    return 0


def _adjust_balance(accs, address: str, delta: int, coin: str, apply: bool) -> int:
    # Target the coin whose DB already knows this address; if none do, require --coin so we
    # don't silently create the same address under the wrong coin.
    targets = [(label, acc) for label, acc in accs
               if (not coin or label.split("/")[0] == coin)
               and (acc.miner_detail(address) is not None or coin)]
    if len(targets) != 1:
        if not targets:
            print(f"address {address!r} not known to any coin - pass --coin <coin> to create it.",
                  file=sys.stderr)
        else:
            print(f"address {address!r} matches {len(targets)} coins - disambiguate with --coin.",
                  file=sys.stderr)
        return 1
    label, acc = targets[0]
    # Validate the address against this coin+network before crediting. Every other address
    # surface (stratum/monero login, config) validates; without it here a typo'd or
    # wrong-network address becomes a real owed balance that the next payout batches into
    # send_many - the wallet then rejects the bad address and the WHOLE batch RPC fails,
    # stalling all payouts for that coin until an operator fixes the row.
    coin_name, _, chain = label.partition("/")
    try:
        if coin_name == "monero":
            validate_address(address, chain)
        else:
            address_to_script(address, COINS[coin_name].network(chain))
    except ValueError as exc:  # AddressError / CryptoNoteError / unknown-network are all ValueError
        print(f"refusing: {address!r} is not a valid {label} address ({exc}).", file=sys.stderr)
        return 1
    cur = (acc.miner_detail(address) or {}).get("owed", 0)
    new = max(0, cur + delta)
    verb = "credit" if delta >= 0 else "debit"
    if not apply:
        print(f"[{label}] DRY RUN: would {verb} {address} by {delta:+d}  "
              f"(owed {cur} -> {new}). Re-run with --yes to apply.")
        return 0
    actual = acc.adjust_balance(address, delta, time.time())
    print(f"[{label}] {verb} {address} by {delta:+d}  (owed {cur} -> {actual}).")
    return 0


# -- config-driven entry points ---------------------------------------------

def _run(cfg, fn, *a):
    accs = _accountings(cfg)
    try:
        return fn(accs, *a)
    finally:
        for _, acc in accs:
            acc.close()


def list_pending(cfg) -> int:
    return _run(cfg, _list_pending)


def resolve_payout(cfg, comment: str, paid: bool, txid: str = "", coin: str = "",
                   force_unpaid: bool = False) -> int:
    return _run(cfg, _resolve, comment, paid, txid, coin, force_unpaid)


def miner_info(cfg, address: str) -> int:
    return _run(cfg, _miner_info, address)


def list_miners(cfg, limit: int) -> int:
    return _run(cfg, _list_miners, limit)


def list_blocks(cfg, limit: int) -> int:
    return _run(cfg, _list_blocks, limit)


def adjust_balance(cfg, address: str, delta: int, coin: str, apply: bool) -> int:
    return _run(cfg, _adjust_balance, address, delta, coin, apply)
