# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Tests for the dashboard backend + render (Layer 4 / dashboard).

  * Accounting: schema migration idempotency, worker/best-share recording,
    hashrate windows, round effort, per-block luck, active counts, worker
    breakdown.
  * Render: _render_html produces valid HTML, all sections, XSS-safe
    escaping, empty-state rows, money formatting, and the not-found path.

Run:  python3 tests/dashboard.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.accounting import Accounting  # noqa: E402
from testnetpool.config import DonateConfig  # noqa: E402
from testnetpool.stratum import short_agent  # noqa: E402
from testnetpool.stats import (  # noqa: E402
    _render_html, _render_landing, _render_miner_page, _render_block_page,
    _render_connect, _render_donate, _render_legal, _payout_panel, _svg_chart, _chart_block,
    fmt_coins,
    _fmt_num, fmt_hashrate, _render_worker_page, _live_for_address, _solo_detail,
)

ok = []


def chk(name, cond, detail=""):
    ok.append((name, bool(cond), detail))


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


def test_accounting():
    path = _tmpdb()
    try:
        acc = Accounting(path, "bitcoin")
        cols = lambda t: {r[1] for r in acc.conn.execute(f"PRAGMA table_info({t})")}
        chk("migration: shares.worker", "worker" in cols("shares"))
        chk("migration: miners.best_share", "best_share" in cols("miners"))
        chk("migration: blocks.net_diff", "net_diff" in cols("blocks"))
        acc.close()
        # reopen: migration must be idempotent (no raise, columns intact)
        acc = Accounting(path, "bitcoin")
        chk("migration: idempotent reopen", "worker" in cols("shares"))

        NOW = 1_800_000_000  # fixed clock
        # worker + best_share recording
        acc.record_share("tb1qA", 1000, NOW - 30, share_diff=5000, worker="")
        acc.record_share("tb1qA", 1000, NOW - 200, share_diff=99000, worker="rig1")
        acc.record_share("tb1qA", 1000, NOW - 4000, share_diff=10, worker="rig2")
        acc.record_share("tb1qA", 1000, NOW - 50000, share_diff=1, worker="rig1")
        wrec = acc.conn.execute(
            "SELECT worker FROM shares ORDER BY id").fetchall()
        chk("record_share stores worker", {w[0] for w in wrec} == {"", "rig1", "rig2"}, str(wrec))
        best = acc.conn.execute(
            "SELECT best_share FROM miners WHERE address='tb1qA'").fetchone()[0]
        chk("best_share = max(share_diff)", best == 99000, str(best))

        # pool_hashrate_windows: diffs are all 1000; counts per window
        pw = acc.pool_hashrate_windows(NOW)
        chk("pool window 60s", pw[60] == 1000, str(pw))
        chk("pool window 300s", pw[300] == 2000, str(pw))
        chk("pool window 3600s", pw[3600] == 2000, str(pw))
        chk("pool window 86400s", pw[86400] == 4000, str(pw))

        # miner window isolation
        acc.record_share("tb1qB", 7777, NOW - 10)
        mwA = acc.miner_hashrate_windows("tb1qA", NOW)
        chk("miner window excludes other miners", mwA[300] == 2000, str(mwA))

        # active_counts: A (recent), B (recent); third addr only old
        acc.record_share("tb1qC", 1, NOW - 100000)
        ac = acc.active_counts(NOW)
        chk("active_counts active", ac["active_miners"] == 2, str(ac))
        chk("active_counts known", ac["known_miners"] == 3, str(ac))
        chk("pool_best_share", acc.pool_best_share() == 99000)

        acc.close()
    finally:
        _cleanup(path)


def test_round_and_luck():
    path = _tmpdb()
    try:
        acc = Accounting(path, "bitcoin")
        NOW = 1_800_000_000
        # round 1: shares then block at T1
        acc.record_share("tb1qA", 100, NOW - 1000)
        acc.record_share("tb1qA", 200, NOW - 900)  # round1 diff = 300
        acc.credit_block(100, "h1" * 32, 5_000_000_000, 0.0, 100, "tb1qfaucet",
                         NOW - 800, net_diff=1000.0)
        # round 2: shares then block at T2
        acc.record_share("tb1qA", 400, NOW - 700)  # round2 diff = 400
        acc.credit_block(101, "h2" * 32, 5_000_000_000, 0.0, 100, "tb1qfaucet",
                         NOW - 600, net_diff=800.0)
        # current round: shares after last block
        acc.record_share("tb1qA", 50, NOW - 100)

        rd, rstart = acc.round_share_diff(NOW)
        chk("round_share_diff current sum", rd == 50, str(rd))
        chk("round_share_diff start = last block", rstart == NOW - 600, str(rstart))

        luck = acc.block_luck()
        by_h = {b["height"]: b for b in luck}
        chk("block_luck has both blocks", set(by_h) == {100, 101}, str(list(by_h)))
        chk("block 100 round_diff", by_h[100]["round_diff"] == 300, str(by_h[100]))
        chk("block 100 luck%", by_h[100]["luck_percent"] == 30.0, str(by_h[100]))  # 300/1000
        chk("block 101 round_diff", by_h[101]["round_diff"] == 400, str(by_h[101]))
        chk("block 101 luck%", by_h[101]["luck_percent"] == 50.0, str(by_h[101]))  # 400/800
        chk("credit_block stored net_diff", by_h[100]["net_diff"] == 1000.0)

        # orphaned block: now SHOWN in the block list (transparency) but with no
        # luck%, and still excluded from the pool-luck aggregate / round boundaries.
        acc.orphan_block(acc.conn.execute("SELECT id FROM blocks WHERE height=101").fetchone()[0])
        bl = {b["height"]: b for b in acc.block_luck()}
        chk("orphaned block still listed", set(bl) == {100, 101}, str(set(bl)))
        chk("orphaned block has no luck%",
            bl[101]["luck_percent"] is None and bl[101]["status"] == "orphaned")
        chk("won block keeps its luck%", bl[100]["luck_percent"] == 30.0)

        # stale block (lost the race): recorded, shown, never credited
        acc.record_stale_block(102, "h3" * 32, 5_000_000_000, NOW - 500, net_diff=900.0, finder="tb1qA")
        bl2 = {b["height"]: b for b in acc.block_luck()}
        chk("stale block listed with no luck%",
            102 in bl2 and bl2[102]["status"] == "stale" and bl2[102]["luck_percent"] is None)
        bc = acc.block_counts()
        chk("block_counts: won/orphaned/stale + orphan rate",
            bc["won"] == 1 and bc["orphaned"] == 1 and bc["stale"] == 1 and bc["solved"] == 3
            and bc["orphan_rate"] == round(2 / 3 * 100, 1))
        chk("blocks_found counts won only", acc.blocks_found() == 1)
        cr = acc.conn.execute("SELECT COUNT(*) FROM credits WHERE block_id="
                              "(SELECT id FROM blocks WHERE height=102)").fetchone()[0]
        chk("stale block creates no PPLNS credits", cr == 0)

        # worker_breakdown
        acc.record_share("tb1qW", 10, NOW - 10, worker="")
        acc.record_share("tb1qW", 20, NOW - 10, worker="r1")
        acc.record_share("tb1qW", 30, NOW - 10, worker="r1")
        wb = {w["worker"]: w for w in acc.worker_breakdown("tb1qW", NOW)}
        chk("worker_breakdown default label", "(default)" in wb, str(list(wb)))
        chk("worker_breakdown r1 diff", wb["r1"]["diff"][300] == 50, str(wb.get("r1")))
        chk("worker_breakdown r1 shares", wb["r1"]["shares"] == 2, str(wb.get("r1")))

        # review fix: a legacy NULL-worker share must merge with the '' default,
        # not split into two "(default)" rows.
        acc.conn.execute(
            "INSERT INTO shares(miner_id, difficulty, ts, worker) "
            "SELECT id, 5, ?, NULL FROM miners WHERE address='tb1qW'", (NOW - 5,))
        acc.conn.commit()
        wb2 = [w for w in acc.worker_breakdown("tb1qW", NOW) if w["worker"] == "(default)"]
        chk("worker NULL+'' merge to one default row", len(wb2) == 1, str(wb2))
        chk("merged default has both shares", wb2 and wb2[0]["shares"] == 2, str(wb2))
        acc.close()
    finally:
        _cleanup(path)


def test_render():
    XSS = "<script>alert(1)</script>"
    ATTR_XSS = '"><img src=x onerror=alert(1)>'
    snap = {
        "coin": "bitcoin", "chain": "testnet4", "mode": "public", "height": 139670,
        "uptime": 3661.0, "network_difficulty": 1.48e9, "network_hashrate_hs": 4.79e15,
        "active_miners": 3,
        "known_miners": 10, "connected_miners": 2, "blocks_found": 1,
        "est_seconds_per_block": 31780, "current_round": {"effort_percent": 142.5},
        "pool_hashrate": {"5m": 2.1e14}, "pool_hashrate_hs": 2.1e14,
        "algo": "sha256d", "accepted_shares": 4096, "best_share": 98765.0,
        "miner_agents": {"XMRig/6.26": 2, "cgminer/4.11": 1}, "faucet_address": "tb1qminer",
        "node_health": {"peers": 8, "tip_age_seconds": 240, "synced": True},
    }
    detail = {
        "address": "tb1qexampleaddress", "first_seen": int(time.time()) - 86400,
        "last_seen": int(time.time()) - 30, "owed": 105_000_000, "paid": 300_000_000,
        "shares": 4096, "best_share": 12345.0,
        "hashrate": {"5m": 1e12, "1h": 1e12, "24h": 1e12},
        "workers": [{"worker": XSS, "last_seen": int(time.time()), "shares": 10,
                     "hashrate": {"5m": 1e12, "1h": 1e12, "24h": 1e12}}],
        "recent_payouts": [{"amount": 105_000_000, "txid": ATTR_XSS, "ts": int(time.time())}],
    }
    luck = [{"height": 139670, "hash": "00ff" * 16, "reward": 312_500_000,
             "found_ts": int(time.time()) - 600, "status": "matured",
             "net_diff": 1.4e9, "round_diff": 1.3e9, "luck_percent": 92.8}]
    miners = [{"address": "tb1qminer", "owed": 105_000_000, "paid": 0,
               "last_seen": int(time.time()) - 5, "shares": 100}]
    payouts = [{"address": "tb1qminer", "amount": 105_000_000, "txid": ATTR_XSS,
                "ts": int(time.time())}]

    html = _render_html(snap, detail, "tb1qexampleaddress", luck, miners, payouts)
    chk("render: is str", isinstance(html, str))
    # The "every transaction" note links to /template only when the pool is actually
    # building full blocks (snap.full_block), not merely when the config flag is set -
    # so post-MWEB Litecoin (config off, mweb-forced full) still gets the note.
    chk("dashboard note absent when not building full blocks", "See the next block" not in html)
    chk("dashboard note ignores the bare config flag (gates on actual full_block)",
        "See the next block" not in _render_html({**snap, "include_transactions": True},
                                                  detail, "tb1qexampleaddress", luck, miners, payouts))
    note_html = _render_html({**snap, "full_block": True}, detail, "tb1qexampleaddress",
                             luck, miners, payouts, coin_base="/bitcoin")
    chk("dashboard note links to /template when building full blocks",
        'href="/bitcoin/template"' in note_html and "every transaction" in note_html
        and "See the next block" in note_html)
    chk("render: doctype", html.lstrip().startswith("<!doctype html"))
    chk("render: closes html", "</html>" in html)
    chk("render: nav API link -> self-describing index", 'href="/api"' in html and ">API</a>" in html)
    for s in ("Your stats", "Found blocks", "Recent payouts", "Top miners"):
        chk(f"render: section {s!r}", s in html)
    # the pool's faucet (here = the credited miner) is badged, not mistaken for a miner
    chk("render: faucet badged", 'class="pill faucet"' in html and ">faucet</span>" in html)
    # XSS: malicious worker/txid must be escaped, never raw
    chk("render: escapes <script>", "&lt;script&gt;" in html)
    chk("render: no raw <script>alert", XSS not in html)
    chk("render: no raw attr-breakout", ATTR_XSS not in html, "raw attr xss present!")
    chk("render: status pill", "st-matured" in html)
    chk("render: luck colored", ("luck-good" in html or "luck-bad" in html))
    chk("render: money formatted", "1.05000000" in html)

    # attribute escaping for the lookup echo
    html2 = _render_html(snap, None, ATTR_XSS, [], [], [])
    chk("render: addr attr escaped", ATTR_XSS not in html2 and "&quot;&gt;" in html2)

    # empty-state rows
    he = _render_html(snap, None, "", [], [], [])
    for s in ("no blocks found yet", "no payouts yet", "no miners yet"):
        chk(f"render empty: {s!r}", s in he)

    # not-found path
    hnf = _render_html(snap, None, "tb1qdoesnotexist", luck, miners, payouts)
    chk("render not-found line", "no shares recorded" in hnf)
    chk("render not-found has no detail panel", "class=detail" not in hnf)

    chk("fmt_coins int", fmt_coins(105_000_000) == "1.05000000", fmt_coins(105_000_000))
    chk("fmt_coins None", fmt_coins(None) == "—")

    # theme: nav, hero, coin identity, icons, favicon
    chk("render: best-effort disclaimer", "class=disclaimer" in html
        and "without warranty" in html and "not guaranteed" in html
        and "hosted service" in html and "as-is" in html)
    chk("render: node health stats", "Node peers" in html and "Node tip age" in html)
    chk("render: meta description + theme-color", 'name=description' in html
        and 'name="theme-color"' in html)
    chk("render: open-graph + twitter card", 'property="og:title"' in html
        and 'property="og:description"' in html and 'name="twitter:card"' in html)
    chk("render: noindex without a site_url", 'content="noindex"' in html)
    # site_url turns on indexing; node_dashboard_url adds the footer link. There is
    # no share/banner image - link previews are text-only (twitter card=summary).
    from testnetpool.stats import _META as _M
    from testnetpool.config import _onion_url
    chk("onion: bare address -> http url", _onion_url("abc.onion") == "http://abc.onion")
    chk("onion: full url kept, trailing slash trimmed", _onion_url("http://abc.onion/") == "http://abc.onion")
    _M["site_url"] = "https://x.test"; _M["node_dashboard_url"] = "https://n.test"
    _M["onion"] = "http://abc.onion"
    try:
        hp = _render_html(snap, None, "", [], None, None)
        chk("meta: site_url enables indexing, text-only card",
            'content="index,follow"' in hp and 'name="twitter:card" content="summary"' in hp
            and "og:image" not in hp and "twitter:image" not in hp)
        chk("meta: node_dashboard_url adds footer link", ">node status</a>" in hp)
        chk("onion: footer .onion link", 'href="http://abc.onion"' in hp and ">.onion</a>" in hp)
    finally:
        _M["site_url"] = ""; _M["node_dashboard_url"] = ""; _M["onion"] = ""
    chk("render: sticky nav + brand", "<nav>" in html and "brand-mark" in html and ">TestnetPool</a>" in html)
    chk("render: favicon data-uri", "rel=icon" in html and "data:image/svg+xml;base64," in html)
    chk("render: hero KPI cards", "class=hero" in html and "class=kpi" in html)
    chk("render: coin context bar + mark", "class=coinbar" in html and 'class="coin-mark"' in html)
    chk("render: UI icons inlined", html.count('<span class="ico"') >= 8)
    chk("render: decorative icons hidden from AT", html.count('class="ico" aria-hidden="true"') >= 8)
    from testnetpool.stats import chain_label, algo_label  # noqa: E402
    chk("label: chain test->testnet, main->mainnet",
        chain_label("test") == "testnet" and chain_label("main") == "mainnet"
        and chain_label("testnet4") == "testnet4")
    chk("label: algo sha256d->SHA-256, scrypt->Scrypt",
        algo_label("sha256d") == "SHA-256" and algo_label("scrypt") == "Scrypt")
    chk("render: friendly algo pill", ">SHA-256<" in html)        # snap algo=sha256d
    chk("render: chain pill shown, not raw 'test'", ">testnet4<" in html and ">test<" not in html)
    chk("render: no redundant 'public' pill", ">public<" not in html)
    for anchor in ("id=you", "id=blocks", "id=payouts", "id=miners"):
        chk(f"render: section anchor {anchor}", anchor in html)
    # offline / zero-dep: nothing the browser auto-LOADS may be remote. xmlns namespace
    # URIs are identifiers (never fetched) and <a href> credit links are user navigation,
    # not fetches - only src=/url()/@import/external <link rel> would hit the network.
    low = html.lower()
    chk("render: inline script only", "<script>" in html and "<script src" not in low)
    # light + dark theming with an OS-following toggle
    chk("render: theme toggle", "id=theme-toggle" in html and "ico-sun" in html and "ico-moon" in html)
    chk("render: light+dark palettes", ':root[data-theme="dark"]' in html
        and "prefers-color-scheme:dark" in html and "color-scheme:light" in html)
    chk("render: theme persists pre-paint", "localStorage.getItem('tnp-theme')" in html)
    chk("render: no external fetches",
        'src="http' not in html and "url(http" not in html and "@import" not in low
        and "rel=stylesheet" not in low and "rel=preload" not in low
        and 'rel=icon type="image/svg+xml" href="data:' in html)  # only <link> is the inline favicon
    # the only off-site link is the Tech1k credit, and it is a plain <a> (navigation)
    chk("render: tech1k credit link", 'href="https://tech1k.com"' in html and ">Tech1k</a>" in html)
    # XSS via the coin/algo snapshot fields must be escaped, never raw
    evil = {**snap, "coin": "<b>x", "algo": '"><img src=x>'}
    eh = _render_html(evil, None, "", [], [], [])
    chk("render: coin field escaped", "<b>x" not in eh and "&lt;b&gt;x" in eh)
    chk("render: algo field escaped", '"><img src=x>' not in eh)


def test_landing():
    base = {"coin": "bitcoin", "chain": "testnet4", "mode": "public", "height": 139670,
            "network_difficulty": 1.48e9, "network_hashrate_hs": 4.79e15, "active_miners": 3,
            "known_miners": 10,
            "connected_miners": 2, "blocks_found": 1, "current_round": {"effort_percent": 88.0},
            "pool_hashrate": {"5m": 2.1e14}, "pool_hashrate_hs": 2.1e14}
    ltc = {**base, "coin": "litecoin", "chain": "test"}
    land = _render_landing([{"name": "bitcoin", "snap": base}, {"name": "litecoin", "snap": ltc}])
    chk("landing: doctype", land.lstrip().startswith("<!doctype html"))
    chk("landing: nav + brand", "<nav>" in land and ">TestnetPool</a>" in land)
    chk("landing: links to both coins", 'href="/bitcoin"' in land and 'href="/litecoin"' in land)
    chk("landing: net hashrate column", "net&nbsp;hashrate" in land and "PH/s" in land)
    chk("landing: coin marks", land.count('class="coin-mark"') >= 2)
    chk("landing: aggregate hero", "class=hero" in land and "class=kpi" in land)
    chk("landing: favicon + inline script", "data:image/svg+xml;base64," in land
        and "<script>" in land and "<script src" not in land.lower())
    chk("landing: tech1k credit link", 'href="https://tech1k.com"' in land and ">Tech1k</a>" in land)
    chk("landing: empty state", "no coins configured" in _render_landing([]))
    evil = _render_landing([{"name": "x", "snap": {**base, "coin": "<i>z"}}])
    # the coin name is title-cased in the badge, so compare case-insensitively
    chk("landing: coin name escaped", "<i>z" not in evil and "&lt;i&gt;z" in evil.lower())


def test_pages():
    XSS = "<script>alert(1)</script>"
    ADDR = "tltc1qexampleaddr"
    snap = {"coin": "litecoin", "chain": "test", "algo": "scrypt", "mode": "public", "height": 500,
            "uptime": 100.0, "network_difficulty": 1000.0, "network_hashrate_hs": 4.79e15,
            "active_miners": 1, "known_miners": 1,
            "connected_miners": 1, "blocks_found": 1, "est_seconds_per_block": 600,
            "current_round": {"effort_percent": 50.0}, "pool_hashrate": {"5m": 1e9},
            "pool_hashrate_hs": 1e9, "accepted_shares": 10, "best_share": 1234.0,
            "miner_agents": {"XMRig/6.26": 1}}

    # SVG chart: line + per-bucket hover targets (instant JS tooltip via data-tip,
    # native <title> as the no-JS fallback); empty state
    svg = _svg_chart([(1000, 1e9), (2000, 2e9), (3000, 1.5e9)])
    chk("chart: svg + line", "<svg" in svg and "polyline" in svg)
    chk("chart: per-bucket data-tip + title fallback",
        svg.count("data-tip=") == 3 and svg.count("<title>") == 3)
    chk("chart: tooltip carries time + value", "UTC ·" in svg and "GH/s" in svg)
    chk("chart: empty (no points)", "No hashrate data" in _svg_chart([]))
    chk("chart: empty (all zero)", "No hashrate data" in _svg_chart([(1, 0), (2, 0)]))
    chart = _chart_block("hashrate", "Your hashrate", "last 24h", svg)

    # miner page (full, bookmarkable)
    detail = {"address": ADDR, "first_seen": 1, "last_seen": 2, "owed": 105_000_000, "paid": 0,
              "shares": 42, "best_share": 9999.0, "hashrate": {"5m": 1e9, "1h": 1e9, "24h": 1e9},
              "workers": [{"worker": XSS, "last_seen": 3, "shares": 5,
                           "hashrate": {"5m": 1e9, "1h": 1e9, "24h": 1e9}}],
              "block_credits": [{"height": 500, "hash": "ab" * 32, "status": "immature",
                                 "found_ts": 4, "amount": 88_000_000},
                                {"height": 480, "hash": "cd" * 32, "status": "matured",
                                 "found_ts": 3, "amount": 17_000_000}],
              "recent_payouts": [{"amount": 105_000_000, "txid": "ab" * 32, "ts": 4}]}
    mp = _render_miner_page(snap, ADDR, detail, chart, "/api/litecoin", "/", "/c/litecoin")
    chk("miner: doctype + address", mp.lstrip().startswith("<!doctype") and ADDR in mp)
    chk("miner: workers + payouts + chart", "Workers" in mp and "Recent payouts" in mp and "<svg" in mp)
    # per-block earnings (incl. immature) + a Pending KPI summing immature credits
    chk("miner: block earnings + pending", "Block earnings" in mp and "Pending" in mp
        and "/c/litecoin/block/500" in mp and "st-immature" in mp)
    chk("miner: worker XSS escaped", XSS not in mp and "&lt;script&gt;" in mp)
    # icons read semantically: Workers->cpu (chip), Owed->payout (banknote), Best share->star
    chk("miner: meaningful icons (cpu/payout/star)",
        '<rect x="6.6" y="6.6"' in mp        # cpu chip inner square (Workers)
        and '<circle cx="8" cy="8" r="1.7"' in mp   # banknote coin (Owed payout)
        and "M8 1.8 9.9 5.7" in mp)          # star (Best share)
    chk("miner: inline script only", "<script>" in mp and "<script src" not in mp.lower())
    mp_nf = _render_miner_page(snap, "tltc1qnope", None, "", "/api/litecoin", "/", "/c/litecoin")
    chk("miner: not-found page", "no shares recorded" in mp_nf and mp_nf.lstrip().startswith("<!doctype"))

    # block detail page
    block = {"height": 500, "hash": "00ff" * 16, "reward": 312_500_000, "found_ts": 5,
             "status": "matured", "net_diff": 1000.0, "finder": ADDR, "round_diff": 880.0,
             "luck_percent": 88.0, "credited_miners": 2,
             "credits": [{"address": ADDR, "amount": 300_000_000},
                         {"address": "tltc1qfaucet", "amount": 12_500_000}]}
    bp = _render_block_page(snap, block, 120, 100, "/api/litecoin", "/", "/c/litecoin")
    chk("block: doctype + height", bp.lstrip().startswith("<!doctype") and "Block #500" in bp)
    chk("block: finder links to miner page", "/c/litecoin/miner/" in bp)
    chk("block: reward + status pill", "Reward" in bp and "st-matured" in bp)
    # per-miner reward split (who was credited what)
    chk("block: reward split table", "Reward split" in bp and bp.count("/c/litecoin/miner/") >= 2)
    chk("block: hash copy button", "Copy hash" in bp)
    # confirmations show the PER-COIN maturity (the route passes coin.maturity, not a
    # hardcoded 100): Monero matures at 60, BTC/LTC at 100.
    from testnetpool.coin import COINS, COINBASE_MATURITY  # noqa: E402
    chk("block: per-coin maturity (monero 60, btc 100)",
        getattr(COINS["monero"], "maturity", COINBASE_MATURITY) == 60
        and getattr(COINS["bitcoin"], "maturity", COINBASE_MATURITY) == 100)
    bp60 = _render_block_page({**snap, "coin": "monero"}, {**block, "status": "immature"},
                              1, 60, "/api", None, "/c/monero")
    chk("block: confirmations show the passed maturity (e.g. /60, not /100)",
        "/ 60" in bp60 and "/ 100" not in bp60)
    # litecoin/test has a built-in default explorer (litecoinspace.org)
    chk("block: default explorer per coin/chain",
        "View on explorer" in bp and "litecoinspace.org/testnet/block/" in bp)
    bp_exp = _render_block_page(snap, block, 120, 100, "/api/litecoin", "/", "/c/litecoin",
                                explorer_url="https://exp.example/block/{hash}")
    chk("block: configured explorer_url overrides default",
        "exp.example/block/" in bp_exp and "litecoinspace" not in bp_exp)
    # a chain with no public explorer (regtest) gets no link
    bp_rt = _render_block_page({**snap, "chain": "regtest"}, block, 120, 100, "/api/litecoin", "/", "/c/litecoin")
    chk("block: no explorer link for regtest", "View on explorer" not in bp_rt)
    from testnetpool.stats import explorer_for  # noqa: E402
    chk("explorer_for: defaults + override",
        explorer_for("bitcoin", "testnet4").startswith("https://mempool.space/testnet4/")
        and explorer_for("monero", "stagenet").startswith("https://stagenet.xmrchain.net/")
        and explorer_for("litecoin", "regtest") == ""
        and explorer_for("bitcoin", "test", "https://x/{hash}") == "https://x/{hash}")
    bp_nf = _render_block_page(snap, None, None, 100, "/api/litecoin", "/", "/c/litecoin")
    chk("block: not-found page", "no block at that height" in bp_nf)

    # single-coin mode (home_url=None, coin_base=""): the brand logo must link to
    # the dashboard root "/", NOT relative "." (which on /miner/<addr> and
    # /block/<n> resolves to the non-page /miner/ or /block/).
    mp_single = _render_miner_page(snap, ADDR, detail, chart, "/api", None, "")
    bp_single = _render_block_page(snap, block, 120, 100, "/api", None, "")
    chk("miner: single-coin brand links home, not '.'",
        '<a class=brand href="/">' in mp_single and '<a class=brand href="."' not in mp_single)
    chk("block: single-coin brand links home, not '.'",
        '<a class=brand href="/">' in bp_single and '<a class=brand href="."' not in bp_single)

    # connect / getting-started
    cn = _render_connect([{"coin": "litecoin", "chain": "test", "ticker": "tLTC", "algo": "scrypt",
                           "host": "pool.example.com", "port": 3334, "dash": "/litecoin"}], home_url="/")
    chk("connect: per-coin dashboard link", 'class=cc-dash href="/litecoin"' in cn
        and "Litecoin stats" in cn)
    chk("connect: endpoint (scrypt: no cpuminer CLI)",
        "stratum+tcp://pool.example.com:3334" in cn and "minerd" not in cn and "<details" not in cn)
    chk("connect: doctype + script", cn.lstrip().startswith("<!doctype") and "<script>" in cn)
    # Monero (RandomX) keeps an xmrig CPU command - RandomX is CPU-mineable
    cnm = _render_connect([{"coin": "monero", "chain": "stagenet", "ticker": "sXMR",
                            "algo": "randomx", "host": "h", "port": 3335, "dash": "/monero"}], home_url="/")
    chk("connect: monero keeps xmrig CPU command",
        "xmrig" in cnm and "<details" in cnm and "minerd" not in cnm)
    # d=NNNN difficulty-pin is honored only on the share-based (BTC/LTC) stratum; the
    # Monero CryptoNote login ignores the password, so the card must not claim it. The
    # xmrig --url must be a bare host:port (xmrig rejects a stratum+tcp:// scheme prefix).
    chk("connect: d= pin shown on scrypt card, hidden on randomx card",
        "d=NNNN" in cn and "d=NNNN" not in cnm)
    chk("connect: xmrig url is bare host:port (no scheme prefix)",
        "--url h:3335" in cnm and "--url stratum+tcp://" not in cnm)
    cnx = _render_connect([{"coin": "x", "chain": "t", "ticker": "X", "algo": "scrypt",
                            "host": '"><script>', "port": 1, "dash": "/"}])
    chk("connect: host escaped", '"><script>' not in cnx)
    # Worker configurator: live address/rig inputs + a copyable username, fed by data-*.
    chk("connect: worker configurator", "class=cc-addr" in cn and "class=cc-rig" in cn
        and "class=cc-user" in cn and "data-ph=" in cn and "data-url=" in cn)
    chk("connect: monero command is live-updatable", "cc-cmd" in cnm and "cc-cmdcopy" in cnm)
    # Over Tor (onion host) -> a note about tunneling the miner; clearnet has none.
    cn_tor = _render_connect([{"coin": "litecoin", "chain": "test", "ticker": "tLTC", "algo": "scrypt",
                               "host": "abc.onion", "port": 3334, "dash": "/"}])
    chk("connect: tor mining note when on .onion", "Tor mirror" in cn_tor and "torsocks" in cn_tor)
    chk("connect: no tor note on clearnet", "Tor mirror" not in cn)

    # Pending-transactions "next block" page + endpoint (ckpool-style transparency) ----
    from testnetpool.stats import (  # noqa: E402
        _render_template_page, _tx_explorer, _api_endpoints)
    chk("tx-explorer derives /tx/ from a /block/ template",
        _tx_explorer("https://litecoinspace.org/testnet/block/{hash}")
        == "https://litecoinspace.org/testnet/tx/{txid}" and _tx_explorer("") == "")
    chk("api docs list the /template endpoint",
        any(p.endswith("/template") for p, _ in _api_endpoints(True)))
    tsum = {"coin": "litecoin", "chain": "test", "available": True, "height": 4763341,
            "full_block": True, "tx_count": 2, "total_fee": 2800, "total_vsize": 368,
            "txs": [{"txid": "aa" * 32, "fee": 2260, "vsize": 226},
                    {"txid": "bb" * 32, "fee": 540, "vsize": 142}]}
    tpage = _render_template_page(tsum, "/api", "/", "/litecoin", explorer_url="")
    chk("template page: txs table + explorer tx links + json link",
        tpage.lstrip().startswith("<!doctype") and ("aa" * 32) in tpage
        and "litecoinspace.org/testnet/tx/" in tpage and "/api/template" in tpage and "fee/vB" in tpage)
    tempty = _render_template_page({**tsum, "tx_count": 0, "total_fee": 0, "total_vsize": 0, "txs": []},
                                   "/api", "/", "/litecoin")
    chk("template page: coinbase-only empty state",
        "coinbase-only" in tempty and ("aa" * 32) not in tempty)
    tna = _render_template_page({"coin": "monero", "chain": "stagenet", "available": False},
                                "/api", "/", "/monero")
    chk("template page: graceful when unavailable (monero)", "isn't available" in tna)

    # Faucet-address transparency in the payout panel + the inline .mono CSS fix -------
    from testnetpool.stats import _payout_panel  # noqa: E402
    chk("css: inline .mono class is defined", ".mono{font-family:var(--mono)}" in cn)
    psnap = {"coin": "litecoin", "faucet_address": "tltc1qfaucetxyz",
             "payout": {"model": "PPLNS", "maturity_confirmations": 100, "fee_percent": 1.0,
                        "pplns_window": 100_000, "payout_interval_seconds": 300,
                        "min_payout": 0.001, "sweep_after_days": 30}}
    panel = _payout_panel(psnap, "tLTC", "/litecoin")
    # The faucet links to its OWN pool page (Owed/Paid = the fee flow), not a block
    # explorer - so it works for every coin, including Monero's stealth addresses.
    chk("payout panel: faucet is a labeled display linked to its pool /miner/ page, copyable",
        "class=faucet-addr" in panel and ">Faucet<" in panel
        and 'href="/litecoin/miner/tltc1qfaucetxyz"' in panel
        and 'data-copy="tltc1qfaucetxyz"' in panel)
    # A long address (e.g. Monero's ~95 chars) is middle-truncated in the display to match
    # the rest of the UI; the FULL value stays in the link, copy button, and tooltip.
    LONGADDR = "B" + "x" * 91 + "QX4z"
    mpanel = _payout_panel({**psnap, "coin": "monero", "faucet_address": LONGADDR}, "sXMR", "/monero")
    chk("payout panel: long faucet address is truncated in display, full in copy/link",
        (LONGADDR[:12] + "…" + LONGADDR[-8:]) in mpanel
        and f'data-copy="{LONGADDR}"' in mpanel and f'/monero/miner/{LONGADDR}' in mpanel)
    chk("payout panel: no dependency on a block explorer (works for Monero too)",
        "/address/" not in mpanel and "xmrchain" not in mpanel)
    chk("payout panel: single-coin faucet link has no coin prefix",
        'href="/miner/tltc1qfaucetxyz"' in _payout_panel(psnap, "tLTC", ""))
    chk("payout panel: solo mode shows no faucet block",
        "class=faucet-addr" not in _payout_panel({"payout": {"model": "SOLO"}}, "tBTC", ""))

    # dashboard tables now link to the detail pages
    html = _render_html(
        snap, None, "",
        [{"height": 500, "hash": "00ff" * 16, "reward": 1, "found_ts": 1, "status": "matured",
          "net_diff": 1000.0, "round_diff": 1.0, "luck_percent": 1.0}],
        [{"address": ADDR, "owed": 1, "paid": 0, "last_seen": 1, "shares": 1}], [],
        coin_base="/c/litecoin", chart_html=chart)
    chk("dash: block height links to /block/", "/c/litecoin/block/500" in html)
    chk("dash: address links to /miner/", "/c/litecoin/miner/" in html)
    chk("dash: has pool chart + Connect nav", "<svg" in html and 'href="/connect"' in html)
    chk("dash: ships chart-tooltip CSS + JS handler",
        ".chart-tip" in html and "chart-tip" in html and "data-tip" in html
        and ".chart-tip.below" in html              # viewport edge-flip
        and "'mouseleave'" in html and "'blur'" in html)  # hide on window-leave
    chk("dash: live-update hooks", 'data-live="pool_hashrate.5m"' in html and "id=live-updated" in html)
    # network hashrate stat: present, formatted to the real value, live-wired
    chk("dash: network hashrate stat", "Network hashrate" in html
        and 'data-live="network_hashrate_hs"' in html and "4.79 PH/s" in html)
    # semantic icons on the dashboard: Top miners->trophy, Best share->star,
    # Connected by software->software (terminal). (uses 1-miner fixture so Top miners shows)
    chk("dash: meaningful icons (trophy/star/software)",
        "M4.5 2.5h7v3" in html               # trophy (Top miners)
        and "M8 1.8 9.9 5.7" in html         # star (Best share)
        and "M4.5 8.4 6.2 9.9" in html)      # terminal prompt (Connected by software)
    # global address search box lives in the nav on every page
    chk("dash: nav address search", 'class=navfind' in html and 'action="/find"' in html)
    chk("dash: Donate nav", 'href="/donate">Donate' in html)
    chk("dash: CypherFaucet links (header + footer)",
        'href="https://cypherfaucet.com" target=_blank rel=noopener>CypherFaucet' in html
        and 'ext-ico' in html              # header CypherFaucet carries the external-link marker
        and '>CypherFaucet</a>' in html)
    # decluttered footer: no AGPL spelled out, no api-link list; keeps source (§13) + donate
    chk("footer: decluttered", "AGPL-3.0" not in html and "/api/litecoin/blocks" not in html
        and ">source</a>" in html and '/donate">donate' in html)

    # "How payouts work" panel (public mode) with the real configured numbers
    pay = {"model": "PPLNS", "fee_percent": 1.0, "min_payout": 0.001, "pplns_window": 100000,
           "maturity_confirmations": 100, "payout_interval_seconds": 300.0, "sweep_after_days": 30.0}
    pp = _payout_panel({"payout": pay}, "tLTC")
    chk("payout: PPLNS + numbers", "PPLNS" in pp and "100 confs" in pp
        and "1% → " in pp and "0.001 tLTC" in pp and "shares" in pp)
    chk("payout: fee links to CypherFaucet", "cypherfaucet.com" in pp and "CypherFaucet" in pp)
    chk("payout: solo variant", "Solo mode" in _payout_panel({"payout": {"model": "solo"}}, "tBTC"))

    # donate page
    d = DonateConfig(openalias="donate@testnetpool.com", bitcoin="tb1qBTC",
                     litecoin="tltc1qLTC", monero="9zXMR")
    don = _render_donate(d, home_url="/")
    chk("donate: doctype + nav", don.lstrip().startswith("<!doctype") and 'href="/donate"' in don)
    chk("donate: openalias + 3 coins", "donate@testnetpool.com" in don
        and all(a in don for a in ("tb1qBTC", "tltc1qLTC", "9zXMR")))
    chk("donate: copy buttons + marks", "copy-btn" in don and "data-copy" in don
        and don.count('class="coin-mark"') >= 3)
    # one self-contained QR SVG per configured address (pure-Python encoder, no
    # external image/CDN), each with a centered coin-mark logo on a white backing
    chk("donate: one QR svg per coin", don.count("class=qr") == 3
        and don.count("shape-rendering=crispEdges") == 3
        and don.count('rx="2" fill="#fff"') == 3)
    chk("donate: no QR when no addresses", "class=qr" not in _render_donate(DonateConfig()))
    # a misconfigured (oversize) address drops its QR but still renders the page
    big = _render_donate(DonateConfig(bitcoin="x" * 400))
    chk("donate: oversize address degrades gracefully",
        "x" * 400 in big and "class=qr" not in big and "copy-btn" in big)
    chk("donate: empty graceful", "no donation addresses" in _render_donate(DonateConfig()))
    chk("donate: address escaped", '"><script>' not in _render_donate(DonateConfig(bitcoin='"><script>')))
    chk("donate: mainnet note", "mainnet (real) coins" in _render_donate(DonateConfig(bitcoin="x")))

    # legal page: plain-English terms + privacy notice; linked from the footer
    legal = _render_legal(home_url="/")
    chk("legal: doctype + page chrome", legal.lstrip().startswith("<!doctype")
        and "coin-badge>Legal" in legal and legal.count("class=legal") == 6)
    chk("legal: covers the essentials",
        all(s in legal for s in ("no monetary value", "no accounts", "may log payout addresses",
                                 "not guaranteed", "faucet", "AGPL, without warranty",
                                 "hosted service")))
    chk("legal: footer links to /legal", '<a href="/legal">legal</a>' in legal)

    # solo mode now shows the address lookup (for the live connected-rigs view) but
    # still hides the DB-backed payout UI (Recent payouts / Top miners). The
    # consistent top navbar (Connect/Donate/Faucet/API) is the same as every other page.
    # /api/stats is valid in solo (returns pool stats), so the API link is fine.
    sh = _render_html({**snap, "mode": "solo", "payout": {"model": "solo", "maturity_confirmations": 100}},
                      None, "", [], None, None)
    chk("solo: shows address lookup, hides payout UI", "Your stats" in sh
        and "Recent payouts" not in sh and "Top miners" not in sh)
    chk("solo: keeps blocks + solo payout text", "Found blocks" in sh and "Solo mode" in sh)
    chk("solo: consistent navbar still present",
        ">Connect</a>" in sh and ">Donate</a>" in sh and ">API</a>" in sh)

    # connect: miner-agnostic (URL/user/pass + copy), address placeholder, next-step link
    cn2 = _render_connect([{"coin": "litecoin", "chain": "test", "ticker": "tLTC",
                            "algo": "scrypt", "host": "h", "port": 1, "dash": "/"}])
    chk("connect: address placeholder + next-step",
        "YOUR_tLTC_ADDRESS" in cn2 and "look up your address" in cn2)
    chk("connect: miner-agnostic (not minerd-centric), no rental CTA",
        "any Stratum miner" in cn2 and "Bitaxe" in cn2 and ".workername" in cn2
        and "NiceHash" not in cn2 and "MiningRigRentals" not in cn2)
    chk("connect: URL copy button, no cpuminer CLI on scrypt",
        'class="copy-btn mini"' in cn2 and "minerd" not in cn2 and "<details" not in cn2)

    # block page: status legend + correctly-labeled Credited miners
    chk("block: status legend + credited label", "orphaned</b>:" in bp and "Credited miners" in bp)
    # miner page: Owed promoted, no duplicate "Best ever", owed/paid explained
    chk("miner: owed in hero, no dup, explained",
        "Owed" in mp and "Best ever" not in mp and "balance waiting" in mp)


def test_contrast():
    """WCAG AA guard: dim text tokens stay >= 4.5:1 on their surfaces in BOTH themes.

    Checks the light and dark token dicts directly so a palette edit (either mode)
    can't silently regress contrast.
    """
    from testnetpool.stats import _LIGHT, _DARK

    def _lin(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def _lum(hx):
        hx = hx.lstrip("#")
        r, g, b = (int(hx[i:i + 2], 16) for i in (0, 2, 4))
        return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)

    def ratio(fg, bg):
        a, b = _lum(fg), _lum(bg)
        hi, lo = max(a, b), min(a, b)
        return (hi + 0.05) / (lo + 0.05)

    for mode, P in (("light", _LIGHT), ("dark", _DARK)):
        for fg in ("faint", "muted", "soft", "text"):
            # "bg" is the page background; .note/.code/etc. render text directly on it.
            for bg in ("bg", "card", "surface", "row-alt"):
                r = ratio(P[fg], P[bg])
                chk(f"contrast[{mode}]: {fg} on {bg} >= 4.5:1", r >= 4.5, f"{r:.2f}:1")
        rb = ratio(P["on-accent"], P["btn"])
        chk(f"contrast[{mode}]: button label on btn >= 4.5:1", rb >= 4.5, f"{rb:.2f}:1")
        rp = ratio(P["accent-soft"], P["accent-bg"])
        chk(f"contrast[{mode}]: pill text on accent-bg >= 4.5:1", rp >= 4.5, f"{rp:.2f}:1")
        # The .code block (connect page) is accent-soft text on the page bg.
        rc = ratio(P["accent-soft"], P["bg"])
        chk(f"contrast[{mode}]: code text (accent-soft) on bg >= 4.5:1", rc >= 4.5, f"{rc:.2f}:1")


def test_no_scientific_notation():
    """The dashboard must never render numbers in scientific notation (the user's
    complaint).  Cover every formatter that feeds difficulty/best-share/hashrate
    across the full plausible magnitude range, plus a fully-rendered page whose
    snapshot carries astronomically large difficulties."""
    import re
    # Python/JS scientific notation always carries an explicit exponent sign
    # ('1e+03', '7.3e+21', '1e-05'); requiring [+-] avoids matching CSS hex colors
    # like '#e6e8ec' (which contain a bare digit-e-digit run).
    sci = re.compile(r"\d[eE][+-]\d")
    vals = [0, 1, 999, 1000, 16384, 999999, 1234567, 1.48e9, 1e12, 1e15, 1e18,
            9.99e20, 1e21, 7.3e21, 2.0 ** 70, 6.022e23, 1e24, 9.9e30]
    for v in vals:
        s = _fmt_num(v)
        chk(f"_fmt_num({v:g}) not scientific", not sci.search(s), s)
    for v in [0, 999, 1234, 5.2e15, 9.9e18, 9.9e24]:
        s = fmt_hashrate(v)
        chk(f"fmt_hashrate({v:g}) not scientific", not sci.search(s), s)
    # Carry-at-boundary regression: 999999 -> '1.00 M', not '1e+03 K'; compactness
    # preserved: 16384 -> '16.4 K'.
    chk("_fmt_num carries at 1000 boundary", _fmt_num(999999) == "1.00 M", _fmt_num(999999))
    chk("_fmt_num stays compact", _fmt_num(16384) == "16.4 K", _fmt_num(16384))
    # Whole rendered page with huge difficulties: no 'e+NN' anywhere in the numbers.
    snap = {"coin": "litecoin", "chain": "test", "algo": "scrypt", "mode": "public", "height": 5,
            "uptime": 100.0, "network_difficulty": 7.3e21, "active_miners": 1, "known_miners": 1,
            "connected_miners": 1, "blocks_found": 1, "est_seconds_per_block": 600,
            "current_round": {"effort_percent": 50.0, "share_diff": 6.022e23},
            "pool_hashrate": {"5m": 9.9e18}, "pool_hashrate_hs": 9.9e18,
            "accepted_shares": 10, "best_share": 2.0 ** 75}
    page = _render_html(snap, None, "", [], api_base="/api")
    chk("rendered page has no scientific notation", not sci.search(page))


def test_consistent_nav():
    """The header navbar must be one stable bar on every page (no per-page
    '← coins'/'← dashboard' breadcrumb), with the current page marked active."""
    import re
    snap = {"coin": "litecoin", "chain": "test", "algo": "scrypt", "mode": "public", "height": 5,
            "uptime": 100.0, "network_difficulty": 1000.0, "active_miners": 1, "known_miners": 1,
            "connected_miners": 1, "blocks_found": 1, "est_seconds_per_block": 600,
            "current_round": {"effort_percent": 50.0}, "pool_hashrate": {"5m": 1e9},
            "pool_hashrate_hs": 1e9, "accepted_shares": 10, "best_share": 1234.0}
    det = {"address": "tltc1q", "first_seen": 1, "last_seen": 2, "owed": 1, "paid": 0, "shares": 1,
           "best_share": 1.0, "hashrate": {"5m": 1, "1h": 1, "24h": 1}, "workers": [], "recent_payouts": []}
    blk = {"height": 5, "hash": "00" * 32, "reward": 1, "found_ts": 1, "status": "matured",
           "net_diff": 1000.0, "round_diff": 1.0, "luck_percent": 1.0, "finder": "x", "credited_miners": 1}
    ci = [{"coin": "litecoin", "chain": "test", "ticker": "tLTC", "algo": "scrypt",
           "host": "h", "port": 3334, "dash": "/"}]
    D = DonateConfig(bitcoin="b")

    def header(html):
        return re.search(r"<nav>(.*?)</nav>", html, re.S).group(1)

    def labels(html):
        h = header(html)
        return tuple(re.sub(r"<[^>]+>", "", t).strip()
                     for _, t in re.findall(r'<a[^>]*href="[^"]*"[^>]*>(\s*<span[^>]*>.*?</span>)?(.*?)</a>', h, re.S)
                     if "class=brand" not in _)

    # single-coin mode: same labels on every page; no breadcrumb arrows in the header
    pages_single = {
        "dashboard": _render_html(snap, None, "", [], api_base="/api", home_url=None),
        "miner": _render_miner_page(snap, "tltc1q", det, "", "/api", None, ""),
        "block": _render_block_page(snap, blk, 1, 100, "/api", None, ""),
        "connect": _render_connect(ci, home_url=None),
        "donate": _render_donate(D, home_url=None),
    }
    want_single = ("Connect", "Donate", "CypherFaucet", "API")
    for name, html in pages_single.items():
        chk(f"nav[single/{name}]: stable link set", labels(html) == want_single, str(labels(html)))
        chk(f"nav[single/{name}]: no breadcrumb arrow", "←" not in header(html))

    # hub mode: every page gains a leading "Coins" but is otherwise identical
    pages_hub = {
        "dashboard": _render_html(snap, None, "", [], api_base="/api/litecoin", home_url="/", coin_base="/c/litecoin"),
        "miner": _render_miner_page(snap, "tltc1q", det, "", "/api/litecoin", "/", "/c/litecoin"),
        "connect": _render_connect(ci, home_url="/"),
        "donate": _render_donate(D, home_url="/"),
    }
    want_hub = ("Coins", "Connect", "Donate", "CypherFaucet", "API")
    for name, html in pages_hub.items():
        chk(f"nav[hub/{name}]: stable link set", labels(html) == want_hub, str(labels(html)))
        chk(f"nav[hub/{name}]: no breadcrumb arrow", "←" not in header(html))

    # active page is marked (aria-current) on connect/donate
    chk("nav: connect marks itself active",
        'aria-current="page" class=cur>Connect' in header(pages_single["connect"]))
    chk("nav: donate marks itself active",
        'aria-current="page" class=cur>Donate' in header(pages_single["donate"]))
    # in-page back links live in the BODY, correctly labelled by destination
    chk("miner body: back to dashboard", '<a class=back href="/c/litecoin/">← dashboard</a>'
        in pages_hub["miner"])
    chk("block body: back to blocks",
        '← blocks</a>' in _render_block_page(snap, blk, 1, 100, "/api/litecoin", "/", "/c/litecoin"))


def test_chart_ranges():
    from testnetpool.stats import _chart_range, _chart_tabs, _chart_block, _svg_chart  # noqa: E402
    chk("chart range: ?range= parsed", _chart_range("/x?range=1w") == "1w"
        and _chart_range("/x") == "24h" and _chart_range("/x?range=bad") == "24h")
    tabs = _chart_tabs("1h")
    chk("chart tabs: all ranges + active",
        all(f'?range={k}' in tabs for k in ("1h", "24h", "1w", "1m"))
        and '?range=1h" class=cur>1H' in tabs)
    chk("chart tabs: relative hrefs (path-preserving)", 'href="?range=' in tabs and "/c/" not in tabs)
    blk = _chart_block("hashrate", "Pool hashrate", "last 7d",
                       _svg_chart([(1, 1e9), (2, 2e9)]), tabs=tabs)
    chk("chart block uses tabs in place of caption", "chart-tabs" in blk and "last 7d" not in blk)


def test_nav_stat_strip():
    snap = {"coin": "litecoin", "chain": "test", "algo": "scrypt", "mode": "public",
            "height": 139888, "uptime": 100.0, "network_difficulty": 1.6e8, "active_miners": 3,
            "known_miners": 10, "connected_miners": 3, "blocks_found": 2, "est_seconds_per_block": 600,
            "current_round": {"effort_percent": 50.0}, "pool_hashrate": {"5m": 2.1e9},
            "pool_hashrate_hs": 2.1e9, "accepted_shares": 10, "best_share": 1234.0}
    d = _render_html(snap, None, "", [], api_base="/api", home_url=None)
    chk("nav strip: present on coin dashboard", "class=nav-stats" in d)
    chk("nav strip: wired to live refresh",
        'data-live="pool_hashrate.5m" data-fmt="hashrate"' in d
        and 'data-live="active_miners"' in d and 'data-live="height"' in d)
    chk("nav strip: height shown in full (not abbreviated)", ">139888<" in d)
    from testnetpool.config import DonateConfig  # noqa: E402
    land = _render_landing([{"name": "litecoin", "snap": snap}])
    cn = _render_connect([{"coin": "litecoin", "chain": "test", "ticker": "tLTC",
                           "algo": "scrypt", "host": "h", "port": 3334, "dash": "/"}])
    dn = _render_donate(DonateConfig(bitcoin="b"))
    chk("nav strip: absent on global pages (no single coin)",
        "class=nav-stats" not in land and "class=nav-stats" not in cn and "class=nav-stats" not in dn)


def test_transparency_api():
    import time as _t
    from testnetpool.stats import Stats, StatsServer, fmt_count
    from testnetpool.config import StatsConfig
    from testnetpool.stratum import BanManager

    class _V: enabled = True; target_time = 15.0; min_difficulty = 1024; max_difficulty = 1 << 24; start_difficulty = 16384  # noqa: E701,E702
    class _Pub: fee_percent = 1.0; min_payout = 0.001; pplns_window = 100000; payout_interval = 300; sweep_after_days = 30  # noqa: E701,E702
    class _Cfg: coin = "litecoin"; chain = "test"; mode = "public"; template_refresh = 30.0; stratum_port = 3334; coinbase_tag = "/x/"; include_transactions = True; public = _Pub(); vardiff = _V()  # noqa: E701,E702
    class _Coin: algo = "scrypt"; hashes_per_diff1 = 1 << 16; diff1_target = 1 << 256; maturity = 100  # noqa: E701,E702
    class _VD: difficulty = 16384.0  # noqa: E701
    conn = type("C", (), {"id": 1, "worker": "addr.rig", "accepted": 5, "rejected": 1,
                          "last_share": _t.time(), "peer": "9.9.9.9:1", "vardiff": _VD(),
                          "user_agent": "XMRig/6.26.0 (Linux x86_64) libuv/1.51.0 gcc/13.1",
                          "address": "addr", "worker_name": "rig", "best": 4096.0})()

    class _Pool:
        cfg = _Cfg(); coin = _Coin(); accounting = None; connections = {conn}; current_height = 5
        last_template_ts = _t.time(); last_node_contact = _t.time()
        mempool = {"txs": 1247, "vbytes": 5000, "total_fee": 0.05}
        bans = BanManager()
        def current_job(self): return None  # noqa: E704
    p = _Pool(); p.stats = Stats(p)
    p.stats.record_reject("low_diff"); p.stats.record_reject("low_diff"); p.stats.record_reject("stale")
    snap = p.stats.snapshot()
    # Network hashrate prefers the node's own getnetworkhashps (accurate on testnet)
    # over the difficulty-only estimate. (snap above is already captured.)
    p.network_hashps = 4.79e15
    p.stats._snap_cache = None  # bypass the short-TTL snapshot cache to read fresh state
    chk("api: net hashrate prefers node getnetworkhashps",
        p.stats.snapshot()["network_hashrate_hs"] == 4.79e15)
    p.network_hashps = None  # restore; later snapshots fall back to the estimate

    chk("api: snapshot leaks NO miner IP", all("peer" not in m for m in snap["miners"]))
    chk("api: snapshot keeps non-PII fields", snap["miners"][0]["worker"] == "addr.rig"
        and "id" in snap["miners"][0])
    chk("api: reject_reasons + total", snap["reject_reasons"] == {"low_diff": 2, "stale": 1}
        and snap["rejected_shares"] == 3)
    chk("api: mempool + block-tx fields present", snap["mempool"]["txs"] == 1247
        and "block_txs" in snap)
    # Miner software is coarsened to product + major.minor before it leaves the
    # process - the full agent fingerprints a miner (OS/arch/lib/compiler), like its IP.
    chk("api: miner_agents coarsened", snap["miner_agents"] == {"XMRig/6.26": 1})
    live = _live_for_address(p, "addr")
    chk("api: /miner live software coarsened",
        bool(live) and live[0]["user_agent"] == "XMRig/6.26")
    chk("api: full fingerprinting agent NEVER published",
        not any(s in str(snap) + str(live) for s in ("Linux", "x86_64", "libuv", "gcc", "6.26.0")))
    # short_agent reducer: keep product + major.minor, drop platform/lib/compiler/patch.
    # Includes the adversarial inputs the fuzz pass surfaced (OS-as-name, fingerprint
    # tail, and a long-digit "version" used to smuggle entropy past the coarsening).
    for raw, want in [
        ("XMRig/6.26.0 (Linux x86_64) libuv/1.51.0 gcc/13.1", "XMRig/6.26"),
        ("cgminer/4.11.1", "cgminer/4.11"),
        ("BzMiner/v21.0.0", "BzMiner/21.0"),
        ("SRBMiner-MULTI/2.4.9", "SRBMiner-MULTI/2.4"),
        ("Bitaxe", "Bitaxe"), ("someminer/dev", "someminer"),
        ("evilminer/1.2.3 (secret-fingerprint-data here AAAA)", "evilminer/1.2"),
        ("(Linux x86_64)", ""), ("(Windows NT 10.0; Win64; x64)", ""),
        ("name/99999999999999999999.0", "name/9999"),  # entropy-smuggling capped
        ("name/١٢.0", "name"),               # unicode digits don't count as a version
        ("", ""), (None, ""), (12345, ""),
    ]:
        chk(f"short_agent({raw!r})", short_agent(raw) == want, f"got {short_agent(raw)!r}")
    # Hard invariant: coarsened output is always short and never carries the
    # fingerprinting tail, regardless of input.
    chk("short_agent bounds length + drops fingerprint",
        all(len(short_agent(u)) <= 26 and not any(t in short_agent(u)
            for t in ("Linux", "x86_64", "libuv", "gcc", "secret"))
            for u in ["XMRig/6.26.0 (Linux x86_64) libuv/1.51.0 gcc/13.1",
                      "evilminer/9.9.9 (secret AAAA)", "x" * 300 + "/1.2.3"]))
    # Abuse control is surfaced as a COUNT only - never the banned IPs themselves.
    p.bans.strike("6.6.6.6", _t.time())
    p.bans._banned["6.6.6.6"] = _t.time() + 100  # force one active ban
    p.stats._snap_cache = None  # bypass the short-TTL snapshot cache to read fresh state
    snap2 = p.stats.snapshot()
    chk("api: banned_ips is a count, not addresses", snap2["banned_ips"] == 1
        and "6.6.6.6" not in str(snap2))

    srv = StatsServer([p], StatsConfig(enabled=True, host="127.0.0.1", port=0))
    info = srv._info()
    chk("api/info: version + source + license", info["version"] and "github" in info["source"]
        and info["license"].startswith("AGPL"))
    chk("api/info: per-coin rules (verifiable)",
        info["coins"][0]["payout"]["fee_percent"] == 1.0
        and info["coins"][0]["vardiff"]["target_time"] == 15.0
        and info["coins"][0]["include_transactions"] is True)
    idx = srv._api_index()
    chk("api index: self-describing + privacy note",
        "/api/info" in idx["endpoints"] and "/healthz" in idx["endpoints"]
        and "IPs are never exposed" in idx["notes"] and idx["docs"] == "/api/docs")
    b, ctype, st = srv._healthz()
    chk("healthz: 200 + json when fresh", st == b"HTTP/1.1 200 OK\r\n" and ctype == "application/json")
    # API docs page: content-negotiated. Browser -> HTML page, script -> JSON index.
    hb, hc = srv._route("/api", accept="text/html,application/xhtml+xml")
    chk("api: browser gets HTML docs page", hc.startswith("text/html")
        and hb.lstrip().startswith(b"<!doctype") and b"JSON API" in hb)
    jb, jc = srv._route("/api", accept="*/*")
    chk("api: script gets JSON index", jc == "application/json" and jb.lstrip().startswith(b"{"))
    db, dc = srv._route("/api/docs")
    chk("api: /api/docs is always the page", dc.startswith("text/html")
        and b"<!doctype" in db and b"/api/info" in db)


def test_ux_bundle():
    """public-pool UX bundle: software breakdown, best-share leaderboard, live
    per-rig accept/reject, and online/idle/offline worker status."""
    import time as _t
    import tempfile as _tf
    import os as _os
    from testnetpool.accounting import Accounting
    from testnetpool.stats import worker_status_pill

    # --- accounting: best-share leaderboard + miners_overview carries best_share ---
    fd, path = _tf.mkstemp(suffix=".db"); _os.close(fd)
    try:
        acc = Accounting(path, "bitcoin")
        now = int(_t.time())
        acc.record_share("tb1qLOW", 1000, now - 10, share_diff=500, worker="r1")
        acc.record_share("tb1qHIGH", 1000, now - 10, share_diff=900000, worker="r1")
        acc.record_share("tb1qMID", 1000, now - 10, share_diff=4200, worker="r1")
        lb = acc.best_shares(10)
        chk("best_shares ranks by difficulty desc",
            [e["address"] for e in lb] == ["tb1qHIGH", "tb1qMID", "tb1qLOW"], str(lb))
        chk("best_shares carries the value", lb[0]["best_share"] == 900000)
        ov = {m["address"]: m for m in acc.miners_overview()}
        chk("miners_overview includes best_share", ov["tb1qHIGH"]["best_share"] == 900000)
        # the faucet (pool fee sink, 0 shares) is excluded from the miners leaderboard
        ov_ex = {m["address"] for m in acc.miners_overview(exclude="tb1qMID")}
        chk("miners_overview excludes the given (faucet) address",
            "tb1qMID" not in ov_ex and "tb1qHIGH" in ov_ex)
        # transparency: the excluded (faucet) address IS shown when it has live hashrate
        # (recent shares), and stays hidden when dormant.
        ov_active = {m["address"] for m in
                     acc.miners_overview(exclude="tb1qMID", exclude_active_since=now - 600)}
        chk("miners_overview shows the faucet when it has live hashrate", "tb1qMID" in ov_active)
        ov_dormant = {m["address"] for m in
                      acc.miners_overview(exclude="tb1qMID", exclude_active_since=now + 10000)}
        chk("miners_overview hides the faucet when not recently active", "tb1qMID" not in ov_dormant)
        acc.close() if hasattr(acc, "close") else None
    finally:
        _os.unlink(path)

    # --- worker status pill thresholds ---
    now = _t.time()
    chk("status online", "st-online" in worker_status_pill(now - 60, now))
    chk("status idle", "st-idle" in worker_status_pill(now - 1000, now))
    chk("status offline (old)", "st-offline" in worker_status_pill(now - 9999, now))
    chk("status offline (never)", "st-offline" in worker_status_pill(0, now))

    # --- render: software chips, leaderboard, live per-rig reject table ---
    UA_XSS = '<img src=x onerror=alert(1)>'
    snap = {
        "coin": "bitcoin", "chain": "testnet4", "mode": "public", "height": 1,
        "uptime": 10.0, "network_difficulty": 1e6, "active_miners": 1,
        "known_miners": 1, "connected_miners": 1, "blocks_found": 0,
        "est_seconds_per_block": 100, "current_round": {"effort_percent": 50.0},
        "pool_hashrate": {"5m": 1e9}, "pool_hashrate_hs": 1e9,
        "algo": "sha256d", "accepted_shares": 1, "best_share": 1.0,
        "miner_agents": {"bitaxe/2.4": 3, UA_XSS: 1},
    }
    detail = {
        "address": "tb1qme", "first_seen": int(now) - 100, "last_seen": int(now) - 5,
        "owed": 0, "paid": 0, "shares": 5, "best_share": 77.0,
        "hashrate": {"5m": 1e9, "1h": 1e9, "24h": 1e9},
        "workers": [{"worker": "r1", "last_seen": int(now) - 5, "shares": 5,
                     "hashrate": {"5m": 1e9, "1h": 1e9, "24h": 1e9}}],
        "live": [{"worker": "r1", "difficulty": 16384.0, "accepted": 40, "rejected": 7,
                  "user_agent": UA_XSS, "last_share_ago": 3.0}],
        "recent_payouts": [],
    }
    leaderboard = [{"address": "tb1qHIGH", "best_share": 900000.0},
                   {"address": "tb1qme", "best_share": 77.0}]
    html = _render_html(snap, detail, "tb1qme", [], [], [], leaderboard=leaderboard)
    chk("ux: software breakdown section", "Connected by software" in html and "bitaxe/2.4" in html)
    chk("ux: software UA escaped (no raw tag)", "<img src=x" not in html and "&lt;img src=x" in html)
    chk("ux: best-share leaderboard section", "Best shares" in html and "900" in html)
    chk("ux: live rig table", "connected rig" in html and ">40<" in html and ">7<" in html)
    chk("ux: live rig UA escaped (no raw tag)", "<img src=x" not in html)
    chk("ux: online pill in workers/top", "st-online" in html)


def test_worker_model():
    """public-pool worker model: per-worker best (persisted), worker_detail, the
    per-rig page, and the solo live-only view built from connections."""
    import time as _t
    import tempfile as _tf
    import os as _os

    fd, path = _tf.mkstemp(suffix=".db"); _os.close(fd)
    try:
        acc = Accounting(path, "bitcoin")
        now = int(_t.time())
        acc.record_share("tb1qX", 1000, now - 10, share_diff=5000, worker="rig1")
        acc.record_share("tb1qX", 1000, now - 5, share_diff=80000, worker="rig1")
        acc.record_share("tb1qX", 1000, now - 5, share_diff=300, worker="rig2")
        wb = {w["worker"]: w for w in acc.worker_breakdown("tb1qX", now)}
        chk("worker best persisted per rig",
            wb["rig1"]["best_share"] == 80000 and wb["rig2"]["best_share"] == 300, str(wb))
        wd = acc.worker_detail("tb1qX", "rig1", now)
        chk("worker_detail: best + share count", wd["best_share"] == 80000 and wd["shares"] == 2)
        chk("worker_detail: unknown rig -> None", acc.worker_detail("tb1qX", "nope", now) is None)
        ser = acc.hashrate_series(now, span=3600, buckets=12, address="tb1qX", worker="rig2")
        chk("hashrate_series worker filter isolates the rig",
            sum(p["diff"] for p in ser["points"]) == 1000, str(ser))
    finally:
        _os.unlink(path)

    snap = {
        "coin": "bitcoin", "chain": "testnet4", "mode": "public", "height": 1,
        "uptime": 1.0, "network_difficulty": 1e6, "active_miners": 1, "known_miners": 1,
        "connected_miners": 1, "blocks_found": 0, "est_seconds_per_block": 1,
        "current_round": {"effort_percent": 1.0}, "pool_hashrate": {"5m": 1e9},
        "pool_hashrate_hs": 1e9, "algo": "sha256d", "accepted_shares": 1, "best_share": 1.0,
        "miner_agents": {},
    }
    now = _t.time()
    wd2 = {"address": "tb1qX", "worker": "rig1", "shares": 2, "best_share": 80000.0,
           "first_seen": int(now) - 100, "last_seen": int(now) - 5,
           "hashrate": {300: 1e9, 3600: 1e9, 86400: 1e9},
           "live": [{"worker": "rig1", "difficulty": 16384.0, "accepted": 2, "rejected": 0,
                     "best": 80000.0, "user_agent": "xmrig/6", "last_share_ago": 5.0}]}
    wp = _render_worker_page(snap, "tb1qX", "rig1", wd2, "", "/api", None, "")
    chk("worker page: rig name + best + live", "rig1" in wp and "Best share" in wp
        and "Live session" in wp and "80.0 K" in wp)
    chk("worker page: missing rig -> notfound",
        "no shares recorded for this rig" in _render_worker_page(snap, "tb1qX", "z", None, "", "/api", None, ""))

    # solo: live-only view straight off the connections (no DB, no payout_address).
    class _VD:
        difficulty = 16384.0
    conn = type("C", (), {"address": "tb1qSOLO", "worker_name": "rig1", "accepted": 3,
                          "rejected": 0, "best": 1234.0, "user_agent": "xmrig",
                          "last_share": now - 2, "vardiff": _VD(), "payout_address": ""})()
    pool = type("P", (), {"connections": {conn}})()
    live = _live_for_address(pool, "tb1qSOLO")
    chk("live_for_address groups by self.address", len(live) == 1 and live[0]["best"] == 1234.0)
    chk("live_for_address ignores other addresses", _live_for_address(pool, "tb1qOTHER") == [])
    sd = _solo_detail(pool, "tb1qSOLO")
    chk("solo_detail: live-only, best from sessions", sd["solo"] and sd["best_share"] == 1234.0)
    chk("solo_detail: no connection -> None", _solo_detail(pool, "tb1qNONE") is None)
    sp = _render_miner_page({**snap, "mode": "solo"}, "tb1qSOLO", sd, "", "/api", None, "")
    chk("solo miner page: rigs shown, no money UI",
        "Connected rigs" in sp and "Solo mode" in sp and "Owed" not in sp and "Recent payouts" not in sp)


def main():
    test_accounting()
    test_chart_ranges()
    test_nav_stat_strip()
    test_transparency_api()
    test_ux_bundle()
    test_worker_model()
    test_round_and_luck()
    test_render()
    test_landing()
    test_pages()
    test_contrast()
    test_no_scientific_notation()
    test_consistent_nav()
    passed = sum(1 for _, c, _ in ok if c)
    for name, c, detail in ok:
        line = f"  [{'PASS' if c else 'FAIL'}] {name}"
        if not c and detail:
            line += f"   ({detail})"
        print(line)
    print(f"\n{passed}/{len(ok)} dashboard checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
