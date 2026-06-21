# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""End-to-end test for hub mode (multiple coins, one process, one dashboard).

Runs two pools (bitcoin + litecoin regtest) under one Hub with a mocked node,
and verifies: both stratum ports listen, the shared dashboard lists both coins,
per-coin routing works (/c/<coin>, /api/<coin>/*), and a share mined on one
coin's port is recorded only in that coin's DB (coin isolation).

Run:  python3 tests/hub.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool import util  # noqa: E402
from testnetpool.config import (  # noqa: E402
    Config, HubConfig, PublicConfig, RPCConfig, StatsConfig, VardiffConfig,
)
from testnetpool.hub import Hub  # noqa: E402
from testnetpool.selftest import _bech32_encode  # noqa: E402

from integration import FakeRPC, miner_header_from_notify  # noqa: E402

STATS_PORT = 18090
BTC_PORT, LTC_PORT = 13340, 13341
BTC_A = _bech32_encode("bcrt", 0, b"\x11" * 20)
BTC_F = _bech32_encode("bcrt", 0, b"\x22" * 20)
LTC_A = _bech32_encode("rltc", 0, b"\x33" * 20)
LTC_F = _bech32_encode("rltc", 0, b"\x44" * 20)


def _cfg(coin, chain, port, db, addr, faucet):
    return Config(
        coin=coin, chain=chain, mode="public", stratum_host="127.0.0.1", stratum_port=port,
        block_poll_interval=0.2, template_refresh=999,
        rpc=RPCConfig(host="127.0.0.1", port=1, user="x", password="y"),
        vardiff=VardiffConfig(enabled=False, start_difficulty=0.0001),
        stats=StatsConfig(enabled=False),
        public=PublicConfig(db_path=db, pool_address=addr, faucet_address=faucet),
    )


async def get(path):
    r, w = await asyncio.open_connection("127.0.0.1", STATS_PORT)
    w.write(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    await w.drain()
    raw = await r.read()
    w.close()
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""


async def mine_one(port, addr):
    """Subscribe/authorize/mine one scrypt share on a coin's stratum port."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    notif = []

    async def send(o):
        w.write((json.dumps(o) + "\n").encode())
        await w.drain()

    async def wait_id(i):
        while True:
            m = json.loads(await asyncio.wait_for(r.readline(), timeout=3))
            if m.get("id") == i and ("result" in m or "error" in m):
                return m
            if m.get("method"):
                notif.append(m)

    async def wait_notify():
        for m in list(notif):
            if m.get("method") == "mining.notify":
                return m
        while True:
            m = json.loads(await asyncio.wait_for(r.readline(), timeout=3))
            if m.get("method") == "mining.notify":
                return m

    await send({"id": 1, "method": "mining.subscribe", "params": ["t/1"]})
    en1 = (await wait_id(1))["result"][1]
    await send({"id": 2, "method": "mining.authorize", "params": [addr, "x"]})
    await wait_id(2)
    np = (await wait_notify())["params"]
    job = None
    en2 = "00000001"
    for nonce in range(200000):
        hdr, ntime = miner_header_from_notify(np, en1, en2, nonce)
        if util.hash_int_le(util.scrypt_pow(hdr)) <= 0x7FFFFF << 232:
            break
    await send({"id": 3, "method": "mining.submit",
                "params": [addr, np[0], en2, ntime, f"{nonce:08x}"]})
    res = (await wait_id(3)).get("result")
    w.close()
    return res


def _slug_checks(ok) -> None:
    """Two pools of the same coin (different chains) must get distinct slugs and
    route independently - so e.g. Monero testnet + stagenet can run side by side."""
    from testnetpool.config import StatsConfig
    from testnetpool.stats import StatsServer

    def snap(coin, chain):
        return {"coin": coin, "chain": chain, "algo": "randomx", "mode": "public", "height": 5,
                "uptime": 1.0, "network_difficulty": 2, "active_miners": 0, "known_miners": 0,
                "connected_miners": 0, "blocks_found": 0, "est_seconds_per_block": None,
                "current_round": {"effort_percent": 50.0}, "pool_hashrate": {"5m": 0},
                "pool_hashrate_hs": 0, "accepted_shares": 0, "best_share": 0,
                "payout": {"model": "PPLNS", "fee_percent": 1.0, "min_payout": 0.1,
                           "pplns_window": 100, "maturity_confirmations": 60,
                           "payout_interval_seconds": 300, "sweep_after_days": 30}}

    class P:
        def __init__(self, coin, chain, port):
            self.cfg = type("C", (), {"coin": coin, "chain": chain,
                                      "stratum_port": port, "stratum_host": "0.0.0.0"})()
            self.coin = type("K", (), {"algo": "randomx", "hashes_per_diff1": 1,
                                       "diff1_target": 1 << 256, "maturity": 60})()
            self.accounting = object()
            self.stats = type("S", (), {"snapshot": staticmethod(lambda c=coin, h=chain: snap(c, h))})()

    pools = [P("monero", "testnet", 3401), P("monero", "stagenet", 3402), P("bitcoin", "testnet4", 3333)]
    srv = StatsServer(pools, StatsConfig(enabled=True))
    ok.append(("slugs disambiguate same coin",
               set(srv._by_slug) == {"monero-testnet", "monero-stagenet", "bitcoin"}))
    land = srv._route("/", "h")[0].decode()
    ok.append(("landing links both monero instances at /<slug>",
               'href="/monero-testnet"' in land and 'href="/monero-stagenet"' in land
               and 'href="/bitcoin"' in land))
    ta = json.loads(srv._route("/api/monero-testnet/stats", "h")[0])
    sa = json.loads(srv._route("/api/monero-stagenet/stats", "h")[0])
    ok.append(("same-coin instances route independently",
               ta["chain"] == "testnet" and sa["chain"] == "stagenet"))


async def main() -> int:
    ok = []
    db1, db2 = tempfile.mkstemp(suffix=".db")[1], tempfile.mkstemp(suffix=".db")[1]
    cfg = HubConfig(
        stats=StatsConfig(enabled=True, host="127.0.0.1", port=STATS_PORT),
        coins=[
            _cfg("bitcoin", "regtest", BTC_PORT, db1, BTC_A, BTC_F),
            _cfg("litecoin", "regtest", LTC_PORT, db2, LTC_A, LTC_F),
        ],
    )
    hub = Hub(cfg)
    for p in hub.pools:
        p.rpc = FakeRPC()  # type: ignore[assignment]
    btc = next(p for p in hub.pools if p.cfg.coin == "bitcoin")
    ltc = next(p for p in hub.pools if p.cfg.coin == "litecoin")

    run_task = asyncio.create_task(hub.run())
    for _ in range(60):
        if all(p.current_job() is not None for p in hub.pools):
            break
        await asyncio.sleep(0.1)
    ok.append(("both coins have jobs", all(p.current_job() is not None for p in hub.pools)))

    landing = (await get("/")).decode()
    ok.append(("landing lists both coins",
               "bitcoin" in landing and "litecoin" in landing
               and 'href="/bitcoin"' in landing and 'href="/litecoin"' in landing))

    coins = json.loads(await get("/api/coins"))
    ok.append(("/api/coins has both", {c["coin"] for c in coins.get("coins", [])} == {"bitcoin", "litecoin"}))

    btc_dash = (await get("/bitcoin")).decode()
    ok.append(("/bitcoin renders + wired to its API", btc_dash.lstrip().startswith("<!doctype")
               and 'data-api="/api/bitcoin"' in btc_dash))
    legacy = (await get("/c/bitcoin")).decode()
    ok.append(("/c/bitcoin still works (legacy alias)",
               legacy.lstrip().startswith("<!doctype") and 'data-api="/api/bitcoin"' in legacy))

    ltc_stats = json.loads(await get("/api/litecoin/stats"))
    ok.append(("/api/litecoin/stats is litecoin", ltc_stats.get("coin") == "litecoin"))

    unknown = json.loads(await get("/api/dogecoin/stats"))
    ok.append(("unknown coin rejected", "error" in unknown))

    # Onion-Location header: advertised on clearnet HTML, suppressed when already on Tor.
    from testnetpool.stats import _META as _OM

    async def headers_of(path, host):
        r, w = await asyncio.open_connection("127.0.0.1", STATS_PORT)
        w.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        await w.drain(); raw = await r.read(); w.close()
        return raw.split(b"\r\n\r\n", 1)[0]
    _OM["onion"] = "http://abc.onion"
    try:
        h_clear = await headers_of("/connect", "clearnet.test")
        ok.append(("onion: Onion-Location on clearnet HTML",
                   b"Onion-Location: http://abc.onion/connect" in h_clear))
        h_tor = await headers_of("/connect", "abc.onion")
        ok.append(("onion: suppressed when already on .onion", b"Onion-Location" not in h_tor))
        h_json = await headers_of("/api/bitcoin/stats", "clearnet.test")
        ok.append(("onion: not on JSON responses", b"Onion-Location" not in h_json))
    finally:
        _OM["onion"] = ""

    # Coin isolation: mine on the LTC port; it must land only in LTC's DB.
    share_ok = await mine_one(LTC_PORT, LTC_A)
    ok.append(("share accepted on ltc port", share_ok is True))
    await asyncio.sleep(0.2)
    ltc_shares = ltc.accounting.conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
    btc_shares = btc.accounting.conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
    ok.append(("ltc share recorded in ltc DB", ltc_shares >= 1))
    ok.append(("btc DB untouched (coin isolation)", btc_shares == 0))

    _slug_checks(ok)  # two same-coin instances (e.g. monero testnet+stagenet) route distinctly

    hub.stop()
    try:
        await asyncio.wait_for(run_task, timeout=3)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        run_task.cancel()
    for p in (db1, db2):
        for ext in ("", "-wal", "-shm"):
            try:
                os.unlink(p + ext)
            except OSError:
                pass

    passed = sum(1 for _, c in ok if c)
    for name, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(ok)} hub checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
