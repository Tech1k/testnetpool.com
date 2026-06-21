# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""End-to-end test for public (PPLNS) mode - Layer 1.

Verifies, against the real Pool/Stratum with a mocked node:
  * a miner authorizing with a VALID payout address as its username succeeds,
    and its accepted share is recorded in the SQLite accounting DB keyed to that
    address;
  * a miner authorizing with an INVALID address is rejected.

Run:  python3 tests/public.py
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
    Config, PublicConfig, RPCConfig, StatsConfig, VardiffConfig,
)
from testnetpool.pool import Pool  # noqa: E402
from testnetpool.selftest import _bech32_encode  # noqa: E402

from integration import FakeRPC, miner_header_from_notify  # noqa: E402

# Distinct valid regtest (rltc) addresses for miner / pool / faucet.
MINER_ADDR = _bech32_encode("rltc", 0, b"\x11" * 20)
POOL_ADDR = _bech32_encode("rltc", 0, b"\x22" * 20)
FAUCET_ADDR = _bech32_encode("rltc", 0, b"\x33" * 20)


async def main() -> int:
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ok = []
    won = {}  # captures the winning header from the mining session
    cfg = Config(
        coin="litecoin", chain="regtest", mode="public",
        stratum_host="127.0.0.1", stratum_port=13334,
        block_poll_interval=0.2, template_refresh=999,
        rpc=RPCConfig(host="127.0.0.1", port=19443, user="x", password="y"),
        vardiff=VardiffConfig(enabled=False, start_difficulty=0.0001),
        stats=StatsConfig(enabled=True, host="127.0.0.1", port=18085),
        public=PublicConfig(db_path=db_path, pool_address=POOL_ADDR, faucet_address=FAUCET_ADDR),
    )
    pool = Pool(cfg)
    pool.rpc = FakeRPC()  # type: ignore[assignment]
    ok.append(("public coinbase pays the pool wallet", cfg.coinbase_address == POOL_ADDR))

    run_task = asyncio.create_task(pool.run())
    for _ in range(50):
        if pool.current_job() is not None:
            break
        await asyncio.sleep(0.1)
    assert pool.current_job() is not None, "pool never built a job"

    async def session(host, port, username, mine):
        reader, writer = await asyncio.open_connection(host, port)
        notif = []

        async def send(o):
            writer.write((json.dumps(o) + "\n").encode())
            await writer.drain()

        async def wait_id(i):
            while True:
                m = json.loads(await asyncio.wait_for(reader.readline(), timeout=3))
                if m.get("id") == i and ("result" in m or "error" in m):
                    return m
                if m.get("method"):
                    notif.append(m)

        async def wait_method(meth):
            for m in list(notif):
                if m.get("method") == meth:
                    return m
            while True:
                m = json.loads(await asyncio.wait_for(reader.readline(), timeout=3))
                if m.get("method") == meth:
                    return m

        await send({"id": 1, "method": "mining.subscribe", "params": ["t/1.0"]})
        sub = await wait_id(1)
        en1 = sub["result"][1]
        await send({"id": 2, "method": "mining.authorize", "params": [username, "x"]})
        auth = await wait_id(2)
        result = (auth.get("result"), en1, reader, writer, wait_id, wait_method, send)
        if not mine or auth.get("result") is not True:
            writer.close()
            return auth.get("result"), None
        notify = (await wait_method("mining.notify"))["params"]
        job = pool.get_job(notify[0])
        en2 = "00000001"
        for nonce in range(200000):
            hdr, ntime = miner_header_from_notify(notify, en1, en2, nonce)
            if util.hash_int_le(util.scrypt_pow(hdr)) <= job.network_target:
                break
        won["hdr"] = hdr  # capture the winning header for the block-id regression
        await send({"id": 3, "method": "mining.submit",
                    "params": [username, notify[0], en2, ntime, f"{nonce:08x}"]})
        sresp = await wait_id(3)
        writer.close()
        return auth.get("result"), sresp.get("result")

    # 1) valid address authorizes + share recorded
    auth_ok, share_ok = await session("127.0.0.1", 13334, MINER_ADDR, mine=True)
    ok.append(("valid address authorized", auth_ok is True))
    ok.append(("share accepted", share_ok is True))
    await asyncio.sleep(0.2)
    row = pool.accounting.conn.execute(
        "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.address=?",
        (MINER_ADDR,),
    ).fetchone()
    ok.append(("share persisted to DB for that address", row[0] >= 1))

    # On regtest the share also met the network target -> a block -> PPLNS snapshot.
    blk = pool.accounting.conn.execute("SELECT status, hash FROM blocks").fetchone()
    ok.append(("block recorded immature in public mode", blk is not None and blk[0] == "immature"))
    # Regression: the stored block identity must be sha256d(header), NOT the scrypt
    # PoW hash - otherwise the maturity loop's getblockhash comparison orphans every
    # Litecoin block and no one is ever paid.
    hdr = won.get("hdr")
    ok.append(("block id is sha256d(header), not scrypt PoW",
               hdr is not None and blk is not None
               and blk[1] == util.internal_to_display(util.sha256d(hdr))
               and blk[1] != util.internal_to_display(util.scrypt_pow(hdr))))
    cred = pool.accounting.conn.execute("SELECT COUNT(*) FROM credits").fetchone()[0]
    ok.append(("PPLNS credits snapshotted (miner + faucet)", cred >= 2))

    # JSON API.
    async def get_api(path):
        r, w = await asyncio.open_connection("127.0.0.1", 18085)
        w.write(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        await w.drain()
        raw = await r.read()
        w.close()
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b"{}"
        return json.loads(body or b"{}")

    miners_api = await get_api("/api/miners")
    ok.append(("/api/miners lists the miner",
               any(m["address"] == MINER_ADDR for m in miners_api.get("miners", []))))

    stats_api = await get_api("/api/stats")
    ok.append(("/api/stats has pool_hashrate windows",
               isinstance(stats_api.get("pool_hashrate"), dict) and "5m" in stats_api["pool_hashrate"]))
    ok.append(("/api/stats has current_round", isinstance(stats_api.get("current_round"), dict)))
    ok.append(("/api/stats has active/known/best",
               all(k in stats_api for k in ("active_miners", "known_miners", "best_share"))))
    ok.append(("/api/stats has algo", stats_api.get("algo") in ("scrypt", "sha256d")))
    ok.append(("/api/stats has payout economics",
               stats_api.get("payout", {}).get("model") == "PPLNS"
               and "fee_percent" in stats_api["payout"]))

    luck_api = await get_api("/api/luck")
    ok.append(("/api/luck shape",
               isinstance(luck_api.get("blocks"), list) and "pool_luck_percent" in luck_api))

    miner_api = await get_api(f"/api/miner/{MINER_ADDR}")
    ok.append(("/api/miner enriched (hashrate+best+workers)",
               all(k in miner_api for k in ("hashrate", "best_share", "workers"))))

    chart_api = await get_api("/api/chart")
    ok.append(("/api/chart series", isinstance(chart_api.get("points"), list)
               and "bucket_width" in chart_api))

    template_api = await get_api("/api/template")
    ok.append(("/api/template shape (current block template txs)",
               template_api.get("available") is True and isinstance(template_api.get("txs"), list)
               and all(k in template_api for k in
                       ("height", "tx_count", "total_fee", "total_vsize", "full_block"))))

    # New HTML pages: bookmarkable miner page, block detail, connect.
    async def get_html(path, host="pool.example.com"):
        r, w = await asyncio.open_connection("127.0.0.1", 18085)
        w.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        await w.drain()
        raw = await r.read()
        w.close()
        return (raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b"").decode("utf-8", "replace")

    from urllib.parse import quote  # noqa: E402
    miner_page = await get_html(f"/miner/{quote(MINER_ADDR)}")
    ok.append(("/miner/<addr> page renders",
               miner_page.lstrip().startswith("<!doctype html") and MINER_ADDR in miner_page
               and "Workers" in miner_page))
    blk_height = pool.accounting.conn.execute("SELECT height FROM blocks").fetchone()[0]
    block_page = await get_html(f"/block/{blk_height}")
    ok.append(("/block/<height> page renders",
               block_page.lstrip().startswith("<!doctype html") and f"#{blk_height}" in block_page))
    connect_page = await get_html("/connect")
    ok.append(("/connect page renders endpoint (miner-agnostic, no cpuminer)",
               "stratum+tcp://pool.example.com:13334" in connect_page
               and "YOUR_" in connect_page and "minerd" not in connect_page))
    donate_page = await get_html("/donate")
    ok.append(("/donate page renders",
               donate_page.lstrip().startswith("<!doctype html") and "Support TestnetPool" in donate_page))
    template_page = await get_html("/template")
    ok.append(("/template page renders (next block's transactions)",
               template_page.lstrip().startswith("<!doctype html")
               and "Next block" in template_page and "/api/template" in template_page))
    evil_connect = await get_html("/connect", host='x"><script>alert(1)</script>')
    ok.append(("/connect escapes malicious Host", '"><script>' not in evil_connect))

    # Crafted block heights must not drop the connection: an oversized all-digit
    # height (overflows SQLite int64) and a raw non-ASCII "digit" byte
    # (\xb2 = '²', which isdigit() but int() rejects).
    async def get_raw(raw: bytes):
        r, w = await asyncio.open_connection("127.0.0.1", 18085)
        w.write(raw)
        await w.drain()
        out = await r.read()
        w.close()
        return out

    big = await get_html("/block/" + "9" * 25)
    ok.append(("/block/<overflow> graceful", "no block at that height" in big))
    big_api = await get_api("/api/block/" + "9" * 25)
    ok.append(("/api/block/<overflow> graceful", big_api.get("error") == "unknown block"))
    nonascii = await get_raw(b"GET /block/\xb2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    ok.append(("/block/<non-ascii> returns a response", nonascii.startswith(b"HTTP/1.1 200")
               and b"no block at that height" in nonascii))

    # The dashboard HTML renders and is XSS-safe against an injected ?address=.
    r3, w3 = await asyncio.open_connection("127.0.0.1", 18085)
    w3.write(b"GET /?address=%22%3E%3Cscript%3E HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    await w3.drain()
    raw3 = await r3.read()
    w3.close()
    html = (raw3.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw3 else b"").decode("utf-8", "replace")
    ok.append(("dashboard HTML renders",
               html.lstrip().startswith("<!doctype html") and "Found blocks" in html))
    ok.append(("dashboard escapes injected address",
               '"><script>' not in html and "&lt;script&gt;" in html))

    # 2) invalid address rejected
    auth_bad, _ = await session("127.0.0.1", 13334, "not_a_real_address", mine=False)
    ok.append(("invalid address rejected", auth_bad is False))

    pool.stop()
    try:
        await asyncio.wait_for(run_task, timeout=3)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        run_task.cancel()
    for p in (db_path, db_path + "-wal", db_path + "-shm"):
        try:
            os.unlink(p)
        except OSError:
            pass

    passed = sum(1 for _, c in ok if c)
    for name, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(ok)} public-mode checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
