# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""End-to-end integration test, no litecoind required.

Runs the real Pool/StratumServer with a mocked RPC, then drives a simulated
miner over a real TCP socket: subscribe -> authorize -> receive job -> rebuild
the header *from the mining.notify wire fields only* -> submit.  This proves the
on-the-wire encodings (prevhash word-reversal, coinb1/coinb2 split, merkle
branch, version/ntime/nbits/nonce byte order) all round-trip with what the pool
independently reconstructs on submit, and that a network-target share triggers
submitblock.

Run:  python3 tests/integration.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool import util  # noqa: E402
from testnetpool.address import _b58check_decode  # noqa: E402  (only to keep import side simple)
from testnetpool.config import (  # noqa: E402
    Config, RPCConfig, StatsConfig, VardiffConfig,
)
from testnetpool.pool import Pool  # noqa: E402

PREVHASH = "00000000000000000000000000000000000000000000000000000000deadbeef"


class FakeRPC:
    """Stand-in for RPCClient that serves one easy regtest template."""

    def __init__(self):
        self.submitted: list[str] = []

    async def get_blockchain_info(self):
        return {"chain": "regtest", "blocks": 200, "headers": 200}

    async def get_best_block_hash(self):
        return PREVHASH

    async def get_mempool_info(self, timeout=None):
        return {"size": 3, "bytes": 1024, "total_fee": 0.0001}

    async def get_block_template(self, rules=("segwit", "mweb"), longpollid=None, timeout=None):
        bits = "207fffff"  # near-max target: any header hashes "below" it
        return {
            "height": 200,
            "previousblockhash": PREVHASH,
            "version": 0x20000000,
            "bits": bits,
            "curtime": 1_700_000_123,
            "mintime": 1_700_000_000,
            "target": f"{util.bits_to_target(int(bits, 16)):064x}",
            "coinbasevalue": 2_500_000_000,
            "transactions": [],
        }

    async def submit_block(self, block_hex):
        self.submitted.append(block_hex)
        return None  # accepted


def miner_header_from_notify(notify, en1_hex, en2_hex, nonce, version_override=None):
    """Reconstruct the 80-byte header the way a real miner would, using only the
    notify params + the subscribe-assigned extranonce1.  ``version_override`` lets
    a version-rolling miner substitute its rolled nVersion."""
    (_job_id, prevhash, coinb1, coinb2, branch, version_be, nbits_be, ntime_be, _clean) = notify

    coinbase = bytes.fromhex(coinb1) + bytes.fromhex(en1_hex) + bytes.fromhex(en2_hex) + bytes.fromhex(coinb2)
    h = util.sha256d(coinbase)
    for step in branch:
        h = util.sha256d(h + bytes.fromhex(step))
    merkle_root = h

    # prevhash field -> internal order = reverse bytes within each 4-byte word.
    pb = bytes.fromhex(prevhash)
    prev_internal = b"".join(pb[i:i + 4][::-1] for i in range(0, 32, 4))

    ver_le = util.pack_u32le(version_override) if version_override is not None else bytes.fromhex(version_be)[::-1]
    header = (
        ver_le
        + prev_internal
        + merkle_root
        + bytes.fromhex(ntime_be)[::-1]
        + bytes.fromhex(nbits_be)[::-1]
        + util.pack_u32le(nonce)
    )
    return header, ntime_be


async def main() -> int:
    cfg = Config(
        chain="regtest",
        address="rltc1qw508d6qejxtdg4y5r3zarvary0c5xw7k693xs3",  # valid rltc bech32
        stratum_host="127.0.0.1",
        stratum_port=13333,
        include_transactions=False,
        block_poll_interval=0.2,
        template_refresh=999,
        rpc=RPCConfig(host="127.0.0.1", port=19443, user="x", password="y"),
        vardiff=VardiffConfig(enabled=False, start_difficulty=0.0001),
        stats=StatsConfig(enabled=False),
    )
    pool = Pool(cfg)
    fake = FakeRPC()
    pool.rpc = fake  # type: ignore[assignment]

    run_task = asyncio.create_task(pool.run())

    # Wait for the first job to be built.
    for _ in range(50):
        if pool.current_job() is not None:
            break
        await asyncio.sleep(0.1)
    assert pool.current_job() is not None, "pool never built a job"

    reader, writer = await asyncio.open_connection("127.0.0.1", 13333)

    # Messages from the pool interleave request-replies (have "id") with pushed
    # notifications (have "method"), so dispatch by which kind we're waiting for.
    notif_buffer: list[dict] = []

    async def send(obj):
        writer.write((json.dumps(obj) + "\n").encode())
        await writer.drain()

    async def wait_for_id(target_id):
        while True:
            m = json.loads(await asyncio.wait_for(reader.readline(), timeout=3))
            if m.get("id") == target_id and ("result" in m or "error" in m):
                return m
            if m.get("method"):
                notif_buffer.append(m)

    async def wait_for_method(method):
        for m in list(notif_buffer):
            if m.get("method") == method:
                notif_buffer.remove(m)
                return m
        while True:
            m = json.loads(await asyncio.wait_for(reader.readline(), timeout=3))
            if m.get("method") == method:
                return m
            if m.get("method"):
                notif_buffer.append(m)

    # subscribe
    await send({"id": 1, "method": "mining.subscribe", "params": ["tester/1.0"]})
    sub = await wait_for_id(1)
    en1_hex = sub["result"][1]
    en2_size = sub["result"][2]
    ok = []
    ok.append(("subscribe returns en1+en2_size", isinstance(en1_hex, str) and en2_size == 4))

    # authorize
    await send({"id": 2, "method": "mining.authorize", "params": ["myworker", "x"]})
    auth = await wait_for_id(2)
    ok.append(("authorize ok", auth["result"] is True))

    # set_difficulty should have been pushed before the job.
    diff_msg = await wait_for_method("mining.set_difficulty")
    ok.append(("set_difficulty pushed", isinstance(diff_msg["params"][0], (int, float))))

    notify_msg = await wait_for_method("mining.notify")
    notify_params = notify_msg["params"]

    # Confirm the miner-reconstructed header equals the pool's own reconstruction.
    job = pool.get_job(notify_params[0])
    en2_hex = "00000001"

    # Mine: iterate nonce until the header hashes below the (easy) network target.
    header = None
    nonce = 0
    for nonce in range(200000):
        header, ntime_be = miner_header_from_notify(notify_params, en1_hex, en2_hex, nonce)
        if util.hash_int_le(util.scrypt_pow(header)) <= job.network_target:
            break
    pool_header = job.build_header(bytes.fromhex(en1_hex), bytes.fromhex(en2_hex),
                                   int(ntime_be, 16), nonce)
    ok.append(("miner header == pool header (wire encodings round-trip)", header == pool_header))
    ok.append(("found nonce below network target", util.hash_int_le(util.scrypt_pow(header)) <= job.network_target))

    # submit
    await send({
        "id": 3,
        "method": "mining.submit",
        "params": ["myworker", notify_params[0], en2_hex, ntime_be, f"{nonce:08x}"],
    })
    sub_resp = await wait_for_id(3)
    ok.append(("share accepted", sub_resp.get("result") is True))

    # Give the block-submit coroutine a moment.
    await asyncio.sleep(0.3)
    ok.append(("submitblock called once", len(fake.submitted) == 1))
    ok.append(("block recorded as accepted", pool.stats.blocks and pool.stats.blocks[-1]["accepted"]))

    # The submitted block must parse: header(80) + 0x01 + coinbase, no trailing.
    block = bytes.fromhex(fake.submitted[0]) if fake.submitted else b""
    ok.append(("submitted block starts with our header", block[:80] == header))
    ok.append(("submitted block is coinbase-only", len(block) > 80 and block[80] == 0x01))

    writer.close()

    # MiningRigRentals path: a worker that authorizes with a "d=<diff>" password
    # must be pinned to that fixed difficulty.
    r2, w2 = await asyncio.open_connection("127.0.0.1", 13333)

    async def send2(obj):
        w2.write((json.dumps(obj) + "\n").encode())
        await w2.drain()

    async def wait2(method):
        while True:
            m = json.loads(await asyncio.wait_for(r2.readline(), timeout=3))
            if m.get("method") == method:
                return m

    await send2({"id": 1, "method": "mining.subscribe", "params": ["rentedrig/1.0"]})
    await send2({"id": 2, "method": "mining.authorize", "params": ["renter", "d=777"]})
    pinned = None
    for _ in range(4):
        msg = await asyncio.wait_for(wait2("mining.set_difficulty"), timeout=3)
        pinned = msg["params"][0]
        if pinned == 777:
            break
    ok.append(("password 'd=777' pins fixed difficulty", pinned == 777))
    # whatsminer/MRR fix: a fresh job is pushed AFTER mining.authorize (some rigs discard
    # any work received before they're authorized), so a mining.notify follows the auth-time
    # difficulty. Without the post-authorize push these rigs idle out and reconnect forever.
    post_auth_notify = await asyncio.wait_for(wait2("mining.notify"), timeout=3)
    ok.append(("job (re)pushed after authorize",
               isinstance(post_auth_notify.get("params"), list) and len(post_auth_notify["params"]) == 9))
    w2.close()

    # Version-rolling (ASICBoost / MRR) end-to-end: negotiate a mask, mine with a
    # rolled nVersion, submit it as the 6th param, and confirm the pool folds it
    # in - the submitted block's header version must carry the rolled bits.
    r3, w3 = await asyncio.open_connection("127.0.0.1", 13333)

    async def send3(obj):
        w3.write((json.dumps(obj) + "\n").encode())
        await w3.drain()

    async def wait3(pred):
        while True:
            m = json.loads(await asyncio.wait_for(r3.readline(), timeout=3))
            if pred(m):
                return m

    await send3({"id": 1, "method": "mining.configure",
                 "params": [["version-rolling"], {"version-rolling.mask": "1fffe000"}]})
    cfg_resp = await wait3(lambda m: m.get("id") == 1 and "result" in m)
    mask = int(cfg_resp["result"]["version-rolling.mask"], 16)
    ok.append(("version-rolling negotiated", cfg_resp["result"]["version-rolling"] is True and mask == 0x1FFFE000))

    await send3({"id": 2, "method": "mining.subscribe", "params": ["asic/1.0"]})
    sub3 = await wait3(lambda m: m.get("id") == 2 and "result" in m)
    en1_3 = sub3["result"][1]
    await send3({"id": 3, "method": "mining.authorize", "params": ["asicrig", "x"]})
    notify3 = await wait3(lambda m: m.get("method") == "mining.notify")
    np3 = notify3["params"]

    job_version = int(np3[5], 16)
    rolled_version = (job_version & ~mask) | 0x00002000   # roll one bit inside the mask
    en2_3 = "00000002"
    blocks_before = len(fake.submitted)
    hdr3 = None
    for nonce in range(200000):
        hdr3, ntime3 = miner_header_from_notify(np3, en1_3, en2_3, nonce, version_override=rolled_version)
        if util.hash_int_le(util.scrypt_pow(hdr3)) <= pool.get_job(np3[0]).network_target:
            break
    await send3({"id": 4, "method": "mining.submit",
                 "params": ["asicrig", np3[0], en2_3, ntime3, f"{nonce:08x}", f"{rolled_version:08x}"]})
    resp3 = await wait3(lambda m: m.get("id") == 4 and "result" in m)
    ok.append(("version-rolled share accepted", resp3.get("result") is True))

    await asyncio.sleep(0.2)
    block_ver = None
    if len(fake.submitted) > blocks_before:
        block_ver = int.from_bytes(bytes.fromhex(fake.submitted[-1])[:4], "little")
    ok.append(("submitted block header carries rolled version", block_ver == rolled_version))
    w3.close()

    pool.stop()
    try:
        await asyncio.wait_for(run_task, timeout=3)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        run_task.cancel()

    passed = sum(1 for _, c in ok if c)
    for name, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(ok)} integration checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
