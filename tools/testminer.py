# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""A tiny real Stratum miner for testing TestnetPool on regtest.

This is NOT a serious miner - it's a single-threaded Python client that lets you
exercise the whole pipeline (pool + a real litecoind) without installing cgminer
or cpuminer.  On regtest the difficulty is trivial, so it finds a block almost
instantly and you can watch the node's block count go up.

Usage:
    python3 tools/testminer.py --host 127.0.0.1 --port 3333 --user worker

For a fast regtest test, set a low difficulty in the pool config so each share
is found in a handful of hashes, e.g.:
    [vardiff]
    enabled = false
    start_difficulty = 0.001
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool import util  # noqa: E402


def build_header(notify, en1_hex, en2_hex, nonce):
    (_jid, prevhash, coinb1, coinb2, branch, ver_be, nbits_be, ntime_be, _clean) = notify
    coinbase = bytes.fromhex(coinb1) + bytes.fromhex(en1_hex) + bytes.fromhex(en2_hex) + bytes.fromhex(coinb2)
    h = util.sha256d(coinbase)
    for step in branch:
        h = util.sha256d(h + bytes.fromhex(step))
    pb = bytes.fromhex(prevhash)
    prev_internal = b"".join(pb[i:i + 4][::-1] for i in range(0, 32, 4))
    return (
        bytes.fromhex(ver_be)[::-1]
        + prev_internal
        + h
        + bytes.fromhex(ntime_be)[::-1]
        + bytes.fromhex(nbits_be)[::-1]
        + util.pack_u32le(nonce)
    )


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=3333)
    ap.add_argument("--user", default="worker")
    ap.add_argument("--password", default="x")
    ap.add_argument("--shares", type=int, default=0, help="stop after N accepted shares (0 = forever)")
    args = ap.parse_args()

    reader, writer = await asyncio.open_connection(args.host, args.port)
    msg_id = [0]

    async def send(method, params):
        msg_id[0] += 1
        writer.write((json.dumps({"id": msg_id[0], "method": method, "params": params}) + "\n").encode())
        await writer.drain()
        return msg_id[0]

    state = {"en1": None, "en2_size": 4, "diff": 1.0, "notify": None}
    accepted = 0

    async def reader_loop():
        while True:
            line = await reader.readline()
            if not line:
                break
            msg = json.loads(line)
            if msg.get("method") == "mining.set_difficulty":
                state["diff"] = msg["params"][0]
                print(f"[miner] difficulty -> {state['diff']}")
            elif msg.get("method") == "mining.notify":
                state["notify"] = msg["params"]
                print(f"[miner] new job {msg['params'][0]} (clean={msg['params'][8]})")
            elif "result" in msg and msg.get("id") == 1:
                state["en1"] = msg["result"][1]
                state["en2_size"] = msg["result"][2]
                print(f"[miner] subscribed: extranonce1={state['en1']} en2_size={state['en2_size']}")
            elif "result" in msg:
                nonlocal_accept(msg)

    def nonlocal_accept(msg):
        nonlocal accepted
        if msg.get("result") is True:
            accepted += 1
            print(f"[miner] share ACCEPTED ({accepted})")
        elif msg.get("error"):
            print(f"[miner] share rejected: {msg['error']}")

    rt = asyncio.create_task(reader_loop())

    await send("mining.subscribe", ["testminer/0.1"])
    await send("mining.authorize", [args.user, args.password])

    # Wait until we have a job + extranonce.
    while state["notify"] is None or state["en1"] is None:
        await asyncio.sleep(0.05)

    en2 = 0
    print("[miner] mining... (Ctrl-C to stop)")
    while True:
        notify = state["notify"]
        target = util.difficulty_to_target(state["diff"])
        en2_hex = en2.to_bytes(state["en2_size"], "big").hex()
        ntime_be = notify[7]
        found = None
        # Sweep the nonce space for this (job, extranonce2).  On regtest a hit
        # comes almost immediately; bail out early if the job changes.
        for nonce in range(0, 1 << 32):
            header = build_header(notify, state["en1"], en2_hex, nonce)
            if util.hash_int_le(util.scrypt_pow(header)) <= target:
                found = nonce
                break
            if nonce % 2000 == 0:
                await asyncio.sleep(0)  # yield; pick up new jobs
                if state["notify"] is not notify:
                    break
        if found is None:
            en2 += 1
            continue
        print(f"[miner] found share: job={notify[0]} en2={en2_hex} nonce={found:08x}")
        await send("mining.submit", [args.user, notify[0], en2_hex, ntime_be, f"{found:08x}"])
        en2 += 1
        await asyncio.sleep(0.1)
        if args.shares and accepted >= args.shares:
            break

    rt.cancel()
    writer.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
