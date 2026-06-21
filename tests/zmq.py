# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Loopback test for the pure-Python ZMTP SUB listener.

A fake ZMQ PUB peer performs the ZMTP 3.0 handshake (greeting + READY), consumes
the listener's SUBSCRIBE, then publishes a multipart `hashblock` message. We assert
the listener completes the handshake, parses the message, and fires its callback -
proving our hand-rolled ZMTP framing is correct, no pyzmq needed.

Run:  python3 tests/zmq.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.zmq_listener import _GREETING, _frame, _ready_command, ZmqBlockListener  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def _frame_more(body: bytes) -> bytes:
    return bytes([0x01]) + bytes([len(body)]) + body  # short frame, MORE set


async def _read_frame(reader):
    flags = (await reader.readexactly(1))[0]
    length = (int.from_bytes(await reader.readexactly(8), "big") if flags & 0x02
              else (await reader.readexactly(1))[0])
    body = await reader.readexactly(length) if length else b""
    return flags, body


async def main() -> int:
    received = []
    got = asyncio.Event()

    async def on_block():
        received.append(1)
        got.set()

    handshake = {"greeting_len": None, "subscribed": None}

    async def fake_pub(reader, writer):
        # Server side of ZMTP: send greeting + READY, then read the client's.
        writer.write(_GREETING)
        writer.write(_ready_command())
        await writer.drain()
        peer_greeting = await reader.readexactly(64)
        handshake["greeting_len"] = len(peer_greeting)
        await _read_frame(reader)                  # client READY command
        _flags, sub = await _read_frame(reader)    # client SUBSCRIBE message
        handshake["subscribed"] = sub              # expect b"\x01hashblock"
        # Publish a hashblock multipart message: [topic, 32-byte hash, 4-byte seq].
        block_hash = bytes(range(32))
        writer.write(_frame_more(b"hashblock") + _frame_more(block_hash)
                     + _frame((0).to_bytes(4, "little")))
        await writer.drain()
        await asyncio.sleep(0.3)
        writer.close()

    server = await asyncio.start_server(fake_pub, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    listener = ZmqBlockListener(f"tcp://127.0.0.1:{port}", on_block)
    task = asyncio.create_task(listener.run())
    try:
        await asyncio.wait_for(got.wait(), timeout=4)
    except asyncio.TimeoutError:
        pass
    listener.stop()
    task.cancel()
    server.close()
    await server.wait_closed()

    chk("client sent a valid 64-byte greeting", handshake["greeting_len"] == 64)
    chk("client subscribed to 'hashblock'", handshake["subscribed"] == b"\x01hashblock")
    chk("on_block fired on the hashblock message", len(received) == 1)

    # a bad URL must disable cleanly, not crash
    bad = ZmqBlockListener("not-a-url", on_block)
    await bad.run()  # returns immediately (logs an error)
    chk("bad zmq_block_url disables cleanly", True)

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} zmq checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
