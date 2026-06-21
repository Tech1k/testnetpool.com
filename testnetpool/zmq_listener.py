# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Minimal pure-Python ZMTP (ZeroMQ) SUB client - stdlib only, no pyzmq.

Bitcoin/Litecoin Core can publish block notifications over ZMQ
(``-zmqpubhashblock=tcp://127.0.0.1:28332``). Subscribing to that gives the pool
INSTANT new-tip detection without holding an RPC worker open (long-poll) or
polling - which also sidesteps the slow-GBT contention a held long-poll can cause.

We implement just enough of ZMTP 3.0 over TCP - the 64-byte greeting, the NULL
security handshake (READY command exchange), a SUB subscription, and frame parsing
- to receive ``hashblock`` messages. No third-party dependency.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlsplit

log = logging.getLogger("testnetpool.zmq")

# A hashblock notification is ~40 bytes (topic + 32-byte hash); cap a single frame
# far above that but far below "buffer gigabytes" so a bogus length can't OOM us.
MAX_FRAME_BYTES = 1 << 20  # 1 MiB
MAX_MESSAGE_FRAMES = 16    # a hashblock message is ~2-3 parts; bound the multipart count

# ZMTP 3.0 greeting (64 bytes): signature(10) + version(2) + mechanism(20) +
# as-server(1) + filler(31). Signature is 0xFF, 8 padding bytes, 0x7F.
_GREETING = (b"\xff" + b"\x00" * 8 + b"\x7f"      # signature
             + b"\x03\x00"                         # version 3.0
             + b"NULL" + b"\x00" * 16              # mechanism "NULL"
             + b"\x00"                             # as-server = 0 (we're the client)
             + b"\x00" * 31)                       # filler


def _frame(body: bytes, command: bool = False) -> bytes:
    """Serialize one ZMTP frame (final, never MORE)."""
    flags = 0x04 if command else 0x00
    if len(body) > 255:                           # long frame: 8-byte length
        return bytes([flags | 0x02]) + len(body).to_bytes(8, "big") + body
    return bytes([flags]) + bytes([len(body)]) + body


def _ready_command() -> bytes:
    """A READY command advertising Socket-Type=SUB (the NULL-mechanism handshake)."""
    name = b"Socket-Type"
    value = b"SUB"
    meta = bytes([len(name)]) + name + len(value).to_bytes(4, "big") + value
    return _frame(bytes([len(b"READY")]) + b"READY" + meta, command=True)


class ZmqBlockListener:
    """Subscribes to a node's ZMQ block publisher and invokes ``on_block`` (an async
    callback) the instant a new block is announced. Reconnects on its own."""

    def __init__(self, url: str, on_block, topic: bytes = b"hashblock",
                 reconnect_delay: float = 5.0, label: str = ""):
        self.url = url
        self.on_block = on_block
        self.topic = topic
        self.reconnect_delay = reconnect_delay
        self.label = label                 # e.g. "litecoin/test" - names the coin in a hub log
        self._pfx = f"{label}: " if label else ""
        self._running = False

    async def _read_frame(self, reader) -> tuple[bool, bool, bytes]:
        flags = (await reader.readexactly(1))[0]
        is_command = bool(flags & 0x04)
        is_more = bool(flags & 0x01)
        if flags & 0x02:                          # long frame
            length = int.from_bytes(await reader.readexactly(8), "big")
        else:
            length = (await reader.readexactly(1))[0]
        # A hashblock notification is tiny (topic + 32-byte hash); refuse an absurd
        # advertised length so a buggy/malicious local publisher can't make us try to
        # buffer gigabytes. The listener reconnects after the raised error.
        if length > MAX_FRAME_BYTES:
            raise ValueError(f"ZMTP frame too large: {length} bytes (cap {MAX_FRAME_BYTES})")
        body = await reader.readexactly(length) if length else b""
        return is_command, is_more, body

    async def _read_message(self, reader) -> list[bytes]:
        """Read one (multipart) message, skipping any interleaved commands (PING)."""
        parts: list[bytes] = []
        frames = 0
        total = 0
        while True:
            is_command, is_more, body = await self._read_frame(reader)
            # Bound the multipart accumulation: a sender that keeps the MORE bit set on
            # tiny frames would grow parts without limit (the per-frame MAX_FRAME_BYTES cap
            # doesn't bound the COUNT). run() treats ValueError as recoverable + reconnects.
            frames += 1
            total += len(body)
            if frames > MAX_MESSAGE_FRAMES or total > MAX_FRAME_BYTES:
                raise ValueError("ZMTP message too large (too many/oversized frames)")
            if not is_command:
                parts.append(body)
            if not is_more:
                return parts

    async def run(self) -> None:
        self._running = True
        sp = urlsplit(self.url)
        if sp.scheme != "tcp" or not sp.hostname or not sp.port:
            log.error("%szmq_block_url must be tcp://host:port, got %r - ZMQ disabled",
                      self._pfx, self.url)
            return
        while self._running:
            writer = None
            try:
                reader, writer = await asyncio.open_connection(sp.hostname, sp.port)
                writer.write(_GREETING)
                await writer.drain()
                await reader.readexactly(64)               # peer's greeting
                writer.write(_ready_command())
                await writer.drain()
                await self._read_frame(reader)             # peer's READY command
                writer.write(_frame(b"\x01" + self.topic))  # SUBSCRIBE <topic>
                await writer.drain()
                log.info("%szmq: subscribed to '%s' at %s for instant block updates",
                         self._pfx, self.topic.decode("ascii", "replace"), self.url)
                while self._running:
                    parts = await self._read_message(reader)
                    if parts and parts[0] == self.topic:
                        await self.on_block()
            except asyncio.CancelledError:
                raise
            except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError) as exc:
                if self._running:
                    log.warning("%szmq %s lost (%s); reconnecting in %.0fs",
                                self._pfx, self.url, exc, self.reconnect_delay)
            except Exception:
                log.exception("%szmq listener error", self._pfx)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except OSError:
                        pass
            if self._running:
                await asyncio.sleep(self.reconnect_delay)

    def stop(self) -> None:
        self._running = False
