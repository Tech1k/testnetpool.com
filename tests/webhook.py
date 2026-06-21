# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Loopback test for the generic block-found webhook.

A throwaway HTTP server captures the POST; we assert post_block delivers the JSON
body and content-type, and that a dead endpoint / empty URL never raises (a notify
failure must never touch the block path).

Run:  python3 tests/webhook.py
"""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.webhook import post_block  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


received = {}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        received["body"] = self.rfile.read(n).decode()
        received["ctype"] = self.headers.get("Content-Type")
        received["ua"] = self.headers.get("User-Agent")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):  # silence the default stderr logging
        pass


async def main() -> int:
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    payload = {"event": "block_found", "pool": "TestnetPool", "coin": "litecoin",
               "chain": "test", "height": 123, "hash": "ab" * 32, "reward": 12.5}
    await post_block(f"http://127.0.0.1:{port}/hook", payload)

    chk("webhook delivered a body", "body" in received)
    chk("webhook body is the JSON payload", json.loads(received.get("body", "{}")) == payload)
    chk("webhook sets application/json", received.get("ctype") == "application/json")
    chk("webhook identifies itself", received.get("ua") == "TestnetPool")
    chk("payload carries no miner identity",
        "ip" not in payload and "miner" not in payload and "worker" not in payload)

    # A dead endpoint must be swallowed, not raised.
    raised = False
    try:
        await post_block("http://127.0.0.1:1/nope", {"x": 1}, timeout=1.0)
    except Exception:
        raised = True
    chk("dead endpoint never raises", not raised)

    # Empty URL is a clean no-op (feature disabled).
    received.clear()
    await post_block("", {"x": 1})
    chk("empty URL is a no-op", "body" not in received)

    # Non-http(s) schemes are refused (no local file read / surprising request).
    received.clear()
    await post_block("file:///etc/passwd", {"x": 1})
    chk("file:// scheme is refused", "body" not in received)

    srv.shutdown()
    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} webhook checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
