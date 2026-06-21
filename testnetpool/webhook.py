# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Fire-and-forget block-found webhook.

When the pool finds a block it can POST a small JSON body to an operator-configured
URL. No third-party service is assumed - point it at your own endpoint, a shell
script behind a tiny HTTP server, a self-hosted relay, anything that accepts a POST.
Best-effort and isolated: a slow or failing endpoint is logged and never delays or
breaks mining, crediting, or payouts. Pure stdlib (urllib), no dependency.

The payload carries only public block facts (height, hash, reward, coin/chain) - no
miner identities or IPs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("testnetpool.webhook")


async def post_block(url: str, payload: dict, timeout: float = 10.0) -> None:
    """POST ``payload`` as JSON to ``url``. Never raises - logs and returns."""
    if not url:
        return
    # Only http(s): refuse file://, ftp://, etc. The URL is operator-set, so this
    # just stops a fat-fingered scheme from triggering a surprising local read.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        log.warning("block webhook url %s has an unsupported scheme; skipping", _host(url))
        return
    try:
        await asyncio.to_thread(_post, url, payload, timeout)
        log.info("block webhook delivered to %s", _host(url))
    except Exception as exc:  # noqa: BLE001 - a notify failure must not touch the block path
        log.warning("block webhook to %s failed: %s", _host(url), exc)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow 3xx. The scheme of the *initial* URL is vetted in post_block, but
    urllib would otherwise follow a redirect to an arbitrary (possibly internal) target -
    a weak SSRF. Returning None makes a 3xx surface as an HTTPError instead."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post(url: str, payload: dict, timeout: float) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "TestnetPool"},
    )
    with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310 - operator-set URL, no redirects
        resp.read()


def _host(url: str) -> str:
    try:
        sp = urllib.parse.urlsplit(url)
        # host[:port] only - never the raw netloc, which would leak any embedded
        # "user:pass@" credentials from an operator-set webhook URL into the logs.
        h = (sp.hostname or "") + (f":{sp.port}" if sp.port else "")
        h = h or sp.netloc.rsplit("@", 1)[-1] or url
    except Exception:  # noqa: BLE001
        h = url
    # Strip control chars so an operator-set URL can't inject forged log lines.
    return "".join(c for c in h if c.isprintable())
