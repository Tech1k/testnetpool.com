# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Minimal async JSON-RPC client for litecoind.

Uses the stdlib ``urllib`` under ``asyncio.to_thread`` to avoid a third-party
HTTP dependency while keeping the event loop responsive.  litecoind's RPC is
plain HTTP/1.1 with HTTP basic auth, which urllib handles directly.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import itertools
import json
import socket
import urllib.error
import urllib.request


class RPCError(Exception):
    """A non-zero ``error`` object returned by the node, or a transport failure."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class RPCTimeout(RPCError):
    """The request timed out; benign for a long-poll that saw no block."""


async def await_node_ready(
    probe,
    should_continue,
    *,
    retry_on=RPCError,
    label: str = "node",
    logger=None,
    backoff_start: float = 2.0,
    backoff_cap: float = 30.0,
):
    """Await ``probe()`` until it returns without raising, retrying transient RPC
    failures with capped exponential backoff.

    A node that is briefly slow, restarting, or not yet up at startup must never
    *permanently* down a coin - especially in a hub, where it would otherwise stop that
    one coin while the others keep mining. This self-heals: it keeps probing and returns
    the instant the node answers. Returns the probe's result, or ``None`` if
    ``should_continue()`` becomes false first (e.g. the pool was asked to stop before the
    node ever came up). Only ``retry_on`` (RPC errors, incl. their timeout subclass) is
    retried; any other exception - e.g. a fail-closed mainnet guard - propagates at once.
    """
    delay = backoff_start
    attempt = 0
    while should_continue():
        try:
            return await probe()
        except retry_on as exc:
            attempt += 1
            if logger is not None:
                logger.error(
                    "%s not ready (attempt %d): %s; retrying in %.0fs",
                    label, attempt, exc, delay,
                )
            await asyncio.sleep(delay)
            delay = min(delay * 2, backoff_cap)
    return None


class RPCClient:
    def __init__(
        self,
        host: str,
        port: int,
        user: str = "",
        password: str = "",
        cookie_file: str | None = None,
        timeout: float = 30.0,
        wallet: str = "",
    ):
        self.url = f"http://{host}:{port}/"
        self.timeout = timeout
        self._cookie_file = cookie_file
        self._user = user
        self._password = password
        self._wallet = wallet
        self._ids = itertools.count(1)

    def _wallet_url(self) -> str:
        return f"{self.url}wallet/{self._wallet}" if self._wallet else self.url

    def _auth_header(self) -> str:
        user, password = self._user, self._password
        if self._cookie_file:
            # litecoind rewrites this file on each restart; read it fresh.
            try:
                with open(self._cookie_file, "r") as fh:
                    user, password = fh.read().strip().split(":", 1)
            except OSError as exc:
                raise RPCError(f"cannot read RPC cookie {self._cookie_file}: {exc}") from exc
            except ValueError as exc:
                raise RPCError(
                    f"RPC cookie {self._cookie_file} is malformed (expected 'user:pass')"
                ) from exc
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return f"Basic {token}"

    def _blocking_call(
        self, method: str, params: list, timeout: float | None = None, url: str | None = None
    ) -> object:
        body = json.dumps(
            {"jsonrpc": "1.0", "id": next(self._ids), "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            url or self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self._auth_header(),
            },
        )
        eff_timeout = self.timeout if timeout is None else timeout
        try:
            with urllib.request.urlopen(req, timeout=eff_timeout) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            # litecoind/bitcoind return the JSON-RPC error body even on HTTP 500.
            try:
                payload = json.loads(exc.read().decode())
            except Exception:
                raise RPCError(f"HTTP {exc.code} calling {method}") from exc
            # Only trust the body if it's an actual JSON-RPC error; an unexpected
            # error page that happens to parse would otherwise mask the failure.
            if not isinstance(payload, dict) or payload.get("error") is None:
                raise RPCError(f"HTTP {exc.code} calling {method}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RPCTimeout(f"{method} timed out after {eff_timeout}s") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise RPCTimeout(f"{method} timed out") from exc
            raise RPCError(f"cannot reach node at {self.url}: {exc.reason}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError, http.client.HTTPException, OSError) as exc:
            # A malformed/truncated body or a dropped read (e.g. the node restarting
            # mid-response) must surface as a retryable RPCError - not an unhandled crash
            # that escapes the resilient RPC loops and permanently downs the coin.
            raise RPCError(f"bad response from node calling {method}: {exc}") from exc

        # A 200 response that is valid JSON but not an object ([], null, 42, ...) would
        # raise AttributeError on .get below and escape the retryable-RPCError loops,
        # permanently downing the coin. Treat any non-object (and a non-object "error")
        # as a retryable RPCError. The HTTPError branch above is already guarded.
        if not isinstance(payload, dict):
            raise RPCError(f"non-object response from node calling {method}")
        err = payload.get("error")
        if err:
            if not isinstance(err, dict):
                raise RPCError(f"{method} error: {err}")
            raise RPCError(err.get("message", str(err)), err.get("code"))
        return payload.get("result")

    async def call(
        self, method: str, *params, timeout: float | None = None, url: str | None = None
    ) -> object:
        return await asyncio.to_thread(self._blocking_call, method, list(params), timeout, url)

    # -- convenience wrappers ------------------------------------------------

    async def get_block_template(
        self, rules: list, longpollid: str | None = None, timeout: float | None = None
    ) -> dict:
        params: dict = {"rules": list(rules)}
        if longpollid is not None:
            # The node holds the request open until the tip/template changes.
            params["longpollid"] = longpollid
        return await self.call("getblocktemplate", params, timeout=timeout)  # type: ignore[return-value]

    async def submit_block(self, block_hex: str, timeout: float = 120.0) -> object:
        # Returns None on accept, or a string ("inconclusive", "duplicate",
        # "high-hash", ...) describing the rejection. A found block is precious, so
        # give the node generous time to process it even under load (the default RPC
        # timeout is far too tight for submitblock on a busy/slow node).
        return await self.call("submitblock", block_hex, timeout=timeout)

    async def get_best_block_hash(self) -> str:
        return await self.call("getbestblockhash")  # type: ignore[return-value]

    async def get_blockchain_info(self, timeout: float | None = None) -> dict:
        return await self.call("getblockchaininfo", timeout=timeout)  # type: ignore[return-value]

    async def get_connection_count(self, timeout: float | None = None) -> int:
        return await self.call("getconnectioncount", timeout=timeout)  # type: ignore[return-value]

    async def get_block_hash(self, height: int) -> str:
        return await self.call("getblockhash", height)  # type: ignore[return-value]

    async def get_network_hashps(self, nblocks: int = 120, timeout: float | None = None) -> float:
        """The node's own network-hashrate estimate (H/s): the chainwork done over the
        last ``nblocks`` blocks divided by their actual elapsed time - the same value
        Bitcoin Core / explorers (mempool.space) report. Far more accurate than a
        difficulty-only estimate, especially on testnet, where the 20-minute
        min-difficulty rule makes the instantaneous difficulty a poor proxy."""
        return await self.call("getnetworkhashps", nblocks, timeout=timeout)  # type: ignore[return-value]

    async def get_mempool_info(self, timeout: float | None = None) -> dict:
        # {size: tx count, bytes: vsize, total_fee: BTC/LTC, ...}
        return await self.call("getmempoolinfo", timeout=timeout)  # type: ignore[return-value]

    # -- wallet calls (public-mode payouts; target the pool wallet) ----------

    async def get_balance(self) -> float:
        return await self.call("getbalance", url=self._wallet_url())  # type: ignore[return-value]

    async def send_many(self, outputs: dict, comment: str = "") -> str:
        # sendmany "" {address: amount, ...} (minconf) "comment" - amounts in whole
        # coins. The comment tags the batch so a send whose RPC reply times out can
        # be located afterwards (find_wallet_tx) instead of being blindly retried,
        # which would pay everyone twice.
        params: list = ["", outputs]
        if comment:
            params += [1, comment]  # minconf=1, then the comment
        return await self.call("sendmany", *params, url=self._wallet_url())  # type: ignore[return-value]

    async def find_wallet_tx(self, comment: str, count: int = 100) -> str:
        """Return the txid of a recent wallet 'send' carrying ``comment``, or "".

        Recovery path for a sendmany whose reply timed out after the wallet had
        already broadcast: we credit the real tx rather than pay the batch twice.
        """
        if not comment:
            return ""
        try:
            txs = await self.call("listtransactions", "*", count, url=self._wallet_url())
        except RPCError:
            return ""
        for t in (txs or []):  # type: ignore[union-attr]
            if isinstance(t, dict) and t.get("comment") == comment and t.get("category") == "send":
                return t.get("txid", "")
        return ""
