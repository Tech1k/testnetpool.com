# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""JSON-RPC 2.0 clients for monerod and monero-wallet-rpc (stdlib only).

monerod and monero-wallet-rpc both expose JSON-RPC 2.0 at ``/json_rpc``. This is
the analogue of rpc.py for the Monero side: blocking urllib under
``asyncio.to_thread`` so the event loop never stalls, with optional HTTP digest
auth (what monerod's ``--rpc-login`` uses).
"""

from __future__ import annotations

import asyncio
import http.client
import json
import socket
import threading
import urllib.error
import urllib.request


class MoneroRPCError(Exception):
    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class MoneroRPCTimeout(MoneroRPCError):
    pass


class _JsonRPC:
    """Shared JSON-RPC 2.0 plumbing for monerod / wallet-rpc."""

    def __init__(self, host: str, port: int, user: str = "", password: str = "",
                 timeout: float = 30.0):
        self.url = f"http://{host}:{port}/json_rpc"
        self.timeout = timeout
        self._auth = (user, password) if user else None
        # A urllib opener (esp. HTTPDigestAuthHandler) is stateful; calls run on
        # ThreadPoolExecutor threads (asyncio.to_thread), so a SHARED opener gets its
        # digest nonce/state mutated by concurrent threads -> spurious auth failures.
        # Give each worker thread its own opener via threading.local instead.
        self._local = threading.local()

    def _opener(self):
        op = getattr(self._local, "opener", None)
        if op is None:
            if self._auth:
                mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                mgr.add_password(None, self.url, *self._auth)
                op = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))
            else:
                op = urllib.request.build_opener()
            self._local.opener = op
        return op

    def _blocking_call(self, method: str, params, timeout):
        body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                           "params": params}).encode()
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"})
        eff = self.timeout if timeout is None else timeout
        try:
            with self._opener().open(req, timeout=eff) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode())
            except Exception:
                raise MoneroRPCError(f"HTTP {exc.code} calling {method}") from exc
            if not isinstance(payload, dict) or payload.get("error") is None:
                raise MoneroRPCError(f"HTTP {exc.code} calling {method}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise MoneroRPCTimeout(f"{method} timed out after {eff}s") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise MoneroRPCTimeout(f"{method} timed out") from exc
            raise MoneroRPCError(f"cannot reach {self.url}: {exc.reason}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError, http.client.HTTPException, OSError) as exc:
            # Malformed/truncated body or a dropped read => retryable RPC error, never an
            # unhandled crash that escapes the resilient loops and downs the coin.
            raise MoneroRPCError(f"bad response from {self.url} calling {method}: {exc}") from exc
        # A 200 response that is valid JSON but not an object would raise AttributeError on
        # .get below and escape the retryable-error loops. Treat any non-object (and a
        # non-object "error") as a retryable MoneroRPCError.
        if not isinstance(payload, dict):
            raise MoneroRPCError(f"non-object response from {self.url} calling {method}")
        err = payload.get("error")
        if err:
            if not isinstance(err, dict):
                raise MoneroRPCError(f"{method} error: {err}")
            raise MoneroRPCError(err.get("message", str(err)), err.get("code"))
        return payload.get("result")

    async def call(self, method: str, params=None, timeout: float | None = None):
        return await asyncio.to_thread(self._blocking_call, method, params or {}, timeout)


class MoneroRPC(_JsonRPC):
    """monerod daemon RPC."""

    async def get_info(self) -> dict:
        return await self.call("get_info")

    async def get_block_template(self, wallet_address: str, reserve_size: int = 0) -> dict:
        return await self.call("get_block_template",
                               {"wallet_address": wallet_address, "reserve_size": reserve_size})

    async def submit_block(self, blob_hex: str):
        # params is a positional array of one block blob; raises on rejection.
        return await self.call("submit_block", [blob_hex])

    async def get_block_header_by_height(self, height: int) -> dict:
        res = await self.call("get_block_header_by_height", {"height": height})
        return res.get("block_header", {})


class MoneroWalletRPC(_JsonRPC):
    """monero-wallet-rpc, for reading the balance and sending payouts."""

    async def get_balance(self, account_index: int = 0) -> dict:
        return await self.call("get_balance", {"account_index": account_index})

    async def transfer(self, destinations: list, priority: int = 0,
                       account_index: int = 0) -> dict:
        """destinations: [{"amount": piconero, "address": str}, ...].

        Returns ``{tx_hash, amount, fee, ...}``.  ``get_tx_keys`` etc. are omitted
        to keep the tx out of the wallet's persisted key store unless asked.
        """
        return await self.call("transfer", {
            "destinations": destinations,
            "account_index": account_index,
            "priority": priority,
            "get_tx_key": False,
            "ring_size": 16,
        })

    async def get_transfers(self, out: bool = True, pending: bool = True,
                            in_: bool = False, account_index: int = 0) -> dict:
        """List wallet transfers by category. Used to detect whether a payout
        actually broadcast when transfer_split's reply timed out."""
        return await self.call("get_transfers", {
            "in": in_, "out": out, "pending": pending,
            "account_index": account_index,
        })

    async def transfer_split(self, destinations: list, priority: int = 0,
                             account_index: int = 0) -> dict:
        """Like ``transfer`` but lets the wallet split across several txs when a
        payout batch is too large for one transaction.  Returns
        ``{tx_hash_list, amount_list, fee_list, ...}``."""
        return await self.call("transfer_split", {
            "destinations": destinations,
            "account_index": account_index,
            "priority": priority,
            "get_tx_keys": False,
            "ring_size": 16,
        })
