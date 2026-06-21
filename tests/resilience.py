# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Startup-resilience regression: a transient/unreachable node at startup must NOT
permanently down a coin.

A single getblockchaininfo (BTC/LTC) or get_info (Monero) timeout used to escape
Pool.run()/MoneroPool.run(); the hub logged 'coin ... stopped' and that coin stayed
dead while the others kept mining. rpc.await_node_ready now retries transient RPC
failures with capped exponential backoff and self-heals the instant the node answers,
while still letting a fail-closed guard (e.g. Monero mainnet) propagate.

Run:  python3 tests/resilience.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import testnetpool.rpc as rpcmod  # noqa: E402
from testnetpool.rpc import RPCClient, RPCError, RPCTimeout, await_node_ready  # noqa: E402
from testnetpool.monero_rpc import MoneroRPCError, MoneroRPCTimeout  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def flaky_probe(fail_times, exc, result):
    """A probe coroutine that raises `exc` its first `fail_times` calls, then returns
    `result`. Returns (probe, state) where state['n'] counts the failures consumed."""
    state = {"n": 0}

    async def probe():
        if state["n"] < fail_times:
            state["n"] += 1
            raise exc
        return result

    return probe, state


class _FakeResp:
    """Stand-in for a urlopen() response context manager with a scripted read()."""

    def __init__(self, data=None, exc=None):
        self._data, self._exc = data, exc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        if self._exc is not None:
            raise self._exc
        return self._data


def _seq_urlopen(behaviors):
    """A urlopen() stand-in yielding behaviors[i] on call i (the last one repeats)."""
    state = {"i": 0}

    def _open(req, timeout=None):
        resp = behaviors[min(state["i"], len(behaviors) - 1)]
        state["i"] += 1
        return resp

    return _open


async def main() -> int:
    # 1) Transient timeouts then success: it retries and returns the node info (the
    #    exact scenario from the incident - getblockchaininfo timed out at startup).
    probe, st = flaky_probe(2, RPCTimeout("getblockchaininfo timed out after 30.0s"),
                            {"chain": "test", "blocks": 42})
    info = await await_node_ready(probe, lambda: True, backoff_start=0, backoff_cap=0)
    chk("retries transient startup timeout then returns node info",
        info == {"chain": "test", "blocks": 42} and st["n"] == 2)

    # 2) Already asked to stop: never probes, returns None (no spurious work/log).
    probe2, st2 = flaky_probe(0, RPCError("x"), {"ok": True})
    info2 = await await_node_ready(probe2, lambda: False, backoff_start=0)
    chk("returns None without probing when stop is already requested",
        info2 is None and st2["n"] == 0)

    # 3) Node never comes up AND stop() is requested mid-wait: gives up with None
    #    rather than blocking forever (so hub shutdown isn't wedged by a dead node).
    tries = {"n": 0}

    async def always_fail():
        tries["n"] += 1
        raise RPCTimeout("still down")

    gate = {"left": 3}  # allow exactly 3 probes, then "stop"

    def cont():
        if gate["left"] <= 0:
            return False
        gate["left"] -= 1
        return True

    info3 = await await_node_ready(always_fail, cont, backoff_start=0, backoff_cap=0)
    chk("gives up with None once stop is requested (never blocks forever)",
        info3 is None and tries["n"] == 3)

    # 4) A non-RPC error (e.g. the fail-closed Monero mainnet guard) must propagate -
    #    NEVER get swallowed/retried into a mainnet run.
    async def boom():
        raise RuntimeError("nettype=mainnet - aborting")

    raised = False
    try:
        await await_node_ready(boom, lambda: True, backoff_start=0)
    except RuntimeError:
        raised = True
    chk("non-RPC error (fail-closed guard) is not retried - it propagates", raised)

    # 5) Monero error family: retry_on=MoneroRPCError catches MoneroRPCTimeout.
    mprobe, mst = flaky_probe(2, MoneroRPCTimeout("get_info timed out"),
                              {"height": 3026023, "nettype": "stagenet"})
    minfo = await await_node_ready(mprobe, lambda: True, retry_on=MoneroRPCError,
                                   backoff_start=0, backoff_cap=0)
    chk("monero: retries MoneroRPCTimeout then returns get_info result",
        minfo == {"height": 3026023, "nettype": "stagenet"} and mst["n"] == 2)

    # 6) Backoff is exponential but capped (no unbounded growth, no forever-fast spin).
    delays = []
    orig_sleep = rpcmod.asyncio.sleep

    async def rec_sleep(d):
        delays.append(d)

    rpcmod.asyncio.sleep = rec_sleep
    try:
        pr, _ = flaky_probe(5, RPCError("down"), {"ok": 1})
        await await_node_ready(pr, lambda: True, backoff_start=1, backoff_cap=4, label="t")
    finally:
        rpcmod.asyncio.sleep = orig_sleep
    chk("backoff is exponential and capped", delays == [1, 2, 4, 4, 4])

    # 7) The REAL rpc layer (not a mock probe) must wrap a malformed/truncated body as
    #    RPCError so the resilient loops retry it, instead of leaking a JSONDecodeError.
    client = RPCClient("127.0.0.1", 18332)
    orig_open = rpcmod.urllib.request.urlopen
    rpcmod.urllib.request.urlopen = _seq_urlopen([_FakeResp(data=b"<html>502 Bad Gateway</html>")])
    bad_json_wrapped = False
    try:
        await client.call("getblockchaininfo")
    except RPCError:
        bad_json_wrapped = True
    except Exception:
        bad_json_wrapped = False  # any non-RPCError escaping is the bug we're guarding
    finally:
        rpcmod.urllib.request.urlopen = orig_open
    chk("malformed response body is wrapped as RPCError (not a raw JSONDecodeError)",
        bad_json_wrapped)

    # 8) A dropped read (connection reset mid-response) is likewise wrapped as RPCError.
    rpcmod.urllib.request.urlopen = _seq_urlopen([_FakeResp(exc=ConnectionResetError("reset"))])
    drop_wrapped = False
    try:
        await client.call("getblockchaininfo")
    except RPCError:
        drop_wrapped = True
    except Exception:
        drop_wrapped = False
    finally:
        rpcmod.urllib.request.urlopen = orig_open
    chk("dropped read (ConnectionResetError) is wrapped as RPCError", drop_wrapped)

    # 9) End-to-end: await_node_ready retries past wrapped malformed/dropped responses
    #    through the real _blocking_call and returns the parsed result once it's clean.
    good = json.dumps({"result": {"chain": "test", "blocks": 7}, "error": None, "id": 1}).encode()
    rpcmod.urllib.request.urlopen = _seq_urlopen([
        _FakeResp(data=b"not json at all"),        # malformed -> wrapped RPCError
        _FakeResp(exc=ConnectionResetError("x")),  # dropped   -> wrapped RPCError
        _FakeResp(data=good),                      # clean
    ])
    try:
        out = await await_node_ready(lambda: client.call("getblockchaininfo"),
                                     lambda: True, backoff_start=0, backoff_cap=0)
    finally:
        rpcmod.urllib.request.urlopen = orig_open
    chk("await_node_ready retries past wrapped bad responses then returns parsed result",
        out == {"chain": "test", "blocks": 7})

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} resilience checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
