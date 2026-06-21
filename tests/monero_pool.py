# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""End-to-end test for the Monero engine against a mocked monerod (no node).

A fake monerod (FakeMoneroRPC) serves a low-difficulty template; a fake xmrig
logs in over CryptoNote Stratum and submits a (trusted) result that clears both
the share and network targets, so it is accepted AND submitted as a block. We
verify: the login/job handshake, trust-based share acceptance + PPLNS recording,
block reconstruction + submission to monerod, the credited block, and that the
shared dashboard reports the Monero pool (algo=randomx).

Run:  python3 tests/monero_pool.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool.config import (  # noqa: E402
    Config, PublicConfig, RPCConfig, StatsConfig, VardiffConfig,
)
from testnetpool.cryptonote import NETWORKS, b58_encode, write_varint  # noqa: E402
from testnetpool.keccak import keccak256  # noqa: E402
from testnetpool.monero_pool import MoneroPool  # noqa: E402

STRATUM_PORT, STATS_PORT = 14444, 18099


def _addr(kind="standard"):
    prefix = NETWORKS["stagenet"][kind]
    body = write_varint(prefix) + bytes(range(32)) + bytes(range(32, 64)) + \
        (b"\x33" if kind == "standard" else b"\x44") * 0
    # vary the keys per kind so addresses differ
    seed = 0x11 if kind == "standard" else 0x22
    body = write_varint(prefix) + bytes([seed]) * 32 + bytes([seed + 1]) * 32
    return b58_encode(body + keccak256(body)[:4])


MINER = _addr("standard")
POOL = _addr("subaddress")
FAUCET = b58_encode((lambda b: b + keccak256(b)[:4])(
    write_varint(NETWORKS["stagenet"]["standard"]) + bytes([0x55]) * 32 + bytes([0x56]) * 32))

# A minimal but structurally-valid block: shared header (3 varints + prev_id + nonce).
_HEADER = write_varint(16) + write_varint(0) + write_varint(1_700_000_000) + bytes(32) + bytes(4)
_BLOCKHASHING = _HEADER + bytes(32) + b"\x01"          # + tree root + tx count
_BLOCKTEMPLATE = _HEADER + b"\x02\x00\x00" + bytes(40)  # + (fake) miner tx etc., same header


class FakeMoneroRPC:
    def __init__(self):
        self.submitted = []
        self.height = 100

    async def get_info(self):
        return {"height": self.height, "stagenet": True, "nettype": "stagenet"}

    async def get_block_template(self, wallet_address, reserve_size=0):
        return {
            "blockhashing_blob": _BLOCKHASHING.hex(),
            "blocktemplate_blob": _BLOCKTEMPLATE.hex(),
            "difficulty": 2,                      # trivially easy: any tiny hash is a block
            "height": self.height,
            "seed_hash": "ab" * 32,
            "prev_hash": "cd" * 32,
            "expected_reward": 600_000_000_000,   # 0.6 XMR in piconero
        }

    async def submit_block(self, blob_hex):
        self.submitted.append(blob_hex)
        return {"status": "OK"}

    async def get_block_header_by_height(self, height):
        return {"hash": "de" * 32}  # already-unwrapped header (matches MoneroRPC)


async def main() -> int:
    ok = []
    db = tempfile.mktemp(suffix=".db")
    cfg = Config(
        coin="monero", chain="stagenet", mode="public",
        coinbase_tag="/CUSTOM-IGNORED/",  # BTC/LTC-only; must warn it's a no-op on Monero
        stratum_host="127.0.0.1", stratum_port=STRATUM_PORT, block_poll_interval=0.2,
        rpc=RPCConfig(host="127.0.0.1", port=0, user="", password=""),
        vardiff=VardiffConfig(enabled=False, start_difficulty=1.0),
        stats=StatsConfig(enabled=True, host="127.0.0.1", port=STATS_PORT),
        public=PublicConfig(db_path=db, pool_address=POOL, faucet_address=FAUCET, monero_wallet_port=0),
    )
    pool = MoneroPool(cfg)
    pool.rpc = FakeMoneroRPC()  # type: ignore[assignment]
    ok.append(("coinbase pays the pool wallet", cfg.coinbase_address == POOL))

    # Capture startup logs so we can assert the coinbase_tag no-op warning fires.
    _logs: list[str] = []

    class _Cap(logging.Handler):
        def emit(self, rec):
            _logs.append(rec.getMessage())
    _cap = _Cap()
    logging.getLogger("testnetpool.monero").addHandler(_cap)

    run_task = asyncio.create_task(pool.run())
    for _ in range(50):
        if pool.template is not None:
            break
        await asyncio.sleep(0.1)
    ok.append(("template fetched", pool.template is not None and pool.template.difficulty == 2))
    logging.getLogger("testnetpool.monero").removeHandler(_cap)
    ok.append(("custom coinbase_tag warns it's a no-op on Monero",
               any("coinbase_tag" in m and "no effect on Monero" in m for m in _logs)))

    # fake xmrig: login -> get a job -> submit a trusted block-worthy result
    r, w = await asyncio.open_connection("127.0.0.1", STRATUM_PORT)

    async def send(o):
        w.write((json.dumps(o) + "\n").encode())
        await w.drain()

    async def recv():
        return json.loads(await asyncio.wait_for(r.readline(), timeout=3))

    await send({"id": 1, "method": "login", "params": {"login": MINER, "pass": "x", "agent": "t"}})
    login = await recv()
    job = login.get("result", {}).get("job", {})
    ok.append(("login OK + job issued", login["result"]["status"] == "OK" and "blob" in job))
    ok.append(("job has seed_hash + rx algo", job.get("algo") == "rx/0" and len(job.get("seed_hash", "")) == 64))

    # result int = 1 (LE) satisfies any difficulty -> share AND block (trust-based)
    result_hex = (1).to_bytes(32, "little").hex()
    await send({"id": 2, "method": "submit", "params": {
        "id": login["result"]["id"], "job_id": job["job_id"], "nonce": "01000000", "result": result_hex}})
    submit = await recv()
    ok.append(("share accepted", submit.get("result", {}).get("status") == "OK"))

    # a duplicate (same job_id + nonce) is rejected
    await send({"id": 3, "method": "submit", "params": {
        "id": login["result"]["id"], "job_id": job["job_id"], "nonce": "01000000", "result": result_hex}})
    dup = await recv()
    ok.append(("duplicate rejected", dup.get("error") is not None))
    # SAME result under a DIFFERENT nonce must ALSO be a duplicate: acceptance is
    # trust-based on the result, so keying dedup on the nonce let one valid result be
    # credited under unlimited nonces (payout theft). Dedup now keys on the result bytes.
    await send({"id": 4, "method": "submit", "params": {
        "id": login["result"]["id"], "job_id": job["job_id"], "nonce": "02000000", "result": result_hex}})
    dup2 = await recv()
    ok.append(("same result + different nonce rejected (result-keyed dedup)",
               dup2.get("error") is not None))
    # C1: a fresh getjob mints a NEW job_id for the SAME template. Replaying the same
    # result under that new job_id must STILL be a duplicate - dedup keys on the template
    # blob, pool-globally, NOT the per-getjob job_id, so one valid result cannot be
    # re-credited by re-fetching getjob (the trust-share inflation bypass). [C1]
    await send({"id": 5, "method": "getjob", "params": {"id": login["result"]["id"]}})
    jr = await recv()
    new_job = jr.get("result", {})
    ok.append(("getjob mints a fresh job_id",
               bool(new_job.get("job_id")) and new_job.get("job_id") != job["job_id"]))
    await send({"id": 6, "method": "submit", "params": {
        "id": login["result"]["id"], "job_id": new_job.get("job_id"), "nonce": "09000000", "result": result_hex}})
    replay = await recv()
    ok.append(("same result under a fresh job_id rejected (template-keyed pool-global dedup) [C1]",
               replay.get("error") is not None))
    w.close()
    await asyncio.sleep(0.3)

    ok.append(("block submitted to monerod", len(pool.rpc.submitted) == 1))
    # the submitted block carries our nonce at the right offset
    blk = bytes.fromhex(pool.rpc.submitted[0])
    off = pool.template.nonce_offset
    ok.append(("submitted block has our nonce", blk[off:off + 4] == bytes.fromhex("01000000")))

    row = pool.accounting.conn.execute("SELECT height, status, finder FROM blocks").fetchone()
    ok.append(("block recorded immature", row is not None and row[1] == "immature" and row[0] == 100))
    ok.append(("finder is the miner", row is not None and row[2] == MINER))
    cred = pool.accounting.conn.execute("SELECT COUNT(*) FROM credits").fetchone()[0]
    ok.append(("PPLNS credited (miner + faucet)", cred >= 2))
    shares = pool.accounting.conn.execute(
        "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.address=?",
        (MINER,)).fetchone()[0]
    ok.append(("share persisted for miner", shares >= 1))

    # the shared dashboard reports the Monero pool
    rr, ww = await asyncio.open_connection("127.0.0.1", STATS_PORT)
    ww.write(b"GET /api/stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    await ww.drain()
    raw = await rr.read()
    ww.close()
    api = json.loads(raw.split(b"\r\n\r\n", 1)[1])
    ok.append(("dashboard: monero/randomx", api.get("coin") == "monero" and api.get("algo") == "randomx"))
    ok.append(("dashboard: net diff + block", api.get("network_difficulty") == 2 and api.get("blocks_found") == 1))

    # submit-timeout recovery: a slow submit that monerod actually ACCEPTED must be
    # credited (verified via the chain), not recorded as a loss - and a submit that
    # never landed must be recorded lost. Mirrors the BTC/LTC chain-verify.
    from testnetpool.monero_rpc import MoneroRPCError, MoneroRPCTimeout  # noqa: E402

    class _TimeoutOnChain(FakeMoneroRPC):
        async def submit_block(self, blob_hex):
            raise MoneroRPCTimeout("submit timed out")  # but it's on-chain (header below)

        async def get_block_header_by_height(self, height):
            return {"hash": "%064x" % height}  # unique per height (so credit_block won't dedup)

    pool.rpc = _TimeoutOnChain()
    tmpl = pool.template
    tmpl.height = 105
    await pool.handle_block_candidate(tmpl, b"\x09\x00\x00\x00", finder=MINER)
    r = pool.accounting.conn.execute("SELECT status FROM blocks WHERE height=105").fetchone()
    ok.append(("submit-timeout but on-chain -> accepted+credited", r is not None and r[0] == "immature"))

    class _TimeoutLost(FakeMoneroRPC):
        async def submit_block(self, blob_hex):
            raise MoneroRPCTimeout("submit timed out")

        async def get_block_header_by_height(self, height):
            raise MoneroRPCError("height not found")  # not on-chain

    pool.rpc = _TimeoutLost()
    tmpl.height = 106
    await pool.handle_block_candidate(tmpl, b"\x0a\x00\x00\x00", finder=MINER)
    no_db = pool.accounting.conn.execute("SELECT COUNT(*) FROM blocks WHERE height=106").fetchone()[0] == 0
    lost = any(b["height"] == 106 and not b["accepted"] for b in pool.stats.blocks)
    ok.append(("submit-timeout not on-chain -> recorded lost, not credited", no_db and lost))
    pool.rpc = FakeMoneroRPC()  # restore for the payout section below

    # payouts: mature the block (applies credits to balances), then pay via wallet-rpc
    class FakeWallet:
        def __init__(self, unlocked=10 ** 18):
            self.transfers = []
            self._unlocked = unlocked

        async def get_balance(self, account_index=0):
            return {"balance": self._unlocked, "unlocked_balance": self._unlocked}

        async def transfer_split(self, destinations, **kw):
            self.transfers.append(destinations)
            return {"tx_hash_list": ["ab" * 32], "fee_list": [100000]}

        async def get_transfers(self, **kw):
            return {"out": [], "pending": []}

    bid = pool.accounting.conn.execute("SELECT id FROM blocks").fetchone()[0]
    pool.accounting.mature_block(bid)
    pool.wallet = FakeWallet()
    cfg.public.min_payout = 0.0  # pay any positive balance
    await pool._do_payouts()
    ok.append(("payout sent via wallet-rpc", len(pool.wallet.transfers) == 1))
    dests = pool.wallet.transfers[0]
    # 0.6 XMR reward, 1% fee -> miner gets ~0.594 XMR = 594000000000 piconero
    ok.append(("payout amounts in piconero", all(d["amount"] > 0 and d["address"] for d in dests)
               and sum(d["amount"] for d in dests) == 600_000_000_000))
    paid = pool.accounting.conn.execute("SELECT COUNT(*) FROM payouts").fetchone()[0]
    ok.append(("payouts recorded", paid >= 1))

    # an insufficient unlocked balance must defer the payout (no overspend attempt).
    # Re-credit a payable owed amount, then pay with a zero-unlocked wallet.
    pool2_wallet = FakeWallet(unlocked=0)
    pool.wallet = pool2_wallet
    cfg.public.min_payout = 0.0005  # exclude zero-owed balances (e.g. the faucet)
    mid = pool.accounting.conn.execute(
        "SELECT id FROM miners WHERE address=?", (MINER,)).fetchone()[0]
    pool.accounting.conn.execute(
        "INSERT INTO balances(miner_id, owed) VALUES(?, 100000) "
        "ON CONFLICT(miner_id) DO UPDATE SET owed=100000", (mid,))
    pool.accounting.conn.commit()
    await pool._do_payouts()
    ok.append(("zero unlocked balance defers payout", len(pool2_wallet.transfers) == 0))

    # a bad-address login is rejected
    r2, w2 = await asyncio.open_connection("127.0.0.1", STRATUM_PORT)
    w2.write((json.dumps({"id": 1, "method": "login",
                          "params": {"login": "not_a_monero_address", "pass": "x"}}) + "\n").encode())
    await w2.drain()
    bad = json.loads(await asyncio.wait_for(r2.readline(), timeout=3))
    w2.close()
    ok.append(("bad address login rejected", bad.get("error") is not None))

    # --- H-2 regression: a non-block share on a SUPERSEDED tip earns NO PPLNS credit ---
    # Retained jobs let an old-tip job still RESOLVE, but a non-block share for a tip that has
    # since advanced must not be credited (it can never lead to a live block). The gate keys
    # on HEIGHT so a same-height refresh's shares are NOT over-rejected.
    from testnetpool.monero_stratum import MoneroConnection, MoneroJob  # noqa: E402

    class _RecW:
        def __init__(self):
            self.lines = []

        def get_extra_info(self, _k):
            return ("127.0.0.1", 0)

        def write(self, d):
            for ln in d.decode().splitlines():
                if ln.strip():
                    self.lines.append(json.loads(ln))

        async def drain(self):
            pass

        def close(self):
            pass

    def _mk_job(height, tag, diff=1 << 240):
        return MoneroJob({
            "blockhashing_blob": (_HEADER + bytes(32) + tag).hex(),
            "blocktemplate_blob": _BLOCKTEMPLATE.hex(),
            "difficulty": diff, "height": height,
            "seed_hash": "ab" * 32, "prev_hash": "cd" * 32, "expected_reward": 1,
        })

    def _shares():
        return pool.accounting.conn.execute(
            "SELECT COUNT(*) FROM shares s JOIN miners m ON m.id=s.miner_id WHERE m.address=?",
            (MINER,)).fetchone()[0]

    tip = pool.current_height
    mc = MoneroConnection(None, _RecW(), pool)
    mc.authorized = True
    mc.payout_address = MINER
    mc.worker_name = ""
    # Results that clear the SHARE target (diff=2) but NOT the huge block target -> genuine
    # non-block shares (so the stale gate actually applies; a block would bypass it by design).
    live_res = ((1 << 255) - 1).to_bytes(32, "little").hex()   # meets diff 2, not 2^240; not a block
    stale_res = ((1 << 255) - 2).to_bytes(32, "little").hex()  # distinct, same properties

    # LIVE tip (job.height-1 == current_height): the non-block share IS credited (no over-reject).
    mc._jobs["live"] = (_mk_job(tip + 1, b"\x07"), 2)
    n0 = _shares()
    await mc._on_submit(70, {"id": "x", "job_id": "live", "nonce": "01000000", "result": live_res},
                        time.time())
    ok.append(("monero live-tip non-block share is credited", _shares() == n0 + 1))

    # SUPERSEDED tip (job.height-1 < current_height): the non-block share earns NO credit.
    mc._jobs["stale"] = (_mk_job(tip, b"\x08"), 2)             # height=tip -> builds on tip-1
    mc.writer.lines.clear()
    n1 = _shares()
    await mc._on_submit(71, {"id": "x", "job_id": "stale", "nonce": "02000000", "result": stale_res},
                        time.time())
    ok.append(("monero dead-tip non-block share earns NO credit", _shares() == n1))
    ok.append(("monero dead-tip share rejected as stale",
               any(ln.get("error") and "stale" in json.dumps(ln).lower() for ln in mc.writer.lines)))

    pool.stop()
    try:
        await asyncio.wait_for(run_task, timeout=3)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        run_task.cancel()
    for e in ("", "-wal", "-shm"):
        try:
            os.unlink(db + e)
        except OSError:
            pass

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} monero pool checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
