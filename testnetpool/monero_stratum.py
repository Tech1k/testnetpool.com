# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""CryptoNote (Monero) Stratum server: login / getjob / submit / keepalived.

A different, simpler dialect than Bitcoin Stratum: the pool hands the miner a
block-hashing blob + a target, and the miner returns a nonce and the result hash.
Shares are accepted trust-based on the submitted result (testnet coins are
worthless, so share fraud is pointless; monerod verifies real blocks on submit).
The per-connection difficulty controller (vardiff) is reused from stratum.py.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections import OrderedDict, deque

from . import util
from .cryptonote import (
    CryptoNoteError, block_nonce_offset, difficulty_to_target,
    hash_meets_difficulty, validate_address,
)
from .stratum import (
    HANDSHAKE_TIMEOUT, REJECT_FLOOD_MIN, REJECT_FLOOD_RATIO, Vardiff, clean_agent,
)

log = logging.getLogger("testnetpool.monero.stratum")

MAX_SEEN_SHARES = 100_000
JOBS_RETAINED = 8
SEND_JOB_TIMEOUT = 15      # per-miner job-push deadline (see pool.SEND_JOB_TIMEOUT)
# Shares are trust-based, so a miner could submit a tiny fake result claiming a
# block to force a submit_block RPC (monerod rejects it, but the call still costs).
# Real blocks at network difficulty are minutes apart, so rate-limit how often one
# connection can trigger a block reconstruction + node submission.
BLOCK_SUBMIT_COOLDOWN = 2.0  # seconds, per connection


class MoneroJob:
    """A network block template ready to hand to miners and to submit from."""

    def __init__(self, gbt: dict):
        self.height = int(gbt["height"])
        self.difficulty = int(gbt["difficulty"])
        self.blockhashing_blob = bytes.fromhex(gbt["blockhashing_blob"])
        self.blocktemplate_blob = bytes.fromhex(gbt["blocktemplate_blob"])
        self.seed_hash = gbt.get("seed_hash", "")
        self.prev_hash = gbt.get("prev_hash", "")
        self.reward = int(gbt.get("expected_reward", 0))  # piconero
        # The nonce sits at the same offset in the hashing and full blobs (shared
        # block header), so we can locate it once and reuse it for submission.
        self.nonce_offset = block_nonce_offset(self.blockhashing_blob)
        # 2^256 / difficulty, so the shared Stats recovers net_diff/eta correctly.
        self.network_target = (1 << 256) // max(1, self.difficulty)

    def build_block(self, nonce_bytes: bytes) -> bytes:
        off = self.nonce_offset
        return self.blocktemplate_blob[:off] + nonce_bytes + self.blocktemplate_blob[off + 4:]


class MoneroConnection:
    _counter = 0

    def __init__(self, reader, writer, pool):
        MoneroConnection._counter += 1
        self.id = MoneroConnection._counter
        self.reader = reader
        self.writer = writer
        self.pool = pool
        peer = writer.get_extra_info("peername")
        self.peer_ip = peer[0] if peer else "?"
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "?"
        self.session_id = secrets.token_hex(8)
        self.vardiff = Vardiff(pool.cfg.vardiff, time.time())
        self.payout_address = ""
        self.worker = ""
        self.address = ""         # login's address part, ALL modes (live grouping key)
        self.worker_name = ""     # rig suffix after "." in the login, if any
        self.user_agent = ""      # self-reported miner UA from the login "agent"
        self.best = 0.0           # best (highest-difficulty) share this session
        self.authorized = False
        self.accepted = 0
        self.rejected = 0
        self._flood_dropped = False  # reject-flood guard fires at most once per connection
        self.last_share = 0.0
        self._last_block_submit = 0.0         # throttle fake-block submit spam
        self._jobs: dict[str, tuple] = {}     # job_id -> (MoneroJob, share_difficulty)
        self._job_order: deque[str] = deque()
        self._write_lock = asyncio.Lock()

    @property
    def difficulty(self) -> float:  # for StatsServer's miner list
        return self.vardiff.difficulty

    async def _send(self, obj: dict) -> None:
        data = (json.dumps(obj) + "\n").encode()
        async with self._write_lock:
            self.writer.write(data)
            await self.writer.drain()

    async def reply(self, msg_id, result=None, error=None) -> None:
        await self._send({"id": msg_id, "jsonrpc": "2.0", "error": error, "result": result})

    async def notify_job(self, job: dict) -> None:
        await self._send({"jsonrpc": "2.0", "method": "job", "params": job})

    def _make_job(self) -> dict:
        tmpl = self.pool.template
        if tmpl is None:
            return {}
        job_id = secrets.token_hex(8)
        diff = self.vardiff.difficulty
        self._jobs[job_id] = (tmpl, diff)
        self._job_order.append(job_id)
        while len(self._job_order) > JOBS_RETAINED:
            self._jobs.pop(self._job_order.popleft(), None)
        return {
            "blob": tmpl.blockhashing_blob.hex(),
            "job_id": job_id,
            "target": difficulty_to_target(int(diff)),
            "height": tmpl.height,
            "seed_hash": tmpl.seed_hash,
            "algo": "rx/0",
        }

    async def vardiff_idle_check(self, now: float) -> None:
        if self.vardiff.idle_retarget(now) is not None and self.authorized:
            await self.notify_job(self._make_job())

    async def handle(self) -> None:
        try:
            while True:
                try:
                    if self.authorized:
                        line = await self.reader.readline()
                    else:  # drop unauthenticated sockets that stall mid-handshake
                        line = await asyncio.wait_for(
                            self.reader.readline(), timeout=HANDSHAKE_TIMEOUT)
                except asyncio.TimeoutError:
                    break
                except (ValueError, asyncio.LimitOverrunError):
                    break
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue  # scanners / junk
                await self._dispatch(msg)
                if self._flood_dropped:
                    break  # flood guard fired; stop draining buffered lines
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        except Exception:
            log.debug("monero stratum connection error", exc_info=True)
        finally:
            self.pool.unregister(self)
            self.writer.close()

    async def _dispatch(self, msg: dict) -> None:
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}
        now = time.time()
        if method == "login":
            await self._on_login(mid, params, now)
        elif method == "getjob":
            await self.reply(mid, self._make_job())
        elif method == "submit":
            await self._on_submit(mid, params, now)
        elif method == "keepalived":
            await self.reply(mid, {"status": "KEEPALIVED"})
        else:
            await self.reply(mid, None, {"code": -1, "message": "unknown method"})

    async def _on_login(self, mid, params, now) -> None:
        login = str(params.get("login", "")).strip()
        self.worker = login
        self.address = login.split(".", 1)[0].strip()[:96]  # grouping label, all modes
        self.worker_name = login.split(".", 1)[1].strip()[:64] if "." in login else ""
        # XMRig and most CryptoNote miners report their UA in the login "agent".
        self.user_agent = clean_agent(params.get("agent"))
        # Public mode: the login is the miner's payout address (rewards go there);
        # solo mode mines to the configured wallet, so any login is accepted.
        if self.pool.accounting is not None:
            addr = login.split(".", 1)[0].strip()
            try:
                validate_address(addr, self.pool.network.name)
            except CryptoNoteError as exc:
                await self.reply(mid, None, {"code": -1, "message": f"bad payout address: {exc}"})
                log.info("rejected monero login %r from %s: %s", login, self.peer, exc)
                return
            self.payout_address = addr
        self.authorized = True
        log.info("monero login: %s (%s)", login or "?", self.peer)
        await self.reply(mid, {"id": self.session_id, "job": self._make_job(),
                               "status": "OK", "extensions": ["algo"]})

    async def _reject(self, mid, message: str, reason: str = "other") -> None:
        """Reply with a rejection, count it, and drop the connection on a reject
        flood (almost all bad shares - broken rig or abuse)."""
        self.rejected += 1
        self.pool.stats.record_reject(reason)
        await self.reply(mid, None, {"code": -1, "message": message})
        total = self.accepted + self.rejected
        if (total >= REJECT_FLOOD_MIN and self.rejected >= REJECT_FLOOD_RATIO * total
                and not self._flood_dropped):
            # Strike once per connection (see stratum.py): writer.close() doesn't stop
            # handle() from draining already-buffered lines, so without this one pipelined
            # connection would re-strike repeatedly and self-ban its own IP.
            self._flood_dropped = True
            # Don't IP-strike a STALE-dominated flood (a proxy lagging behind our jobs, not an
            # abuser); banning would lock out even its fresh shares. Drop the connection but
            # don't ban. Mirrors stratum.py.
            banned = self.pool.bans.strike(self.peer_ip, time.time()) if reason != "stale" else False
            log.warning("dropping %s (%s): reject flood (%d/%d rejected)%s",
                        self.worker or "?", self.peer, self.rejected, total,
                        "; IP temp-banned" if banned else "")
            self.writer.close()

    async def _on_submit(self, mid, params, now) -> None:
        if not self.authorized:
            await self.reply(mid, None, {"code": -1, "message": "unauthenticated"})
            return
        job_id = str(params.get("job_id", ""))
        nonce_hex = str(params.get("nonce", ""))
        result_hex = str(params.get("result", ""))
        entry = self._jobs.get(job_id)
        if entry is None:
            await self._reject(mid, "stale or unknown job", "stale")
            return
        tmpl, diff = entry
        try:
            nonce_bytes = bytes.fromhex(nonce_hex)
            result_bytes = bytes.fromhex(result_hex)
            if len(nonce_bytes) != 4 or len(result_bytes) != 32:
                raise ValueError
        except ValueError:
            await self._reject(mid, "malformed submit", "other")
            return
        # Dedup on (TEMPLATE, result-bytes), pool-globally. Acceptance is trust-based (the
        # result is taken at face value, never recomputed from the nonce), so a miner who
        # finds ONE valid result must not credit it twice. Keying must be on the TEMPLATE,
        # not the per-getjob job_id: job_id is freshly minted on every getjob against the
        # same template, so a job_id key let the same result be re-credited under unlimited
        # fresh job_ids. The blockhashing_blob is stable per template and distinct between
        # templates. The set lives on the POOL, not the connection, so the same result can't
        # be replayed across multiple sockets either. (Keying on result-bytes, not the hex,
        # also stops '0a' vs '0A' counting twice.) One valid result per template = one share.
        seen = self.pool._seen_shares
        key = (tmpl.blockhashing_blob, result_bytes)
        if key in seen:
            await self._reject(mid, "duplicate share", "duplicate")
            return

        # Trust-based: accept on the submitted result meeting the share target. Check this
        # BEFORE recording the dedup key below - otherwise a rejected low-diff submit would
        # poison the pool-global set and block a later-valid resubmit after a vardiff drop.
        if not hash_meets_difficulty(result_bytes, diff):
            await self._reject(mid, "low difficulty share", "low_diff")
            return

        # Dead-tip stale gate: the trust-based twin of the BTC/LTC prevhash gate. Retained
        # jobs let a slightly-old job still RESOLVE, but a non-block share for a SUPERSEDED tip
        # must earn NO PPLNS credit - it can never lead to a block on the live chain. Compare
        # by HEIGHT, not template identity: a same-height refresh (new blob/ntime) keeps
        # current_height, so its still-live shares are not falsely rejected. A genuine block
        # solve is never dropped here - it flows to handle_block_candidate below.
        is_block = hash_meets_difficulty(result_bytes, tmpl.difficulty)
        if not is_block and tmpl.height - 1 != self.pool.current_height:
            await self._reject(mid, "stale share (tip changed)", "stale")
            return

        # Record the dedup key only now that the share is accepted: one valid result per
        # template = one share. The sliding window bounds memory (evicts oldest first).
        seen[key] = None
        if len(seen) > MAX_SEEN_SHARES:
            seen.popitem(last=False)

        self.accepted += 1
        self.last_share = now
        result_int = int.from_bytes(result_bytes, "little")
        actual_diff = (1 << 256) // result_int if result_int else (1 << 256)
        self.best = max(self.best, float(actual_diff))  # session best (all modes)
        self.pool.stats.record_share(diff, now)
        if self.pool.accounting is not None and self.payout_address:
            # A DB hiccup must NOT drop the miner or skip the block submit below.
            try:
                self.pool.accounting.record_share(self.payout_address, diff, now,
                                                  share_diff=actual_diff, worker=self.worker_name)
            except Exception:
                log.exception("record_share failed for %s (%s); continuing", self.worker, self.peer)
        await self.reply(mid, {"status": "OK"})

        # Block-worthy? Reconstruct the full block with this nonce and submit. (is_block was
        # computed above against tmpl.difficulty; a stale block still flows here so monerod -
        # the real arbiter - decides, exactly as the BTC/LTC engine does.)
        if is_block:
            if now - self._last_block_submit < BLOCK_SUBMIT_COOLDOWN:
                log.warning("monero block-submit throttled for %s (%s)", self.worker or "?", self.peer)
            else:
                self._last_block_submit = now
                log.info("*** MONERO BLOCK CANDIDATE from %s (%s) height=%d ***",
                         self.worker or "?", self.peer, tmpl.height)
                await self.pool.handle_block_candidate(tmpl, nonce_bytes, finder=self.payout_address)

        new_diff = self.vardiff.record_share(now)
        if new_diff is not None:
            log.info("monero vardiff %s -> %s (%s)", self.worker, util.numfmt(new_diff), self.peer)
            await self.notify_job(self._make_job())


class CryptoNoteStratumServer:
    def __init__(self, pool):
        self.pool = pool
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        cfg = self.pool.cfg
        self._server = await asyncio.start_server(self._handle, cfg.stratum_host, cfg.stratum_port)
        log.info("cryptonote stratum on %s:%d", cfg.stratum_host, cfg.stratum_port)

    async def _handle(self, reader, writer) -> None:
        util.enable_tcp_nodelay(writer)  # Nagle OFF (see util.enable_tcp_nodelay)
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        ok, reason = self.pool.bans.allow(ip, time.time())
        if not ok:
            log.debug("refusing connection from %s: %s", ip, reason)
            writer.close()
            return
        self.pool.bans.register(ip)
        try:
            conn = MoneroConnection(reader, writer, self.pool)
            self.pool.register(conn)
            await conn.handle()
        finally:
            self.pool.bans.unregister(ip)

    async def broadcast(self) -> None:
        """Push a fresh job (new template) to every connected miner."""
        subs = [c for c in list(self.pool.connections) if c.authorized]
        if not subs:
            return
        # Concurrent fan-out with a per-miner deadline so one slow/non-reading miner's
        # drain() can't head-of-line-block job delivery to everyone (mirrors pool._broadcast).
        results = await asyncio.gather(
            *(asyncio.wait_for(c.notify_job(c._make_job()), SEND_JOB_TIMEOUT) for c in subs),
            return_exceptions=True,
        )
        for conn, res in zip(subs, results):
            if isinstance(res, Exception):
                self.pool.unregister(conn)
                try:
                    conn.writer.close()
                except Exception:
                    pass

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
