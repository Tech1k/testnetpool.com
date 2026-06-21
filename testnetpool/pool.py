# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Pool orchestrator: poll litecoind for templates, broadcast jobs, submit blocks."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from collections import OrderedDict

from . import util
from .accounting import Accounting
from .address import address_to_script
from .coin import COIN, COINBASE_MATURITY, COINS
from .config import Config
from .rpc import RPCClient, RPCError, RPCTimeout, await_node_ready
from .stats import Stats, StatsServer, explorer_for
from .webhook import post_block
from .stratum import BanManager, MinerConnection, StratumServer
from .template import Job, TemplateBuilder
from .zmq_listener import ZmqBlockListener

log = logging.getLogger("testnetpool.pool")

EXTRANONCE1_SIZE = 4
# Job (workbase) retention. We keep jobs by AGE, not a small count, and DON'T wipe them
# on a block change - so a miner (or a rental proxy lagging slightly behind, e.g. behind
# MiningRigRentals) submitting against a job a few minutes old still resolves it instead of
# getting "job not found (stale)". Mirrors ckpool: it ages workbases out at 600s with a
# floor of 3 and never deletes them on a new block (stratifier.c __age_workbase). We add a
# hard upper cap ckpool lacks, purely for memory safety.
JOB_RETENTION_SECONDS = 600  # 10 min, ckpool's horizon
MIN_RETAINED_JOBS = 3        # ckpool's floor
MAX_RETAINED_JOBS = 64       # hard memory cap (ckpool has none)
# Keep a little spendable headroom so sendmany can always cover the network fee.
PAYOUT_FEE_RESERVE = 100_000  # base units (0.001 coin)
# Don't orphan a found block on a shallow tip mismatch - a 1-2 block reorg is routine
# (esp. testnet min-difficulty resets). Only orphan once it's this deep and STILL not on
# the main chain; orphan_block() is irreversible (it deletes the PPLNS credits).
REORG_TOLERANCE = 6
# Retention horizon for the insert-only shares table. Must exceed the longest
# dashboard chart window (~30 days) so a prune can't blank a chart; one full PPLNS
# window of recent rows is always kept regardless of age.
SHARES_RETENTION_SECONDS = 35 * 86400
# prune_shares deletes at most this many rows per call (a synchronous DELETE on the event
# loop); the maintenance tick loops, yielding between chunks, until a backlog is drained.
PRUNE_CHUNK = 20000
PRUNE_MAX_CHUNKS_PER_TICK = 100  # backstop: <=2M rows/tick, the rest drains next hour
# Leading debounce window for ZMQ block notifications: a fast-chain block storm collapses to
# one getblocktemplate instead of one per notify. ~100 ms is imperceptible to miners.
ZMQ_REFRESH_DEBOUNCE = 0.1
# Per-miner deadline for pushing a job/difficulty. One slow or non-reading miner's
# drain() blocks once its write buffer passes the high-water mark; without a bound it
# head-of-line-blocks job delivery to everyone else. A miner that can't take a job in
# this long is treated as dead and dropped.
SEND_JOB_TIMEOUT = 15


class Pool:
    def __init__(self, cfg: Config, serve_stats: bool = True):
        self.cfg = cfg
        self.coin = COINS[cfg.coin]
        self.network = self.coin.network(cfg.chain)
        self.rpc = RPCClient(
            cfg.rpc.host,
            cfg.rpc.port,
            user=cfg.rpc.user,
            password=cfg.rpc.password,
            cookie_file=cfg.rpc.cookie_file,
            timeout=cfg.rpc.timeout,
            wallet=cfg.public.wallet if cfg.mode == "public" else "",
        )
        # Coinbase pays the solo address, or the pool wallet in public mode.
        payout_script = address_to_script(cfg.coinbase_address, self.network)
        self.builder = TemplateBuilder(
            payout_script=payout_script,
            coinbase_tag=cfg.coinbase_tag,
            extranonce1_size=EXTRANONCE1_SIZE,
            extranonce2_size=cfg.extranonce2_size,
            include_transactions=cfg.include_transactions,
        )
        # Share/payout accounting (public mode only).
        self.accounting = (
            Accounting(cfg.public.db_path, cfg.coin) if cfg.mode == "public" else None
        )
        self.stats = Stats(self)
        self.stratum = StratumServer(self)
        # In hub mode the Hub owns one shared stats server over all pools.
        self.stats_server = StatsServer([self], cfg.stats, donate=cfg.donate) if serve_stats else None

        self.connections: set[MinerConnection] = set()
        # Per-IP abuse control: optional connection caps + a temp-ban for IPs that
        # keep getting reject-flood-dropped. Same policy on every coin's listener.
        self.bans = BanManager(max_per_ip=cfg.max_conns_per_ip,
                               max_total=cfg.max_conns_total)
        self.jobs: "OrderedDict[str, Job]" = OrderedDict()
        self.current_job_id: str | None = None
        self.current_height: int | None = None

        self._en1_counter = int(time.time()) & 0xFFFFFFFF  # spread starting point
        # Seed the job-id counter from the wall clock in the HIGH 32 bits so a restart always
        # jumps the id space forward - a cached pre-restart job_id from a proxy can never
        # alias a fresh job, and is unambiguously old. Mirrors ckpool's
        # `randomiser = time(NULL); randomiser <<= 32` (stratifier.c). Emitted as 16 hex.
        self._job_counter = int(time.time()) << 32
        self._best_hash = ""
        self._running = False
        self._mweb_upgrade_logged = False  # one-shot notice when MWEB forces full blocks
        self.last_template_ts = 0.0  # set on each successful build; the dashboard's template age
        self.last_node_contact = 0.0  # last successful node poll (steady heartbeat, even between
        #                               blocks); /healthz keys on THIS so a long inter-block gap
        #                               with template_refresh=0 isn't mistaken for a dead node
        self._stats_refreshing = False  # a node-stats display refresh task is in flight
        self._stats_task = None         # hold a ref so the fire-and-forget task isn't GC'd
        self.mempool = None  # {txs, vbytes, total_fee} - node mempool depth, for the API
        self._template_lock = asyncio.Lock()  # serialize template application (poll + ZMQ)
        # Broadcasting the new job to every miner happens OUTSIDE the template lock (a slow
        # per-miner write must not delay the next ingest). This lock serializes broadcasts,
        # and the seq guard drops a superseded one so a slower older broadcast can't land
        # after a newer one and walk a miner backward onto a stale job.
        self._broadcast_lock = asyncio.Lock()
        self._broadcast_seq = 0
        self._last_broadcast_seq = 0
        self._pending_broadcast = None  # (job, clean, seq) staged under the template lock
        self._max_height_seen = 0       # for the deep-reorg solvency alarm
        self._zmq = (ZmqBlockListener(cfg.zmq_block_url, self._on_zmq_block,
                                      label=f"{cfg.coin}/{cfg.chain}")
                     if getattr(cfg, "zmq_block_url", "") else None)
        self._zmq_busy = False     # a debounced ZMQ-triggered template refresh is in flight
        self._zmq_pending = False  # another tip-change arrived during that refresh
        self._webhook_tasks: set = set()  # keep block-webhook tasks from being GC'd
        self._payout_seq = 0  # disambiguates payout-batch comments within a second
        self.node_health = {}  # {peers, tip_age_seconds, synced} - for the dashboard
        self.network_hashps = None  # node's getnetworkhashps (H/s); None until first poll
        self._last_health_ts = 0.0  # throttle the node-health probe

    # -- interface used by stratum connections -------------------------------

    def next_extranonce1(self) -> bytes:
        self._en1_counter = (self._en1_counter + 1) & 0xFFFFFFFF
        return struct.pack(">I", self._en1_counter)

    def current_job(self) -> Job | None:
        if self.current_job_id is None:
            return None
        return self.jobs.get(self.current_job_id)

    def get_job(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def register(self, conn: MinerConnection) -> None:
        self.connections.add(conn)

    def unregister(self, conn: MinerConnection) -> None:
        self.connections.discard(conn)

    # -- block submission ----------------------------------------------------

    async def handle_block_candidate(
        self, job: Job, en1: bytes, en2: bytes, ntime: int, nonce: int, pow_hash: bytes,
        version: int | None = None, finder: str | None = None,
    ) -> None:
        block_hex = job.build_block_hex(en1, en2, ntime, nonce, version)
        # Block identity is sha256d(header) for BOTH coins: Litecoin's *PoW* is
        # scrypt, but its block *hash* (what getblockhash returns and the maturity
        # loop compares against) is sha256d. Using the scrypt pow_hash here made
        # the maturity loop orphan every Litecoin block.
        header = job.build_header(en1, en2, ntime, nonce, version)
        display_hash = util.internal_to_display(util.sha256d(header))
        try:
            result = await self.rpc.submit_block(block_hex)
        except RPCTimeout:
            # Ambiguous: an overloaded node was too slow to answer, but the block may
            # well have been ACCEPTED. Verify against the chain rather than assuming a
            # loss - otherwise a block we actually won goes uncredited on a slow node.
            log.warning("submitblock timed out at height %d; verifying against the chain", job.height)
            try:
                chain_hash = await self.rpc.get_block_hash(job.height)
            except RPCError:
                chain_hash = None
            if chain_hash == display_hash:
                log.info("submitblock timed out but block %d (%s) IS on-chain - accepted after all",
                         job.height, display_hash)
                result = None  # fall through to the accepted path and credit it
            else:
                log.error("submitblock timed out and block %d is not on the chain; treating as lost "
                          "(check `getblockhash %d` if unsure)", job.height, job.height)
                self.stats.record_block(job.height, display_hash, False, "submit timeout (not on-chain)")
                self._best_hash = ""
                return
        except RPCError as exc:
            log.error("submitblock RPC error: %s", exc)
            self.stats.record_block(job.height, display_hash, False, f"rpc: {exc}")
            self._best_hash = ""
            return
        if result is None:
            log.info("################ BLOCK ACCEPTED at height %d! ################", job.height)
            log.info("block hash (display): %s", display_hash)
            self.stats.record_block(job.height, display_hash, True, "")
            self._notify_block(job.height, display_hash, job.coinbase_value)
            # Public mode: snapshot the PPLNS split now; it's applied to balances
            # only once the block matures (handled by the maturity loop).
            if self.accounting is not None:
                net_diff = (
                    self.coin.diff1_target / job.network_target if job.network_target else None
                )
                info = self.accounting.credit_block(
                    job.height, display_hash, job.coinbase_value,
                    self.cfg.public.fee_percent, self.cfg.public.pplns_window,
                    self.cfg.public.faucet_address, time.time(), net_diff=net_diff,
                    finder=finder,
                )
                if not info.get("duplicate"):
                    log.info(
                        "PPLNS snapshot: reward=%d to %d miners (%d) + faucet (%d) [immature]",
                        job.coinbase_value, info["miners"], info["to_miners"], info["to_faucet"],
                    )
        else:
            self.stats.record_block(job.height, display_hash, False, str(result))
            # submitblock returns a string on non-accept. Some verdicts mean the block
            # was VALID but isn't the best-chain tip: a competing block at this
            # height won the propagation race (a stale / orphan block). That's variance,
            # not a construction bug, so don't log it as an error.
            if str(result).lower() in ("inconclusive", "duplicate-inconclusive", "duplicate"):
                log.warning(
                    "block %d may be STALE: node says '%s'. A competing block may have won "
                    "the race - crediting it IMMATURE (not terminal 'stale'): the maturity "
                    "check decides whether the chain keeps our hash (pays) or not (orphans).",
                    job.height, result,
                )
                # A node verdict of inconclusive/duplicate does NOT mean the block lost -
                # it may still become the tip. Credit it immature so it pays IF it wins;
                # the maturity loop orphans it otherwise. (Routing it straight to terminal
                # 'stale' would never pay even when our block ultimately wins the reorg.)
                if self.accounting is not None:
                    net_diff = (
                        self.coin.diff1_target / job.network_target if job.network_target else None
                    )
                    self.accounting.credit_block(
                        job.height, display_hash, job.coinbase_value,
                        self.cfg.public.fee_percent, self.cfg.public.pplns_window,
                        self.cfg.public.faucet_address, time.time(), net_diff=net_diff,
                        finder=finder,
                    )
            else:
                log.error("block REJECTED by node: %s", result)
                # Diagnostics (esp. MWEB "mweb-missing"): full block? how many txs? did
                # the template carry an mweb extension we appended?
                log.error(
                    "  rejected-block detail: full=%s txs=%d mweb=%s mweb_len=%d height=%d",
                    job.include_transactions, 1 + len(job.tx_data),
                    bool(job.mweb_hex), len(job.mweb_hex or ""), job.height,
                )
                log.debug("rejected block hex: %s", block_hex)
        # Tip almost certainly changed; force a fresh template on the next poll.
        self._best_hash = ""

    def _notify_block(self, height: int, block_hash: str, reward_internal: int) -> None:
        """Fire the optional block-found webhook (best-effort, non-blocking). Fully
        isolated: nothing here may raise into the block-credit path that follows."""
        url = getattr(self.cfg, "block_webhook_url", "")
        if not url:
            return
        try:
            tmpl = explorer_for(self.cfg.coin, self.cfg.chain, getattr(self.cfg, "explorer_url", ""))
            payload = {
                "event": "block_found",
                "pool": "TestnetPool",
                "coin": self.cfg.coin,
                "chain": self.cfg.chain,
                "mode": self.cfg.mode,
                "height": height,
                "hash": block_hash,
                "reward": round(reward_internal / COIN, 8),
                # .replace (not .format) so a stray brace in a configured explorer_url
                # can't raise; mirrors _explorer_link in stats.py.
                "explorer_url": tmpl.replace("{hash}", block_hash) if (tmpl and "{hash}" in tmpl) else "",
                "timestamp": int(time.time()),
            }
            task = asyncio.create_task(post_block(url, payload))
            self._webhook_tasks.add(task)
            task.add_done_callback(self._webhook_tasks.discard)
        except Exception as exc:  # noqa: BLE001 - must never break crediting
            log.warning("block webhook setup failed: %s", exc)

    # -- template polling ----------------------------------------------------

    async def _apply_template(self, gbt: dict, clean: bool) -> None:
        self._job_counter += 1
        job_id = f"{self._job_counter:016x}"  # 16-hex, ckpool's %016lx width
        # build() FIRST: it validates the template (a parseable-but-malformed 200 response raises
        # here, caught by _ingest_template) BEFORE any job-state or liveness mutation - so a run
        # of bad-but-200 templates can't advance the health timestamps while producing no job.
        job = self.builder.build(gbt, job_id)
        job.created = time.time()  # wall-clock, for age-based retention below
        # Stamp liveness only after a successful build. last_node_contact is ALSO stamped on every
        # bare tip poll (_interval_loop), so /healthz stays green across a long inter-block gap
        # even when template_refresh=0 (no idle rebuild) keeps last_template_ts old.
        self.last_template_ts = job.created
        self.last_node_contact = job.created
        # If the operator asked for coinbase-only blocks but the chain is post-MWEB,
        # the builder upgrades to a full block (a coinbase-only block would be
        # rejected "mweb-missing"). Tell the operator once so the override is visible.
        if job.include_transactions and not self.cfg.include_transactions and not self._mweb_upgrade_logged:
            self._mweb_upgrade_logged = True
            log.info(
                "MWEB is active on this chain: building FULL blocks (with the MWEB "
                "extension) despite include_transactions=false - a coinbase-only block "
                "would be rejected by the node as 'mweb-missing'."
            )
        # Do NOT clear jobs on a clean/block change. `clean` is purely a mining.notify hint
        # telling miners to abandon work for the new tip - it must not delete server-side
        # jobs, or an in-flight share crossing the block boundary (and a proxy lagging a few
        # minutes) gets "job not found (stale)". ckpool never deletes a workbase on a block
        # change; it ages them out at 600s. Shares for a superseded tip still resolve here but
        # are gated from PPLNS credit in _on_submit (the prevhash/height stale check).
        self.jobs[job_id] = job
        now = time.time()
        while (len(self.jobs) > MIN_RETAINED_JOBS
               and next(iter(self.jobs.values())).created < now - JOB_RETENTION_SECONDS):
            self.jobs.popitem(last=False)  # age out (oldest-first), keeping a floor
        while len(self.jobs) > MAX_RETAINED_JOBS:
            self.jobs.popitem(last=False)  # hard memory cap
        self.current_job_id = job_id
        self.current_height = job.height
        self._broadcast_seq += 1
        self._pending_broadcast = (job, clean, self._broadcast_seq)
        netdiff = self.coin.diff1_target / job.network_target if job.network_target else 0
        # bits + curtime make a "suspicious" netdiff self-explaining: a testnet
        # min-difficulty reset shows the powLimit bits (e.g. litecoin 1e0ffff0) with
        # a low netdiff - that is the node's own value (target read straight from GBT),
        # not a parser quirk.
        log.info(
            "new job %s height=%d txs=%d clean=%s netdiff=%s bits=%s curtime=%d",
            job_id, job.height, len(job.tx_data), clean,
            f"{netdiff:,.2f}" if netdiff < 1000 else f"{netdiff:,.0f}",
            job.nbits_hex, job.curtime,
        )
        # Refresh the best-effort DISPLAY fields (mempool/peers/tip-age/net-hashrate) OFF the
        # template critical path: a slow node's stats RPCs must never delay this job's broadcast.
        # Throttled to node_stats_interval and guarded so refreshes can't pile up.
        if (now - self._last_health_ts >= self.cfg.node_stats_interval
                and not self._stats_refreshing):
            self._last_health_ts = now
            self._stats_refreshing = True
            self._stats_task = asyncio.create_task(self._refresh_node_stats())

    async def _refresh_node_stats(self) -> None:
        """Best-effort DISPLAY fields (mempool depth, peers, tip age, network hashrate). Runs as
        its own task, OFF the template critical path, so a slow node can't delay job broadcast;
        each probe failure is swallowed and leaves the last value in place. Throttled by the
        caller (node_stats_interval) and serialized by self._stats_refreshing."""
        try:
            now = time.time()
            try:
                mp = await self.rpc.get_mempool_info(timeout=10)
                self.mempool = {"txs": mp.get("size"), "vbytes": mp.get("bytes"),
                                "total_fee": mp.get("total_fee")}
            except Exception:
                log.debug("mempool refresh failed", exc_info=True)
            try:
                info = await self.rpc.get_blockchain_info(timeout=10)
                peers = await self.rpc.get_connection_count(timeout=10)
                tip_time = info.get("time") or info.get("mediantime")
                self.node_health = {
                    "peers": peers,
                    "tip_age_seconds": max(0, int(now) - tip_time) if tip_time else None,
                    "synced": (info.get("blocks") == info.get("headers")
                               if info.get("headers") else None),
                }
            except Exception:
                log.debug("node health refresh failed", exc_info=True)
            # Network hashrate straight from the node (work over actual block times - what
            # mempool.space/Core show). Separate try so its failure doesn't lose node_health.
            try:
                self.network_hashps = float(await self.rpc.get_network_hashps(timeout=10))
            except Exception:
                log.debug("getnetworkhashps refresh failed", exc_info=True)
        finally:
            self._stats_refreshing = False

    async def _broadcast(self, job: Job, clean: bool) -> None:
        subs = [c for c in list(self.connections) if c.subscribed]
        if not subs:
            return
        # Fan out concurrently with a per-miner deadline: a sequential await would let one
        # stalled/non-reading miner block job delivery to everyone behind it. Drop miners
        # that time out or error so they can't wedge the next broadcast either.
        results = await asyncio.gather(
            *(asyncio.wait_for(c.send_job(job, clean), SEND_JOB_TIMEOUT) for c in subs),
            return_exceptions=True,
        )
        for conn, res in zip(subs, results):
            if isinstance(res, Exception):
                self.connections.discard(conn)
                try:
                    conn.writer.close()  # EOF ends its handle() loop
                except Exception:
                    pass

    async def _ingest_template(self, gbt: dict) -> None:
        """Apply a freshly fetched template (clean job iff the tip changed). The lock
        serializes the poll loop and the ZMQ callback so they can't interleave."""
        pending = None
        async with self._template_lock:
            try:
                # Drop an out-of-order OLDER template. The poll loop and the ZMQ callback fetch
                # concurrently OUTSIDE this lock, so a slower fetch for a now-superseded tip can
                # resolve last; applying it would regress current_height/_best_hash, briefly admit
                # superseded-tip shares to PPLNS, and rebroadcast a stale clean job. (Mirrors the
                # Monero engine's monotonic height guard.) Same-height refreshes still pass.
                new_height = gbt.get("height")
                if (self.current_height is not None and new_height is not None
                        and new_height < self.current_height):
                    return
                is_new = gbt["previousblockhash"] != self._best_hash
                await self._apply_template(gbt, clean=is_new)
                self._best_hash = gbt["previousblockhash"]
                pending = self._pending_broadcast
            except (KeyError, ValueError, TypeError) as exc:
                # A parseable-but-malformed template (missing/odd field, bad int) must NOT
                # escape and tear the coin down via run()'s finally. build() runs before any
                # job-state mutation, so on failure we keep serving the last good template;
                # the poll loop refetches next cycle. (RPCError from the fetch is handled by
                # the callers' retry/backoff; this catches parse errors from a 200 response.)
                log.error("ignoring malformed block template: %s", exc)
                return
        if pending is None:
            return
        # Broadcast outside the template lock; serialize + drop a superseded broadcast.
        job, clean, seq = pending
        async with self._broadcast_lock:
            if seq < self._last_broadcast_seq:
                return
            self._last_broadcast_seq = seq
            await self._broadcast(job, clean)

    async def _on_zmq_block(self) -> None:
        """ZMQ told us the tip changed - pull a fresh template (instant block updates, no
        waiting on the poll loop). DEBOUNCED: a testnet block storm fires many hashblock
        notifications in a burst; coalesce them into a SINGLE getblocktemplate (the heaviest
        call, especially on Litecoin where it builds the MWEB extension block) instead of one
        per notify. A 100 ms leading window collapses a burst; one trailing re-fetch catches a
        tip that changed while we were building, so the served template is never behind."""
        self._zmq_pending = True
        if self._zmq_busy:
            return                       # a refresh is already running; it will re-fetch
        self._zmq_busy = True
        try:
            await asyncio.sleep(ZMQ_REFRESH_DEBOUNCE)   # collapse a tight burst into one fetch
            while self._zmq_pending and self._running:
                self._zmq_pending = False
                try:
                    gbt = await self.rpc.get_block_template(self.coin.gbt_rules)
                    await self._ingest_template(gbt)
                except RPCError as exc:
                    log.debug("zmq-triggered template refresh failed: %s", exc)
        finally:
            self._zmq_busy = False

    async def _poll_loop(self) -> None:
        # Fetch an initial template, then either long-poll (the node holds the
        # request open until the tip changes) or fall back to interval polling
        # if the node/config don't support it.
        while self._running:
            try:
                gbt = await self.rpc.get_block_template(self.coin.gbt_rules)
            except RPCError as exc:
                log.error("getblocktemplate failed: %s", exc)
                await asyncio.sleep(self.cfg.block_poll_interval)
                continue
            await self._ingest_template(gbt)
            longpollid = gbt.get("longpollid")
            if self.cfg.longpoll and longpollid:
                await self._longpoll_loop(longpollid)
            else:
                if self.cfg.longpoll:
                    log.info("node provides no longpollid; using interval polling")
                await self._interval_loop()
            # An inner loop only returns on error/lost-support; re-init above.

    async def _longpoll_loop(self, longpollid: str) -> None:
        log.info("using getblocktemplate long-polling for instant block updates")
        # The fallback refresh gets extra headroom: a node can be slow to build a
        # template (large mempool / MWEB), and the long-poll we just abandoned may
        # still be tying up an RPC worker thread.
        slow_timeout = max(self.cfg.rpc.timeout, 60.0)
        slow_warned = False
        while self._running:
            try:
                # Blocks server-side until the tip changes; our timeout bounds it
                # so we also refresh ntime periodically when no block arrives.
                gbt = await self.rpc.get_block_template(
                    self.coin.gbt_rules, longpollid=longpollid,
                    # template_refresh<=0 ("rebuild on block only"): hold the long-poll on a long
                    # timeout instead of busy-refetching for ntime.
                    timeout=self.cfg.template_refresh if self.cfg.template_refresh > 0 else 600.0,
                )
            except RPCTimeout:
                try:  # no new block within the window -> plain refresh for ntime
                    gbt = await self.rpc.get_block_template(
                        self.coin.gbt_rules, timeout=slow_timeout)
                except RPCTimeout:
                    # Node is slow right now. Keep serving the last template (miners
                    # keep working; a real new block still wakes the long-poll) and
                    # retry - warn ONCE instead of erroring every cycle.
                    if not slow_warned:
                        slow_warned = True
                        log.warning(
                            "getblocktemplate is slow (>%.0fs) on this node; serving the "
                            "last template and retrying. If it persists, raise rpc.timeout "
                            "or set longpoll = false for lighter interval polling.",
                            slow_timeout)
                    await asyncio.sleep(self.cfg.block_poll_interval)
                    continue
                except RPCError as exc:
                    log.error("getblocktemplate failed: %s", exc)
                    await asyncio.sleep(self.cfg.block_poll_interval)
                    return
            except RPCError as exc:
                log.error("long-poll getblocktemplate failed: %s", exc)
                await asyncio.sleep(self.cfg.block_poll_interval)
                return
            if slow_warned:
                log.info("getblocktemplate recovered")
                slow_warned = False
            await self._ingest_template(gbt)
            longpollid = gbt.get("longpollid")
            if not longpollid:
                return  # node stopped providing longpollid -> fall back

    async def _interval_loop(self) -> None:
        last_refresh = time.monotonic()
        while self._running:
            await asyncio.sleep(self.cfg.block_poll_interval)
            try:
                best = await self.rpc.get_best_block_hash()
            except RPCError as exc:
                log.error("cannot reach node: %s", exc)
                continue
            # The node answered: this is the steady liveness heartbeat (even when the tip hasn't
            # changed and we don't rebuild), so /healthz doesn't read a long inter-block gap as a
            # dead node under template_refresh=0.
            self.last_node_contact = time.time()
            now = time.monotonic()
            # Always rebuild on a tip change. The idle rebuild (refresh ntime/mempool fees)
            # fires only every template_refresh seconds; set template_refresh <= 0 to disable it
            # and rebuild ONLY when a block arrives - lightest on a node shared with a faucet
            # (miners roll ntime themselves; ZMQ/this poll still catch real blocks).
            if best == self._best_hash and (
                    self.cfg.template_refresh <= 0
                    or (now - last_refresh) < self.cfg.template_refresh):
                continue
            try:
                gbt = await self.rpc.get_block_template(self.coin.gbt_rules)
            except RPCError as exc:
                log.error("getblocktemplate failed: %s", exc)
                continue
            await self._ingest_template(gbt)
            last_refresh = now

    # -- public mode: maturity + payouts ------------------------------------

    async def _vardiff_loop(self) -> None:
        """Periodically nudge idle miners' difficulty down so an over-set value
        self-heals even with no shares arriving. record_share covers the up path."""
        interval = max(5.0, self.cfg.vardiff.target_time)
        while self._running:
            await asyncio.sleep(interval)
            now = time.time()
            for conn in list(self.connections):
                try:
                    await conn.vardiff_idle_check(now)
                except (ConnectionError, OSError):
                    self.connections.discard(conn)
                    try:
                        conn.writer.close()  # EOF ends its handle() loop, frees the socket + the
                        #                       per-IP ban slot (rental proxies funnel many rigs
                        #                       through one IP - a leak refuses their new rigs)
                    except Exception:
                        pass
                except Exception:
                    log.debug("vardiff idle check failed", exc_info=True)

    async def _maturity_loop(self) -> None:
        """Mature or orphan found blocks based on confirmations (credit-on-mature)."""
        while self._running:
            await asyncio.sleep(60)
            try:
                if self.current_height is None:
                    continue
                # current_height is the height we're MINING (tip+1), so confirmations of a
                # found block = current_height - its height (the block itself is conf #1 when
                # it is the tip). depth keeps the legacy +1 metric for the discretionary
                # orphan tolerance so that behaviour is unchanged.
                if self.current_height > self._max_height_seen:
                    self._max_height_seen = self.current_height
                elif self._max_height_seen - self.current_height > COINBASE_MATURITY:
                    # Deep-reorg solvency alarm. Matured blocks are no longer re-scanned
                    # (orphan_block only acts on immature), so a reorg deeper than maturity
                    # can strand credits/payouts for a block no longer on-chain. We can't
                    # auto-undo a paid block; alarm the operator to reconcile by hand.
                    log.warning("CHAIN REORG ALARM: tip regressed %d -> %d (>%d blocks); "
                                "already-matured blocks may be off-chain - reconcile wallet "
                                "balance against credited payouts manually",
                                self._max_height_seen, self.current_height, COINBASE_MATURITY)
                for blk in self.accounting.immature_blocks():
                    try:
                        main_hash = await self.rpc.get_block_hash(blk["height"])
                    except RPCError:
                        continue  # height beyond tip or transient; try next round
                    confs = self.current_height - blk["height"]
                    depth = confs + 1
                    if main_hash != blk["hash"]:
                        # Only orphan once the block is deep enough that the mismatch can't
                        # be a transient tip wobble that re-confirms us; orphan_block()
                        # irreversibly drops the credits, so don't act on a shallow reorg.
                        if depth >= REORG_TOLERANCE:
                            self.accounting.orphan_block(blk["id"])
                            log.info("block %d (%s...) ORPHANED at depth %d - credits dropped",
                                     blk["height"], blk["hash"][:16], depth)
                        else:
                            log.debug("block %d hash mismatch at shallow depth %d - waiting "
                                      "(possible transient reorg)", blk["height"], depth)
                    elif confs >= COINBASE_MATURITY:
                        self.accounting.mature_block(blk["id"])
                        log.info("block %d matured (%d confs) - credits applied",
                                 blk["height"], confs)
            except Exception:
                log.exception("maturity loop iteration failed")

    async def _payout_loop(self) -> None:
        min_payout = int(self.cfg.public.min_payout * COIN)
        last_sweep = time.monotonic()
        while self._running:
            await asyncio.sleep(self.cfg.public.payout_interval)
            # Self-healing: re-resolve any pending intent FIRST (a node outage during the
            # startup reconcile may have left one unresolved). _do_payouts then skips any
            # miner still named in an unresolved intent, so it can't be paid twice.
            try:
                await self._reconcile_pending_payouts()
            except Exception:
                log.exception("payout reconcile failed")
            try:
                await self._do_payouts(min_payout)
            except RPCError as exc:
                log.error("payout failed: %s", exc)
            except Exception:
                log.exception("payout loop iteration failed")
            try:
                if time.monotonic() - last_sweep >= 3600:  # hourly sweep + prune
                    last_sweep = time.monotonic()
                    cutoff = int(time.time() - self.cfg.public.sweep_after_days * 86400)
                    swept = self.accounting.sweep_stale(
                        cutoff, self.cfg.public.faucet_address, time.time()
                    )
                    if swept:
                        log.info("swept %d base units of idle balances to the faucet", swept)
                    # Bound the insert-only shares table (keeps >=30d of history for the
                    # charts + one full PPLNS window); otherwise it grows forever. Drain in
                    # chunks, yielding between each so a large first-time backlog can't stall
                    # share validation in one long DELETE; the per-tick cap bounds the rest.
                    cutoff_ts = int(time.time() - SHARES_RETENTION_SECONDS)
                    pruned = 0
                    floor_id = self.accounting.shares_keep_floor(self.cfg.public.pplns_window)
                    for _ in range(PRUNE_MAX_CHUNKS_PER_TICK if floor_id is not None else 0):
                        n = self.accounting.prune_shares(
                            cutoff_ts, self.cfg.public.pplns_window, chunk=PRUNE_CHUNK,
                            floor_id=floor_id)
                        pruned += n
                        if n < PRUNE_CHUNK:  # short read => backlog drained
                            break
                        await asyncio.sleep(0)  # let queued share validations run
                    if pruned:
                        log.info("pruned %d shares older than %d days", pruned,
                                 SHARES_RETENTION_SECONDS // 86400)
            except Exception:
                log.exception("idle-balance sweep failed")

    async def _do_payouts(self, min_payout: int) -> None:
        # Exclude any miner with an UNRESOLVED in-flight payout (a prior batch that was
        # sent but not yet confirmed-debited): paying them now would double-pay. They
        # resume the moment _reconcile_pending_payouts resolves their intent.
        in_flight = self.accounting.pending_payout_miner_ids()
        payable = [p for p in self.accounting.payable(min_payout)
                   if p["miner_id"] not in in_flight]
        if not payable:
            return
        balance = await self.rpc.get_balance()  # whole coins, spendable (matured) only
        budget = int(balance * COIN) - PAYOUT_FEE_RESERVE
        outputs: dict[str, int] = {}
        paid: list[dict] = []
        total = 0
        for p in payable:
            if total + p["owed"] > budget:
                continue  # not enough matured funds yet; pay this one a later round
            outputs[p["address"]] = p["owed"]
            paid.append({"miner_id": p["miner_id"], "amount": p["owed"]})
            total += p["owed"]
        if not outputs:
            log.info("payouts: %d owed but only %.8f spendable - waiting on maturity",
                     len(payable), balance)
            return
        out_coins = {addr: round(sats / COIN, 8) for addr, sats in outputs.items()}
        # Persist the intent BEFORE sending; record the txid the instant the send returns
        # it (proof of broadcast). Balances are debited ONLY once we know the tx broadcast.
        self._payout_seq += 1
        comment = f"testnetpool-payout-{int(time.time())}-{self._payout_seq}"
        self.accounting.begin_payout(comment, paid, time.time())
        try:
            txid = await self.rpc.send_many(out_coins, comment=comment)
            self.accounting.set_payout_txid(comment, txid)
        except RPCTimeout:
            # Ambiguous: may or may not have broadcast. The tx (if any) is at the wallet
            # tip RIGHT NOW, so find_wallet_tx's recent window is reliable here.
            log.warning("sendmany timed out; checking whether the payout broadcast")
            txid = await self.rpc.find_wallet_tx(comment)
            if not txid:
                log.warning("payout did not broadcast (no tx for %s); retrying next round", comment)
                self.accounting.clear_payout(comment)
                return
            self.accounting.set_payout_txid(comment, txid)
            log.info("recovered payout tx after timeout: %s", txid)
        except RPCError as exc:
            # The node REJECTED the request (insufficient funds, locked wallet, bad fee):
            # it did NOT broadcast, so drop the intent and let it retry next round.
            self.accounting.clear_payout(comment)
            log.error("payout send failed (not broadcast): %s", exc)
            return
        # Debit + clear the pending intent atomically (exactly-once).
        self.accounting.record_payouts(paid, txid, time.time(), comment=comment)
        log.info("paid %d recipients, total %.8f, txid=%s", len(paid), total / COIN, txid)

    async def _reconcile_pending_payouts(self) -> None:
        """Resolve any payout batch sent but not confirmed-debited before a crash. Runs at
        startup AND every payout tick (self-healing across a transient outage). Errs toward
        never losing funds: a batch is cleared-without-debit ONLY when we can prove it never
        broadcast; anything indeterminate stays pending (and its miners aren't re-paid)."""
        if self.accounting is None:
            return
        for pend in self.accounting.pending_payouts():
            comment, txid = pend["comment"], pend.get("txid")
            if txid:
                # The send returned a txid => it broadcast. Debit exactly once (no wallet
                # scan needed - this is the path that fixes the recent-tx-window blind spot).
                self.accounting.record_payouts(pend["items"], txid, time.time(), comment=comment)
                log.warning("reconciled broadcast payout %s -> %s (debited now)", comment, txid)
                continue
            # No txid: we crashed during/just-before the send. If it broadcast, the tx is
            # recent, so the wallet's recent-tx window is reliable here.
            try:
                txid = await self.rpc.find_wallet_tx(comment)
            except Exception:
                log.warning("can't reconcile pending payout %s yet (node unreachable); left pending",
                            comment)
                continue
            if txid:
                self.accounting.record_payouts(pend["items"], txid, time.time(), comment=comment)
                log.warning("reconciled broadcast payout %s -> %s (debited now)", comment, txid)
            else:
                # INDETERMINATE: no txid and not in recent wallet txs. Do NOT clear-and-risk
                # a double-pay - leave it pending (its miners stay un-re-paid) and alarm the
                # operator to verify the wallet and clear it only if it truly never sent.
                log.error("pending payout %s has no txid and isn't in recent wallet txs - "
                          "INDETERMINATE; left pending (its miners won't be re-paid until you "
                          "verify the wallet and clear it).", comment)

    # -- lifecycle -----------------------------------------------------------

    async def run(self) -> None:
        self._running = True
        # A node that's briefly unreachable/slow at startup must not permanently down
        # this coin - in a hub the other coins keep running. Retry with backoff until the
        # node answers (or we're asked to stop) instead of failing fast and dying for good.
        info = await await_node_ready(
            self.rpc.get_blockchain_info, lambda: self._running,
            label=f"{self.cfg.coin} node", logger=log)
        if info is None:  # stop() was called before the node ever answered
            self._running = False
            return
        log.info(
            "connected to %s node: chain=%s blocks=%s headers=%s",
            self.cfg.coin, info.get("chain"), info.get("blocks"), info.get("headers"),
        )
        if info.get("chain") != self.network.node_chain:
            # FAIL CLOSED. The coinbase is built network-agnostically (address -> H160)
            # and mainnet consensus ignores address version bytes, so an operator who
            # points rpc at the wrong-chain node (e.g. a mainnet bitcoind while configured
            # for testnet) would otherwise build a valid coinbase and submitblock a REAL
            # block on the wrong network behind a single warning. Refuse to start instead.
            raise RuntimeError(
                f"config {self.cfg.coin}/{self.cfg.chain} expects node chain="
                f"{self.network.node_chain!r} but the node reports chain="
                f"{info.get('chain')!r}; refusing to mine. Point rpc at the correct node "
                f"or fix the coin/chain config."
            )
        # From here on, any failure must still run the cleanup below (close the listener, the
        # stats server, the DB; cancel bg tasks) instead of leaking a half-started coin with
        # _running stuck True. bg_tasks is initialised before the try so the finally can always
        # reference it. The chain-mismatch RuntimeError above stays OUTSIDE this try - it's a
        # fatal misconfig that must crash the coin, and nothing has been started yet.
        bg_tasks = []
        try:
            # Build the first job BEFORE opening the listener, so every miner that connects
            # already has work the instant it authorizes - closes the authorize-before-first-
            # template race and the MRR/NiceHash pool-verify window. Best-effort: if the fetch
            # fails the poll loop retries, and miners just wait for the broadcast as before.
            try:
                await self._ingest_template(await self.rpc.get_block_template(self.coin.gbt_rules))
            except Exception:
                log.warning("initial template fetch failed; the poll loop will retry", exc_info=True)
            await self.stratum.start()
            if self.stats_server is not None:
                await self.stats_server.start()
            log.info(
                "mode=%s | mining %s to %s (%s) | algo=%s include_transactions=%s",
                self.cfg.mode, self.cfg.coin, self.cfg.coinbase_address, self.cfg.chain,
                self.coin.algo, self.cfg.include_transactions,
            )
            if self.accounting is not None:
                s = self.accounting.summary()
                log.info(
                    "public mode: db=%s fee=%.2f%% min_payout=%s faucet=%s | known miners=%d",
                    self.cfg.public.db_path, self.cfg.public.fee_percent,
                    self.cfg.public.min_payout, self.cfg.public.faucet_address,
                    s["miners_known"],
                )
            # The coinbase scriptSig is capped at 100 bytes and also holds the BIP34
            # height push (~4) + extranonce (en1 4 + en2 N); warn if the message won't
            # fit and would be truncated.
            tag_bytes = self.cfg.coinbase_tag.encode()
            avail = 100 - 5 - (EXTRANONCE1_SIZE + self.cfg.extranonce2_size)
            if len(tag_bytes) > avail:
                log.warning(
                    "coinbase message is %d bytes but only ~%d fit in the scriptSig - "
                    "it will be truncated", len(tag_bytes), avail,
                )
            log.info("coinbase message: %r (%d bytes)", self.cfg.coinbase_tag, len(tag_bytes))

            if self.cfg.vardiff.enabled:
                bg_tasks.append(asyncio.create_task(self._vardiff_loop()))
            if self.accounting is not None:
                # Resolve any payout that broadcast-but-wasn't-debited before a prior crash
                # BEFORE the payout loop can issue new sends (else we'd re-pay it). A startup
                # DB hiccup must NOT abort coin startup - the payout loop re-runs reconcile
                # (itself guarded) every tick and self-heals.
                try:
                    await self._reconcile_pending_payouts()
                except Exception:
                    log.exception("startup payout reconcile failed; the payout loop will retry")
                bg_tasks.append(asyncio.create_task(self._maturity_loop()))
                bg_tasks.append(asyncio.create_task(self._payout_loop()))
                log.info("public-mode loops started (maturity + payouts)")
            # Block-detection posture: one line per coin so the operator can confirm the
            # RPC-load settings actually took effect (the whole point on a faucet-shared node)
            # without grepping the config. The async "zmq: subscribed ..." line follows once
            # the listener connects; this prints immediately and names the coin.
            idle = ("on new block only" if self.cfg.template_refresh <= 0
                    else "every %.0fs" % self.cfg.template_refresh)
            if self._zmq is not None:
                log.info(
                    "%s/%s: block detection = ZMQ %s (instant) + %.0fs safety poll; "
                    "idle template rebuild %s; longpoll=%s",
                    self.cfg.coin, self.cfg.chain, self.cfg.zmq_block_url,
                    self.cfg.block_poll_interval, idle, "on" if self.cfg.longpoll else "off",
                )
                if self.cfg.longpoll:
                    log.warning(
                        "%s/%s: longpoll is ON alongside ZMQ - longpoll holds an RPC worker open "
                        "that ZMQ makes unnecessary; set longpoll = false for the lightest load "
                        "on a faucet-shared node", self.cfg.coin, self.cfg.chain,
                    )
            elif self.cfg.longpoll:
                log.info("%s/%s: block detection = getblocktemplate longpoll; "
                         "idle template rebuild %s", self.cfg.coin, self.cfg.chain, idle)
            else:
                log.info("%s/%s: block detection = interval poll every %.0fs; "
                         "idle template rebuild %s",
                         self.cfg.coin, self.cfg.chain, self.cfg.block_poll_interval, idle)
            if self._zmq is not None:
                bg_tasks.append(asyncio.create_task(self._zmq.run()))
            await self._poll_loop()
        finally:
            self._running = False
            if self._zmq is not None:
                self._zmq.stop()
            for t in bg_tasks:
                t.cancel()
            # Await the cancelled tasks so a loop suspended at an RPC await finishes
            # unwinding (incl. any open `with self.conn` transaction) BEFORE we close
            # the DB - otherwise it resumes after close() on a dead connection.
            if bg_tasks:
                await asyncio.gather(*bg_tasks, return_exceptions=True)
            # Also cancel the fire-and-forget side tasks (node-stats refresh + block webhooks).
            # They only touch display fields / external POSTs, never the DB, but cancelling them
            # avoids a "Task was destroyed but it is pending" warning and a lingering RPC await.
            side = [t for t in (self._stats_task, *self._webhook_tasks)
                    if t is not None and not t.done()]
            for t in side:
                t.cancel()
            if side:
                await asyncio.gather(*side, return_exceptions=True)
            await self.stratum.close()
            if self.stats_server is not None:
                await self.stats_server.close()
            if self.accounting is not None:
                self.accounting.close()

    def stop(self) -> None:
        self._running = False
