# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""MoneroPool: the trust-based Monero pool engine.

Mirrors Pool's interface (run/stop, .stats/.accounting/.coin/.current_height/
.connections/.cfg) so it reuses the shared Stats, dashboard, accounting and hub
unchanged. The pool polls monerod for a block template, serves CryptoNote
Stratum, accepts shares on the miner's submitted result (testnet/trust-based),
and when a result clears network difficulty it reconstructs the full block and
submits it to monerod (which is the real RandomX arbiter). Payouts go out via
monero-wallet-rpc.

Amounts are kept on the internal 1e8 scale and converted to/from piconero (1e12)
at the wallet boundary via MONERO.unit_scale.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict

from .accounting import Accounting
from .coin import COIN
from .config import Config
from .monero_coin import MONERO
from .monero_rpc import MoneroRPC, MoneroRPCError, MoneroRPCTimeout, MoneroWalletRPC
from .rpc import await_node_ready
from .monero_stratum import CryptoNoteStratumServer, MoneroJob
from .stats import Stats, StatsServer, explorer_for
from .stratum import BanManager
from .webhook import post_block

log = logging.getLogger("testnetpool.monero")

POLL_INTERVAL_FLOOR = 5.0  # seconds; Monero blocks are ~2 min, no need to poll fast
MAX_RECIPIENTS = 15        # cap payouts per sweep; the rest roll to the next round
SHARES_RETENTION_SECONDS = 35 * 86400  # bound the shares table (see pool.SHARES_RETENTION_SECONDS)
REORG_TOLERANCE = 6        # depth-grace before orphaning (see pool.REORG_TOLERANCE)
FEE_RESERVE_PICO = 10 ** 9  # ~0.001 XMR held back so a max-balance payout still covers the fee


class MoneroPool:
    def __init__(self, cfg, serve_stats: bool = True):
        self.cfg = cfg
        self.coin = MONERO
        self.network = MONERO.network(cfg.chain)
        self.rpc = MoneroRPC(
            cfg.rpc.host, cfg.rpc.port or self.network.rpc_port,
            cfg.rpc.user, cfg.rpc.password, cfg.rpc.timeout,
        )
        self.accounting = (
            Accounting(cfg.public.db_path, cfg.coin) if cfg.mode == "public" else None
        )
        pub = cfg.public
        self.wallet = (
            MoneroWalletRPC(pub.monero_wallet_host, pub.monero_wallet_port,
                            pub.monero_wallet_user, pub.monero_wallet_password)
            if (cfg.mode == "public" and pub.monero_wallet_port) else None
        )
        self.stats = Stats(self)
        self._payout_seq = 0  # disambiguates pending-payout intents within a run
        self.stratum = CryptoNoteStratumServer(self)
        self.stats_server = (
            StatsServer([self], cfg.stats, donate=cfg.donate) if serve_stats else None
        )
        self.connections: set = set()
        # Same per-IP abuse control as the Bitcoin/Litecoin listener.
        self.bans = BanManager(max_per_ip=cfg.max_conns_per_ip,
                               max_total=cfg.max_conns_total)
        self._webhook_tasks: set = set()  # keep block-webhook tasks from being GC'd
        self.current_height: int | None = None
        self.node_health = {}        # {peers, tip_age_seconds, synced} - for the dashboard
        self._last_health_ts = 0.0   # throttle the node-health probe
        self.template: MoneroJob | None = None
        self.last_template_ts = 0.0  # set on each template; powers the /healthz probe
        # Pool-GLOBAL trust-share dedup. Trust-based acceptance takes the result at
        # face value, so a miner who finds ONE valid result must not be able to credit
        # it more than once - not by re-fetching getjob for a fresh job_id (same
        # template), and not by replaying it across multiple connections. Keying on the
        # template's blockhashing_blob (stable per template, distinct per template)
        # instead of the per-getjob job_id, and living on the pool instead of the
        # connection, closes both. Sliding-window bounded like the per-conn set was.
        self._seen_shares: "OrderedDict[tuple, None]" = OrderedDict()
        self._running = False

    # -- duck-typed Pool interface used by Stats / StatsServer ----------------

    def current_job(self) -> MoneroJob | None:
        return self.template

    def register(self, conn) -> None:
        self.connections.add(conn)

    def unregister(self, conn) -> None:
        self.connections.discard(conn)

    # -- templates ------------------------------------------------------------

    async def _refresh_template(self) -> None:
        # reserve_size=0: we don't reserve tx_extra space for a per-miner extra-nonce, so
        # every connected miner gets the SAME blockhashing_blob and searches the same
        # 4-byte nonce space (the engine is effectively per-miner SOLO on a shared
        # template). That's fine here - shares are trust-based (credited on the miner's
        # self-reported result, monerod is the arbiter for real blocks), and on testnet
        # the overlap just costs a little redundant work, never funds. A real PoW pool
        # would request reserve_size>0 and splice a unique extra-nonce per connection.
        gbt = await self.rpc.get_block_template(self.cfg.coinbase_address, 0)
        job = MoneroJob(gbt)
        prev = self.current_height
        new_height = job.height - 1  # the block being mined is the next height
        # Monotonic guard: _poll_loop and handle_block_candidate can refresh concurrently
        # (no lock, matching the BTC/LTC design where the fetch stays unlocked) and resolve
        # out of order; never let an older fetch regress the tip/template and broadcast a
        # stale job. A same-height refresh (new blob/ntime) is still applied, just not
        # re-broadcast.
        if prev is not None and new_height < prev:
            return
        self.last_template_ts = time.time()
        self.template = job
        self.current_height = new_height
        if prev != self.current_height:
            log.info("monero new template: height=%d difficulty=%d", job.height, job.difficulty)
            await self.stratum.broadcast()
        # Node health (peers + sync), throttled + best-effort - mirrors the BTC/LTC pool.
        now = time.time()
        if now - self._last_health_ts >= 30:
            self._last_health_ts = now
            try:
                info = await self.rpc.get_info()
                peers = (info.get("incoming_connections_count", 0)
                         + info.get("outgoing_connections_count", 0))
                self.node_health = {
                    "peers": peers,
                    "tip_age_seconds": None,  # monerod get_info exposes no tip timestamp
                    "synced": info.get("synchronized"),
                }
            except Exception:  # best-effort: must never break template handling
                log.debug("monero node health refresh failed", exc_info=True)

    async def _poll_loop(self) -> None:
        interval = max(POLL_INTERVAL_FLOOR, self.cfg.block_poll_interval)
        outage_warned = False  # warn once on a sustained outage, not every cycle
        while self._running:
            try:
                await self._refresh_template()
                if outage_warned:
                    log.info("monero get_block_template recovered")
                    outage_warned = False
            except MoneroRPCError as exc:
                if not outage_warned:
                    log.error("monero get_block_template failed: %s (quiet until recovered)", exc)
                    outage_warned = True
                else:
                    log.debug("monero get_block_template still failing: %s", exc)
            except (KeyError, ValueError, TypeError) as exc:
                log.error("monero block template malformed: %s", exc)
            except Exception:
                log.exception("monero template poll crashed")
            await asyncio.sleep(interval)

    # -- block submission -----------------------------------------------------

    async def handle_block_candidate(self, tmpl: MoneroJob, nonce_bytes: bytes,
                                     finder: str | None = None) -> None:
        block_hex = tmpl.build_block(nonce_bytes).hex()
        block_hash = ""
        try:
            await self.rpc.submit_block(block_hex)
        except MoneroRPCTimeout:
            # Ambiguous: monerod was too slow to answer but may have ACCEPTED the block.
            # Verify the chain reached this height before treating it as lost (mirrors
            # the BTC/LTC submit-timeout chain-check at pool.py). We can't recompute the
            # CryptoNote hash locally, so "this height now exists" is the signal we have;
            # right after our own submit, that block is almost certainly ours.
            log.warning("monero submit_block timed out at height %d; checking the chain", tmpl.height)
            try:
                hdr = await self.rpc.get_block_header_by_height(tmpl.height)
            except MoneroRPCError:
                hdr = None
            if not (hdr and hdr.get("hash")):
                log.error("monero block %d not on-chain after submit timeout; treating as lost", tmpl.height)
                self.stats.record_block(tmpl.height, "", False, "submit timeout (not on-chain)")
                return
            block_hash = hdr["hash"]
            log.info("monero block %d IS on-chain after the timeout - accepted after all", tmpl.height)
        except MoneroRPCError as exc:
            log.error("monero submit_block rejected at height %d: %s", tmpl.height, exc)
            self.stats.record_block(tmpl.height, "", False, str(exc))
            return
        log.info("############ MONERO BLOCK ACCEPTED at height %d! ############", tmpl.height)
        if not block_hash:
            block_hash = await self._block_hash_at(tmpl.height)
        if not block_hash:
            # NEVER credit against a placeholder hash. The maturity loop compares the
            # on-chain hash at this height to the stored hash, so a fake id (e.g. the
            # block-template prefix) would ALWAYS orphan this genuinely-won block - a
            # permanent loss. Skip the PPLNS snapshot instead; the reward is still in the
            # pool wallet via the coinbase, just not split this round (manual reconcile).
            log.error("monero block %d accepted but its real hash is unavailable after "
                      "retries - SKIPPING the PPLNS snapshot to avoid a guaranteed orphan",
                      tmpl.height)
            self.stats.record_block(tmpl.height, "", True, "")
            return
        self.stats.record_block(tmpl.height, block_hash, True, "")
        self._notify_block(tmpl.height, block_hash, tmpl.reward / MONERO.atomic)
        if self.accounting is not None:
            reward_internal = tmpl.reward // MONERO.unit_scale
            if reward_internal <= 0:
                log.warning("monero block at height %d has zero expected_reward; "
                            "its PPLNS round will pay nothing", tmpl.height)
            info = self.accounting.credit_block(
                tmpl.height, block_hash, reward_internal,
                self.cfg.public.fee_percent, self.cfg.public.pplns_window,
                self.cfg.public.faucet_address, time.time(),
                net_diff=tmpl.difficulty, finder=finder,
            )
            if not info.get("duplicate"):
                log.info("monero PPLNS snapshot: reward=%d to %d miners [immature]",
                         reward_internal, info.get("miners", 0))
        # Tip changed; pull a fresh template promptly.
        try:
            await self._refresh_template()
        except MoneroRPCError:
            pass

    async def _block_hash_at(self, height: int, attempts: int = 5) -> str:
        """The real on-chain block hash at ``height``, retried briefly. The block was
        just accepted, so monerod should surface it within a moment; returns "" only if
        it's still unavailable after the retries (caller must not store a placeholder)."""
        for i in range(attempts):
            try:
                h = (await self.rpc.get_block_header_by_height(height)).get("hash", "")
                if h:
                    return h
            except MoneroRPCError:
                pass
            await asyncio.sleep(0.5 * (i + 1))
        return ""

    def _notify_block(self, height: int, block_hash: str, reward_coins: float) -> None:
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
                "reward": round(reward_coins, 8),
                # .replace (not .format) so a stray brace in a configured explorer_url
                # can't raise; mirrors _explorer_link in stats.py.
                "explorer_url": (tmpl.replace("{hash}", block_hash)
                                 if (tmpl and block_hash and "{hash}" in tmpl) else ""),
                "timestamp": int(time.time()),
            }
            task = asyncio.create_task(post_block(url, payload))
            self._webhook_tasks.add(task)
            task.add_done_callback(self._webhook_tasks.discard)
        except Exception as exc:  # noqa: BLE001 - must never break crediting
            log.warning("block webhook setup failed: %s", exc)

    # -- background loops (mirror Pool) ---------------------------------------

    async def _vardiff_loop(self) -> None:
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
                        conn.writer.close()  # free the socket + per-IP ban slot (see pool.py)
                    except Exception:
                        pass
                except Exception:
                    log.debug("monero vardiff idle check failed", exc_info=True)

    async def _maturity_loop(self) -> None:
        while self._running:
            await asyncio.sleep(30)
            try:
                if self.current_height is None:
                    continue
                for blk in self.accounting.immature_blocks():
                    try:
                        hdr = await self.rpc.get_block_header_by_height(blk["height"])
                    except MoneroRPCError:
                        continue
                    main_hash = hdr.get("hash", "")
                    depth = self.current_height - blk["height"] + 1
                    if main_hash and main_hash != blk["hash"]:
                        # Depth-grace (mirrors the BTC/LTC pool): only orphan once it's deep
                        # enough that the mismatch can't be a transient reorg - orphan_block
                        # irreversibly drops the won round's PPLNS credits.
                        if depth >= REORG_TOLERANCE:
                            self.accounting.orphan_block(blk["id"])
                            log.info("monero block %d (%s...) ORPHANED at depth %d",
                                     blk["height"], blk["hash"][:16], depth)
                        else:
                            log.debug("monero block %d hash mismatch at shallow depth %d - waiting",
                                      blk["height"], depth)
                    elif depth >= MONERO.maturity:
                        self.accounting.mature_block(blk["id"])
                        log.info("monero block %d matured", blk["height"])
            except Exception:
                log.exception("monero maturity loop iteration failed")

    async def _payout_loop(self) -> None:
        last_sweep = time.monotonic()
        while self._running:
            await asyncio.sleep(self.cfg.public.payout_interval)
            try:
                await self._reconcile_pending_payouts()  # self-healing each tick
            except Exception:
                log.exception("monero payout reconcile failed")
            try:
                await self._do_payouts()
            except MoneroRPCError as exc:
                log.error("monero payout failed: %s", exc)
            except Exception:
                log.exception("monero payout loop iteration failed")
            # Hourly idle-balance sweep to the faucet - mirrors the BTC/LTC pool, which
            # MoneroPool previously omitted (sweep_after_days was silently ignored here).
            try:
                if self.accounting is not None and time.monotonic() - last_sweep >= 3600:
                    last_sweep = time.monotonic()
                    cutoff = int(time.time() - self.cfg.public.sweep_after_days * 86400)
                    swept = self.accounting.sweep_stale(
                        cutoff, self.cfg.public.faucet_address, time.time())
                    if swept:
                        log.info("monero: swept %d base units of idle balances to the faucet", swept)
                    pruned = self.accounting.prune_shares(
                        int(time.time() - SHARES_RETENTION_SECONDS), self.cfg.public.pplns_window)
                    if pruned:
                        log.info("monero: pruned %d shares older than %d days", pruned,
                                 SHARES_RETENTION_SECONDS // 86400)
            except Exception:
                log.exception("monero idle-balance sweep failed")

    async def _do_payouts(self) -> None:
        if self.wallet is None:
            return
        min_internal = int(self.cfg.public.min_payout * COIN)
        # Exclude miners with an unresolved in-flight payout (don't double-pay).
        in_flight = self.accounting.pending_payout_miner_ids()
        payable = [p for p in self.accounting.payable(min_internal)
                   if p["miner_id"] not in in_flight]
        if not payable:
            return
        # Budget against the wallet's *unlocked* (spendable) balance, in internal
        # units, so an immature/locked balance can't make us attempt to overspend.
        bal = await self.wallet.get_balance()
        unlocked_pico = int(bal.get("unlocked_balance", 0))
        # Hold back a fee reserve (mirrors the BTC PAYOUT_FEE_RESERVE) so a batch sized to
        # the full unlocked balance doesn't fail for the network fee and re-queue forever.
        budget = max(0, unlocked_pico - FEE_RESERVE_PICO) // MONERO.unit_scale
        chosen: list[dict] = []
        total = 0
        for it in payable:
            if len(chosen) >= MAX_RECIPIENTS:
                break
            if it["owed"] <= 0:
                continue  # never emit a zero-amount destination
            if total + it["owed"] > budget:
                continue  # not enough spendable yet; this one waits a later round
            chosen.append(it)
            total += it["owed"]
        if not chosen:
            log.info("monero payouts: %d owed but only %.8f spendable - waiting on maturity",
                     len(payable), unlocked_pico / MONERO.atomic)
            return
        dests = [{"amount": it["owed"] * MONERO.unit_scale, "address": it["address"]}
                 for it in chosen]
        # Snapshot the wallet's outgoing txids first so that, if transfer_split's
        # reply times out after the wallet already broadcast, we can tell a real
        # send from a no-op and avoid debiting (then re-sending) a paid batch.
        # _outgoing_txids returns None when the wallet was unreachable, so we never
        # mistake "couldn't check" for "nothing broadcast".
        before = await self._outgoing_txids()
        pay_items = [{"miner_id": it["miner_id"], "amount": it["owed"]} for it in chosen]
        # Persist the intent + the pre-send txid snapshot BEFORE broadcasting, so a crash
        # after broadcast but before the debit is reconcilable on restart (the wallet has
        # no queryable comment like Bitcoin's sendmany, so we diff outgoing txids instead).
        self._payout_seq += 1
        comment = f"monero-payout-{int(time.time())}-{self._payout_seq}"
        self.accounting.begin_payout(
            comment, {"items": pay_items, "before": sorted(before) if before is not None else None},
            time.time())
        try:
            # transfer_split lets the wallet break a large batch into several txs.
            res = await self.wallet.transfer_split(dests)
            txids = res.get("tx_hash_list") or ([res["tx_hash"]] if res.get("tx_hash") else [])
            if len(txids) > 1:
                # MAX_RECIPIENTS keeps a batch within a SINGLE tx, so transfer_split should
                # never actually split today. If it ever does, a partial-broadcast failure
                # could not be attributed per-destination (the all-or-nothing debit assumes
                # one tx), so alarm loudly for the operator to verify every destination paid.
                log.error("monero payout produced %d txs (expected 1); per-destination "
                          "partial-broadcast attribution is not implemented - verify all "
                          "%d recipients were paid before trusting the books", len(txids), len(pay_items))
            if not txids:
                # 200 OK but no txid in the reply (shouldn't happen): only debit if
                # the wallet actually shows a new outgoing tx, else wait a round.
                txids = self._new_txids(before, await self._outgoing_txids())
                if not txids:
                    log.warning("monero transfer_split returned no txid; not debiting this round")
                    self.accounting.clear_payout(comment)
                    return
        except MoneroRPCError as exc:
            after = await self._outgoing_txids()
            if before is None or after is None:
                # We genuinely cannot tell whether the batch broadcast. Don't debit
                # (and don't pretend it failed) - make it loud for the operator. The
                # intent stays pending so startup reconcile can resolve it later.
                log.error("monero payout UNVERIFIED (wallet unreachable: %s); NOT debiting - the "
                          "batch may or may not have broadcast, reconcile before the next round", exc)
                return
            txids = self._new_txids(before, after)
            if not txids:
                log.warning("monero payout failed and did not broadcast (%s); retrying next round", exc)
                self.accounting.clear_payout(comment)
                return
            log.info("recovered monero payout after error: %s", ",".join(txids)[:32])
        txid = ",".join(txids)
        self.accounting.set_payout_txid(comment, txid)  # proof of broadcast for reconcile
        self.accounting.record_payouts(pay_items, txid, time.time(), comment=comment)
        log.info("monero payout: %d miners, total %.8f, tx %s",
                 len(chosen), total / COIN, (txid or "?")[:16])

    async def _reconcile_pending_payouts(self) -> None:
        """Resolve a Monero payout sent but not confirmed-debited before a crash. Runs at
        startup AND every payout tick. Prefers the persisted txid (proof of broadcast);
        falls back to diffing the wallet's outgoing txids against the pre-send snapshot.
        Errs toward never losing funds - never debits on an UNVERIFIABLE snapshot."""
        if self.accounting is None or self.wallet is None:
            return
        pend = self.accounting.pending_payouts()
        if not pend:
            return
        after = None
        for p in pend:
            comment, intent, txid = p["comment"], p["items"], p.get("txid")
            items = (intent or {}).get("items") or []
            if txid:
                # transfer_split returned a txid => it broadcast. Debit exactly once.
                self.accounting.record_payouts(items, txid, time.time(), comment=comment)
                log.warning("reconciled monero broadcast payout %s (debited now)", comment)
                continue
            # No txid: crashed before transfer_split returned. Fall back to the snapshot
            # diff. CRITICAL: distinguish a persisted before=null (snapshot was UNAVAILABLE
            # at send time -> we cannot tell if it broadcast) from before=[] (a real empty
            # snapshot). Coercing null->set() would diff against the WHOLE current out-set
            # and wrongly debit the batch against an unrelated, pre-existing txid.
            before_raw = (intent or {}).get("before")
            if before_raw is None:
                log.error("monero pending payout %s has no txid and an UNVERIFIABLE pre-send "
                          "snapshot - left pending (won't re-pay its miners until you verify "
                          "the wallet and clear it).", comment)
                continue
            if after is None:
                after = await self._outgoing_txids()
            if after is None:
                log.warning("can't reconcile monero pending payout %s yet (wallet unreachable); "
                            "left pending", comment)
                continue
            new = after - set(before_raw)
            if new:
                self.accounting.record_payouts(items, ",".join(sorted(new)), time.time(), comment=comment)
                log.warning("reconciled monero payout broadcast before restart: %s (debited now)", comment)
            else:
                self.accounting.clear_payout(comment)
                log.info("monero pending payout %s never broadcast; dropped (will retry)", comment)

    @staticmethod
    def _new_txids(before, after) -> list:
        """Txids in ``after`` but not ``before``; empty if either snapshot is missing."""
        if before is None or after is None:
            return []
        return list(after - before)

    async def _outgoing_txids(self):
        """Set of the wallet's out + pending txids, or None if it was unreachable
        (so callers can distinguish 'no new tx' from 'could not check')."""
        try:
            r = await self.wallet.get_transfers(out=True, pending=True)
        except MoneroRPCError:
            return None
        ids = set()
        for cat in ("out", "pending"):
            for t in (r.get(cat) or []):
                if t.get("txid"):
                    ids.add(t["txid"])
        return ids

    # -- lifecycle ------------------------------------------------------------

    async def run(self) -> None:
        self._running = True
        # A transient/unreachable monerod at startup must not permanently down this coin
        # (the hub's other coins keep running); retry with backoff until it answers. The
        # mainnet guard below still aborts fail-closed - only RPC errors are retried.
        info = await await_node_ready(
            self.rpc.get_info, lambda: self._running,
            retry_on=MoneroRPCError, label="monero node", logger=log)
        if info is None:  # stop() was called before monerod ever answered
            self._running = False
            return
        nettype = info.get("nettype") or (
            "stagenet" if info.get("stagenet") else "testnet" if info.get("testnet") else "mainnet")
        log.info("connected to monerod: height=%s nettype=%s", info.get("height"), nettype)
        # Fail closed: trust-based shares must never touch mainnet, no matter what the
        # config says - the node itself is the source of truth here.
        if nettype == "mainnet":
            raise RuntimeError(
                "monerod reports nettype=mainnet - TestnetPool's monero engine is "
                "trust-based (no RandomX verification) and must never run on mainnet; aborting")
        if nettype != self.network.node_chain:
            # Fail closed (positive whitelist): nettype must match the configured chain.
            # mainnet is already rejected above; an unexpected/unknown value or a
            # testnet<->stagenet swap would otherwise mine to / submit on the wrong chain.
            raise RuntimeError(
                f"config monero/{self.cfg.chain} expects nettype={self.network.node_chain!r} "
                f"but monerod reports {nettype!r}; refusing to mine on the wrong network")
        # The first template fetch is on the startup path (before the resilient poll
        # loop); a transient node failure here must retry, not down the coin for good.
        await await_node_ready(self._refresh_template, lambda: self._running,
                               retry_on=MoneroRPCError, label="monero template", logger=log)
        if not self._running:  # asked to stop while waiting for the first template
            return
        await self.stratum.start()
        if self.stats_server is not None:
            await self.stats_server.start()
        log.info("mode=%s | mining monero to %s (%s)",
                 self.cfg.mode, self.cfg.coinbase_address, self.cfg.chain)
        # Block-detection posture, matching the Bitcoin/Litecoin line for a uniform hub log.
        # Monero has no ZMQ/longpoll path here - monerod is polled (separate node, not
        # faucet-shared), floored at POLL_INTERVAL_FLOOR since blocks are ~2 min apart.
        log.info("monero/%s: block detection = interval poll every %.0fs (RandomX, trust-based)",
                 self.cfg.chain, max(POLL_INTERVAL_FLOOR, self.cfg.block_poll_interval))
        # coinbase_tag is a Bitcoin/Litecoin scriptSig feature; Monero's coinbase
        # (miner_tx) is built by monerod, so a custom tag here has no effect. Warn
        # rather than silently ignoring what the operator configured.
        if self.cfg.coinbase_tag != Config.coinbase_tag:
            log.warning("coinbase_tag=%r has no effect on Monero - monerod builds the "
                        "coinbase; only coinbase_address applies", self.cfg.coinbase_tag)
        bg = []
        if self.cfg.vardiff.enabled:
            bg.append(asyncio.create_task(self._vardiff_loop()))
        if self.accounting is not None:
            await self._reconcile_pending_payouts()  # before the payout loop can re-send
            bg.append(asyncio.create_task(self._maturity_loop()))
            bg.append(asyncio.create_task(self._payout_loop()))
        try:
            await self._poll_loop()
        finally:
            self._running = False
            for t in bg:
                t.cancel()
            # Await cancelled loops before closing the DB so none resumes on a dead conn.
            if bg:
                await asyncio.gather(*bg, return_exceptions=True)
            await self.stratum.stop()
            if self.stats_server is not None:
                await self.stats_server.close()
            if self.accounting is not None:
                self.accounting.close()

    def stop(self) -> None:
        self._running = False
