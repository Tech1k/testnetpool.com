# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Stratum v1 TCP server: connection handling, share validation, vardiff."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import OrderedDict

from . import util
from .address import AddressError, address_to_script
from .template import Job

log = logging.getLogger("testnetpool.stratum")

# mining.submit rejection codes (de-facto Stratum standard).
ERR_OTHER = 20
ERR_STALE = 21  # job not found / stale
ERR_DUPLICATE = 22
ERR_LOW_DIFF = 23
ERR_UNAUTHORIZED = 24
ERR_NOT_SUBSCRIBED = 25

# Human reason names for the public reject-reason tally (API transparency).
REJECT_REASON = {
    ERR_OTHER: "other", ERR_STALE: "stale", ERR_DUPLICATE: "duplicate",
    ERR_LOW_DIFF: "low_diff", ERR_UNAUTHORIZED: "unauthorized",
    ERR_NOT_SUBSCRIBED: "not_subscribed",
}

# Absolute clamp for a miner-requested fixed difficulty (password "d=" or
# mining.suggest_difficulty).  Big enough for any rented rig, bounded so a typo
# can't wedge a connection.
MAX_REQUESTED_DIFF = 1 << 32

# Bits a miner may roll for version-rolling / ASICBoost (BIP320).  SHA256 ASICs
# (and MiningRigRentals rigs) negotiate this via mining.configure; if we don't
# support it but the rig rolls anyway, every share mismatches and is rejected.
ALLOWED_VERSION_MASK = 0x1FFFE000

# Throttle reject logging so a misconfigured high-hashrate rig can't flood the log.
REJECT_LOG_INTERVAL = 10.0  # seconds, per (connection, reason)

# Drop a connection that is almost all bad shares (badly misconfigured rig, or an
# attacker forcing PoW hashing on every submit). Judged only after enough submits.
REJECT_FLOOD_MIN = 50       # minimum submits before judging
REJECT_FLOOD_RATIO = 0.9    # reject fraction at/above which we disconnect

# Slowloris guard: an unauthenticated socket must finish subscribe+authorize within
# this window or it is dropped.  Only applied before authorization - an established
# miner may legitimately stay quiet for minutes (it just receives notifies), so we
# do NOT impose a read timeout once authorized.
HANDSHAKE_TIMEOUT = 60.0  # seconds

# Surface per-IP / total connection-cap refusals (NOT routine scanner bans) at a visible
# level, throttled per IP, so an operator can SEE when a rental proxy that funnels every
# rig through one IP (e.g. MiningRigRentals) is hitting max_conns_per_ip.
CAP_REFUSE_LOG_INTERVAL = 60.0  # seconds, per IP

# Cap the per-connection duplicate-share cache so a long-lived job at high
# hashrate can't grow it without bound; clearing it loses dup detection until
# the cache refills, which only re-accepts an exact replay (harmless).
MAX_SEEN_SHARES = 100_000


class BanManager:
    """Per-IP abuse control for a pool's Stratum listener: optional connection caps
    (per-IP and global) plus a temp-ban for IPs that keep getting dropped for reject
    floods. Now is passed in (testable); bans expire on their own. Shared by the
    Bitcoin/Litecoin and Monero listeners (same policy on every coin)."""

    def __init__(self, max_per_ip: int = 0, max_total: int = 0,
                 ban_threshold: int = 3, ban_seconds: float = 900.0,
                 strike_window: float = 600.0):
        self.max_per_ip = max_per_ip          # 0 = unlimited
        self.max_total = max_total            # 0 = unlimited
        self.ban_threshold = ban_threshold    # reject-flood drops before a ban (0 = off)
        self.ban_seconds = ban_seconds
        self.strike_window = strike_window
        self._conns: dict[str, int] = {}      # active connections per IP
        self._total = 0
        self._strikes: dict[str, list[float]] = {}
        self._banned: dict[str, float] = {}   # ip -> ban-expiry timestamp

    def allow(self, ip: str, now: float) -> tuple[bool, str]:
        """Whether a new connection from ``ip`` is allowed (call before register)."""
        until = self._banned.get(ip)
        if until is not None:
            if now < until:
                return False, "temporarily banned"
            del self._banned[ip]
        if self.max_total and self._total >= self.max_total:
            return False, "pool connection limit reached"
        if self.max_per_ip and self._conns.get(ip, 0) >= self.max_per_ip:
            return False, "too many connections from this IP"
        return True, ""

    def register(self, ip: str) -> None:
        self._conns[ip] = self._conns.get(ip, 0) + 1
        self._total += 1

    def unregister(self, ip: str) -> None:
        n = self._conns.get(ip, 0) - 1
        if n > 0:
            self._conns[ip] = n
        else:
            self._conns.pop(ip, None)
        self._total = max(0, self._total - 1)

    def strike(self, ip: str, now: float) -> bool:
        """Record an abuse strike against ``ip`` (e.g. it was reject-flood-dropped);
        temp-ban it once it passes the threshold within the window. Returns True iff
        it became banned now."""
        if not self.ban_threshold:
            return False
        # Reap fully-aged strike records so IPs that struck a few times but never
        # crossed the threshold don't accumulate forever (strikes are appended in
        # order, so [-1] is the newest). Only when the map has grown, to stay cheap.
        if len(self._strikes) > 1024:
            self._strikes = {k: v for k, v in self._strikes.items()
                             if v and now - v[-1] < self.strike_window}
        recent = [t for t in self._strikes.get(ip, []) if now - t < self.strike_window]
        recent.append(now)
        self._strikes[ip] = recent
        if len(recent) >= self.ban_threshold:
            self._banned[ip] = now + self.ban_seconds
            self._strikes.pop(ip, None)
            return True
        return False

    def is_banned(self, ip: str, now: float) -> bool:
        until = self._banned.get(ip)
        return until is not None and now < until

    def snapshot(self, now: float) -> dict:
        active = sum(1 for t in self._banned.values() if t > now)
        return {"connections": self._total, "banned_ips": active}


def clean_agent(s: object) -> str:
    """Sanitize a self-reported miner user-agent for display: printable + capped.

    It is untrusted (the miner sets it) and gets stored + rendered, so treat it
    like the worker name: keep only printable chars and bound the length.
    """
    if not isinstance(s, str):
        return ""
    return "".join(c for c in s if c.isprintable()).strip()[:48]


# ASCII-digit version groups only (not \d, which also matches unicode digits), each
# capped to 4 chars: real versions are 1-3 digits, and an uncapped run would let a
# miner smuggle a high-entropy value into the published string as a fake "version".
_AGENT_VER_RE = re.compile(r"([0-9]{1,4})(?:\.([0-9]{1,4}))?")


def short_agent(s: object) -> str:
    """Coarsen a miner user-agent to a low-entropy form safe to publish: just the
    product name + major.minor version, dropping the OS / arch / library / compiler
    detail that fingerprints an individual miner.  e.g.

        XMRig/6.26.0 (Linux x86_64) libuv/1.51.0 gcc/13.1   ->   XMRig/6.26
        cgminer/4.11.1                                       ->   cgminer/4.11
        BzMiner/v21.0.0                                      ->   BzMiner/21.0

    The pool still knows the full agent internally (like the connecting IP); it
    just never exposes it on a public page or in the JSON API.  Returns "" for an
    empty/blank agent, or one with no usable product name (callers label "unknown")."""
    s = clean_agent(s)
    if not s:
        return ""
    name, _, ver = s.split()[0].partition("/")  # drop "(Linux x86_64) libuv/… gcc/…"
    # Strip any parenthetical platform/build info so a UA that leads with "(Linux …)"
    # can't publish an OS token as the product name. Bound the remaining name.
    name = name.split("(")[0][:20]
    if not name:
        return ""
    m = _AGENT_VER_RE.match(ver.lstrip("vV")) if ver else None
    if not m:
        return name
    return f"{name}/{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")


def parse_password_difficulty(password: str) -> float | None:
    """Extract a fixed-difficulty request from a Stratum password.

    MiningRigRentals and most rental proxies set the password to e.g. ``d=8192`` (some
    use ``diff=8192``) to pin a worker's share difficulty - the standard way a big rented
    ASIC asks for the high difficulty it needs. Tolerant of surrounding tokens
    (``x;d=8192``). Returns the requested difficulty, or None if absent/invalid.
    """
    if not password:
        return None
    for token in re.split(r"[;,\s]+", password.strip()):
        low = token.lower()
        for prefix in ("d=", "diff="):
            if low.startswith(prefix):
                try:
                    d = float(token[len(prefix):])
                except ValueError:
                    return None
                return d if d > 0 else None
    return None


# A retarget normally waits retarget_time, but once this many shares pile up we
# retarget early so a miner that started far too low ramps up in seconds, not
# after the full window. Steady-state (shares ~ target_time apart) never hits it.
FAST_RETARGET_SHARES = 16
# If a connection produces no share for this many target_times, its difficulty was
# set too high to ever submit; halve it so a quiet miner self-heals downward.
IDLE_RETARGET_FACTOR = 4.0
# A password-pinned worker that produced AT MOST this many shares before going idle is
# pinned too high for its hashrate (a real ASIC at a matching pin produces far more, so it
# never hits this) - relax the pin so vardiff can take over. Keeps the A1/A2 floor for a
# genuinely-mining ASIC while healing an MRR-style "d=8M onto a tiny rig" mis-pin.
RELAX_PIN_GRACE_SHARES = 2


class Vardiff:
    """Per-connection variable difficulty controller (NOMP-style retargeting).

    Self-tuning in both directions and needs no operator configuration: it ramps
    up quickly for a fast miner (share-count retarget) and, via idle_retarget,
    ramps down for one that has gone quiet because its difficulty is too high.
    """

    def __init__(self, cfg, now: float):
        self.cfg = cfg
        # Clamp the opening difficulty into [min, max]: start_difficulty is a separate
        # config field that isn't otherwise bounded against min/max, so an out-of-band
        # value would open every connection off-band until the first retarget. Clamp here
        # (not a load-time raise) so a partial [vardiff] override stays forgiving.
        self.difficulty = min(max(cfg.start_difficulty, cfg.min_difficulty), cfg.max_difficulty)
        self.previous_difficulty = self.difficulty
        self.fixed = False  # pinned by a password "d=" / suggest_difficulty request
        self.fixed_floor = 0.0  # a password "d=" pin acts as a floor a later suggest can't undercut
        self._last_retarget = now
        self._last_share = now  # for idle_retarget; starts at connect time
        self._fixed_shares = 0  # accepted shares since the current pin (for the relax net)
        self._timestamps: list[float] = []

    def _clamp(self, diff: float) -> float:
        return round(max(self.cfg.min_difficulty, min(self.cfg.max_difficulty, diff)), 8)

    def record_share(self, now: float) -> float | None:
        """Record an accepted share; return a new difficulty if it changed."""
        if not self.cfg.enabled:
            return None
        self._last_share = now  # liveness - tracked even when pinned, so the relax safety net
        #                         in idle_retarget can tell a producing pin from a dead one.
        if self.fixed:
            self._fixed_shares += 1
            return None
        self._timestamps.append(now)
        elapsed = now - self._last_retarget
        # Retarget on the time window, or early once enough shares have arrived.
        if elapsed < self.cfg.retarget_time and len(self._timestamps) < FAST_RETARGET_SHARES:
            return None
        if elapsed <= 0:  # coarse/non-monotonic clock: reset, don't divide by zero
            self._last_retarget = now
            self._timestamps = []
            return None

        avg_time = elapsed / len(self._timestamps)
        variance = self.cfg.variance_percent / 100.0
        lo = self.cfg.target_time * (1 - variance)
        hi = self.cfg.target_time * (1 + variance)
        self._last_retarget = now
        self._timestamps = []
        if lo <= avg_time <= hi:
            return None  # within tolerance, leave difficulty alone

        new_diff = self.difficulty * (self.cfg.target_time / avg_time)
        # Bound the per-retarget change so difficulty can't swing wildly.
        new_diff = self._clamp(max(self.difficulty / 4, min(self.difficulty * 4, new_diff)))
        if new_diff == self.difficulty:
            return None
        self.previous_difficulty = self.difficulty
        self.difficulty = new_diff
        return new_diff

    def idle_retarget(self, now: float) -> float | None:
        """Lower difficulty for a connection that has gone quiet (its difficulty is
        too high to produce shares). Called periodically by the pool; returns the
        new difficulty if it changed, else None. This is the down-only safety net
        record_share can't provide, since it only fires when a share arrives."""
        if not self.cfg.enabled:
            return None
        if now - self._last_share < IDLE_RETARGET_FACTOR * self.cfg.target_time:
            return None
        if self.fixed:
            # A pin that IS producing shares (a real ASIC at a matching d=) keeps _fixed_shares
            # climbing - leave it pinned, the A1/A2 floor must hold even across a brief quiet
            # spell. But a pin that produced at most RELAX_PIN_GRACE_SHARES before going idle is
            # pinned far too high for this rig's hashrate (e.g. an MRR proxy pinning d=8M onto a
            # 1.4 MH/s rig - ~4 days per share): drop the pin and re-open vardiff from
            # start_difficulty so it ramps to a level this rig can actually hit.
            if self._fixed_shares > RELAX_PIN_GRACE_SHARES:
                return None
            self.fixed = False
            self.fixed_floor = 0.0
            relaxed = self._clamp(self.cfg.start_difficulty)
            self._last_share = now
            self._last_retarget = now
            self._timestamps = []
            self.previous_difficulty = relaxed
            self.difficulty = relaxed
            return relaxed
        if self.difficulty <= self.cfg.min_difficulty:
            return None
        new_diff = self._clamp(self.difficulty / 2)
        # Reset the clocks so we re-evaluate after another idle window.
        self._last_share = now
        self._last_retarget = now
        self._timestamps = []
        if new_diff == self.difficulty:
            return None
        self.previous_difficulty = self.difficulty
        self.difficulty = new_diff
        return new_diff

    def set_difficulty(self, diff: float) -> None:
        self.previous_difficulty = self.difficulty
        self.difficulty = diff

    def set_fixed(self, diff: float, floor: bool = False) -> None:
        """Pin difficulty (miner-requested); disables vardiff for this worker.

        ``floor=True`` marks this as a password "d=" pin and records it as a FLOOR: a
        rental proxy (e.g. MiningRigRentals) pins the difficulty it wants via the password,
        but a whatsminer behind it ALSO sends its firmware-default mining.suggest_difficulty
        far below that value. Letting the later (lower) suggest win drops the worker far
        under the proxy's intended difficulty - MRR then flags "Low Worker Difficulty" and
        the ASIC won't mine. Treating the password as a floor (ckpool's rule) keeps the
        difficulty where the proxy wants it; a suggest may raise it but never undercut it."""
        upper = min(MAX_REQUESTED_DIFF, self.cfg.max_difficulty)
        if floor:
            self.fixed_floor = max(self.cfg.min_difficulty, min(upper, diff))
        diff = max(self.cfg.min_difficulty, self.fixed_floor, min(upper, diff))
        # Pin previous_difficulty to the NEW value too. The accept threshold is
        # min(difficulty, previous_difficulty), and while fixed=True record_share never
        # retargets - so a stale previous_difficulty would never re-sync, leaving a permanent
        # accept-low/credit-high window (pin d=8192 but submit diff-16 shares). A pin happens
        # at authorize/suggest before any work is in flight, so there is no in-flight share
        # to tolerate here.
        self.previous_difficulty = diff
        self.difficulty = diff
        self.fixed = True
        self._fixed_shares = 0  # restart the produced-since-pin count for the relax safety net


class MinerConnection:
    _counter = 0

    def __init__(self, reader, writer, pool):
        MinerConnection._counter += 1
        self.id = MinerConnection._counter
        self.reader = reader
        self.writer = writer
        self.pool = pool
        peer = writer.get_extra_info("peername")
        self.peer_ip = peer[0] if peer else "?"
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "?"
        self.extranonce1 = pool.next_extranonce1()
        self.subscribed = False
        self.authorized = False
        self.worker = ""
        self.payout_address = ""  # public mode: the miner's validated payout address
        self.address = ""         # username's address part, ALL modes (live grouping key)
        self.worker_name = ""     # the suffix after "." in the username (rig name)
        self.user_agent = ""      # self-reported miner UA from mining.subscribe
        self.best = 0.0           # best (highest-difficulty) share this session
        self.vardiff = Vardiff(pool.cfg.vardiff, time.time())
        self._seen: "OrderedDict[bytes, None]" = OrderedDict()  # sliding-window dedup, keyed on
        #   the 80-byte PoW header (build_header), NOT job_id; NOT reset on job change (see _on_submit)
        self.accepted = 0
        self.rejected = 0
        self._jobs_sent = 0  # mining.notify count, for the disconnect diagnostic
        self._flood_dropped = False  # reject-flood guard fires at most once per connection
        self.last_share = 0.0
        self._write_lock = asyncio.Lock()
        # version-rolling (ASICBoost) negotiated via mining.configure
        self.version_rolling = False
        self.version_mask = 0
        self._reject_log: dict[int, float] = {}  # error code -> last-logged time

    # -- low level send ------------------------------------------------------

    async def _send(self, obj: dict) -> None:
        data = (json.dumps(obj) + "\n").encode()
        if log.isEnabledFor(logging.DEBUG):  # full wire trace at -v debug for diagnosing
            log.debug("send id=%d %s", self.id, data.decode("utf-8", "replace").rstrip())
        async with self._write_lock:
            self.writer.write(data)
            await self.writer.drain()

    async def reply(self, msg_id, result, error=None) -> None:
        await self._send({"id": msg_id, "result": result, "error": error})

    async def notify(self, method: str, params: list) -> None:
        await self._send({"id": None, "method": method, "params": params})

    async def send_difficulty(self) -> None:
        await self.notify("mining.set_difficulty", [self.vardiff.difficulty])

    async def vardiff_idle_check(self, now: float) -> None:
        """Pool-driven periodic check: lower difficulty if this miner has gone
        quiet (its difficulty was too high to submit), and push the new value."""
        was_pinned = self.vardiff.fixed
        new_diff = self.vardiff.idle_retarget(now)
        if new_diff is not None and self.subscribed:
            if was_pinned and not self.vardiff.fixed:
                # The pin produced nothing for a full idle window -> too high for this rig.
                # Surface it loudly so the operator (or the rental's "d=") gets corrected.
                log.warning(
                    "worker %s found NO shares at its pinned difficulty - relaxing to %s so "
                    "vardiff can find a workable level; the pin (rental 'd=' / suggest) is "
                    "likely too high for this rig's hashrate (%s)",
                    self.worker or "?", util.numfmt(new_diff), self.peer)
            else:
                log.info("vardiff idle %s -> %s (%s)",
                         self.worker or "?", util.numfmt(new_diff), self.peer)
            await self.send_difficulty()

    async def send_job(self, job: Job, clean: bool) -> None:
        await self.notify("mining.notify", job.notify_params(clean))
        self._jobs_sent += 1

    async def _send_initial_work(self) -> None:
        """Deliver set_difficulty + the first clean job. The SOLE work-delivery point, called
        by whichever of authorize/subscribe completes LAST: both are required (subscribe assigns
        the extranonce the miner needs; work is withheld until authorize). ckpool-solo parity."""
        await self.send_difficulty()
        job = self.pool.current_job()
        if job is not None:
            await self.send_job(job, clean=True)

    async def reject(self, msg_id, code: int, reason: str, now: float) -> None:
        """Reply with a rejection and log it. Logging is throttled per error code
        so a fast rig submitting many distinct low-diff shares can't flood it."""
        self.rejected += 1
        self.pool.stats.record_reject(REJECT_REASON.get(code, "other"))
        last = self._reject_log.get(code, 0.0)
        if now - last >= REJECT_LOG_INTERVAL:
            self._reject_log[code] = now
            log.info(
                "reject from %s (%s): %s [accepted=%d rejected=%d]",
                self.worker or "?", self.peer, reason, self.accepted, self.rejected,
            )
        await self._send({"id": msg_id, "result": False, "error": [code, reason, None]})
        # Reject-flood guard: a connection that is overwhelmingly bad shares is either
        # broken or abusive (each submit costs a PoW hash). Drop it after a clear signal.
        total = self.accepted + self.rejected
        if (total >= REJECT_FLOOD_MIN and self.rejected >= REJECT_FLOOD_RATIO * total
                and not self._flood_dropped):
            # Strike ONCE per connection. writer.close() doesn't stop handle() from
            # draining lines already buffered from the reader, so without this guard
            # every buffered reject would re-strike and one pipelined connection would
            # self-ban its own IP - defeating the multi-drop ban policy.
            self._flood_dropped = True
            # Don't IP-strike a STALE-dominated reject flood: that's a proxy lagging behind
            # our jobs (e.g. MiningRigRentals replaying old job_ids), not an abuser - a temp
            # ban would lock out even its fresh shares. ckpool never bans for stale/old-job
            # shares. We still drop THIS connection (it reconnects and resyncs to fresh work);
            # we just don't ban the IP. Low-diff / duplicate floods still strike as before.
            banned = self.pool.bans.strike(self.peer_ip, now) if code != ERR_STALE else False
            log.warning("dropping %s (%s): reject flood (%d/%d rejected)%s",
                        self.worker or "?", self.peer, self.rejected, total,
                        "; IP temp-banned" if banned else "")
            self.writer.close()  # EOF on the next readline ends handle()

    # -- request dispatch ----------------------------------------------------

    async def handle(self) -> None:
        log.debug("connection from %s (id=%d)", self.peer, self.id)
        reason = "peer-eof"  # how the connection ended, for the disconnect diagnostic
        try:
            while True:
                try:
                    if self.authorized:
                        line = await self.reader.readline()
                    else:
                        # Drop unauthenticated sockets that stall mid-handshake.
                        line = await asyncio.wait_for(
                            self.reader.readline(), timeout=HANDSHAKE_TIMEOUT)
                except asyncio.TimeoutError:
                    log.debug("handshake timeout from %s (id=%d)", self.peer, self.id)
                    reason = "handshake-timeout"
                    break
                except (ValueError, asyncio.LimitOverrunError):
                    reason = "oversized-line"
                    break  # oversized line with no newline (scanner / junk client)
                if not line:
                    reason = "peer-eof"  # client closed the socket cleanly (FIN)
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Public endpoints get a steady stream of port scanners and
                    # bots sending non-JSON / binary garbage; just drop it.
                    log.debug("non-JSON from %s: %r", self.peer, line[:64])
                    continue
                if isinstance(msg, dict):
                    await self._dispatch(msg)
                if self._flood_dropped:
                    reason = "flood-dropped"
                    break  # flood guard fired; stop draining buffered lines
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            reason = "reset"  # client aborted (RST) or vanished
        except Exception:  # never let one miner take down the server
            reason = "error"
            log.exception("error handling %s", self.peer)
        finally:
            self.pool.unregister(self)
            self.writer.close()
            if self.authorized or self.subscribed:
                # Surface the handshake state reached, so a churning client (e.g. an MRR
                # proxy that authorizes but never subscribes, or subscribes but submits
                # nothing) tells us where it bailed without needing a full debug capture.
                log.info("miner disconnected: %s %s (id=%d) subscribed=%s jobs_sent=%d "
                         "diff=%s accepted=%d rejected=%d reason=%s", self.worker or "?", self.peer,
                         self.id, self.subscribed, self._jobs_sent,
                         util.numfmt(self.vardiff.difficulty), self.accepted, self.rejected, reason)
            else:
                log.debug("connection closed %s (id=%d)", self.peer, self.id)

    async def _dispatch(self, msg: dict) -> None:
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params", []) or []
        if log.isEnabledFor(logging.DEBUG):  # full wire trace at -v debug for diagnosing
            log.debug("recv id=%d %s", self.id, json.dumps(msg))
        if method == "mining.subscribe":
            await self._on_subscribe(msg_id, params)
        elif method == "mining.authorize":
            await self._on_authorize(msg_id, params)
        elif method == "mining.submit":
            await self._on_submit(msg_id, params)
        elif method == "mining.configure":
            await self._on_configure(msg_id, params)
        elif method == "mining.suggest_difficulty":
            await self._on_suggest_difficulty(msg_id, params)
        elif method == "mining.extranonce.subscribe":
            await self.reply(msg_id, True)
        elif method == "mining.multi_version":
            await self.reply(msg_id, True)
        else:
            log.debug("unhandled method %r from %s", method, self.peer)
            if msg_id is not None:
                await self.reply(msg_id, None, [ERR_OTHER, "unknown method", None])

    async def _on_subscribe(self, msg_id, params) -> None:
        # params[0], when present, is the miner's user-agent (e.g. "bitaxe/2.4",
        # "cgminer/4.10"). Keep a sanitized copy for the connected-miners breakdown.
        if params and params[0]:
            self.user_agent = clean_agent(params[0])
        en1_hex = self.extranonce1.hex()
        sub_id = f"{self.id:08x}"
        # ckpool-parity subscribe reply: a single-entry subscription list carrying only
        # mining.notify, then [extranonce1, extranonce2_size]. We used to lead with a
        # second ("mining.set_difficulty", id) tuple; that's legal but a shape no major
        # pool emits, and a strict proxy (e.g. MiningRigRentals) parses this array.
        # set_difficulty is NOT sent here: it (and the first mining.notify) are pushed only
        # after mining.authorize, matching ckpool-solo - see the note at the end of this method.
        result = [
            [["mining.notify", sub_id]],
            en1_hex,
            self.pool.cfg.extranonce2_size,
        ]
        await self.reply(msg_id, result)
        self.subscribed = True
        # Deliberately send NO work here. ckpool-solo (btcsolo - what solo.ckpool.org runs,
        # the reference that works with this exact MiningRigRentals rental) sends the
        # subscribe RESPONSE only, and pushes set_difficulty + the first mining.notify
        # solely AFTER mining.authorize succeeds (parse_authorise). A whatsminer behind the
        # MRR proxy appears to require that ordering - work delivered before authorize is at
        # best ignored and, in practice, the proxy reaps the session without ever mining.
        # The first job is normally sent in _on_authorize. EXCEPTION: a non-conformant client
        # that authorized BEFORE subscribing had its work withheld then (no extranonce yet);
        # now that subscribe has assigned one, deliver it here so the rig isn't left idle.
        if self.authorized:
            await self._send_initial_work()

    async def _on_authorize(self, msg_id, params) -> None:
        # Untrusted input: tolerate a non-list params and a non-string username/password
        # (a JSON number/array would otherwise raise outside the validation path and spam
        # an un-throttled log.exception via the reconnect loop).
        if not isinstance(params, list):
            params = []
        # Cap at source: the full username is stored and emitted verbatim in the live snapshot.
        # asyncio's 64 KiB readline already bounds it, but a tight cap keeps logs/JSON sane.
        self.worker = (params[0][:160] if params and isinstance(params[0], str) else "")
        password = params[1] if len(params) > 1 and isinstance(params[1], str) else ""
        # Worker name + address part are caller-supplied; cap their length (they're
        # stored + grouped). Parsed for every mode (mirrors the Monero login) so the
        # live/worker views work in solo too; the payout-address validation below
        # stays public-only (self.address is just a grouping label, never a payout).
        self.address = self.worker.split(".", 1)[0].strip()[:96]
        self.worker_name = (
            self.worker.split(".", 1)[1].strip()[:64] if "." in self.worker else ""
        )

        # In public mode the username IS the miner's payout address (optionally
        # "address.workername"); validate it for this coin/network before
        # authorizing, so we never mine for an unpayable worker. Reuse the already
        # length-capped self.address (not a fresh uncapped re-parse of self.worker).
        if self.pool.cfg.mode == "public":
            addr = self.address
            try:
                address_to_script(addr, self.pool.network)
            except AddressError as exc:
                await self.reply(msg_id, False, [ERR_UNAUTHORIZED, f"bad payout address: {exc}", None])
                log.info("rejected worker %r from %s: %s", self.worker, self.peer, exc)
                return
            self.payout_address = addr

        self.authorized = True
        await self.reply(msg_id, True)
        log.info("worker authorized: %s (%s)", self.worker, self.peer)

        # Honour a "d=<diff>" fixed-difficulty request in the password (the way
        # MiningRigRentals and rental proxies pin difficulty).
        requested = parse_password_difficulty(password)
        if requested is not None:
            self.vardiff.set_fixed(requested, floor=True)  # password pin = floor (see set_fixed)
            log.info("fixed difficulty %s for %s (password request)",
                     util.numfmt(self.vardiff.difficulty), self.worker or self.peer)

        # Deliver the first job now (set_difficulty + a clean mining.notify), the sole place
        # work flows - matching ckpool-solo's parse_authorise. Only meaningful once subscribed
        # (the extranonce is set); if subscribe has not arrived yet, _on_subscribe delivers it
        # instead when it does (symmetric - whichever of the two completes last sends work).
        if self.subscribed:
            await self._send_initial_work()

    async def _on_configure(self, msg_id, params) -> None:
        requested = params[0] if params and isinstance(params[0], list) else []
        ext = params[1] if len(params) > 1 and isinstance(params[1], dict) else {}
        result: dict = {}
        if "version-rolling" in requested:
            try:
                client_mask = int(ext.get("version-rolling.mask", "ffffffff"), 16)
            except (ValueError, TypeError):
                client_mask = 0xFFFFFFFF
            self.version_mask = client_mask & ALLOWED_VERSION_MASK
            self.version_rolling = self.version_mask != 0
            result["version-rolling"] = self.version_rolling
            result["version-rolling.mask"] = f"{self.version_mask:08x}"
            log.info("version-rolling enabled for %s mask=%08x", self.peer, self.version_mask)
        if "minimum-difficulty" in requested:
            result["minimum-difficulty"] = True
        if "subscribe-extranonce" in requested:
            result["subscribe-extranonce"] = True
        await self.reply(msg_id, result)

    async def _on_suggest_difficulty(self, msg_id, params) -> None:
        try:
            requested = float(params[0]) if params else None
        except (ValueError, TypeError):
            requested = None
        if requested and requested > 0:
            self.vardiff.set_fixed(requested)
            log.info("suggested difficulty -> %s for %s",
                     util.numfmt(self.vardiff.difficulty), self.worker or self.peer)
            if self.subscribed:
                await self.send_difficulty()
        if msg_id is not None:
            await self.reply(msg_id, True)

    async def _on_submit(self, msg_id, params) -> None:
        now = time.time()
        if not self.authorized:
            await self.reject(msg_id, ERR_UNAUTHORIZED, "unauthorized worker", now)
            return
        if not self.subscribed:
            await self.reject(msg_id, ERR_NOT_SUBSCRIBED, "not subscribed", now)
            return
        if not isinstance(params, list) or len(params) < 5:
            await self.reject(msg_id, ERR_OTHER, "malformed submit", now)
            return

        worker, job_id, en2_hex, ntime_hex, nonce_hex = params[:5]
        # A connection authorizes one payout address; a submit must claim that same
        # address (the rig suffix after "." may vary). Stops a proxy that authorized
        # once from crediting shares for a different address to this connection.
        if self.payout_address and str(worker).split(".", 1)[0].strip() != self.payout_address:
            await self.reject(msg_id, ERR_UNAUTHORIZED, "worker address not authorized", now)
            return
        # job_id must be a hashable string for the dict lookup; a JSON array/object would
        # raise TypeError outside the guarded block below. Real job_ids are hex strings.
        job = self.pool.get_job(job_id) if isinstance(job_id, str) else None
        if job is None:
            await self.reject(msg_id, ERR_STALE, "job not found (stale)", now)
            return

        # Validate field shapes.
        try:
            if len(en2_hex) != self.pool.cfg.extranonce2_size * 2:
                raise ValueError("bad extranonce2 size")
            extranonce2 = bytes.fromhex(en2_hex)
            # Mask ntime to the on-wire 32-bit width build_header serializes (as with
            # nonce below), so high-word variants of one solution can't key as distinct
            # dedup entries. Identity for every value the range check below accepts.
            ntime = int(ntime_hex, 16) & 0xFFFFFFFF
            # Canonicalize to the on-wire 32-bit width that build_header serializes
            # (util.pack_u32le masks to 0xFFFFFFFF). Without this, high-word variants of
            # ONE valid solution (0x1f, 0x1_0000001f, ...) build the identical header +
            # PoW yet key as DISTINCT dedup entries, letting a miner re-submit one share
            # many times to inflate its PPLNS weight (payout theft).
            nonce = int(nonce_hex, 16) & 0xFFFFFFFF
        except (ValueError, TypeError) as exc:
            await self.reject(msg_id, ERR_OTHER, str(exc), now)
            return

        # Effective version: fold in rolled version bits from the optional 6th
        # submit param (ASICBoost / version-rolling). Some proxies roll the
        # version and send these bits without a formal mining.configure
        # negotiation, so honour them whenever present, masked to the negotiated
        # range, or the BIP320 default if nothing was negotiated.
        version = job.version
        rolled = params[5] if len(params) >= 6 and params[5] else None
        if rolled:
            mask = self.version_mask or ALLOWED_VERSION_MASK
            try:
                version = (job.version & ~mask) | (int(rolled, 16) & mask)
            except (ValueError, TypeError):
                rolled = None

        # ntime must be within an acceptable window. The consensus floor is the
        # template's mintime (MedianTimePast+1), which the node advertised; using
        # curtime would reject valid shares a miner rolled down into [mintime, curtime).
        ntime_floor = job.mintime or job.curtime
        # Ceiling is anchored to the NODE's template time (curtime), not the pool's local
        # clock: a skewed pool clock could otherwise accept an ntime the node will reject as
        # "time-too-new", or reject one the node would take. +7200 matches Bitcoin's 2h rule.
        if ntime < ntime_floor or ntime > job.curtime + 7200:
            await self.reject(msg_id, ERR_OTHER, "ntime out of range", now)
            return

        # Duplicate detection. Key on the actual PoW identity - the 80-byte header - NOT on the
        # job_id. job_id and the template's curtime are NOT part of the header, so an idle
        # same-tip rebuild mints a fresh job_id over byte-identical work; keying on job_id would
        # let one physical solution be resubmitted under each retained same-tip job and credited
        # as N PPLNS shares (payout theft). The header encodes version/prevhash/merkleroot/ntime/
        # nbits/nonce - everything the PoW depends on - and extranonce1 is fixed per connection
        # (this _seen set is per connection), so two submissions are duplicates iff their headers
        # match. This also subsumes re-encoding bypasses (the parsed nonce/ntime serialize
        # identically) and mirrors the Monero path, which keys on the blockhashing blob. We must
        # NOT clear _seen on a job change: with job retention many same-tip jobs are live at once,
        # and clearing would let a miner re-credit an already-counted share by ping-ponging jobs.
        # The sliding MAX_SEEN_SHARES window bounds memory; the oldest key is evicted only after
        # 100k newer shares. The header is built here (cheap) and reused for the PoW hash below.
        header = job.build_header(self.extranonce1, extranonce2, ntime, nonce, version)
        if header in self._seen:
            await self.reject(msg_id, ERR_DUPLICATE, "duplicate share", now)
            return
        self._seen[header] = None
        if len(self._seen) > MAX_SEEN_SHARES:
            self._seen.popitem(last=False)  # evict OLDEST (sliding window, not a full reset
            #                                  that would forget recent shares -> re-credit)

        # Compute the PoW hash (coin-specific: scrypt for LTC, sha256d for BTC).
        pow_hash = self.pool.coin.pow_hash(header)
        hash_int = util.hash_int_le(pow_hash)
        share_diff = self.pool.coin.hash_to_difficulty(pow_hash)

        # Check against the network target first: a block is always a valid
        # share regardless of the miner's configured difficulty (this can happen
        # on regtest, where the network target is trivially easy).
        is_block = hash_int <= job.network_target

        # Stale gate. We retain jobs across block changes (pool.py) so a slightly-old job still
        # RESOLVES instead of "job not found" - but a non-block share whose job is for a
        # SUPERSEDED tip can never lead to a block on the live chain, so it must earn NO credit.
        # Gate on HEIGHT, not the prevhash string: job.height == current_height for the live tip
        # AND any same-height refresh, while a retained prior-tip job has job.height <
        # current_height. This never false-rejects a current-tip share and - unlike a _best_hash
        # string compare - has no falsy-empty hole during the post-solve refetch window, when
        # pool._best_hash is transiently "" (which would otherwise let dead-tip shares slip into
        # the next block's PPLNS split). Mirrors ckpool's `id < blockchange_id`. A genuine block
        # solve is NEVER dropped (is_block short-circuits) - it flows to handle_block_candidate.
        if not is_block and job.height < self.pool.current_height:
            await self.reject(msg_id, ERR_STALE, "stale share (block changed)", now)
            return

        # A block is always an accepted share; otherwise require meeting the
        # miner's current or just-previous difficulty (tolerating an in-flight
        # change).
        accept_diff = min(self.vardiff.difficulty, self.vardiff.previous_difficulty)
        if not is_block and share_diff + 1e-9 < accept_diff:
            reason = f"low difficulty share ({util.numfmt(share_diff)} < {util.numfmt(accept_diff)})"
            # Diagnostic: surface whether the rig is rolling the version, since a
            # version mismatch produces exactly this (random-looking) low share_diff.
            reason += f" vroll={rolled}" if rolled else " vroll=none"
            await self.reject(msg_id, ERR_LOW_DIFF, reason, now)
            return

        # Credit each share at the difficulty it was actually VALIDATED against, not the
        # live difficulty. They differ during a difficulty change: accept_diff is the lower
        # of (current, previous), so crediting at self.vardiff.difficulty would over-credit a
        # share accepted under the lower threshold (up to the configured ratio - and, with a
        # stale previous_difficulty, permanently). A block is credited at the live difficulty
        # (it cleared the network target, far above any share difficulty).
        credit_diff = self.vardiff.difficulty if is_block else accept_diff

        # Record the accepted share BEFORE handling a block, so a block-finding
        # share is included in its own PPLNS window.
        self.accepted += 1
        self.last_share = now
        self.best = max(self.best, share_diff)  # session best (all modes; solo too)
        self.pool.stats.record_share(credit_diff, now)
        if self.pool.accounting is not None and self.payout_address:
            # A DB hiccup (locked/full) must NOT drop the miner or skip the block
            # submission below - persistence is best-effort relative to the block.
            try:
                self.pool.accounting.record_share(
                    self.payout_address, credit_diff, now,
                    share_diff=share_diff, worker=self.worker_name,
                )
            except Exception:
                log.exception("record_share failed for %s (%s); continuing", self.worker, self.peer)

        if is_block:
            log.info(
                "*** BLOCK CANDIDATE from %s (%s) height=%d hash=%s ***",
                self.worker, self.peer, job.height, util.internal_to_display(pow_hash),
            )
            await self.pool.handle_block_candidate(
                job, self.extranonce1, extranonce2, ntime, nonce, pow_hash, version,
                finder=self.payout_address,
            )

        if self.accepted == 1 or self.accepted % 500 == 0:
            log.info("accepted share #%d from %s (%s) diff=%s",
                     self.accepted, self.worker or "?", self.peer, util.numfmt(self.vardiff.difficulty))
        await self.reply(msg_id, True)

        # Vardiff retarget.
        new_diff = self.vardiff.record_share(now)
        if new_diff is not None:
            log.info("vardiff %s -> %s (%s)", self.worker, util.numfmt(new_diff), self.peer)
            await self.send_difficulty()


class StratumServer:
    def __init__(self, pool):
        self.pool = pool
        self._server: asyncio.AbstractServer | None = None
        self._cap_log_at: dict[str, float] = {}  # ip -> last cap-refusal log time (throttle)

    async def start(self) -> None:
        cfg = self.pool.cfg
        self._server = await asyncio.start_server(
            self._on_client, cfg.stratum_host, cfg.stratum_port
        )
        log.info("stratum listening on %s:%d", cfg.stratum_host, cfg.stratum_port)

    async def _on_client(self, reader, writer) -> None:
        # Nagle OFF: stratum sends several tiny messages per handshake; the coalescing
        # delay can blow a latency-sensitive proxy's tight connection window (see util).
        util.enable_tcp_nodelay(writer)
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        now = time.time()
        ok, reason = self.pool.bans.allow(ip, now)
        if not ok:
            # Routine scanner/abuse bans are noisy -> debug. A connection-CAP refusal is
            # operator-actionable (a rental proxy like MiningRigRentals funnels many rigs
            # through one IP and can exceed max_conns_per_ip), so surface it - throttled.
            if reason == "temporarily banned":
                log.debug("refusing connection from %s: %s", ip, reason)
            elif now - self._cap_log_at.get(ip, 0.0) >= CAP_REFUSE_LOG_INTERVAL:
                # Bound the throttle map: drop entries older than the interval before
                # it can grow unbounded under churned source IPs.
                if len(self._cap_log_at) > 4096:
                    self._cap_log_at = {k: t for k, t in self._cap_log_at.items()
                                        if now - t < CAP_REFUSE_LOG_INTERVAL}
                self._cap_log_at[ip] = now
                log.warning("connection refused from %s: %s (max_conns_per_ip=%d) - raise it for "
                            "a rental/proxy IP that funnels many rigs through one address",
                            ip, reason, getattr(self.pool.cfg, "max_conns_per_ip", 0))
            writer.close()
            return
        self.pool.bans.register(ip)
        try:
            conn = MinerConnection(reader, writer, self.pool)
            self.pool.register(conn)
            await conn.handle()
        finally:
            self.pool.bans.unregister(ip)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
