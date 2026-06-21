# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Share/hashrate accounting and a tiny status HTTP server."""

from __future__ import annotations

import asyncio
import html as _html
import ipaddress
import itertools
import json
import logging
import time
from collections import deque
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import __version__, address, assets, cryptonote, qr, util
from .coin import COINBASE_MATURITY
from .stratum import short_agent

log = logging.getLogger("testnetpool.stats")

# AGPL §13: the running version's corresponding source. A forked deployment should
# repoint this at its own published source (footer + /api/info both use it).
SOURCE_URL = "https://github.com/Tech1k/testnetpool.com"

# Brand strings for page <meta> + social cards. TAGLINE is the short slogan (also
# what you'd put on the OG banner image); META_DESCRIPTION is the fuller sentence
# search engines and link previews show.
# Bland + descriptive, a set with CypherFaucet's "Free testnet coins for developers".
TAGLINE = "Testnet mining pool for developers"
META_DESCRIPTION = ("Testnet mining pool for developers - a transparent, open-source pool "
                    "for Bitcoin, Litecoin, and Monero. Solo or PPLNS, no sign-up.")
# Per-deployment public-URL / share-image, set once from [stats] at server start.
_META = {"site_url": "", "node_dashboard_url": "", "onion": ""}

# Rolling windows (seconds) surfaced on the dashboard / API.
POOL_WINDOWS = (("1m", 60), ("5m", 300), ("1h", 3600), ("1d", 86400))
MINER_WINDOWS = (("5m", 300), ("1h", 3600), ("24h", 86400))


def _limiter_key(ip: str) -> str:
    """Rate-limit key for an IP. IPv6 is collapsed to its /64 so a client holding a /64
    (the smallest routed IPv6 allocation) can't rotate unlimited distinct /128 addresses
    to defeat the per-IP limit. IPv4 is used verbatim."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 6:
        return f"{ipaddress.ip_network(f'{ip}/64', strict=False).network_address}/64"
    return ip


def client_ip(peer_ip: str, xff: str, trust_private: bool = False) -> str:
    """The real client IP for rate limiting. Behind a reverse proxy on LOOPBACK (the
    normal topology) the socket peer is the proxy, so trust the last X-Forwarded-For hop.
    A private (RFC1918/ULA) peer is trusted ONLY when the operator opts in
    (stats.trust_private_proxy) - otherwise a client on a private/overlay bind could spoof
    XFF to evade the per-IP limit. A direct public peer is never trusted (XFF is spoofable)."""
    if xff:
        try:
            a = ipaddress.ip_address(peer_ip)
        except ValueError:
            a = None
        if a is not None and (a.is_loopback or (trust_private and a.is_private)):
            hop = xff.split(",")[-1].strip()
            if hop:
                return hop
    return peer_ip


class HttpRateLimiter:
    """Per-IP sliding-window rate limit for the stats HTTP server - in-memory, no
    dependency. `limit` requests per `window` seconds; limit<=0 disables it."""

    MAX_KEYS = 100_000  # bound the tracked-IP map against a distinct-IP flood

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque] = {}
        self._last_prune = 0.0

    def allow(self, ip: str, now: float) -> bool:
        if self.limit <= 0:
            return True
        if now - self._last_prune > 300:
            self._prune(now)
            self._last_prune = now
        key = _limiter_key(ip)
        dq = self._hits.get(key)
        if dq is None:
            # Evict the oldest-inserted key when at the cap so a flood of distinct IPs
            # (esp. spoofed/rotated) can't grow the map without bound. The 300s prune
            # already reclaims idle keys; this is the hard backstop.
            if len(self._hits) >= self.MAX_KEYS:
                self._hits.pop(next(iter(self._hits)), None)
            dq = self._hits[key] = deque()
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.limit:
            return False
        dq.append(now)
        return True

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        for ip in list(self._hits):
            dq = self._hits[ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._hits[ip]

# A share of difficulty D represents ~D * coin.hashes_per_diff1 hash attempts
# (2^16 for scrypt, 2^32 for sha256d).  The multiplier is taken from the coin.
HASHRATE_WINDOW = 600.0  # seconds
MAX_KEPT_BLOCKS = 200  # in-memory recent-block ring; full history lives in SQLite
# The snapshot drives every dashboard/JSON hit and runs SQLite aggregates + a per-connection
# pass ON the event loop. Browsers poll it (auto-refresh) and CORS is open, so without a cache
# N concurrent viewers => N rebuilds/sec, each stalling share validation. A short TTL collapses
# that to at most one rebuild per window; the dashboard does not need sub-second freshness.
SNAPSHOT_TTL = 2.0  # seconds
# Cap the per-connection array the JSON API serializes (the HTML dashboard never renders it,
# only the connected_miners count + agent histogram). Bounds one rebuild's cost and the
# response size with thousands of rigs; the exact count stays in connected_miners.
MAX_SNAPSHOT_MINERS = 2000
MAX_HTTP_CONNS = 512   # hard concurrent-connection cap for the dashboard/API server


class Stats:
    def __init__(self, pool):
        self.pool = pool
        self.start_time = time.time()
        self.accepted_shares = 0
        self.total_difficulty = 0.0
        self.blocks: deque[dict] = deque(maxlen=MAX_KEPT_BLOCKS)
        self.blocks_found = 0  # lifetime count (the deque is capped for display)
        self.reject_reasons: dict[str, int] = {}  # reason -> count, for transparency
        self._recent: deque[tuple[float, float]] = deque()  # (time, difficulty)
        self._snap_cache: tuple[float, dict] | None = None  # (monotonic_ts, snapshot)

    def record_share(self, difficulty: float, now: float) -> None:
        self.accepted_shares += 1
        self.total_difficulty += difficulty
        self._recent.append((now, difficulty))
        self._trim(now)

    def record_reject(self, reason: str) -> None:
        """Tally a rejected share by reason (low-diff / stale / duplicate / ...), so
        the API can show the pool isn't silently dropping work."""
        self.reject_reasons[reason] = self.reject_reasons.get(reason, 0) + 1

    def record_block(self, height: int, block_hash: str, accepted: bool, reason: str) -> None:
        if accepted:  # a node-rejected candidate isn't a found block
            self.blocks_found += 1
        self.blocks.append(
            {
                "height": height,
                "hash": block_hash,
                "accepted": accepted,
                "reason": reason,
                "time": int(time.time()),
            }
        )

    def _trim(self, now: float) -> None:
        cutoff = now - HASHRATE_WINDOW
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def hashrate(self) -> float:
        now = time.time()
        self._trim(now)
        if not self._recent:
            return 0.0
        window = max(now - self._recent[0][0], 1.0)
        diff_sum = sum(d for _, d in self._recent)
        return diff_sum * self.pool.coin.hashes_per_diff1 / window

    def snapshot(self) -> dict:
        """Cached public snapshot. Callers treat the result as read-only (verified: every
        external consumer only reads it; all snap[...] writes are inside _build_snapshot),
        so returning the shared cached dict within the TTL is safe."""
        mono = time.monotonic()
        cached = self._snap_cache
        if cached is not None and (mono - cached[0]) < SNAPSHOT_TTL:
            return cached[1]
        snap = self._build_snapshot()
        self._snap_cache = (mono, snap)
        return snap

    def _build_snapshot(self) -> dict:
        conns = self.pool.connections
        job = self.pool.current_job()
        hr = self.hashrate()
        net_target = job.network_target if job else None
        # Network difficulty (relative to the coin's diff-1) and, given current
        # pool hashrate, the expected time to find a block: E[hashes] = 2^256 /
        # target, so E[seconds] = (2^256 / target) / hashrate.  Coin-independent.
        net_diff = (self.pool.coin.diff1_target / net_target) if net_target else None
        eta = ((1 << 256) / net_target / hr) if (net_target and hr > 0) else None
        # Network hashrate. Prefer the node's own getnetworkhashps (chainwork over the
        # ACTUAL elapsed time of recent blocks - the value Bitcoin Core / mempool.space
        # report, and the only sane one on testnet, where the 20-min min-difficulty rule
        # makes the instantaneous difficulty a terrible proxy). Fall back to the
        # difficulty-based estimate H = diff * hashes_per_diff1 / block_time for Monero,
        # which has no such RPC and whose per-block retarget makes it the canonical value.
        node_hps = getattr(self.pool, "network_hashps", None)
        if node_hps:
            net_hr = node_hps
        else:
            block_time = getattr(self.pool.coin, "block_time", 0)
            net_hr = (net_diff * self.pool.coin.hashes_per_diff1 / block_time
                      if (net_diff and block_time) else None)
        # NOTE: no peer IP here on purpose - the public API exposes the pool's
        # behaviour, never the miners' network identities. The connection id is
        # enough to distinguish sessions; raw IPs stay in the operator's logs only.
        # Per-connection detail is a JSON-API field only (the HTML dashboard renders the
        # connected_miners count + agent histogram, never this list). Cap it so one rebuild
        # and the response stay bounded with thousands of rigs; connected_miners stays exact.
        miners = [
            {
                "id": c.id,
                "worker": c.worker,
                "difficulty": c.vardiff.difficulty,
                "accepted": c.accepted,
                "rejected": c.rejected,
                "best": getattr(c, "best", 0.0),
                "last_share_ago": round(time.time() - c.last_share, 1) if c.last_share else None,
            }
            for c in itertools.islice(conns, MAX_SNAPSHOT_MINERS)  # conns is a set; cap the slice
        ]
        # Connected-miner breakdown by self-reported software (public-pool style).
        # Self-reported and trivially spoofed, so advisory only.  Coarsened to
        # product + major.minor (short_agent) before it ever leaves the process: the
        # full agent fingerprints a miner (OS/arch/lib/compiler), like its IP, so -
        # like the IP - we keep it internal and never publish it.
        agent_counts: dict[str, int] = {}
        for c in conns:
            ua = short_agent(getattr(c, "user_agent", "")) or "unknown"
            agent_counts[ua] = agent_counts.get(ua, 0) + 1
        snap = {
            "coin": self.pool.cfg.coin,
            "chain": self.pool.cfg.chain,
            "explorer_url": getattr(self.pool.cfg, "explorer_url", ""),
            "explorer_tx_url": getattr(self.pool.cfg, "explorer_tx_url", ""),
            "algo": self.pool.coin.algo,
            "mode": self.pool.cfg.mode,
            "uptime": round(time.time() - self.start_time, 1),
            "connected_miners": len(conns),
            "accepted_shares": self.accepted_shares,
            "pool_hashrate_hs": round(hr, 2),
            "network_difficulty": round(net_diff, 4) if net_diff else None,
            "network_hashrate_hs": round(net_hr, 2) if net_hr else None,
            "est_seconds_per_block": round(eta) if eta else None,
            "blocks_found": self.blocks_found,
            "blocks": list(self.blocks)[-20:],
            "height": self.pool.current_height,
            # Age of the current block template; rises if the node stalls (lets a
            # monitor catch a wedged-but-running pool). None until the first template.
            "template_age_seconds": (round(time.time() - self.pool.last_template_ts, 1)
                                     if getattr(self.pool, "last_template_ts", 0) else None),
            # Transactions in the block we're currently mining (None = coin not parsed
            # for it, e.g. Monero), and the node's mempool depth if we poll it.
            "block_txs": (len(job.tx_data) if (job is not None and hasattr(job, "tx_data"))
                          else None),
            "mempool": getattr(self.pool, "mempool", None),
            "rejected_shares": sum(self.reject_reasons.values()),
            "reject_reasons": dict(self.reject_reasons),
            # Count of IPs currently temp-banned for abuse (never the IPs themselves).
            "banned_ips": (self.pool.bans.snapshot(time.time())["banned_ips"]
                           if getattr(self.pool, "bans", None) else 0),
            # Node/RPC health: peer count, tip age, sync - so the dashboard can tell
            # "node isolated / network stuck" apart from a merely busy node.
            "node_health": getattr(self.pool, "node_health", {}) or {},
            "include_transactions": bool(getattr(self.pool.cfg, "include_transactions", False)),
            # Whether the pool is ACTUALLY building full blocks right now (config OR
            # MWEB-forced, from the live job) - the honest signal for the /template view,
            # since post-MWEB Litecoin includes every tx even when the config flag is off.
            "full_block": bool(getattr(job, "include_transactions", False)),
            "miners": miners,
            "miner_agents": agent_counts,
            # The pool's own faucet (fee + swept-dust destination), so the UI
            # can badge it. It's a public pool address, never a miner's identity.
            "faucet_address": getattr(getattr(self.pool.cfg, "public", None),
                                      "faucet_address", "") or "",
        }

        # Public mode: extra pool stats from the DB (hashrate windows, current
        # round effort, active/known counts, best share).
        acc = self.pool.accounting
        if acc is not None:
            now = int(time.time())
            # Found-block count comes from the DB so it survives restarts (the
            # in-memory counter resets to 0 on each start).
            snap["blocks_found"] = acc.blocks_found()
            mult = self.pool.coin.hashes_per_diff1
            pw = acc.pool_hashrate_windows(now)
            snap["pool_hashrate"] = {lbl: round(pw[w] * mult / w, 2) for lbl, w in POOL_WINDOWS}
            snap["pool_hashrate_hs"] = snap["pool_hashrate"]["5m"]  # back-compat
            rd, rstart = acc.round_share_diff(now)
            snap["current_round"] = {
                "share_diff": round(rd, 4),
                "network_diff": round(net_diff, 4) if net_diff else None,
                "effort_percent": round(rd / net_diff * 100, 2) if net_diff else None,
                "round_start_ts": rstart,
                "round_age_seconds": (now - rstart) if rstart else None,
            }
            counts = acc.active_counts(now)
            snap["active_miners"] = counts["active_miners"]
            snap["known_miners"] = counts["known_miners"]
            snap["best_share"] = acc.pool_best_share()
            snap["block_counts"] = acc.block_counts()
            pub = self.pool.cfg.public
            snap["payout"] = {
                "model": "PPLNS",
                "fee_percent": pub.fee_percent,
                "min_payout": pub.min_payout,
                "pplns_window": pub.pplns_window,
                "maturity_confirmations": getattr(self.pool.coin, "maturity", COINBASE_MATURITY),
                "payout_interval_seconds": pub.payout_interval,
                "sweep_after_days": pub.sweep_after_days,
            }
        else:
            snap["pool_hashrate"] = {lbl: (snap["pool_hashrate_hs"] if w <= 600 else None)
                                     for lbl, w in POOL_WINDOWS}
            snap["current_round"] = None
            snap["active_miners"] = None
            snap["known_miners"] = None
            # Solo keeps no DB, so the best share is the best across live sessions.
            live_best = max((getattr(c, "best", 0.0) for c in conns), default=0.0)
            snap["best_share"] = live_best or None
            snap["block_counts"] = None
            snap["payout"] = {"model": "solo",
                              "maturity_confirmations": getattr(self.pool.coin, "maturity", COINBASE_MATURITY)}
        return snap


# --- formatting / escaping helpers ------------------------


def esc(s) -> str:
    """HTML-escape for text AND double-quoted attributes (quote=True)."""
    return _html.escape("" if s is None else str(s), quote=True)


def _fmt_num(n) -> str:
    """Compact human number for the UI (None -> em-dash placeholder). The number
    formatting itself lives in util.numfmt so logs and dashboard agree exactly and
    neither ever shows scientific notation."""
    return "—" if n is None else util.numfmt(n)


def fmt_coins(base_units, dp: int = 8) -> str:
    """Integer base units (1e8 = 1 coin) -> fixed-dp decimal, integer math only."""
    if base_units is None:
        return "—"
    neg = base_units < 0
    whole, frac = divmod(abs(int(base_units)), 100_000_000)
    s = f"{whole:,}.{frac:08d}"
    if dp == 0:
        s = s.split(".")[0]
    elif dp != 8:
        s = s[: -(8 - dp)]
    return ("-" if neg else "") + s


def fmt_hashrate(hs) -> str:
    if not hs:
        return "0 H/s"
    hs = float(hs)
    for unit in ("H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s", "ZH/s"):
        if hs < 1000:
            return f"{hs:.2f} {unit}"
        hs /= 1000
    return f"{hs:.2f} YH/s"


def fmt_count(n) -> str:
    if n is None:
        return "—"
    return f"{int(n):,}".replace(",", " ")  # narrow no-break space


def ago(ts) -> str:
    if not ts:
        return "—"
    d = int(time.time()) - int(ts)
    if d < 0:
        return "just now"
    for unit, size in (("s", 60), ("m", 60), ("h", 24), ("d", 365)):
        if d < size:
            return f"{d}{unit} ago"
        d //= size
    return f"{d}y ago"


def fmt_duration(seconds) -> str:
    if not seconds:
        return "—"
    seconds = float(seconds)
    for unit, size in (("s", 60), ("m", 60), ("h", 24), ("d", 365)):
        if seconds < size:
            return f"{seconds:.1f}{unit}"
        seconds /= size
    return f"{seconds:.1f}y"


def trunc(s, head: int = 8, tail: int = 4) -> str:
    """Middle-truncate AND escape.  Never re-escape the result."""
    s = "" if s is None else str(s)
    shown = s if len(s) <= head + tail + 1 else f"{s[:head]}…{s[-tail:]}"
    return esc(shown)


def addr_link(addr, base: str = "", faucet: str = "") -> str:
    """Link an address to its full miner page at ``{base}/miner/<addr>``. If it is
    the pool's ``faucet`` address (fee + swept-dust destination), badge it so it is
    not mistaken for a regular miner - it tops payouts/balances by design."""
    a = "" if addr is None else str(addr)
    link = f'<a href="{esc(base)}/miner/{esc(quote(a, safe=""))}">{trunc(a)}</a>'
    if faucet and a == faucet:
        link += (' <span class="pill faucet" '
                 'title="The pool\'s faucet - pool fees + swept dust collect here">faucet</span>')
    return link


def _worker_link(base: str, addr: str, worker: str) -> str:
    """Link a named rig to its per-worker page; the default (unnamed) rig stays
    plain text (there is no name to drill into)."""
    label = worker or "(default)"
    if not worker or worker == "(default)":
        return esc(label)
    return (f'<a href="{esc(base)}/worker/{esc(quote(addr, safe=""))}/'
            f'{esc(quote(worker, safe=""))}">{esc(label)}</a>')


def _live_for_address(pool, addr: str) -> list:
    """Currently-connected sessions for an address, read straight off the live
    connections - no DB, so it works in solo mode too, and it never exposes an IP.
    Keyed on the connection's parsed ``address`` (set in every mode), so it answers
    "is this rig healthy right now". Resets on reconnect by design."""
    now_f = time.time()
    out = []
    for c in pool.connections:
        if getattr(c, "address", "") != addr or not addr:
            continue
        ls = getattr(c, "last_share", 0) or 0
        vd = getattr(c, "vardiff", None)
        out.append({
            "worker": getattr(c, "worker_name", "") or "(default)",
            "difficulty": vd.difficulty if vd else None,
            "accepted": getattr(c, "accepted", 0),
            "rejected": getattr(c, "rejected", 0),
            "best": getattr(c, "best", 0.0),
            # Coarsened (product + major.minor) - never the full fingerprinting agent.
            "user_agent": short_agent(getattr(c, "user_agent", "")),
            "last_share_ago": round(now_f - ls, 1) if ls else None,
        })
    return out


def _solo_detail(pool, addr: str) -> dict | None:
    """A live-only miner detail built from the connections (solo mode keeps no DB).
    None if no rig is currently connected under that address. Money/share-history
    fields are deliberately absent - the renderers treat ``solo`` as marker."""
    live = _live_for_address(pool, addr)
    if not live:
        return None
    best = max((w.get("best") or 0.0 for w in live), default=0.0)
    return {"address": addr, "solo": True, "live": live, "best_share": best or None}


def block_link(height, base: str = "") -> str:
    return f'<a href="{esc(base)}/block/{esc(quote(str(height), safe=""))}">{fmt_count(height)}</a>'


def _parse_height(h: str):
    """Parse a block-height path segment to an int, or None if invalid.

    ``str.isdigit()`` alone is not enough: it is True for non-ASCII digit
    characters (``²``, ``③``) that ``int()`` rejects with ValueError, and a huge
    all-digit string parses fine but overflows SQLite's signed 64-bit bind
    (OverflowError).  Both must fall through to the not-found path, not crash.
    """
    if h.isascii() and h.isdigit():
        n = int(h)
        if 0 <= n < (1 << 63):
            return n
    return None


def luck_cell(pct):
    """(text, css_class) for a luck/effort %.  <=100 = good (green), else amber."""
    if pct is None:
        return "—", "dim"
    return f"{pct:.0f}%", ("luck-good" if pct <= 100 else "luck-bad")


# Liveness thresholds (seconds) for a worker's last share. ONLINE matches the
# active-miner window; testnet/low-hashrate rigs can be quiet for minutes, so the
# IDLE band is generous before a worker is called OFFLINE.
WORKER_ONLINE_S = 600
WORKER_IDLE_S = 1800


def worker_status_pill(last_seen, now) -> str:
    """An online/idle/offline pill from a worker's last-share timestamp."""
    if not last_seen:
        return '<span class="st st-offline">offline</span>'
    age = now - last_seen
    if age < WORKER_ONLINE_S:
        return '<span class="st st-online">online</span>'
    if age < WORKER_IDLE_S:
        return '<span class="st st-idle">idle</span>'
    return '<span class="st st-offline">offline</span>'


STATUS_CLASS = {"immature": "st-immature", "matured": "st-matured",
                "orphaned": "st-orphaned", "stale": "st-stale"}


def status_pill(status, confs=None, maturity=None) -> str:
    cls = STATUS_CLASS.get(status, "st-immature")
    label = status
    # For an immature block, show how close it is to paying out, e.g. "immature 30/100".
    if status == "immature" and confs is not None and maturity:
        label = f"immature {max(0, min(int(maturity), int(confs)))}/{int(maturity)}"
    return f'<span class="st {cls}">{esc(label)}</span>'


def block_status_pill(block, snap) -> str:
    """status_pill for a found block, adding the maturity progress (confs / required) to an
    immature one. confs = current tip height - the block's height (matches the maturity loop)."""
    confs = maturity = None
    if block.get("status") == "immature":
        tip, h = snap.get("height"), block.get("height")
        maturity = snap.get("payout", {}).get("maturity_confirmations", COINBASE_MATURITY)
        if tip is not None and h is not None:
            confs = tip - h
    return status_pill(block.get("status"), confs, maturity)


def coin_ticker(coin, chain) -> str:
    base = {"bitcoin": "BTC", "litecoin": "LTC", "monero": "XMR"}.get(coin, (coin or "?")[:3].upper())
    chain = chain or ""
    if chain.startswith("stage"):   # Monero stagenet -> sXMR (distinct from testnet's tXMR)
        return "s" + base
    if chain.startswith(("test", "signet", "regtest")):
        return "t" + base
    return base


def chain_label(chain) -> str:
    """Human chain name for display: litecoin/bitcoin call testnet "test" and
    mainnet "main" internally; show the full words instead."""
    return {"test": "testnet", "main": "mainnet"}.get(chain, chain or "?")


# Friendly algorithm names for the UI (the cpuminer/xmrig command keeps the raw
# id: "sha256d"/"scrypt"/"rx/0"). sha256d is double-SHA256 - miners call it SHA-256.
ALGO_LABEL = {"sha256d": "SHA-256", "scrypt": "Scrypt", "randomx": "RandomX"}


def algo_label(algo) -> str:
    return ALGO_LABEL.get(algo, algo or "?")


# Built-in block-explorer URL templates per coin+chain ("{hash}" is filled in), so
# block pages link out with zero config. A coin's explorer_url in config overrides
# its default. No entry (e.g. regtest) -> no link.
DEFAULT_EXPLORERS = {
    ("bitcoin", "main"): "https://mempool.space/block/{hash}",
    ("bitcoin", "test"): "https://mempool.space/testnet/block/{hash}",
    ("bitcoin", "testnet4"): "https://mempool.space/testnet4/block/{hash}",
    ("bitcoin", "signet"): "https://mempool.space/signet/block/{hash}",
    ("litecoin", "main"): "https://litecoinspace.org/block/{hash}",
    ("litecoin", "test"): "https://litecoinspace.org/testnet/block/{hash}",
    ("monero", "mainnet"): "https://xmrchain.net/block/{hash}",
    ("monero", "stagenet"): "https://stagenet.xmrchain.net/block/{hash}",
    ("monero", "testnet"): "https://testnet.xmrchain.com/block/{hash}",
}


def explorer_for(coin, chain, configured="") -> str:
    """Block-explorer URL template; a configured explorer_url overrides the built-in
    per-coin/chain default. Empty for chains with no public explorer (regtest)."""
    return configured or DEFAULT_EXPLORERS.get((coin, chain), "")


def _tx_explorer(block_explorer: str) -> str:
    """Best-effort tx-explorer template ('.../tx/{txid}') derived from a block-explorer
    template ('.../block/{hash}'); '' when it can't be derived (then we just show txids)."""
    if block_explorer and "/block/{hash}" in block_explorer:
        return block_explorer.replace("/block/{hash}", "/tx/{txid}")
    return ""


def tx_explorer_for(coin, chain, explorer_url="", explorer_tx_url="") -> str:
    """Resolve the tx-explorer template ('.../tx/{txid}'): an explicit explorer_tx_url wins,
    otherwise derive it from the (configured or built-in) block explorer. '' when none."""
    return explorer_tx_url or _tx_explorer(explorer_for(coin, chain, explorer_url))


def _txid_cell(txid, tx_tpl, head=12, tail=8) -> str:
    """A <td> with the (truncated) txid, linked to the block explorer's tx page when a
    tx-template is available; plain monospace otherwise (regtest / no public explorer)."""
    txid = str(txid or "")
    short = esc(trunc(txid, head, tail)) if txid else "—"
    if txid and tx_tpl:
        url = esc(tx_tpl.replace("{txid}", quote(txid, safe="")))
        return (f'<td class=mono><a href="{url}" target=_blank rel=noopener '
                f'title="view transaction on block explorer">{short}</a></td>')
    return f'<td class=mono>{short}</td>'


# --- dashboard (light + dark, OS-following) ---

# Color tokens per mode.  Light is the default; the OS
# preference switches to dark via prefers-color-scheme, and data-theme on <html>
# forces a choice.  Dim foregrounds clear WCAG AA on their surfaces in BOTH modes
# (guarded by tests/dashboard.py::test_contrast).
_LIGHT = {
    "bg": "#f7f7f7", "card": "#ffffff", "surface": "#f4f5f7", "row-alt": "#f8f8f8",
    "border": "#e5e5e5", "border2": "#cccccc",
    "text": "#1b1d23", "soft": "#44474e", "muted": "#6b6b6b", "faint": "#686c75",
    "accent": "#5271ff", "accent-soft": "#2f49c9", "accent-bg": "#eef1ff", "accent-dim": "#d7ddff",
    "on-accent": "#ffffff", "btn": "#3f57e0", "nav-bg": "rgba(255,255,255,.85)",
    "ok": "#2a8a4a", "warn": "#b5532a", "bad": "#b52a2a", "num": "#1b1d23", "scheme": "light",
}
_DARK = {
    "bg": "#14161b", "card": "#1c1f27", "surface": "#232730", "row-alt": "#1f232b",
    "border": "#2a2e37", "border2": "#3a3f4a",
    "text": "#e6e8ec", "soft": "#c4c8d0", "muted": "#9aa0ab", "faint": "#8b919b",
    "accent": "#6b86ff", "accent-soft": "#9db2ff", "accent-bg": "#1b2236", "accent-dim": "#2e3a5c",
    "on-accent": "#0b1020", "btn": "#6b86ff", "nav-bg": "rgba(20,22,27,.86)",
    "ok": "#4fbf75", "warn": "#e0894f", "bad": "#ef6b6b", "num": "#e6e8ec", "scheme": "dark",
}
_STATIC_VARS = (
    "--font:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
    "--mono:ui-monospace,'SF Mono','JetBrains Mono','DejaVu Sans Mono',Menlo,Consolas,'Liberation Mono',monospace;"
    "--r:10px;--r-sm:7px;--pill:999px;--s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;"
)


def _vars(d: dict) -> str:
    return "".join(f"--{k}:{v};" for k, v in d.items() if k != "scheme") + f"color-scheme:{d['scheme']};"


_ROOT_CSS = (
    ":root{" + _vars(_LIGHT) + _STATIC_VARS + "}"
    '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){' + _vars(_DARK) + "}}"
    ':root[data-theme="dark"]{' + _vars(_DARK) + "}"
)

_CSS = _ROOT_CSS + """
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.5 var(--font);font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:2px}
.ico{display:inline-flex;vertical-align:-2px}
.ico svg{width:15px;height:15px;display:block}
/* trailing "leaves the site" marker - small, dim, lifted toward the cap height */
.ext-ico{display:inline-flex;vertical-align:2px;margin-left:3px;opacity:.55}
.ext-ico svg{width:10px;height:10px;display:block}
a:hover .ext-ico{opacity:.9}

/* nav */
nav{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:var(--s4);
  height:54px;padding:0 var(--s5);background:var(--nav-bg);
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:var(--s2);font-weight:700;color:var(--text);
  letter-spacing:.3px;font-size:15px}
.brand:hover{text-decoration:none}
.brand-mark{display:flex} .brand-mark svg{width:24px;height:24px;display:block}
.nav-links{display:flex;gap:2px;flex-wrap:wrap}
.nav-links a{color:var(--soft);padding:6px 11px;border-radius:var(--r-sm);font-size:13px;font-weight:500}
.nav-links a:hover{color:var(--text);background:var(--surface);text-decoration:none}
.nav-links a.cur{color:var(--accent-soft);background:var(--accent-bg)}  /* current page */
.navfind{display:inline-flex;align-items:center;gap:4px;margin-left:4px}
.navfind input{background:var(--card);border:1px solid var(--border2);color:var(--text);
  border-radius:var(--r-sm);padding:5px 9px;font:13px var(--font);width:148px;min-width:96px}
.navfind input::placeholder{color:var(--faint)}
.navfind input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.navfind button{display:inline-flex;align-items:center;justify-content:center;cursor:pointer;
  background:none;border:1px solid var(--border2);color:var(--muted);border-radius:var(--r-sm);padding:5px 7px}
.navfind button:hover{color:var(--text);border-color:var(--accent)}
.navfind button svg{width:15px;height:15px}
.theme-toggle{background:none;border:1px solid var(--border2);color:var(--muted);
  border-radius:var(--r-sm);padding:5px 7px;cursor:pointer;display:inline-flex;
  align-items:center;line-height:0;font:inherit}
.theme-toggle:hover{color:var(--text);border-color:var(--accent)}
.theme-toggle .ico-sun{display:none}
:root[data-theme="dark"] .theme-toggle .ico-sun{display:inline-flex}
:root[data-theme="dark"] .theme-toggle .ico-moon{display:none}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]) .theme-toggle .ico-sun{display:inline-flex}
  :root:not([data-theme="light"]) .theme-toggle .ico-moon{display:none}
}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:var(--s3);
  color:var(--muted);font-size:12px;font-family:var(--mono)}
.nav-stats{display:inline-flex;align-items:center;gap:var(--s3)}
.nav-stats .ns{display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
.nav-stats .ns .ico{color:var(--accent)} .nav-stats .ns svg{width:13px;height:13px}
.nav-stats .ns b{color:var(--soft);font-weight:600}
.live-status{display:inline-flex;align-items:center;gap:6px}
.live-dot{color:var(--ok);display:inline-flex;animation:pulse 2s ease-in-out infinite}
.live-dot svg{width:9px;height:9px}
.live-dot.stale{color:var(--warn);animation:none}  /* API unreachable */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 14px}

/* page */
.wrap{max-width:1180px;margin:0 auto;padding:var(--s5) var(--s5) var(--s6)}

/* coin context bar */
.coinbar{display:flex;align-items:center;flex-wrap:wrap;gap:var(--s2) var(--s3);margin-bottom:var(--s5)}
.coin-badge{display:inline-flex;align-items:center;gap:8px;font-weight:600;font-size:16px;color:var(--text)}
.coin-mark{display:inline-flex} .coin-mark svg{width:20px;height:20px;display:block;border-radius:50%}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:var(--pill);
  font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
  background:var(--surface);border:1px solid var(--border2);color:var(--soft)}
.pill.accent{background:var(--accent-bg);border-color:var(--accent-dim);color:var(--accent-soft)}
.pill.faucet{background:rgba(79,191,117,.13);border-color:rgba(79,191,117,.4);color:var(--ok)}

/* hero KPI cards */
.hero{display:grid;gap:var(--s3);grid-template-columns:repeat(auto-fit,minmax(190px,1fr));margin-bottom:var(--s5)}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:var(--s4)}
.kpi .top{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:11px;
  text-transform:uppercase;letter-spacing:.07em}
.kpi .top .ico{color:var(--accent)}
.kpi .val{margin-top:9px;font:600 26px/1.1 var(--mono);color:var(--num);white-space:nowrap}
.kpi .val .u{font-size:13px;color:var(--faint);font-weight:400;margin-left:4px}
.kpi .val.ok{color:var(--ok)} .kpi .val.warn{color:var(--warn)}

/* secondary stat grid */
/* Cells carry their own hairline (box-shadow), and the grid background matches the
   card - so a partial last row leaves no highlighted empty tracks, it just blends. */
.stats{display:grid;gap:0;background:var(--card);border:1px solid var(--border);
  border-radius:var(--r);overflow:hidden;margin-bottom:var(--s5);
  grid-template-columns:repeat(auto-fit,minmax(168px,1fr))}
.stat{background:var(--card);padding:var(--s3) var(--s4);box-shadow:0 0 0 .5px var(--border)}
/* label wraps (icon stays top-aligned) instead of being clipped by the card's
   overflow:hidden when it's wider than the column, e.g. "NETWORK DIFFICULTY". */
.stat .k{display:flex;align-items:flex-start;gap:6px;color:var(--faint);font-size:11px;
  text-transform:uppercase;letter-spacing:.05em;line-height:1.3}
.stat .k .ico{flex:none;margin-top:1px}
.stat .k .ico svg{width:13px;height:13px}
.stat .v{margin-top:5px;font:500 16px/1.2 var(--mono);color:var(--soft);white-space:nowrap}
.stat .v .u{color:var(--faint);font-size:12px;margin-left:3px}
.stat .v a{color:var(--accent-soft);text-decoration:none}
.stat .v a:hover{text-decoration:underline}
.stat .v.good{color:var(--ok)} .stat .v.bad{color:var(--warn)}

/* section heading */
h2{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.09em;margin:40px 0 var(--s3);
  padding-bottom:7px;border-bottom:1px solid var(--border);scroll-margin-top:64px}
h2 .ico{color:var(--accent)}

/* card-wrapped tables */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
  overflow:hidden;margin-bottom:var(--s2)}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{background:var(--surface);color:var(--faint);font-weight:600;text-transform:uppercase;
  font-size:11px;letter-spacing:.04em;text-align:left;padding:9px 14px;white-space:nowrap;
  border-bottom:1px solid var(--border)}
tbody td{padding:10px 14px;border-top:1px solid var(--border);white-space:nowrap;color:var(--soft)}
tbody tr:first-child td{border-top:none}
tbody tr:nth-child(even){background:var(--row-alt)}
tbody tr:hover td{background:var(--surface)}
.rowlink{cursor:pointer}
td.num,th.num{text-align:right;font-family:var(--mono);color:var(--num)}
.mono{font-family:var(--mono)}
td.mono{font-family:var(--mono);color:var(--muted)}
.faucet-addr{margin-top:7px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  background:var(--bg);border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 10px}
.faucet-addr .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--faint);flex:none}
.faucet-addr a{font-family:var(--mono);font-size:13px;color:var(--accent)}
.faucet-addr .copy-btn{margin-left:auto}
td.dim{color:var(--faint)}
.empty{color:var(--faint);text-align:center;padding:var(--s5)}

/* status / luck */
.st{display:inline-block;padding:2px 8px;border-radius:var(--pill);font-size:10.5px;
  font-weight:600;text-transform:uppercase;letter-spacing:.03em}
.st-matured{color:var(--ok);background:rgba(79,191,117,.13)}
.st-immature{color:var(--warn);background:rgba(224,137,79,.13)}
.st-orphaned{color:var(--bad);background:rgba(239,107,107,.13);text-decoration:line-through}
.st-stale{color:var(--faint);background:var(--surface);text-decoration:line-through}
.st-online{color:var(--ok);background:rgba(79,191,117,.13)}
.st-idle{color:var(--warn);background:rgba(224,137,79,.13)}
.st-offline{color:var(--faint);background:var(--surface)}
.luck-good{color:var(--ok)} .luck-bad{color:var(--warn)}

/* lookup */
.lookup{display:flex;gap:var(--s2);flex-wrap:wrap;margin-bottom:var(--s3)}
.lookup input{flex:1;min-width:260px;background:var(--card);color:var(--text);
  border:1px solid var(--border2);border-radius:var(--r-sm);padding:9px 12px;font:13px var(--mono)}
.lookup input::placeholder{color:var(--faint)}
.lookup input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.lookup button{background:var(--btn);color:var(--on-accent);border:none;border-radius:var(--r-sm);
  padding:9px 18px;font:600 13px var(--font);cursor:pointer}
.lookup button:hover{opacity:.9}
/* /find disambiguation list */
.find-cands{list-style:none;display:flex;flex-direction:column;gap:8px;margin:14px 0;max-width:440px}
.find-cands a{display:flex;align-items:center;gap:10px;background:var(--card);
  border:1px solid var(--border);border-radius:var(--r);padding:12px 14px;color:var(--text)}
.find-cands a:hover{border-color:var(--accent);text-decoration:none}
.find-cands .coin-mark svg{width:22px;height:22px}
.find-cands .ch{color:var(--faint);font-size:12px}

/* miner detail */
.detail{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
  padding:var(--s4);margin-bottom:var(--s3)}
.detail .addr{color:var(--accent);font-family:var(--mono);word-break:break-all;
  margin-bottom:var(--s3);font-size:13px}
.kv{display:grid;gap:1px;background:var(--border);border:1px solid var(--border);
  border-radius:var(--r-sm);overflow:hidden;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.kv>div{background:var(--card);padding:var(--s2) var(--s3)}
.kv .k{color:var(--faint);font-size:11px;text-transform:uppercase}
.kv .v{margin-top:3px;font-family:var(--mono);color:var(--soft);font-size:13px}
.detail .card{margin-top:var(--s3);margin-bottom:0}
.notfound{color:var(--warn);margin-bottom:var(--s3)}

/* landing coin cell */
.coin-cell{display:flex;align-items:center;gap:9px}
.coin-cell .coin-mark svg{width:22px;height:22px}
.coin-cell b{color:var(--text)} .coin-cell .ch{color:var(--faint);font-weight:400}

/* footer */
footer{max-width:1180px;margin:var(--s6) auto 0;padding:var(--s4) var(--s5);
  border-top:1px solid var(--border);display:flex;flex-wrap:wrap;align-items:center;
  gap:var(--s2) var(--s4);color:var(--faint);font-size:12px}
footer a{color:var(--muted);display:inline-block;padding:6px 4px;margin:-4px 0}
footer a:hover{color:var(--text)}
footer .grow{margin-left:auto}
.disclaimer{max-width:760px;margin:var(--s2) auto var(--s5);padding:0 var(--s5);
  color:var(--faint);font-size:11px;line-height:1.5;text-align:center}
/* keyboard focus: a visible, theme-matched ring on every header/footer control */
.brand:focus-visible,.nav-links a:focus-visible,.theme-toggle:focus-visible,footer a:focus-visible{
  outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--r-sm)}
/* respect reduced-motion: stop the only looping animation (the live status dot) */
@media (prefers-reduced-motion:reduce){.live-dot{animation:none}.chart-tip{transition:none}}

/* charts (server-rendered inline SVG; instant JS tooltip + native <title> fallback) */
.chart-wrap{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
  padding:var(--s3) var(--s4) var(--s2);margin-bottom:var(--s5)}
.chart-title{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:11px;
  text-transform:uppercase;letter-spacing:.07em;margin-bottom:var(--s2)}
.chart-title .ico{color:var(--accent)} .chart-title .sub{color:var(--faint);margin-left:auto;font-family:var(--mono);text-transform:none;letter-spacing:0}
.chart-tabs{margin-left:auto;display:inline-flex;gap:2px}
.chart-tabs a{color:var(--faint);font-family:var(--mono);text-transform:none;letter-spacing:0;
  font-size:11px;padding:2px 7px;border-radius:var(--r-sm)}
.chart-tabs a:hover{color:var(--text);background:var(--surface);text-decoration:none}
.chart-tabs a.cur{color:var(--accent-soft);background:var(--accent-bg)}
.chart{width:100%;height:140px;display:block}
.chart rect:hover{fill:rgba(107,134,255,.12)}
.chart rect{cursor:crosshair}
.chart-tip{position:fixed;z-index:60;pointer-events:none;left:0;top:0;
  transform:translate(-50%,calc(-100% - 10px));background:var(--card);color:var(--text);
  border:1px solid var(--border2);border-radius:var(--r-sm);padding:5px 9px;
  font:12px/1.2 var(--mono);white-space:nowrap;box-shadow:0 6px 18px rgba(0,0,0,.28);
  opacity:0;transition:opacity .08s ease}
.chart-tip.show{opacity:1}
.chart-tip.below{transform:translate(-50%,12px)}  /* flipped when near the top edge */
.chart-axis{display:flex;justify-content:space-between;color:var(--faint);font-size:11px;
  font-family:var(--mono);margin-top:4px}
.chart-empty{color:var(--faint);text-align:center;padding:var(--s5);font-size:13px}

/* connect / getting-started */
.connect{display:grid;gap:var(--s3);grid-template-columns:repeat(auto-fit,minmax(320px,1fr));margin-bottom:var(--s4)}
.cc{background:var(--card);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.cc-h{display:flex;align-items:center;gap:8px;padding:var(--s3) var(--s4);
  border-bottom:1px solid var(--border);font-weight:600;background:var(--surface)}
.cc-b{padding:var(--s3) var(--s4)}
.cc-row{display:flex;gap:var(--s3);padding:6px 0;font-size:13px;align-items:baseline}
.cc-row .k{color:var(--faint);min-width:84px;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.cc-row .v{font-family:var(--mono);color:var(--soft);word-break:break-all;
  display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.cc-row .v .dim{color:var(--faint)}
.copy-btn.mini{margin:0;padding:1px 8px;font-size:11px}
.cc-dash{display:inline-block;margin-top:var(--s3);font-size:12px;color:var(--accent)}
.cc-dash:hover{text-decoration:underline}
.cc-cli{margin-top:var(--s2)}
.cc-cli summary{cursor:pointer;color:var(--faint);font-size:11px;text-transform:uppercase;
  letter-spacing:.04em;list-style:revert}
.cc-cli summary:hover{color:var(--muted)}
.cc-cfg{display:flex;gap:var(--s2);margin:var(--s2) 0 4px}
.cc-cfg input{flex:1;min-width:0;background:var(--card);color:var(--text);
  border:1px solid var(--border2);border-radius:var(--r-sm);padding:7px 10px;font:13px var(--mono)}
.cc-cfg input::placeholder{color:var(--faint)}
.cc-cfg input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.cc-cli .code{position:relative;padding-right:52px}
.cc-cmdcopy{position:absolute;top:8px;right:8px;margin:0}
.cc-cli .code{margin-top:var(--s2)}
.code{background:var(--bg);border:1px solid var(--border);border-radius:var(--r-sm);padding:10px 12px;
  font-family:var(--mono);font-size:12px;color:var(--accent-soft);white-space:pre-wrap;
  word-break:break-all;line-height:1.6;margin-top:var(--s2)}
.note{color:var(--faint);font-size:12px;line-height:1.6}

/* donate */
.donate-intro{max-width:660px;color:var(--muted);line-height:1.6;margin:0 0 var(--s4);font-size:14px}
.legal{max-width:68ch;color:var(--soft);line-height:1.65;margin:0 0 var(--s3);font-size:14px}
.openalias{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px;background:var(--accent-bg);
  border:1px solid var(--accent-dim);border-radius:var(--r);padding:12px 16px;margin-bottom:var(--s5)}
.openalias .lbl{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.openalias .oa{font-family:var(--mono);font-weight:700;color:var(--accent-soft);font-size:15px}
.openalias .note{margin-left:auto}
.dcards{display:grid;gap:var(--s3);grid-template-columns:repeat(auto-fit,minmax(300px,1fr));margin-bottom:var(--s4)}
.dcard{background:var(--card);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.dcard-h{display:flex;align-items:center;gap:9px;padding:var(--s3) var(--s4);font-weight:600;
  background:var(--surface);border-bottom:1px solid var(--border)}
.dcard-h .coin-mark svg{width:22px;height:22px}
.dcard-b{padding:var(--s3) var(--s4)}
.qr{display:block;width:168px;height:168px;margin:0 auto var(--s3);border-radius:var(--r-sm);
  background:#fff;padding:8px;box-sizing:content-box}
.dcard .addr{font-family:var(--mono);font-size:12px;word-break:break-all;background:var(--bg);
  border:1px solid var(--border);border-radius:var(--r-sm);padding:9px 11px;color:var(--soft)}
.copy-btn{margin-top:10px;cursor:pointer;border:1px solid var(--border2);background:var(--card);
  color:var(--muted);border-radius:var(--r-sm);padding:6px 14px;font:13px var(--font);text-decoration:none}
.copy-btn:hover{color:var(--text);border-color:var(--accent)}
.copy-btn.copied{background:var(--ok);color:#fff;border-color:var(--ok)}
.dcard-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.hashrow{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap}
.btn-link{margin-top:10px;border:1px solid var(--border2);background:var(--card);color:var(--muted);
  border-radius:var(--r-sm);padding:6px 14px;font-size:13px}
.btn-link:hover{color:var(--text);border-color:var(--accent);text-decoration:none}

/* miner / block detail pages */
.back{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:13px;margin-bottom:var(--s3)}
.back:hover{color:var(--text);text-decoration:none}
.big-addr{font-family:var(--mono);color:var(--accent);word-break:break-all;font-size:15px;margin:0 0 var(--s4)}
td a,.cc-row a{color:var(--accent)}

/* responsive */
@media (max-width:760px){
  nav{height:auto;flex-wrap:wrap;gap:8px 12px;padding:10px 14px;position:static}
  .nav-links{order:3;width:100%}
  .nav-stats .ns:not(:first-child){display:none}  /* keep only hashrate; avoid wrap */
  .wrap{padding:var(--s4) var(--s3) var(--s5)}
  .hero{grid-template-columns:repeat(2,1fr)}
  .kpi .val{font-size:22px}
}
@media (max-width:560px){
  .nav-stats{display:none}  /* phones: drop the strip entirely */
  .connect,.dcards{grid-template-columns:1fr}  /* 300-320px min would force page h-scroll */
  .lookup input{min-width:0}  /* let the search field shrink instead of overflowing */
}
@media (max-width:440px){.hero{grid-template-columns:1fr}}
"""


_THEME_TOGGLE = (
    '<button class=theme-toggle id=theme-toggle type=button '
    'title="Toggle light / dark" aria-label="Toggle theme">'
    + assets.icon("sun", "ico ico-sun") + assets.icon("moon", "ico ico-moon")
    + "</button>"
)


def _nav(links_html: str, right_html: str, brand_href: str = ".", stats_html: str = "") -> str:
    """Sticky top nav: brand lockup + section links + (coin-page) live stat strip +
    theme toggle + status."""
    return (
        f'<nav><a class=brand href="{esc(brand_href)}">'
        f'<span class=brand-mark aria-hidden="true">{assets.LOGO_SVG}</span>TestnetPool</a>'
        f'<div class=nav-links>{links_html}</div>'
        f'<div class=nav-right>{stats_html}{_THEME_TOGGLE}{right_html}</div></nav>'
    )


def _nav_stats(snap) -> str:
    """Always-visible compact figures in the nav on coin pages (pool hashrate,
    active miners, tip height), wired to the live-refresh mechanism."""
    hr5 = (snap.get("pool_hashrate") or {}).get("5m") or snap.get("pool_hashrate_hs")
    active = snap.get("active_miners")
    if active is None:
        active = snap.get("connected_miners")
    height = snap.get("height")
    items = [
        ("hashrate", "pool hashrate (5m)", fmt_hashrate(hr5), "pool_hashrate.5m", "hashrate"),
        ("miners", "active miners", str(active) if active is not None else "—", "active_miners", ""),
        ("height", "tip height", str(height) if height is not None else "—", "height", ""),
    ]
    out = "".join(
        f'<span class=ns title="{esc(ttl)}">{assets.icon(ic)}'
        f'<b{_live_attrs(live, fmt)}>{esc(val)}</b></span>'
        for ic, ttl, val, live, fmt in items)
    return f'<span class=nav-stats aria-hidden="true">{out}</span>'


def _live(now_utc: str) -> str:
    # The freshness ticker repaints every second; announcing it would spam screen
    # readers, so the whole status group is decorative (aria-hidden). The actual
    # data lives in the KPI/stat cells, which SR users read on demand.
    return ('<span class=live-status aria-hidden="true">'
            f'<span class=live-dot>{assets.ICONS["live"]}</span>'
            f'<span id=live-updated>updated {esc(now_utc)}</span></span>')


def _live_attrs(live: str, fmt: str) -> str:
    return f' data-live="{esc(live)}" data-fmt="{esc(fmt)}"' if live else ""


def _kpi(icon_name: str, label: str, value: str, cls: str = "", live: str = "", fmt: str = "") -> str:
    return (f'<div class=kpi><div class=top>{assets.icon(icon_name)}{esc(label)}</div>'
            f'<div class="val{(" " + cls) if cls else ""}"{_live_attrs(live, fmt)}>{value}</div></div>')


def _stat(icon_name: str, label: str, value: str, cls: str = "", live: str = "", fmt: str = "") -> str:
    return (f'<div class=stat><div class=k>{assets.icon(icon_name)}{esc(label)}</div>'
            f'<div class="v{(" " + cls) if cls else ""}"{_live_attrs(live, fmt)}>{value}</div></div>')


def _svg_chart(series, *, height: int = 140, fmt=fmt_hashrate) -> str:
    """Inline-SVG area+line chart from ``series`` = [(ts, value), ...] (value already
    in display units).  Per-bucket transparent <rect>s carry a ``data-tip`` that a
    tiny shared handler turns into an instant on-hover tooltip (timestamp + value),
    with a native <title> as the no-JS / screen-reader fallback."""
    series = list(series)
    vals = [max(0.0, float(v)) for _, v in series]
    if not vals or max(vals) <= 0:
        return '<div class=chart-empty>No hashrate data for this window yet.</div>'
    n, W, H = len(vals), 640.0, float(height)
    pad_t, pad_b = 10.0, 4.0
    plot_h = H - pad_t - pad_b
    maxv = max(vals)
    # Multi-day ranges need a date in the labels, not just a wall-clock time.
    span_s = (series[-1][0] - series[0][0]) if n > 1 else 0
    tip_fmt = "%m-%d %H:%M" if span_s > 2 * 86400 else "%H:%M"
    axis_fmt = "%b %d" if span_s > 2 * 86400 else "%H:%M"
    fx = (lambda i: i / (n - 1) * W) if n > 1 else (lambda i: W / 2)
    fy = lambda v: pad_t + (1 - v / maxv) * plot_h
    line = " ".join(f"{fx(i):.1f},{fy(v):.1f}" for i, v in enumerate(vals))
    area = f"0,{pad_t + plot_h:.1f} {line} {W:.1f},{pad_t + plot_h:.1f}"
    bwpx = W / n
    # Each bucket gets a full-height transparent hit-rect.  data-tip drives the
    # instant JS tooltip; the <title> is the no-JS / screen-reader fallback.
    def _tip(ts, v):
        return f"{time.strftime(tip_fmt, time.gmtime(ts))} UTC · {fmt(v)}"
    bands = "".join(
        f'<rect x="{i * bwpx:.1f}" y="0" width="{bwpx:.1f}" height="{H:.0f}" '
        f'fill="transparent" pointer-events="all" data-tip="{esc(_tip(ts, v))}">'
        f'<title>{esc(_tip(ts, v))}</title></rect>'
        for i, (ts, v) in enumerate(series)
    )
    t0 = time.strftime(axis_fmt, time.gmtime(series[0][0]))
    t1 = time.strftime(axis_fmt, time.gmtime(series[-1][0]))
    return (
        f'<svg class="chart" viewBox="0 0 640 {H:.0f}" preserveAspectRatio="none" role="img" '
        f'aria-label="hashrate chart">'
        f'<polygon points="{area}" fill="var(--accent-bg)"/>'
        f'<polyline points="{line}" fill="none" stroke="var(--accent)" stroke-width="2" '
        f'vector-effect="non-scaling-stroke" stroke-linejoin="round"/>{bands}</svg>'
        f'<div class=chart-axis><span>peak {esc(fmt(maxv))}</span>'
        f'<span>{esc(t0)}-{esc(t1)} UTC</span></div>'
    )


# Hashrate-chart time ranges, surfaced as tabs above the chart. (key, span_s, buckets, caption)
CHART_RANGES = [
    ("1h", 3600, 60, "last 1h"),
    ("24h", 86400, 48, "last 24h"),
    ("1w", 604800, 84, "last 7d"),
    ("1m", 2592000, 60, "last 30d"),
]
_CHART_RANGE = {k: (s, b, c) for k, s, b, c in CHART_RANGES}


def _chart_range(path: str) -> str:
    """The ?range= value from a request path, defaulting to 24h."""
    r = (parse_qs(urlsplit(path).query).get("range", [""])[0] or "").strip()
    return r if r in _CHART_RANGE else "24h"


def _chart_tabs(active: str) -> str:
    # Relative ?range= links: the browser keeps the current path, so the same tabs
    # work on the dashboard and on /miner/<addr> with no JS and no base-path logic.
    links = "".join(
        f'<a href="?range={k}"{" class=cur" if k == active else ""}>{k.upper()}</a>'
        for k, *_ in CHART_RANGES)
    return f'<span class=chart-tabs>{links}</span>'


def _chart_block(icon_name, title, sub, svg, tabs="") -> str:
    # The range tabs already say which window is shown, so use them in place of the
    # plain caption when present (the axis still labels the actual date range).
    right = tabs or f'<span class=sub>{esc(sub)}</span>'
    return (f'<div class=chart-wrap><div class=chart-title>{assets.icon(icon_name)}{esc(title)}'
            f'{right}</div>{svg}</div>')


# Tiny vanilla JS (no libraries/CDN): ticks a live clock everywhere, and on pages
# with a data-api re-fetches the stats JSON and repaints [data-live] fields in place.
# It only ever sets textContent (never innerHTML) and reads numbers from parsed JSON,
# so injected data can't execute.  The script body is STATIC - no server interpolation.
_JS = r"""
(function(){
  function fmtHs(h){if(h==null)return'—';h=+h;
    var u=['H/s','KH/s','MH/s','GH/s','TH/s','PH/s','EH/s','ZH/s','YH/s'],i=0;
    if(!h)return'0 H/s';while(h>=1000&&i<u.length-1){h/=1000;i++;}return h.toFixed(2)+' '+u[i];}
  function fmtNum(n){if(n==null)return'—';n=+n;var u=['','K','M','G','T','P','E','Z','Y'],i=0;
    while(Math.abs(n)>=999.5&&i<u.length-1){n/=1000;i++;}
    if(!i)return(n===Math.round(n))?''+n:n.toFixed(2);
    var p=Math.abs(n)>=100?0:(Math.abs(n)>=10?1:2);return n.toFixed(p)+' '+u[i];}
  function dig(o,p){return p.split('.').reduce(function(a,k){return(a==null)?null:a[k];},o);}
  var stale=false;
  function clock(){var u=document.getElementById('live-updated');if(!u)return;
    // The viewer's LOCAL time (toTimeString is local; matches their device clock).
    // Only ticks while data is fresh; a dead API reads 'reconnecting…' instead.
    u.textContent=stale?'reconnecting…':'updated '+new Date().toTimeString().slice(0,8);}
  function setStale(s){if(s===stale)return;stale=s;
    var d=document.querySelector('.live-dot');if(d)d.classList.toggle('stale',s);clock();}
  function paint(d){document.querySelectorAll('[data-live]').forEach(function(el){
    var v=dig(d,el.getAttribute('data-live'));if(v==null)return;var f=el.getAttribute('data-fmt');
    // Tagged fields use fmtHs/fmtNum; untagged ones are small counts/heights shown
    // in full (''+v) — they never reach the magnitudes that print in sci notation.
    el.textContent=(f==='hashrate')?fmtHs(v):(f==='num')?fmtNum(v):''+v;});clock();}
  var tt=document.getElementById('theme-toggle');
  if(tt)tt.addEventListener('click',function(){
    var el=document.documentElement,cur=el.getAttribute('data-theme'),
      sys=window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches,
      next=((cur?cur:(sys?'dark':'light'))==='dark')?'light':'dark';
    el.setAttribute('data-theme',next);
    try{localStorage.setItem('tnp-theme',next);}catch(e){}
  });
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.copy-btn');if(!b)return;
    var v=b.getAttribute('data-copy');if(!v||!navigator.clipboard)return;
    navigator.clipboard.writeText(v).then(function(){
      var o=b.textContent;b.classList.add('copied');b.textContent='Copied';
      setTimeout(function(){b.classList.remove('copied');b.textContent=o;},1200);
    }).catch(function(){});
  });
  // Whole-row navigation for tables whose rows carry data-href (e.g. the hub coin
  // list). The cell link still works for keyboard/screen-reader users; this is a
  // mouse convenience that ignores clicks landing on a real link or button.
  document.addEventListener('click',function(e){
    var r=e.target.closest&&e.target.closest('tr[data-href]');if(!r)return;
    if(e.target.closest('a,button'))return;
    location.href=r.getAttribute('data-href');
  });
  // Connect-page worker configurator: type address (+ rig) -> live username/command.
  var ccs=document.querySelectorAll('.cc');
  for(var ci=0;ci<ccs.length;ci++){(function(card){
    var ph=card.getAttribute('data-ph'),url=card.getAttribute('data-url'),
      a=card.querySelector('.cc-addr'),r=card.querySelector('.cc-rig'),
      u=card.querySelector('.cc-user'),uc=card.querySelector('.cc-ucopy'),
      cm=card.querySelector('.cc-cmd'),cc=card.querySelector('.cc-cmdcopy');
    if(!a)return;
    function upd(){
      // strip whitespace AND dots from the rig: the dot is the address/worker
      // separator, so a dotted rig would silently create a sub-worker.
      var addr=a.value.trim()||ph,rig=(r?r.value:'').replace(/[.\s]+/g,'');
      var user=addr+(rig?'.'+rig:'');
      if(u)u.textContent=user;if(uc)uc.setAttribute('data-copy',user);
      if(cm){var c='xmrig --algo rx/0 --url '+url.replace(/^stratum\+tcp:\/\//,'')+' --user '+user+' --pass x';
        cm.textContent=c;if(cc)cc.setAttribute('data-copy',c);}
    }
    a.addEventListener('input',upd);if(r)r.addEventListener('input',upd);
  })(ccs[ci]);}
  // Chart hover tooltip: one reused, text-only node positioned at the cursor.
  // Reads data-tip off the per-bucket <rect>; textContent only, so the
  // (already-escaped) tip can't execute. The SSR <title> is the no-JS / screen-
  // reader fallback - we remove it once JS runs so the OS tooltip doesn't also
  // pop up ~1s later (double tooltip).
  var ctip;
  function hideTip(){if(ctip)ctip.classList.remove('show');}
  (function(){var ts=document.querySelectorAll('.chart rect>title');
    for(var i=0;i<ts.length;i++)ts[i].parentNode.removeChild(ts[i]);})();
  document.addEventListener('mousemove',function(e){
    var t=e.target,r=(t&&t.closest)?t.closest('.chart rect[data-tip]'):null;
    if(!r){hideTip();return;}
    if(!ctip){ctip=document.createElement('div');ctip.className='chart-tip';
      document.body.appendChild(ctip);}
    ctip.textContent=r.getAttribute('data-tip');
    ctip.classList.add('show');
    // Clamp into the viewport: keep the centered tip on-screen horizontally, and
    // flip it below the cursor when it would clip the top edge. One layout read
    // (offsetWidth/Height) after the write, then position - no read/write churn.
    var w=ctip.offsetWidth,h=ctip.offsetHeight,
      vw=document.documentElement.clientWidth,
      x=Math.max(w/2+2,Math.min(e.clientX,vw-w/2-2));
    ctip.classList.toggle('below',(e.clientY-h-12)<0);
    ctip.style.left=x+'px';ctip.style.top=e.clientY+'px';
  });
  // Hide on every exit path, incl. the cursor leaving the window with no further
  // mousemove (alt-tab / off-screen), which would otherwise leave a tip floating.
  document.addEventListener('mouseleave',hideTip);
  window.addEventListener('blur',hideTip);
  window.addEventListener('scroll',hideTip,true);
  var api=document.body.getAttribute('data-api');
  setInterval(clock,1000);clock();
  if(api){var ctrl;var tick=function(){
    if(ctrl){ctrl.abort();}ctrl=new AbortController();
    var to=setTimeout(function(){ctrl.abort();},10000);  // a hang trips .catch -> stale
    fetch(api+'/stats',{cache:'no-store',signal:ctrl.signal})
    .then(function(r){if(!r.ok)throw 0;return r.json();})
    .then(function(d){setStale(false);paint(d);})
    .catch(function(){setStale(true);})
    .then(function(){clearTimeout(to);});};setInterval(tick,30000);tick();}
})();
"""


def _head(title: str, api_base: str = "") -> str:
    site = _META["site_url"]
    # Index once a public URL is configured (signals "this is the live site"); stay
    # noindex behind a private proxy. Text OG/Twitter cards work either way when shared.
    robots = "index,follow" if site else "noindex"
    meta = (
        f'<meta name=robots content="{robots}">\n'
        f'<meta name=description content="{esc(META_DESCRIPTION)}">\n'
        '<meta name="theme-color" content="#6b86ff">\n'
        f'<meta property="og:title" content="{esc(title)}">\n'
        f'<meta property="og:description" content="{esc(META_DESCRIPTION)}">\n'
        '<meta property="og:type" content="website">\n'
        '<meta property="og:site_name" content="TestnetPool">\n'
        + (f'<meta property="og:url" content="{esc(site)}">\n' if site else "")
        + '<meta name="twitter:card" content="summary">\n'
        f'<meta name="twitter:title" content="{esc(title)}">\n'
        f'<meta name="twitter:description" content="{esc(META_DESCRIPTION)}">\n'
    )
    return (
        "<!doctype html>\n<html lang=en>\n<head>\n<meta charset=utf-8>\n"
        '<meta name=viewport content="width=device-width,initial-scale=1">\n'
        + meta
        + f'<link rel=icon type="image/svg+xml" href="{assets.favicon_data_uri()}">\n'
        + f"<title>{esc(title)}</title>\n<style>{_CSS}</style>\n"
        # Apply a saved theme choice before first paint (no flash). Static script.
        "<script>try{var t=localStorage.getItem('tnp-theme');"
        "if(t==='dark'||t==='light')document.documentElement.setAttribute('data-theme',t);}"
        "catch(e){}</script>\n</head>\n"
        f'<body data-api="{esc(api_base)}">\n'
    )


def _foot() -> str:
    # One clean footer everywhere. The "source" link is what AGPL §13 requires of a
    # public deployment (offer the running version's source); operators who modify
    # should repoint it at their own published fork. The brand shows the configured
    # site_url host so forks/mirrors don't display a false domain, else just "TestnetPool".
    brand = _META["site_url"].split("://", 1)[-1].rstrip("/") or "TestnetPool"
    return (
        "</main>\n<footer>\n"
        f"  <span>{esc(brand)} - testnet mining pool · coins have no real value</span>\n"
        "  <span class=grow></span>\n"
        '  <span><a href="/donate">donate</a> · '
        '<a href="https://cypherfaucet.com" target=_blank rel=noopener>CypherFaucet</a> · '
        + (f'<a href="{esc(_META["onion"])}" rel=noopener title="Tor mirror">.onion</a> · '
           if _META.get("onion") else "")
        + (f'<a href="{esc(_META["node_dashboard_url"])}" target=_blank rel=noopener>node status</a> · '
           if _META.get("node_dashboard_url") else "")
        + '<a href="/legal">legal</a> · '
        + f'<a href="{esc(SOURCE_URL)}" target=_blank rel=noopener>source</a> · '
        'built by <a href="https://tech1k.com" target=_blank rel=noopener>Tech1k</a></span>\n'
        "</footer>\n"
        '<p class=disclaimer>Blocks, shares, and payouts are not guaranteed. This software is open '
        'source under the AGPL, and the hosted service is provided as-is, without warranty. '
        'Run your own node and verify.</p>\n'
        f"<script>{_JS}</script>\n</body>\n</html>"
    )


def _empty(cols, msg):
    return f'<tr><td colspan={cols} class=empty>{esc(msg)}</td></tr>'


def _live_table(live) -> str:
    """The 'connected rigs' table (live sessions). Shared by the coin-page lookup,
    the full miner page, and the solo view. Empty string when nothing is connected.
    Reads only address-derived fields - never an IP."""
    if not live:
        return ""
    lr = "".join(
        f"<tr><td>{esc(w['worker'])}</td>"
        f"<td class=num>{_fmt_num(w['difficulty'])}</td>"
        f"<td class=num>{fmt_count(w['accepted'])}</td>"
        f"<td class=num>{fmt_count(w['rejected'])}</td>"
        f"<td class=num>{_fmt_num(w.get('best'))}</td>"
        f"<td class=dim>{esc(w['user_agent'] or '—')}</td>"
        f"<td class=dim>{(str(round(w['last_share_ago']))+'s ago') if w['last_share_ago'] is not None else '—'}</td>"
        "</tr>"
        for w in live
    )
    return (
        '<div class=card><div class=tablewrap><table>'
        "<thead><tr><th>connected rig</th><th class=num>difficulty</th>"
        "<th class=num>accepted</th><th class=num>rejected</th>"
        "<th class=num>best</th><th>software</th>"
        f"<th>last share</th></tr></thead><tbody>{lr}</tbody>"
        "</table></div></div>"
    )


def _detail_panel(detail, tx_tpl=""):
    solo = bool(detail.get("solo"))
    if solo:  # no per-miner DB in solo: just live sessions + their best share
        kv = [
            ("connected rigs", str(len(detail.get("live") or []))),
            ("best share", _fmt_num(detail.get("best_share"))),
        ]
    else:
        hr = detail.get("hashrate", {})
        kv = [
            ("hashrate 5m", fmt_hashrate(hr.get("5m"))),
            ("hashrate 1h", fmt_hashrate(hr.get("1h"))),
            ("hashrate 24h", fmt_hashrate(hr.get("24h"))),
            ("shares", fmt_count(detail.get("shares"))),
            ("owed", fmt_coins(detail.get("owed"))),
            ("paid", fmt_coins(detail.get("paid"))),
            ("best share", _fmt_num(detail.get("best_share"))),
            ("first seen", ago(detail.get("first_seen"))),
            ("last share", ago(detail.get("last_seen"))),
        ]
    kv_html = "".join(f"<div><div class=k>{k}</div><div class=v>{v}</div></div>" for k, v in kv)

    now = time.time()
    workers = detail.get("workers") or []
    if workers:
        wr = "".join(
            f"<tr><td>{esc(w['worker'])}</td>"
            f"<td>{worker_status_pill(w['last_seen'], now)}</td>"
            f"<td class=num>{fmt_hashrate(w['hashrate'].get('5m'))}</td>"
            f"<td class=num>{fmt_count(w['shares'])}</td>"
            f"<td class=num>{_fmt_num(w.get('best_share'))}</td>"
            f"<td class=dim>{ago(w['last_seen'])}</td></tr>"
            for w in workers
        )
        workers_html = (
            '<div class=card><div class=tablewrap><table>'
            "<thead><tr><th>worker</th><th>status</th><th class=num>hashrate 5m</th>"
            "<th class=num>shares</th><th class=num>best share</th>"
            f"<th>last share</th></tr></thead><tbody>{wr}</tbody>"
            "</table></div></div>"
        )
    else:
        workers_html = ""

    # Currently-connected rigs: live accept/reject + reported software per session.
    live_html = _live_table(detail.get("live") or [])

    pays = detail.get("recent_payouts") or []
    if pays:
        pr = "".join(
            f"<tr><td class=num>{fmt_coins(p['amount'])}</td>"
            f"{_txid_cell(p['txid'], tx_tpl, 12, 8)}<td class=dim>{ago(p['ts'])}</td></tr>"
            for p in pays
        )
        pays_html = (
            '<div class=card><div class=tablewrap><table>'
            "<thead><tr><th class=num>amount</th><th>txid</th>"
            f"<th>when</th></tr></thead><tbody>{pr}</tbody></table></div></div>"
        )
    else:
        pays_html = ""

    return (f'<div class=detail><div class=addr>{esc(detail["address"])}</div>'
            f'<div class=kv>{kv_html}</div>{live_html}{workers_html}{pays_html}</div>')


def _coinbar(coin, ticker, chain, mode, algo) -> str:
    # The "solo" pill matters (miners can't join with their own address); "public"
    # is the norm for this kind of pool, so showing it is just noise - omit it.
    mode_pill = f'<span class="pill accent">{esc(mode)}</span>' if mode != "public" else ""
    return (
        '<div class=coinbar>'
        f'<span class=coin-badge>{assets.coin_mark(coin)}{esc((coin or "?").title())}</span>'
        f'<span class=pill>{esc(ticker)}</span>'
        f'<span class=pill>{esc(chain_label(chain))}</span>'
        f'{mode_pill}'
        + (f'<span class=pill>{esc(algo_label(algo))}</span>' if algo else "")
        + '</div>'
    )


def _site_nav(home_url, active="") -> str:
    """The consistent top-nav link set - identical in structure on every page, so
    the header reads as one stable navbar with no per-page "← back" breadcrumb.

    ``home_url`` is the hub landing in hub mode, or None in single-coin mode (the
    brand logo is the home affordance there, so no separate Coins link). ``active``
    marks the current page's link with aria-current for a clear "you are here".
    """
    def link(href, label, key):
        cur = ' aria-current="page" class=cur' if key == active else ""
        return f'<a href="{esc(href)}"{cur}>{label}</a>'
    out = link(home_url, "Coins", "coins") if home_url else ""
    out += link("/connect", "Connect", "connect") + link("/donate", "Donate", "donate")
    # CypherFaucet - the free testnet faucet the pool fees fund (external site).
    # The trailing arrow-out marks it as a link that leaves the site (opens a new tab).
    out += ('<a href="https://cypherfaucet.com" target=_blank rel=noopener>CypherFaucet'
            + assets.icon("external", "ext-ico") + '</a>')
    # "API" goes to the self-describing index (the always-current endpoint list),
    # not a raw stats blob.
    out += link("/api", "API", "api")
    return out + _NAV_FIND


# Global address search: drop any coin address in and /find routes it to the right
# coin's miner page. Plain GET form (no JS); absolute action works under /, /<slug>,
# and the .onion mirror. Lives in the nav so it's on every page in both modes.
_NAV_FIND = (
    '<form class=navfind method=get action="/find" role=search>'
    '<input name=q type=search inputmode=text spellcheck=false autocomplete=off '
    'maxlength=120 placeholder="search address" aria-label="Search miner address">'
    f'<button type=submit aria-label="Search">{assets.icon("search")}</button>'
    '</form>'
)


def _table(rows, head) -> str:
    return (f'<div class=card><div class=tablewrap><table><thead>{head}</thead>'
            f'<tbody>{rows}</tbody></table></div></div>')


def _payout_panel(snap, ticker, coin_base="") -> str:
    """Plain-language explanation of how the pool pays, with the real configured
    numbers, so a miner knows the model, the fee, and when they get paid."""
    p = snap.get("payout") or {}
    mat = p.get("maturity_confirmations", COINBASE_MATURITY)
    if p.get("model") != "PPLNS":
        return ('<div class=card style="padding:14px 16px"><p class=note>'
                'Solo mode: the full block reward (minus any tx fees) is paid by the '
                f'coinbase straight to the pool wallet. Coinbase outputs are spendable '
                f'after {mat} confirmations.</p></div>')
    # Trim a float for prose (fee/min_payout/sweep) WITHOUT scientific notation:
    # f"{x:g}" would print '1e-05' for a tiny min_payout. format(x,'f') never uses
    # an exponent; strip trailing zeros so 1.0 -> '1', 0.0010 -> '0.001'.
    def g(f):
        f = float(f)
        if f == int(f):
            return f"{int(f):,}"
        return format(f, "f").rstrip("0").rstrip(".")
    interval = fmt_duration(p.get("payout_interval_seconds"))
    lead = (
        "<b>PPLNS.</b> Each block reward is split across the most recent "
        f"{fmt_count(p.get('pplns_window'))} shares, so your payout follows your recent work. "
        f"Rewards are credited after {mat} confirmations; orphaned blocks are not paid. "
        f"The {g(p.get('fee_percent', 0))}% pool fee tops up "
        '<a href="https://cypherfaucet.com" target=_blank rel=noopener>CypherFaucet</a>, '
        "so these testnet coins go straight back out to developers for free. "
        f"Payouts run every {interval} once your balance reaches the minimum; small idle "
        f"balances may be swept back to the faucet after {g(p.get('sweep_after_days', 0))} days. "
        "<span class=note>Round effort is luck: under 100% means the block was found early.</span>"
    )
    grid = (
        _stat("coins", "Pool fee", f'{g(p.get("fee_percent", 0))}% → faucet')
        + _stat("payout", "Min payout", f"{g(p.get('min_payout', 0))} {esc(ticker)}")
        + _stat("blocks", "PPLNS window", f"{fmt_count(p.get('pplns_window'))} shares")
        + _stat("blocks", "Block maturity", f"{mat} confs")
        + _stat("uptime", "Payout run", fmt_duration(p.get("payout_interval_seconds")))
        + _stat("uptime", "Idle sweep", f"{g(p.get('sweep_after_days', 0))} days")
    )
    # Transparency: publish the pool's on-chain fee sink (fee % + swept dust collect here,
    # then refill the public faucet), linked to the block explorer so anyone can verify it.
    faucet = snap.get("faucet_address") or ""
    faucet_block = ""
    if faucet:
        # The faucet address links to its OWN page on the pool, which shows what it has
        # collected (Owed) and withdrawn (Paid) - the fee flow, for EVERY coin. Display is
        # middle-truncated like every other address; copy/link/tooltip keep the full value.
        # (A block explorer can't show a Monero stealth address, so we don't depend on one.)
        miner_url = f'{esc(coin_base)}/miner/{esc(quote(faucet, safe=""))}'
        faucet_block = (
            '<p class=note style="margin:10px 0 0">Fees and swept dust collect here, on-chain:</p>'
            f'<div class=faucet-addr><span class=lbl>Faucet</span>'
            f'<a href="{miner_url}" title="{esc(faucet)} - fees collected + paid">'
            f'{trunc(faucet, 12, 8)}</a>'
            f'<button class="copy-btn mini" type=button data-copy="{esc(faucet)}">copy</button></div>'
        )
    return (f'<div class=card style="padding:14px 16px;margin-bottom:var(--s2)">'
            f'<p class=note style="margin:0">{lead}</p>{faucet_block}</div>'
            f'<section class=stats>{grid}</section>')


def _render_html(snap, detail=None, addr="", luck_blocks=None, miners=None, payouts=None,
                 api_base="/api", home_url=None, coin_base="", chart_html="", leaderboard=None) -> str:
    luck_blocks = luck_blocks or []
    miners = miners or []
    payouts = payouts or []
    leaderboard = leaderboard or []

    coin, chain, mode = snap["coin"], snap["chain"], snap["mode"]
    ticker = coin_ticker(coin, chain)
    algo = snap.get("algo")
    effort = (snap.get("current_round") or {}).get("effort_percent")
    effort_txt, effort_cls = luck_cell(effort)
    kpi_effort_cls = {"luck-good": "ok", "luck-bad": "warn"}.get(effort_cls, "")
    hr5 = (snap.get("pool_hashrate") or {}).get("5m") or snap.get("pool_hashrate_hs")
    now_utc = time.strftime("%H:%M:%S", time.gmtime()) + " UTC"
    height = snap["height"] if snap["height"] is not None else "—"
    active = snap["active_miners"] if snap["active_miners"] is not None else snap["connected_miners"]
    known = snap["known_miners"] if snap["known_miners"] is not None else "—"

    is_public = mode == "public"
    tx_tpl = tx_explorer_for(coin, chain, snap.get("explorer_url", ""), snap.get("explorer_tx_url", ""))
    nav = _nav(_site_nav(home_url), _live(now_utc), brand_href=home_url or "/",
               stats_html=_nav_stats(snap))
    coinbar = _coinbar(coin, ticker, chain, mode, algo)

    hero = (
        _kpi("hashrate", "Pool hashrate", fmt_hashrate(hr5), live="pool_hashrate.5m", fmt="hashrate")
        + _kpi("miners", "Active miners",
               f'<span data-live="active_miners">{active}</span>'
               f'<span class=u title="active now / known addresses">/ {known}</span>')
        + _kpi("blocks", "Blocks found", str(snap["blocks_found"]), live="blocks_found")
        + _kpi("effort", "Round effort", effort_txt, kpi_effort_cls)
    )
    stats = (
        _stat("difficulty", "Network difficulty", _fmt_num(snap["network_difficulty"]),
              live="network_difficulty", fmt="num")
        + _stat("hashrate", "Network hashrate",
                fmt_hashrate(snap["network_hashrate_hs"])
                if snap.get("network_hashrate_hs") is not None else "—",
                live="network_hashrate_hs", fmt="hashrate")
        + _stat("eta", "Est. time/block",
                fmt_duration(snap["est_seconds_per_block"]) if snap.get("est_seconds_per_block")
                else "no hashrate")
        + _stat("height", "Tip height", str(height), live="height")
        + _stat("uptime", "Uptime", fmt_duration(snap["uptime"]))
        + _stat("blocks", "Shares", fmt_count(snap.get("accepted_shares")))
        + _stat("star", "Best share", _fmt_num(snap.get("best_share")))
    )
    # Orphan/stale transparency: shown once the pool has actually solved a block.
    bc = snap.get("block_counts") or {}
    if bc.get("solved"):
        rate = bc.get("orphan_rate")
        stats += _stat("blocks", "Orphan rate",
                       f"{rate}%" if rate is not None else "0%",
                       cls="bad" if (rate or 0) >= 10 else "")
    # Transactions: how many we're including this block, and the mempool we're clearing.
    if snap.get("block_txs") is not None:
        stats += _stat("blocks", "Block txs", fmt_count(snap["block_txs"]))
    mp = snap.get("mempool") or {}
    if mp.get("txs") is not None:
        stats += _stat("blocks", "Mempool", f"{fmt_count(mp['txs'])} waiting")
    # Node health: peers (is the node connected?) + tip age (is the chain moving?).
    nh = snap.get("node_health") or {}
    if nh.get("peers") is not None:
        stats += _stat("peers", "Node peers", str(nh["peers"]),
                       cls="bad" if nh["peers"] == 0 else "")
    if nh.get("tip_age_seconds") is not None:
        ta = nh["tip_age_seconds"]
        stats += _stat("uptime", "Node tip age", fmt_duration(ta),
                       cls="bad" if ta > 7200 else "")
    # Gate on the ACTUAL full-block state, not the config flag: post-MWEB Litecoin includes
    # every tx (mweb forces full blocks) even when include_transactions is left off, and a
    # Monero config flag would otherwise link to an unavailable /template page.
    tx_note = ("<p class=note style=\"margin:-8px 0 16px\">This pool includes "
               "<b>every transaction</b>, no filtering, to keep the testnet moving. "
               f"<a href=\"{esc(coin_base)}/template\">See the next block's transactions &rarr;</a></p>\n"
               if snap.get("full_block") else "")

    found_rows = "".join(
        (lambda b, lt_lc: (
            f"<tr><td class=num>{block_link(b['height'], coin_base)}</td>"
            f"<td class=dim>{ago(b['found_ts'])}</td>"
            f"<td class=num>{fmt_coins(b['reward'])}</td>"
            f"<td>{block_status_pill(b, snap)}</td>"
            f"<td class='num {lt_lc[1]}'>{lt_lc[0]}</td>"
            f"<td class=mono>{trunc(b['hash'], 10, 6)}</td></tr>"))(b, luck_cell(b["luck_percent"]))
        for b in luck_blocks
    ) or _empty(6, "no blocks found yet")

    faucet = snap.get("faucet_address", "")
    payout_rows = "".join(
        f"<tr><td class=mono>{addr_link(p['address'], coin_base, faucet)}</td>"
        f"<td class=num>{fmt_coins(p['amount'])}</td>"
        f"{_txid_cell(p['txid'], tx_tpl, 10, 6)}"
        f"<td class=dim>{ago(p['ts'])}</td></tr>"
        for p in payouts
    ) or _empty(4, "no payouts yet")

    now_ts = time.time()
    miner_rows = "".join(
        f"<tr><td class=mono>{addr_link(m['address'], coin_base, faucet)}</td>"
        f"<td>{worker_status_pill(m['last_seen'], now_ts)}</td>"
        f"<td class=num>{fmt_count(m.get('shares'))}</td>"
        f"<td class=num>{fmt_coins(m['owed'])}</td>"
        f"<td class=num>{fmt_coins(m['paid'])}</td>"
        f"<td class=dim>{ago(m['last_seen'])}</td></tr>"
        for m in miners
    ) or _empty(6, "no miners yet")

    if detail is not None:
        full = f'{esc(coin_base)}/miner/{esc(quote(detail["address"], safe=""))}'
        detail_block = _detail_panel(detail, tx_tpl) + f'<p><a class=back href="{full}">open full miner page →</a></p>'
    elif addr:
        miss = ("no shares recorded for that address yet." if is_public
                else "no rig is connected with that address right now.")
        detail_block = f'<p class=notfound>{miss}</p>'
    else:
        detail_block = ""

    # "Your stats" / the address lookup renders in BOTH modes: public shows
    # hashrate/balance/payouts, solo shows the live connected rigs + best share.
    # Top miners / Recent payouts / the leaderboard stay public-only (DB-backed).
    seek = ("hashrate, balance, and payouts" if is_public else "connected rigs and best share")
    place = ("payout address" if is_public else "address you mine with")
    helper = ("" if addr else
              f'<p class=note style="margin:-4px 0 12px">Already mining? Paste the {place} '
              f'you connected with to see your {seek}.</p>')
    you_section = (
        f"<h2 id=you>{assets.icon('miners')}Your stats</h2>\n{helper}"
        '<form class=lookup method=get action="">\n'
        '  <input name=address spellcheck=false autocomplete=off\n'
        f'         placeholder="{place}, {esc(ticker)} ({esc(chain_label(chain))})" value="{esc(addr)}">\n'
        '  <button type=submit>look up</button>\n</form>\n'
        f"{detail_block}\n"
    )
    miners_payouts = ""
    if is_public:
        lb_rows = "".join(
            f"<tr><td class=num>{i}</td>"
            f"<td class=mono>{addr_link(e['address'], coin_base, faucet)}</td>"
            f"<td class=num>{_fmt_num(e['best_share'])}</td></tr>"
            for i, e in enumerate(leaderboard, 1)
        ) or _empty(3, "no shares yet")
        miners_payouts = (
            f"\n<h2 id=payouts>{assets.icon('payout')}Recent payouts</h2>\n"
            + _table(payout_rows, "<tr><th>address</th><th class=num>amount</th><th>txid</th><th>when</th></tr>")
            + f"\n<h2 id=miners>{assets.icon('trophy')}Top miners</h2>\n"
            + _table(miner_rows, "<tr><th>address</th><th>status</th><th class=num>shares</th>"
                     "<th class=num>owed</th><th class=num>paid</th><th>last share</th></tr>")
            + f"\n<h2 id=best>{assets.icon('star')}Best shares</h2>\n"
            "<p class=note style=\"margin:-4px 0 12px\">Highest-difficulty shares submitted - "
            "how close each miner has come to solving a block.</p>\n"
            + _table(lb_rows, "<tr><th class=num>#</th><th>address</th><th class=num>best share</th></tr>")
        )
    # Connected-by-software breakdown (both modes): a compact, advisory pill row of
    # the miner user-agents currently connected. Self-reported, so it's a hint.
    agents = snap.get("miner_agents") or {}
    software_html = ""
    if sum(agents.values()):
        chips = " ".join(
            f"<span class=pill>{esc(k)} <b>{v}</b></span>"
            for k, v in sorted(agents.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        software_html = (f'<h2 id=software>{assets.icon("software")}Connected by software</h2>\n'
                         f'<div class=chips>{chips}</div>\n')
    body = (
        f"{coinbar}\n"
        f'<section class=hero aria-label="pool overview">{hero}</section>\n'
        f"<section class=stats>{stats}</section>\n"
        f"{tx_note}"
        f"{software_html}"
        f"{chart_html}\n"
        f"<h2 id=howpay>{assets.icon('payout')}How payouts work</h2>\n"
        f"{_payout_panel(snap, ticker, coin_base)}\n"
        f"{you_section}"
        f"<h2 id=blocks>{assets.icon('blocks')}Found blocks</h2>\n"
        + _table(found_rows, "<tr><th>height</th><th>when</th><th class=num>reward</th>"
                 "<th>status</th><th class=num>effort</th><th>hash</th></tr>")
        + miners_payouts
    )
    return (_head(f"TestnetPool - {coin}/{chain}", api_base) + nav
            + '<main class=wrap id=top>\n' + body
            + _foot())


def _landing_row(entry) -> str:
    s, name = entry["snap"], entry["name"]
    lt, lc = luck_cell((s.get("current_round") or {}).get("effort_percent"))
    miners = s["active_miners"] if s["active_miners"] is not None else s["connected_miners"]
    hr = (s.get("pool_hashrate") or {}).get("5m") or s.get("pool_hashrate_hs")
    return (
        f'<tr class=rowlink data-href="/{esc(name)}"><td><a class=coin-cell href="/{esc(name)}">'
        f'{assets.coin_mark(s["coin"])}'
        f'<span><b>{esc((s["coin"] or "?").title())}</b> '
        f'<span class=ch>{esc(chain_label(s["chain"]))}</span></span></a></td>'
        f'<td class=num>{fmt_hashrate(hr)}</td>'
        f'<td class=num>{miners}</td>'
        f'<td class=num>{s["blocks_found"]}</td>'
        f'<td class="num {lc}">{lt}</td>'
        f'<td class=num>{_fmt_num(s["network_difficulty"])}</td>'
        f'<td class=num>{fmt_hashrate(s["network_hashrate_hs"]) if s.get("network_hashrate_hs") is not None else "—"}</td>'
        f'<td class=num>{s["height"] if s["height"] is not None else "—"}</td></tr>'
    )


def _render_landing(entries) -> str:
    """Hub landing page: aggregate KPIs + one row per coin, linking to its dashboard."""
    rows = "".join(_landing_row(e) for e in entries) or _empty(8, "no coins configured")
    now_utc = time.strftime("%H:%M:%S", time.gmtime()) + " UTC"
    n = len(entries)
    total_miners = sum(
        (e["snap"]["active_miners"] if e["snap"]["active_miners"] is not None
         else e["snap"]["connected_miners"]) for e in entries
    )
    total_blocks = sum(e["snap"]["blocks_found"] for e in entries)
    # On the hub landing, "Coins" scrolls to the coin list on this same page.
    nav = _nav(_site_nav("#coins", active="coins"), _live(now_utc), brand_href="/")
    hero = (
        _kpi("coins", "Coins", str(n))
        + _kpi("miners", "Active miners", str(total_miners))
        + _kpi("blocks", "Blocks found", str(total_blocks))
    )
    head = ('<tr><th>coin</th><th class=num>hashrate</th><th class=num>miners</th>'
            '<th class=num>blocks</th><th class=num>effort</th><th class=num>net&nbsp;diff</th>'
            '<th class=num>net&nbsp;hashrate</th><th class=num>height</th></tr>')
    body = (
        f'<div class=coinbar><span class=coin-badge>TestnetPool hub</span>'
        f'<span class="pill accent">{n} coin{"s" if n != 1 else ""}</span></div>\n'
        '<p class=note style="margin:-4px 0 16px">Public testnet mining pool. Pick a coin below '
        'for live stats and payouts, or <a href="/connect">connect a miner</a>.</p>\n'
        f'<section class=hero aria-label="hub overview">{hero}</section>\n'
        f"<h2 id=coins>{assets.icon('coins')}Coins</h2>\n"
        f'<div class=card><div class=tablewrap><table><thead>{head}</thead>'
        f'<tbody>{rows}</tbody></table></div></div>'
    )
    return (_head("TestnetPool - hub") + nav + '<main class=wrap id=top>\n'
            + body + _foot())


def _render_miner_page(snap, address, detail, chart_html, api_base, home_url, coin_base) -> str:
    """A full, bookmarkable per-address page."""
    coin, chain, mode = snap["coin"], snap["chain"], snap["mode"]
    ticker, algo = coin_ticker(coin, chain), snap.get("algo")
    dash = (coin_base + "/") if coin_base else "/"
    nav = _nav(_site_nav(home_url),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"), brand_href=home_url or "/",
               stats_html=_nav_stats(snap))
    coinbar = _coinbar(coin, ticker, chain, mode, algo)
    # In-page back link to the coin's own dashboard (the header navbar's "Coins"
    # only goes to the hub landing in hub mode).
    back_to_dash = f'<a class=back href="{esc(dash)}">← dashboard</a>'
    fbadge = (' <span class="pill faucet" title="The pool\'s faucet - pool fees '
              '+ swept dust collect here">faucet</span>'
              if address and address == snap.get("faucet_address", "") else "")

    if detail is None:
        miss = ("no shares recorded for this address yet." if mode == "public"
                else "no rig is connected with that address right now.")
        body = (f'{coinbar}\n{back_to_dash}\n'
                f'<div class=big-addr>{esc(address)}{fbadge}</div>\n'
                f'<p class=notfound>{miss}</p>')
        return (_head(f"TestnetPool - {address}") + nav + '<main class=wrap id=top>\n'
                + body + _foot())

    # Currently-connected rigs (live sessions) - shown in both modes.
    rigs_html = (f"<h2>{assets.icon('miners')}Connected rigs</h2>\n"
                 + (_live_table(detail.get("live") or [])
                    or '<p class=note>no rig connected with that address right now.</p>\n'))

    if detail.get("solo"):  # live-only view: no balance, no share history
        hero = (_kpi("miners", "Connected rigs", str(len(detail.get("live") or [])))
                + _kpi("star", "Best share", _fmt_num(detail.get("best_share"))))
        body = (
            f'{coinbar}\n{back_to_dash}\n'
            f'<div class=big-addr>{esc(address)}{fbadge}</div>\n'
            '<p class=note style="margin:-8px 0 16px">Solo mode: your currently-connected rigs and '
            'the best share each has hit. There is no per-miner balance - the full block reward is '
            'paid straight to the pool wallet.</p>\n'
            f'<section class=hero aria-label="miner overview">{hero}</section>\n'
            f'{rigs_html}'
        )
        return (_head(f"TestnetPool - {address}") + nav + '<main class=wrap id=top>\n'
                + body + _foot())

    hr = detail.get("hashrate", {})
    # Pending = your share of blocks still maturing (not yet in "owed"). Surfacing it
    # makes incoming earnings visible instead of hidden until each block matures.
    pending = sum(b["amount"] for b in (detail.get("block_credits") or [])
                  if b["status"] == "immature")
    hero = (
        _kpi("hashrate", "Hashrate 5m", fmt_hashrate(hr.get("5m")))
        + _kpi("blocks", "Pending", fmt_coins(pending))
        + _kpi("payout", "Owed", fmt_coins(detail.get("owed")))
        + _kpi("coins", "Paid", fmt_coins(detail.get("paid")))
        + _kpi("star", "Best share", _fmt_num(detail.get("best_share")))
    )
    stats = (
        _stat("hashrate", "Hashrate 1h", fmt_hashrate(hr.get("1h")))
        + _stat("hashrate", "Hashrate 24h", fmt_hashrate(hr.get("24h")))
        + _stat("blocks", "Shares", fmt_count(detail.get("shares")))
        + _stat("uptime", "First seen", ago(detail.get("first_seen")))
        + _stat("uptime", "Last share", ago(detail.get("last_seen")))
    )
    workers = detail.get("workers") or []
    now = time.time()
    wr = "".join(
        f"<tr><td>{_worker_link(coin_base, address, w['worker'])}</td>"
        f"<td>{worker_status_pill(w['last_seen'], now)}</td>"
        f"<td class=num>{fmt_hashrate(w['hashrate'].get('5m'))}</td>"
        f"<td class=num>{fmt_hashrate(w['hashrate'].get('1h'))}</td>"
        f"<td class=num>{fmt_count(w['shares'])}</td>"
        f"<td class=num>{_fmt_num(w.get('best_share'))}</td>"
        f"<td class=dim>{ago(w['last_seen'])}</td></tr>"
        for w in workers
    ) or _empty(7, "no workers")
    tx_tpl = tx_explorer_for(coin, chain, snap.get("explorer_url", ""), snap.get("explorer_tx_url", ""))
    pays = detail.get("recent_payouts") or []
    pr = "".join(
        f"<tr><td class=num>{fmt_coins(p['amount'])}</td>"
        f"{_txid_cell(p['txid'], tx_tpl, 12, 8)}<td class=dim>{ago(p['ts'])}</td></tr>"
        for p in pays
    ) or _empty(3, "no payouts yet")
    # Per-block earnings: your PPLNS slice of each block, incl. still-immature ones, so
    # pending (not-yet-paid) earnings are visible rather than hidden until maturity.
    bc = detail.get("block_credits") or []
    bc_rows = "".join(
        f'<tr><td><a href="{esc(coin_base)}/block/{esc(str(b["height"]))}">#{esc(str(b["height"]))}</a></td>'
        f'<td>{block_status_pill(b, snap)}</td>'
        f'<td class=dim>{ago(b["found_ts"])}</td>'
        f'<td class=num>{fmt_coins(b["amount"])} {esc(ticker)}</td></tr>'
        for b in bc
    ) or _empty(4, "no block credits yet - earnings show here once you've contributed shares to a found block")
    earnings_html = (
        f"\n<h2>{assets.icon('coins')}Block earnings</h2>\n"
        '<p class=note style="margin:-4px 0 12px">Your slice of each block\'s reward (PPLNS). '
        '<b>immature</b> credits are pending - they move to your <b>owed</b> balance once the '
        'block matures, then get paid out.</p>\n'
        + _table(bc_rows, "<tr><th>block</th><th>status</th><th>found</th>"
                 "<th class=num>your credit</th></tr>"))
    body = (
        f'{coinbar}\n{back_to_dash}\n'
        f'<div class=big-addr>{esc(address)}{fbadge}</div>\n'
        '<p class=note style="margin:-8px 0 16px">Owed is your balance waiting for the next '
        'payout; paid is the total sent to you so far.</p>\n'
        f'<section class=hero aria-label="miner overview">{hero}</section>\n'
        f"<section class=stats>{stats}</section>\n{chart_html}\n"
        f'{rigs_html}'
        f"<h2>{assets.icon('cpu')}Workers</h2>\n"
        + _table(wr, "<tr><th>worker</th><th>status</th><th class=num>hashrate 5m</th>"
                 "<th class=num>hashrate 1h</th><th class=num>shares</th>"
                 "<th class=num>best share</th><th>last share</th></tr>")
        + earnings_html
        + f"\n<h2>{assets.icon('payout')}Recent payouts</h2>\n"
        + _table(pr, "<tr><th class=num>amount</th><th>txid</th><th>when</th></tr>")
    )
    return (_head(f"TestnetPool - {address}") + nav + '<main class=wrap id=top>\n'
            + body + _foot())


def _render_worker_page(snap, address, worker, wdetail, chart_html,
                        api_base, home_url, coin_base) -> str:
    """A drill-down page for one rig (address + worker name): hashrate chart, best
    share, and its live session if currently connected."""
    coin, chain, mode = snap["coin"], snap["chain"], snap["mode"]
    ticker, algo = coin_ticker(coin, chain), snap.get("algo")
    nav = _nav(_site_nav(home_url),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"), brand_href=home_url or "/",
               stats_html=_nav_stats(snap))
    coinbar = _coinbar(coin, ticker, chain, mode, algo)
    miner_url = f'{esc(coin_base)}/miner/{esc(quote(address, safe=""))}'
    back = f'<a class=back href="{miner_url}">← {esc(trunc(address))}</a>'
    # Raw title - _head escapes it once (matches the miner/block pages).
    page_title = f"TestnetPool - {worker} · {address}"
    if wdetail is None:
        body = (f'{coinbar}\n{back}\n<div class=big-addr>{esc(worker)}</div>\n'
                '<p class=notfound>no shares recorded for this rig yet.</p>')
        return (_head(page_title) + nav + '<main class=wrap id=top>\n'
                + body + _foot())
    hr = wdetail.get("hashrate", {})
    hero = (
        _kpi("hashrate", "Hashrate 5m", fmt_hashrate(hr.get("5m")))
        + _kpi("hashrate", "Hashrate 1h", fmt_hashrate(hr.get("1h")))
        + _kpi("star", "Best share", _fmt_num(wdetail.get("best_share")))
        + _kpi("blocks", "Shares", fmt_count(wdetail.get("shares")))
    )
    stats = (
        _stat("uptime", "First seen", ago(wdetail.get("first_seen")))
        + _stat("uptime", "Last share", ago(wdetail.get("last_seen")))
        + _stat("hashrate", "Hashrate 24h", fmt_hashrate(hr.get("24h")))
    )
    live_html = _live_table(wdetail.get("live") or [])
    rigs = (f"<h2>{assets.icon('miners')}Live session</h2>\n"
            + (live_html or '<p class=note>this rig is not connected right now.</p>\n')
            if (wdetail.get("live") is not None) else "")
    body = (
        f'{coinbar}\n{back}\n'
        f'<div class=big-addr>{esc(worker)}</div>\n'
        f'<p class=note style="margin:-8px 0 16px">One rig under '
        f'<a href="{miner_url}">{esc(trunc(address))}</a>. Best share is the closest this rig '
        'has come to a block.</p>\n'
        f'<section class=hero aria-label="rig overview">{hero}</section>\n'
        f"<section class=stats>{stats}</section>\n{chart_html}\n"
        f'{rigs}'
    )
    return (_head(page_title) + nav + '<main class=wrap id=top>\n'
            + body + _foot())


def _render_block_page(snap, block, confirmations, maturity, api_base, home_url, coin_base,
                       explorer_url="") -> str:
    """A drill-down page for one found block."""
    coin, chain, mode = snap["coin"], snap["chain"], snap["mode"]
    ticker, algo = coin_ticker(coin, chain), snap.get("algo")
    dash = (coin_base + "/") if coin_base else "/"
    nav = _nav(_site_nav(home_url),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"), brand_href=home_url or "/",
               stats_html=_nav_stats(snap))
    coinbar = _coinbar(coin, ticker, chain, mode, algo)
    # In-page back link to the dashboard's Blocks section (the header navbar has no
    # per-coin Blocks link in the consistent-navbar layout).
    back_to_blocks = f'<a class=back href="{esc(dash)}#blocks">← blocks</a>'

    if block is None:
        body = (f'{coinbar}\n{back_to_blocks}\n'
                '<p class=notfound>no block at that height.</p>')
        return (_head("TestnetPool - block") + nav + '<main class=wrap id=top>\n'
                + body + _foot())

    lt, lc = luck_cell(block.get("luck_percent"))
    kpi_lc = {"luck-good": "ok", "luck-bad": "warn"}.get(lc, "")
    if confirmations is None:
        confs_txt = "—"
    elif confirmations >= maturity:
        confs_txt = f'{confirmations}<span class=u>✓ mature</span>'
    else:
        confs_txt = f'{confirmations}<span class=u>/ {maturity}</span>'
    finder = block.get("finder")
    finder_html = addr_link(finder, coin_base, snap.get("faucet_address", "")) if finder else "—"
    credited = "—" if block["status"] == "orphaned" else str(block.get("credited_miners", 0))
    hero = (
        _kpi("coins", "Reward", fmt_coins(block["reward"]))
        + _kpi("effort", "Effort", lt, kpi_lc)
        + _kpi("eta", "Confirmations", confs_txt)
        + _kpi("miners", "Credited miners", credited)
    )
    stats = (
        _stat("blocks", "Status", status_pill(block["status"], confirmations, maturity))
        + _stat("difficulty", "Network difficulty", _fmt_num(block.get("net_diff")))
        + _stat("hashrate", "Round difficulty", _fmt_num(block.get("round_diff")))
        + _stat("eta", "Found", ago(block.get("found_ts")))
        + _stat("miners", "Finder", finder_html)
        + _stat("height", "Height", fmt_count(block["height"]))
    )
    # Per-miner PPLNS split: who earned what from this block (pending until it matures).
    creds = block.get("credits") or []
    split_html = ""
    if creds and block["status"] != "orphaned":
        faucet = snap.get("faucet_address", "")
        pending = block["status"] == "immature"
        cr_rows = "".join(
            f'<tr><td class=mono>{addr_link(c["address"], coin_base, faucet)}</td>'
            f'<td class=num>{fmt_coins(c["amount"])} {esc(ticker)}</td></tr>'
            for c in creds)
        split_html = (
            f"\n<h2>{assets.icon('payout')}Reward split</h2>\n"
            '<p class=note style="margin:-4px 0 12px">How this block\'s reward is split '
            'across the recent-shares (PPLNS) window'
            + (' - <b>pending</b> until the block matures.' if pending else '.') + '</p>\n'
            + _table(cr_rows, "<tr><th>address</th><th class=num>"
                     + ("pending credit" if pending else "credit") + "</th></tr>"))
    body = (
        f'{coinbar}\n{back_to_blocks}\n'
        f'<div class=coinbar><span class=coin-badge>{assets.icon("blocks")}'
        f'Block #{esc(str(block["height"]))}</span>'
        f'{status_pill(block["status"], confirmations, maturity)}</div>\n'
        f'<section class=hero aria-label="block overview">{hero}</section>\n'
        '<p class=note style="margin:-8px 0 16px"><b>immature</b>: reward pending maturity'
        ' · <b>matured</b>: credited to miners · <b>orphaned</b>: replaced by the network,'
        ' pays nothing.</p>\n'
        f"<section class=stats>{stats}</section>\n"
        f"{split_html}"
        f"<h2>{assets.icon('blocks')}Block hash</h2>\n"
        f'<div class=code>{esc(block["hash"])}</div>\n'
        f'<div class=hashrow>'
        f'<button class=copy-btn type=button data-copy="{esc(block["hash"])}">Copy hash</button>'
        + _explorer_link(explorer_for(coin, chain, explorer_url), block["hash"])
        + '</div>'
    )
    return (_head(f"TestnetPool - block #{block['height']}") + nav + '<main class=wrap id=top>\n'
            + body + _foot())


def _explorer_link(explorer_url, block_hash) -> str:
    """An optional 'View on explorer' button, when an explorer_url is configured."""
    if not explorer_url or "{hash}" not in explorer_url:
        return ""
    url = explorer_url.replace("{hash}", quote(str(block_hash), safe=""))
    return (f'<a class="btn-link" href="{esc(url)}" target=_blank rel=noopener>'
            'View on explorer ↗</a>')


# API endpoint catalog - the single source for the JSON index (/api) AND the human
# docs page (/api/docs). Per-coin paths get the /api/<coin> prefix in hub mode.
_API_GLOBAL = [
    ("/api", "This index. JSON to a script, a docs page in a browser."),
    ("/api/info", "Pool rules per coin + software version - verify against the source."),
    ("/api/coins", "Per-coin summary (hub mode only)."),
    ("/healthz", "Liveness probe: 200 when every pool has a fresh template, 503 if any is stalled."),
]
_API_PER_COIN = [  # path suffix after /api (single) or /api/<coin> (hub)
    ("/stats", "Live snapshot: hashrate windows, miners, blocks, reject reasons, mempool, node health."),
    ("/chart?range=1h|24h|1w|1m[&address=ADDR]", "Hashrate time series (pool, or one miner with &address)."),
    ("/miners", "Miner overview (addresses + balances; never IPs)."),
    ("/miner/<address>", "One miner: workers, hashrate, balance, best share, live rigs."),
    ("/worker/<address>/<worker>", "One rig: hashrate, best share, live session."),
    ("/template", "Transactions in the current block template - every tx the next block will include."),
    ("/blocks", "Found blocks (all statuses incl. orphaned/stale)."),
    ("/block/<height>", "One block's detail (round diff, luck, finder)."),
    ("/payouts", "Recent payouts (txids)."),
    ("/luck", "Per-block effort/luck + pool luck + orphan rate."),
    ("/leaderboard", "Best-share high scores (addresses; never IPs)."),
]


def _api_endpoints(single: bool) -> list:
    """[(path, summary), ...] with the per-coin prefix resolved for the mode."""
    per = "/api" if single else "/api/<coin>"
    out = [(p, s) for p, s in _API_GLOBAL if not (p == "/api/coins" and single)]
    out += [(f"{per}{suf}", s) for suf, s in _API_PER_COIN]
    return out


def _render_api_docs(single: bool, home_url=None, base_url="") -> str:
    """Human-readable HTML docs for the JSON API (served to browsers at /api and
    /api/docs). Same endpoint list as the JSON index, so they can't drift.
    ``base_url`` (the canonical site_url, or the request host) makes the curl
    example copy-pasteable; it falls back to a <host> placeholder when unknown."""
    nav = _nav(_site_nav(home_url, active="api"),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"), brand_href=home_url or "/")

    def row(path, summ):
        # Link the ones that resolve to a real URL (no <placeholder>, no query).
        cell = (f'<a href="{esc(path)}">{esc(path)}</a>'
                if ("<" not in path and "?" not in path) else esc(path))
        return f"<tr><td class=mono>{cell}</td><td>{esc(summ)}</td></tr>"

    rows = "".join(row(p, s) for p, s in _api_endpoints(single))
    per_note = ("" if single else
                "<p class=note>This is a multi-coin hub, so every data endpoint is namespaced "
                "by coin: <span class=mono>/api/&lt;coin&gt;/stats</span>, "
                "<span class=mono>/api/litecoin/blocks</span>, and so on. "
                "<span class=mono>/api/coins</span> lists the coins.</p>\n")
    host_part = esc(base_url) if base_url else 'https://&lt;host&gt;'
    example = (
        '<h2>Example</h2>\n<p class=note>Every response is plain JSON. The live snapshot:</p>\n'
        '<div class=code>$ curl -s ' + host_part
        + ('/api/stats' if single else '/api/&lt;coin&gt;/stats') + '\n'
        '{\n  "coin": "litecoin", "chain": "test", "mode": "public",\n'
        '  "height": 4763340, "connected_miners": 3, "active_miners": 7,\n'
        '  "pool_hashrate": { "1m": 1.9e14, "5m": 2.1e14, "1h": 2.0e14, "1d": 1.8e14 },\n'
        '  "network_difficulty": 167314008.0,\n'
        '  "network_hashrate_hs": 4.79e15, "best_share": 4812993.0, "blocks_found": 12,\n'
        '  "node_health": { "peers": 8, "tip_age_seconds": 142, "synced": true }\n}</div>\n'
    )
    body = (
        '<div class=coinbar><span class=coin-badge>JSON API</span></div>\n'
        '<p class=note>Read-only JSON, no auth, open CORS '
        '(<span class=mono>Access-Control-Allow-Origin: *</span>). Amounts are in base units '
        '(1 coin = 100&#8202;000&#8202;000 for every coin, Monero included) and timestamps '
        'are unix seconds. '
        'Miner IPs are never exposed. Per-IP rate-limited - a <span class=mono>429</span> with a '
        '<span class=mono>Retry-After</span> header means slow down (the health probe is exempt).</p>\n'
        f'{per_note}'
        '<h2>Endpoints</h2>\n'
        + _table(rows, "<tr><th>endpoint</th><th>returns</th></tr>")
        + f'\n{example}'
        '<p class=note>This same list is JSON from <span class=mono>GET /api</span> to a script '
        '(a browser gets this page); the exact per-coin rules are at '
        '<a href="/api/info">/api/info</a>.</p>\n'
    )
    return (_head("TestnetPool - API") + nav + '<main class=wrap id=top>\n' + body + _foot())


def _render_connect(coins_info, home_url=None) -> str:
    """Getting-started page: per-coin Stratum endpoint + example miner command."""
    dash = esc(home_url or "/")  # closing "dashboard" link target
    # "How payouts work" lives on a coin dashboard (#howpay). In single-coin mode
    # that's "/#howpay"; on a hub each coin differs, so the per-coin cards link there
    # instead of one dead generic link.
    howpay = ' See <a href="/#howpay">how payouts work</a>.' if home_url is None else ""
    nav = _nav(_site_nav(home_url, active="connect"),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"), brand_href=home_url or "/")
    placeholder_host = any(ci["host"] == "HOST" for ci in coins_info)
    cards = ""
    for ci in coins_info:
        url = f'stratum+tcp://{ci["host"]}:{ci["port"]}'
        addr_ph = f'YOUR_{ci["ticker"]}_ADDRESS'
        # CPU mining is dead on the BTC/LTC testnets (ASIC-class difficulty), so no
        # CLI example there. Monero/RandomX IS CPU-friendly by design, so it keeps an
        # xmrig footnote - xmrig is how you actually mine Monero on CPU.
        cli = ""
        if ci["algo"] == "randomx":
            # xmrig's --url takes a bare host:port (it selects TLS via --tls, not a
            # scheme prefix), so don't hand it the stratum+tcp:// URL the ASIC row uses.
            cmd = f'xmrig --algo rx/0 --url {ci["host"]}:{ci["port"]} --user {addr_ph} --pass x'
            cli = ('<details class=cc-cli><summary>xmrig (CPU) command</summary>'
                   f'<div class=code><span class=cc-cmd>{esc(cmd)}</span>'
                   f'<button class="copy-btn mini cc-cmdcopy" type=button data-copy="{esc(cmd)}">copy</button>'
                   '</div></details>')
        # d=NNNN password difficulty-pinning is honored only on the share-based (BTC/LTC)
        # stratum; Monero's CryptoNote login ignores the password, so don't claim it there.
        pin = ('' if ci["algo"] == "randomx"
               else '<span class=note>&nbsp;or d=NNNN to pin difficulty</span>')
        cards += (
            f'<div class=cc data-ph="{esc(addr_ph)}" data-url="{esc(url)}">'
            f'<div class=cc-h>{assets.coin_mark(ci["coin"])}'
            f'{esc((ci["coin"] or "?").title())} <span class=pill>{esc(chain_label(ci["chain"]))}</span> '
            f'<span class=pill>{esc(algo_label(ci["algo"]))}</span></div><div class=cc-b>'
            f'<div class=cc-row><span class=k>URL</span>'
            f'<span class=v>{esc(url)}'
            f'<button class="copy-btn mini" type=button data-copy="{esc(url)}">copy</button></span></div>'
            # Worker configurator: type the address (+ optional rig) and the username
            # builds live with a copy button. Falls back to the placeholder when empty.
            '<div class=cc-cfg>'
            f'<input class=cc-addr type=text spellcheck=false autocomplete=off autocapitalize=off '
            f'placeholder="{esc(addr_ph)}" aria-label="your {esc(ci["ticker"])} address">'
            '<input class=cc-rig type=text spellcheck=false autocomplete=off '
            'placeholder="rig name (optional)" aria-label="worker name">'
            '</div>'
            f'<div class=cc-row><span class=k>Username</span>'
            f'<span class=v><span class=cc-user>{esc(addr_ph)}</span>'
            f'<button class="copy-btn mini cc-ucopy" type=button data-copy="{esc(addr_ph)}">copy</button></span></div>'
            f'<div class=cc-row><span class=k>Password</span>'
            f'<span class=v>x{pin}</span></div>'
            f'{cli}'
            f'<a class=cc-dash href="{esc(ci["dash"])}">'
            f'{esc((ci["coin"] or "?").title())} stats &amp; payouts →</a>'
            '</div></div>'
        )
    cards = cards or '<div class=chart-empty>no coins configured</div>'
    host_note = (' Replace <b>HOST</b> with the hostname or IP you reached this page on.'
                 if placeholder_host else "")
    on_tor = any(str(ci["host"]).endswith(".onion") for ci in coins_info)
    tor_note = (
        '<p class=note style="margin-top:10px"><b>On the Tor mirror:</b> the endpoint above is an '
        'onion address, and mining software can\'t reach <b>.onion</b> on its own - tunnel it through '
        'a local Tor proxy (<b>torsocks</b> for xmrig, or a <b>socat</b> forwarder for an ASIC/Bitaxe). '
        'Tor adds latency (more stale shares), so for efficiency use the clearnet endpoint - the onion '
        f'is mainly for browsing privately. <a href="{esc(SOURCE_URL)}/blob/master/README.md#tor-optional" '
        'target=_blank rel=noopener>Setup guide</a>.</p>\n'
        if on_tor else ""
    )
    body = (
        '<div class=coinbar><span class=coin-badge>Connect a miner</span></div>\n'
        '<p class=note>Point <b>any Stratum miner</b> at the endpoint below - an ASIC, a Bitaxe, '
        'or cpuminer. Your '
        '<b>username is your payout address</b> (rewards go straight there; add <b>.workername</b> '
        'to label a rig), and the <b>password is x</b> (difficulty auto-tunes).'
        f'{host_note} Monero is CPU-mineable with xmrig (see its card).'
        f'{howpay}</p>\n'
        f'<div class=connect>{cards}</div>\n'
        f'{tor_note}'
        f'<p class=note>Once connected, '
        + (f'look up your address on the <a href="{dash}">dashboard</a>' if home_url is None
           else "open a coin's dashboard (links above)")
        + ' to watch your shares, best difficulty, and payouts.</p>'
    )
    return (_head("TestnetPool - connect") + nav + '<main class=wrap id=top>\n'
            + body + _foot())


def _render_template_page(summary, api_base, home_url, coin_base, explorer_url="",
                          explorer_tx_url="") -> str:
    """Public view of the current block template's transactions - exactly what the next
    block this pool finds will include. Backs the 'every transaction, no filtering' claim
    the way solo.ckpool.org's transaction list does."""
    coin = summary.get("coin") or "?"
    chain = summary.get("chain") or ""
    nav = _nav(_site_nav(home_url, active=""),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"),
               brand_href=home_url or "/")
    coinbar = (f'<div class=coinbar><span class=coin-badge>Next block</span>'
               f'<span class=pill>{esc(coin.title())}</span> '
               f'<span class=pill>{esc(chain_label(chain))}</span></div>')
    dash = (coin_base + "/") if coin_base else "/"
    if not summary.get("available"):
        # Monero's node assembles its own block (permanent); for BTC/LTC this only shows
        # in the brief window before the first template is fetched.
        why = " - its node assembles the block itself" if coin == "monero" else " yet"
        body = (f"{coinbar}\n<p class=note>A transaction list isn't available for "
                f"{esc(coin.title())}{why}. Back to the "
                f'<a href="{esc(dash)}">dashboard</a>.</p>\n')
        return (_head("TestnetPool - next block", api_base) + nav
                + '<main class=wrap id=top>\n' + body + _foot())
    txs = summary.get("txs") or []
    tx_tpl = tx_explorer_for(coin, chain, explorer_url, explorer_tx_url)
    height = summary.get("height")
    intro = ('<p class=note style="margin:-4px 0 16px">Every transaction in the pool\'s current '
             "block template - exactly what the next block we find will include, no filtering. "
             f'Live JSON at <a href="{esc(api_base)}/template">{esc(api_base)}/template</a>.</p>\n')
    stats = ('<section class=stats>'
             + _stat("height", "Next height", fmt_count(height) if height is not None else "—")
             + _stat("blocks", "Transactions", fmt_count(summary.get("tx_count", 0)))
             + _stat("payout", "Total fees", fmt_coins(summary.get("total_fee", 0)))
             + _stat("difficulty", "Total size", f'{fmt_count(summary.get("total_vsize", 0))} vB')
             + '</section>')
    if not txs:
        table = ('<div class=chart-empty>No transactions waiting - the next block this pool '
                 'finds will be coinbase-only.</div>')
    else:
        rows = ""
        for t in txs:
            txid = str(t.get("txid", ""))
            cell = ((f'<a href="{esc(tx_tpl.replace("{txid}", quote(txid, safe="")))}" '
                     f'target=_blank rel=noopener>{esc(txid)}</a>') if tx_tpl else esc(txid))
            vsize = int(t.get("vsize") or 0)
            fee = int(t.get("fee") or 0)
            rate = f"{fee / vsize:.1f}" if vsize else "—"
            rows += (f'<tr><td class=mono>{cell}</td>'
                     f'<td class=num>{fmt_count(vsize)}</td>'
                     f'<td class=num>{fmt_coins(fee)}</td>'
                     f'<td class=num>{rate}</td></tr>')
        table = _table(rows, '<tr><th>txid</th><th class=num>vsize</th>'
                       '<th class=num>fee</th><th class=num>fee/vB</th></tr>')
    body = f"{coinbar}\n{intro}{stats}\n{table}"
    return (_head("TestnetPool - next block", api_base) + nav
            + '<main class=wrap id=top>\n' + body + _foot())


def _qr_svg(data: str, coin: str) -> str:
    """Render ``data`` as a self-contained QR-code SVG with the coin mark centered.
    Pure-Python encoder (testnetpool.qr) - no third-party dependency, no network.
    Returns "" if the data won't fit a QR, so a misconfigured address drops its
    code rather than taking down the donate page."""
    try:
        m = qr.matrix(data.encode("utf-8"))
    except Exception:  # oversize / unencodable -> no QR, page still renders
        return ""
    n = len(m)
    quiet = 4
    tot = n + 2 * quiet
    path = "".join(
        f"M{c + quiet} {r + quiet}h1v1h-1z"
        for r in range(n)
        for c in range(n)
        if m[r][c]
    )
    # A centered coin mark (~26% width -> ~6.8% area, well inside ECC-M's 15% budget)
    # on a white rounded backing so it reads as a logo, not noise.
    lw = round(tot * 0.26, 2)
    off = round((tot - lw) / 2, 2)
    raw = assets.COIN_MARKS.get(coin) or ""
    logo = ""
    if raw:
        logo = (
            f'<rect x="{off - 1}" y="{off - 1}" width="{lw + 2}" height="{lw + 2}" '
            'rx="2" fill="#fff"/>'
            + raw.replace("<svg ", f'<svg x="{off}" y="{off}" width="{lw}" height="{lw}" ', 1)
        )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {tot} {tot}" class=qr '
        f'role=img aria-label="{esc(coin.title())} address QR code">'
        f'<rect width="{tot}" height="{tot}" fill="#fff"/>'
        f'<path fill="#000" shape-rendering=crispEdges d="{path}"/>{logo}</svg>'
    )


def _btc_like_accepts(addr: str, net) -> bool:
    """True if `addr` is a valid address for a Bitcoin/Litecoin network `net`.
    Reuses address.py's own decoders so this agrees exactly with what the miner
    page accepts. Bech32 is matched by hrp (unambiguous); legacy base58 is matched
    by version byte (testnet bytes are shared by BTC and LTC -> caller resolves)."""
    if addr.lower().startswith(net.bech32_hrp + "1"):
        try:
            address._decode_segwit(net.bech32_hrp, addr)
            return True
        except address.AddressError:
            return False
    try:
        payload = address._b58check_decode(addr)
    except address.AddressError:
        return False
    return (len(payload) == 21
            and (payload[0] == net.pubkey_version or payload[0] in net.script_versions))


def _render_find_page(q, status, cands, home_url=None) -> str:
    """The /find results page: prompt (empty), a 'no match' note, or a
    disambiguation list when an address is valid on more than one hosted chain.
    A single match never reaches here - it 302-redirects straight to the miner."""
    nav = _nav(_site_nav(home_url), _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"),
               brand_href=home_url or "/")
    if status == "empty":
        msg = '<p class=note>Enter a wallet address above to jump straight to its miner stats.</p>'
    elif status == "ambiguous":
        links = "".join(
            f'<li><a href="{esc(url)}">{assets.coin_mark(coin)}'
            f'<span><b>{esc((coin or "?").title())}</b> '
            f'<span class=ch>{esc(chain_label(chain))}</span></span></a></li>'
            for url, coin, chain in cands)
        msg = ('<p class=note>That address is valid on more than one chain hosted here - '
               'pick the coin you mined:</p>'
               f'<ul class=find-cands>{links}</ul>')
    else:  # "none"
        msg = ('<p class=note>No coin hosted here recognizes that address. Make sure it is a '
               '<b>testnet</b> address for one of the coins above - mainnet addresses and coins '
               'this pool does not run will not match.</p>')
    echo = f'<p class=big-addr style="font-size:14px;margin-bottom:10px">{esc(q)}</p>' if q else ""
    body = (
        '<div class=coinbar><span class=coin-badge>Find a miner</span></div>\n'
        f'{echo}{msg}'
    )
    return (_head("TestnetPool - find a miner") + nav + '<main class=wrap id=top>\n' + body + _foot())


# Plain-English /legal page (static): no monetary value, no accounts, what's logged
# and why, best-effort with no guarantees, AGPL no-warranty.
_LEGAL_PARAS = (
    "TestnetPool is experimental, best-effort software for testnet and stagenet coins. "
    "These coins have no monetary value.",
    "There are no accounts, emails, or passwords. Your mining username is your payout "
    "address, optionally followed by a worker name.",
    "To operate the pool, calculate payouts, prevent abuse, and debug issues, the service "
    "may log payout addresses, worker names, share submissions, IP addresses, miner "
    "connection data, block records, and payout records.",
    "Blocks, shares, balances, and payouts are not guaranteed. Orphaned blocks, stale "
    "shares, bugs, downtime, node issues, forks, or payout failures may occur.",
    "Small idle balances may be swept back into the pool's faucet after the displayed idle period.",
    "The software is provided as-is under the AGPL, without warranty of any kind. The hosted "
    "service is likewise provided as-is, with no warranties or guarantees. Run your own node "
    "and verify.",
)


def _render_legal(home_url=None) -> str:
    """The /legal page: plain-English terms + privacy notice for a no-accounts pool."""
    nav = _nav(_site_nav(home_url), _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"),
               brand_href=home_url or "/")
    body = (
        '<div class=coinbar><span class=coin-badge>Legal</span></div>\n'
        + "".join(f"<p class=legal>{p}</p>\n" for p in _LEGAL_PARAS)
    )
    return (_head("TestnetPool - legal") + nav + '<main class=wrap id=top>\n' + body + _foot())


def _render_donate(donate, home_url=None) -> str:
    """Donation page: an OpenAlias plus per-coin addresses with copy buttons."""
    nav = _nav(_site_nav(home_url, active="donate"),
               _live(time.strftime("%H:%M:%S", time.gmtime()) + " UTC"), brand_href=home_url or "/")
    oa = getattr(donate, "openalias", "") or ""
    entries = [("bitcoin", "Bitcoin", "BTC", getattr(donate, "bitcoin", "")),
               ("litecoin", "Litecoin", "LTC", getattr(donate, "litecoin", "")),
               ("monero", "Monero", "XMR", getattr(donate, "monero", ""))]
    cards = ""
    for key, name, tic, addr in entries:
        if not addr:
            continue
        cards += (
            f'<div class=dcard><div class=dcard-h>{assets.coin_mark(key)}{esc(name)} '
            f'<span class=pill>{esc(tic)}</span></div><div class=dcard-b>'
            f'{_qr_svg(addr, key)}'
            f'<div class=addr>{esc(addr)}</div>'
            f'<div class=dcard-actions>'
            f'<button class=copy-btn type=button data-copy="{esc(addr)}">Copy address</button>'
            # BIP21-style URI (scheme == the coin name): a click opens a registered wallet
            # with the address prefilled. Degrades gracefully where no handler is installed.
            f'<a class=copy-btn href="{esc(key)}:{esc(addr)}">Open in wallet</a>'
            f'</div>'
            "</div></div>"
        )
    oa_block = ""
    if oa:
        oa_block = (
            '<div class=openalias><span class=lbl>OpenAlias</span>'
            f'<span class=oa>{esc(oa)}</span>'
            f'<button class=copy-btn type=button data-copy="{esc(oa)}">Copy OpenAlias</button>'
            '<span class=note><a href="https://cyphertoshi.com/posts/openalias-wallets" '
            'target=_blank rel=noopener>OpenAlias-aware wallets</a> resolve this to the right '
            'address per coin</span></div>'
        )
    inner = cards or ('' if oa_block
                      else '<div class=chart-empty>no donation addresses configured yet</div>')
    body = (
        '<div class=coinbar><span class=coin-badge>Support TestnetPool</span></div>\n'
        '<p class=donate-intro>TestnetPool is free and open-source. Pool fees top up '
        '<a href="https://cypherfaucet.com" target=_blank rel=noopener>CypherFaucet</a> (the free '
        'testnet faucet); donations help cover the nodes and hosting. The addresses below are '
        '<b>mainnet (real) coins</b> - thank you.</p>\n'
        f'{oa_block}\n<div class=dcards>{inner}</div>'
    )
    return (_head("TestnetPool - donate") + nav + '<main class=wrap id=top>\n' + body + _foot())


class StatsServer:
    """Serves the dashboard + JSON API over one or more pools.  With a single
    pool it behaves exactly as the single-coin server; with several it adds a
    hub landing page and per-coin routing (`/<coin>`, `/api/<coin>/...`; the old
    `/c/<coin>` still resolves as a legacy alias)."""

    def __init__(self, pools, stats_cfg, donate=None):
        self.pools = list(pools)
        self.stats_cfg = stats_cfg
        self.donate = donate
        _META["site_url"] = getattr(stats_cfg, "site_url", "")
        _META["node_dashboard_url"] = getattr(stats_cfg, "node_dashboard_url", "")
        _META["onion"] = getattr(stats_cfg, "onion", "")
        # Pools are addressed by a URL slug: the coin name when it's unique, else
        # "coin-chain" - so two Monero instances (e.g. testnet + stagenet) don't
        # collide on /c/monero.  Config guarantees unique (coin, chain) pairs, so
        # the slugs are unique too.
        from collections import Counter
        counts = Counter(p.cfg.coin for p in self.pools)
        self._slug = {p: (p.cfg.coin if counts[p.cfg.coin] == 1
                          else f"{p.cfg.coin}-{p.cfg.chain}") for p in self.pools}
        self._by_slug = {slug: p for p, slug in self._slug.items()}
        # Coins are now reachable at /<slug>; warn if a slug collides with a global
        # path (it'd be shadowed and unreachable). Real coin names never collide.
        _shadowed = {"api", "connect", "donate", "find", "legal", "healthz", "c", "index.html"} & set(self._by_slug)
        if _shadowed:
            log.warning("coin slug(s) %s shadow a reserved path and are unreachable at "
                        "the top level - rename that coin/chain", sorted(_shadowed))
        self._single = len(self.pools) == 1
        self._server: asyncio.AbstractServer | None = None
        self._ratelimit = HttpRateLimiter(getattr(stats_cfg, "rate_limit_per_min", 120))
        self._trust_private = getattr(stats_cfg, "trust_private_proxy", False)
        self._active_conns = 0  # hard concurrent-connection cap (slowloris / flood guard)

    def slug(self, pool) -> str:
        return self._slug[pool]

    async def start(self) -> None:
        cfg = self.stats_cfg
        if not cfg.enabled:
            return
        self._server = await asyncio.start_server(self._handle, cfg.host, cfg.port)
        kind = "dashboard" if self._single else f"hub dashboard ({len(self.pools)} coins)"
        log.info("%s on http://%s:%d/", kind, cfg.host, cfg.port)

    async def _handle(self, reader, writer) -> None:
        # Hard concurrent-connection cap. Without it, thousands of slow/malformed sockets
        # (each living up to the 15s slowloris deadline) accumulate coroutines and exhaust
        # the server before the per-request rate limiter is ever consulted. Reject over the
        # cap by closing IMMEDIATELY - never await, or the parked coroutines still pile up.
        if self._active_conns >= MAX_HTTP_CONNS:
            try:
                writer.close()
            except Exception:
                pass
            return
        self._active_conns += 1
        try:
            async def _read_request():
                # Read the request line + headers. host/accept feed content negotiation.
                request_line = await reader.readline()
                if not request_line:
                    return None
                parts = request_line.decode("latin1").split()
                p = parts[1] if len(parts) >= 2 else "/"
                hst = None
                acc = ""
                xff = ""
                for _ in range(100):  # drain headers, bounded
                    h = await reader.readline()
                    if h in (b"\r\n", b"\n", b""):
                        break
                    low = h.decode("latin1", "replace").lower()
                    if hst is None and low.startswith("host:"):
                        hst = low[5:].strip()
                    elif low.startswith("accept:"):
                        acc = low[7:].strip()
                    elif low.startswith("x-forwarded-for:"):
                        xff = low[16:].strip()
                else:
                    raise ValueError("too many header lines")  # -> 400
                return p, hst, acc, xff
            try:
                # ONE overall deadline for the whole request-line+headers phase, so a peer
                # trickling one line just under a per-line timeout can't hold the
                # connection (and its coroutine) open for minutes (slowloris).
                parsed = await asyncio.wait_for(_read_request(), timeout=15)
                if parsed is None:
                    return
                path, host, accept, xff = parsed
            except asyncio.TimeoutError:
                return
            except (ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError,
                    UnicodeDecodeError):
                # Oversized/malformed request line or header: reply 400 rather than
                # closing on the client with no response. (readline re-wraps an
                # over-limit line as ValueError.) Meter it against the limiter (raw peer
                # IP - XFF isn't parsed/trusted here) so a malformed flood from one source
                # still counts toward its budget instead of bypassing rate limiting.
                peer = writer.get_extra_info("peername")
                self._ratelimit.allow(peer[0] if peer else "", time.time())
                try:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    await asyncio.wait_for(writer.drain(), timeout=5)
                except Exception:
                    pass
                return

            # Per-IP rate limit (cheap, pre-routing). Exempt the liveness probe so an
            # uptime monitor / load-balancer health check is never throttled.
            clean = path.split("?", 1)[0]
            if clean not in ("/healthz", "/api/health"):
                peer = writer.get_extra_info("peername")
                ip = client_ip(peer[0] if peer else "", xff, self._trust_private)
                if not self._ratelimit.allow(ip, time.time()):
                    rl = b'{"error":"rate limited"}'
                    try:
                        writer.write(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 10\r\n"
                                     b"Content-Type: application/json\r\n"
                                     + f"Content-Length: {len(rl)}\r\n".encode()
                                     + b"Connection: close\r\n\r\n" + rl)
                        await asyncio.wait_for(writer.drain(), timeout=5)
                    except Exception:
                        pass
                    return

            try:
                routed = self._route(path, host, accept)
                # Routes normally return (body, ctype); some also return a status
                # line (3rd element, e.g. /healthz) and/or extra response headers
                # (4th element, e.g. /find's Location: for a 302 redirect).
                body, ctype = routed[0], routed[1]
                status = routed[2] if len(routed) > 2 else b"HTTP/1.1 200 OK\r\n"
                extra = routed[3] if len(routed) > 3 else b""
            except Exception:
                # A bug in one route must still yield an HTTP response, never a
                # silently dropped connection.
                log.debug("stats route failed for %s", path, exc_info=True)
                body, ctype = b'{"error":"internal error"}', "application/json"
                status = b"HTTP/1.1 500 Internal Server Error\r\n"
                extra = b""
            # CORS only on the JSON API, so a custom front-end can fetch it; the
            # HTML pages don't need to be cross-origin readable.
            cors = b"Access-Control-Allow-Origin: *\r\n" if ctype.startswith("application/json") else b""
            # Onion-Location advertises the Tor mirror to Tor Browser (it shows a
            # ".onion available" button) - only on clearnet HTML pages, not when the
            # request already arrived over the onion.
            onion = b""
            # Only reflect a CLEAN request path into the header: starts with "/" and is
            # all-printable. split() already strips whitespace (so no CRLF injection), but
            # other control bytes (NUL, 0x01-0x1f, 0x7f) would otherwise pass through into
            # the response header; a garbage path is a scanner anyway, so just skip it.
            if (_META.get("onion") and ctype.startswith("text/html")
                    and not (host or "").endswith(".onion")
                    and path.startswith("/") and path.isprintable()):
                onion = f"Onion-Location: {_META['onion']}{path}\r\n".encode("latin1", "replace")
            writer.write(
                status
                + f"Content-Type: {ctype}\r\n".encode()
                + cors + onion + extra
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            await asyncio.wait_for(writer.drain(), timeout=10)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        except Exception:
            log.debug("stats request failed", exc_info=True)
        finally:
            self._active_conns -= 1
            writer.close()

    def _json(self, obj) -> tuple[bytes, str]:
        return json.dumps(obj, indent=2).encode(), "application/json"

    def _classify(self, addr: str) -> list:
        """Configured pools whose network accepts `addr`, using each coin's own
        decoder (so a match means the miner page accepts it too). Never raises.
        Bech32/Monero are unambiguous; a legacy base58 testnet address can match
        both a BTC and an LTC pool (shared version bytes) -> caller disambiguates."""
        out = []
        for p in self.pools:
            try:
                if p.cfg.coin == "monero":
                    if cryptonote.is_valid_address(addr, p.cfg.chain):
                        out.append(p)
                elif _btc_like_accepts(addr, p.coin.network(p.cfg.chain)):
                    out.append(p)
            except Exception:
                continue
        return out

    def _miner_url(self, pool, addr: str) -> str:
        a = quote(addr, safe="")
        return f"/miner/{a}" if self._single else f"/{self._slug[pool]}/miner/{a}"

    def _redirect(self, url: str) -> tuple:
        """302 to a same-site path (already slug + quote()'d, so ASCII-safe). The
        body carries a meta-refresh + visible link as a no-Location-header fallback."""
        body = (f'<!doctype html><meta charset=utf-8><title>Redirecting…</title>'
                f'<meta http-equiv=refresh content="0;url={esc(url)}">'
                f'<p>Redirecting to <a href="{esc(url)}">{esc(url)}</a></p>').encode()
        return (body, "text/html; charset=utf-8", b"HTTP/1.1 302 Found\r\n",
                f"Location: {url}\r\n".encode("latin1", "replace"))

    def _find(self, query: str, host=None) -> tuple:
        """Global address search: classify against the configured pools and 302 to
        the matching coin's miner page; 0 / >1 matches render a small results page.
        The address is untrusted input -> esc() in HTML, quote() in the URL."""
        q = (parse_qs(query).get("q", [""])[0] or "").strip()[:120]
        home = None if self._single else "/"
        if not q:
            return _render_find_page("", "empty", [], home).encode(), "text/html; charset=utf-8"
        matches = self._classify(q)
        if len(matches) == 1:
            return self._redirect(self._miner_url(matches[0], q))
        cands = [(self._miner_url(p, q), p.cfg.coin, p.cfg.chain) for p in matches]
        status = "ambiguous" if cands else "none"
        return _render_find_page(q, status, cands, home).encode(), "text/html; charset=utf-8"

    def _enrich_miner(self, pool, detail: dict, addr: str) -> dict:
        """Attach per-miner hashrate windows + worker breakdown (route-side, since
        the coin multiplier and clock live here, not in coin-agnostic accounting)."""
        acc = pool.accounting
        now = int(time.time())
        mult = pool.coin.hashes_per_diff1
        hw = acc.miner_hashrate_windows(addr, now)
        detail["hashrate"] = {lbl: round(hw[w] * mult / w, 2) for lbl, w in MINER_WINDOWS}
        detail["workers"] = [
            {"worker": wk["worker"], "last_seen": wk["last_seen"], "shares": wk["shares"],
             "best_share": wk.get("best_share"),
             "hashrate": {lbl: round(wk["diff"][w] * mult / w, 2) for lbl, w in MINER_WINDOWS}}
            for wk in acc.worker_breakdown(addr, now)
        ]
        detail["live"] = _live_for_address(pool, addr)
        # Per-block credits (incl. immature) so the miner can see pending earnings.
        detail["block_credits"] = acc.miner_block_credits(addr)
        return detail

    def _enrich_worker(self, pool, wd: dict, address: str, worker: str) -> dict:
        """Attach hashrate windows + the live session (if connected) to a worker
        detail. The live row is matched by the rig's name (never an IP)."""
        mult = pool.coin.hashes_per_diff1
        wd["hashrate"] = {lbl: round(wd["diff"][w] * mult / w, 2) for lbl, w in MINER_WINDOWS}
        # The live view labels the unnamed rig "(default)"; match that, not the "" key.
        live_key = worker or "(default)"
        wd["live"] = [r for r in _live_for_address(pool, address) if r["worker"] == live_key]
        return wd

    @staticmethod
    def _clean_host(host) -> str:
        """Sanitize the (untrusted) Host header to a bare hostname for display in
        the connect page, or a 'HOST' placeholder.  esc() still guards the output;
        this just keeps it sane and avoids reflecting junk."""
        if not host:
            return "HOST"
        h = host.split("/")[0].split(":")[0].strip()
        ok = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not h or len(h) > 253 or any(c not in ok for c in h):
            return "HOST"
        return h

    def _connect_info(self, host) -> list[dict]:
        web_host = self._clean_host(host)
        out = []
        for p in self.pools:
            out.append({
                "coin": p.cfg.coin, "chain": p.cfg.chain,
                "ticker": coin_ticker(p.cfg.coin, p.cfg.chain),
                "algo": p.coin.algo, "host": web_host, "port": p.cfg.stratum_port,
                # This coin's own dashboard ("/" single-coin, "/<slug>" on a hub) -
                # where its live stats + "How payouts work" section live.
                "dash": "/" if self._single else "/" + self._slug[p],
            })
        return out

    def _chart_for(self, pool, address=None, rng="24h", worker=None) -> str:
        """Render the hashrate-over-time chart block (with range tabs) for a pool,
        one miner, or one worker. ``rng`` is one of CHART_RANGES (1h/24h/1w/1m)."""
        acc = pool.accounting
        if acc is None:
            return ""
        rng = rng if rng in _CHART_RANGE else "24h"
        span, buckets, sub = _CHART_RANGE[rng]
        now = int(time.time())
        ser = acc.hashrate_series(now, span=span, buckets=buckets, address=address, worker=worker)
        bw, mult = ser["bucket_width"], pool.coin.hashes_per_diff1
        series = [(p["ts"], p["diff"] * mult / bw) for p in ser["points"]]
        svg = _svg_chart(series)
        title = "Rig hashrate" if worker is not None else ("Your hashrate" if address else "Pool hashrate")
        return _chart_block("hashrate", title, sub, svg, _chart_tabs(rng))

    def _landing_payload(self):
        return [{"name": self._slug[p], "snap": p.stats.snapshot()} for p in self.pools]

    def _info(self) -> dict:
        """The exact rules every coin runs by - so anyone can verify the pool's
        behaviour against the AGPL source. No secrets, just the published config."""
        coins = []
        for p in self.pools:
            c, coin = p.cfg, p.coin
            v = c.vardiff
            entry = {
                "coin": c.coin, "chain": c.chain, "algo": coin.algo,
                "mode": c.mode, "stratum_port": c.stratum_port,
                "coinbase_tag": c.coinbase_tag,
                "include_transactions": c.include_transactions,
                "maturity_confirmations": getattr(coin, "maturity", COINBASE_MATURITY),
                "vardiff": {
                    "enabled": v.enabled, "target_time": v.target_time,
                    "min_difficulty": v.min_difficulty, "max_difficulty": v.max_difficulty,
                    "start_difficulty": v.start_difficulty,
                },
            }
            if c.mode == "public":
                pub = c.public
                entry["payout"] = {
                    "model": "PPLNS", "fee_percent": pub.fee_percent,
                    "min_payout": pub.min_payout, "pplns_window": pub.pplns_window,
                    "payout_interval_seconds": pub.payout_interval,
                    "sweep_after_days": pub.sweep_after_days,
                }
            else:
                entry["payout"] = {"model": "solo"}
            coins.append(entry)
        return {
            "software": "TestnetPool", "version": __version__,
            "source": SOURCE_URL, "license": "AGPL-3.0-or-later",
            "coins": coins,
        }

    def _api_index(self) -> dict:
        """Self-describing list of API routes (the p2pool.observer touch). Built from
        the same catalog as the /api/docs page, so the two can never drift."""
        return {
            "software": "TestnetPool", "version": __version__, "source": SOURCE_URL,
            "docs": "/api/docs",
            "endpoints": {p: s for p, s in _api_endpoints(self._single)},
            "notes": ("Read-only, CORS-open, no auth, per-IP rate-limited (HTTP 429 with "
                      "Retry-After when exceeded). Miner IPs are never exposed; reported "
                      "software is coarsened to product + major.minor."),
        }

    def _healthz(self):
        """Healthy iff every pool has a recent block template (the node is reachable
        and we're producing jobs). 200 when all fresh, else 503 - usable by systemd
        WatchdogSec, a load balancer, or an uptime monitor."""
        now = time.time()
        coins, healthy = [], True
        for p in self.pools:
            ts = getattr(p, "last_template_ts", 0.0)
            age = (now - ts) if ts else None
            # Stale if no fresh template in 6x the refresh interval (min 5 min).
            thr = max(300.0, 6 * getattr(p.cfg, "template_refresh", 30.0))
            ok = age is not None and age < thr
            healthy = healthy and ok
            coins.append({"coin": p.cfg.coin, "chain": p.cfg.chain,
                          "template_age_seconds": round(age, 1) if age is not None else None,
                          "ok": ok})
        body = json.dumps({"ok": healthy, "coins": coins}, indent=2).encode()
        status = b"HTTP/1.1 200 OK\r\n" if healthy else b"HTTP/1.1 503 Service Unavailable\r\n"
        return body, "application/json", status

    def _route(self, path: str, host=None, accept="") -> tuple[bytes, str]:
        """Dispatch a request to a coin's pool (single-coin) or the hub (multi)."""
        clean = path.split("?", 1)[0]
        query = path.split("?", 1)[1] if "?" in path else ""

        # Liveness probe (global): the process can be up while mining is wedged
        # (stalled template / unreachable node), so check every pool's template age.
        if clean in ("/healthz", "/api/health"):
            return self._healthz()
        # Transparency: the exact rules the pool runs by, and a self-describing index.
        if clean == "/api/info":
            return self._json(self._info())
        # /api: human docs page to a browser, the JSON index to a script. /api/docs
        # always renders the page (a stable docs URL).
        home = None if self._single else "/"
        if clean == "/api/docs" or (clean in ("/api", "/api/") and "text/html" in accept):
            # Copy-pasteable curl: prefer the operator's canonical site_url, else the
            # sanitized request Host; _render_api_docs falls back to a <host> placeholder.
            base = _META["site_url"].rstrip("/")
            if not base:
                h = self._clean_host(host)
                base = f"https://{h}" if h != "HOST" else ""
            return _render_api_docs(self._single, home, base_url=base).encode(), \
                "text/html; charset=utf-8"
        if clean in ("/api", "/api/"):
            return self._json(self._api_index())

        # Global pages served the same in single- and hub-mode.
        if clean == "/connect":
            home = None if self._single else "/"
            return _render_connect(self._connect_info(host), home_url=home).encode(), \
                "text/html; charset=utf-8"
        if clean == "/donate":
            home = None if self._single else "/"
            return _render_donate(self.donate, home_url=home).encode(), "text/html; charset=utf-8"
        if clean == "/find":
            return self._find(query, host)
        if clean == "/legal":
            home = None if self._single else "/"
            return _render_legal(home_url=home).encode(), "text/html; charset=utf-8"

        if self._single:
            return self._route_for_pool(self.pools[0], path, "/api", host=host)

        if clean in ("/", "", "/index.html"):
            return _render_landing(self._landing_payload()).encode(), "text/html; charset=utf-8"
        if clean == "/api/coins":
            out = []
            for p in self.pools:
                s = p.stats.snapshot()
                out.append({
                    "slug": self._slug[p], "coin": s["coin"], "chain": s["chain"],
                    "height": s["height"],
                    "pool_hashrate_hs": (s.get("pool_hashrate") or {}).get("5m") or s["pool_hashrate_hs"],
                    "active_miners": s["active_miners"], "blocks_found": s["blocks_found"],
                    "network_difficulty": s["network_difficulty"],
                    "network_hashrate_hs": s.get("network_hashrate_hs"),
                    "effort_percent": (s.get("current_round") or {}).get("effort_percent"),
                })
            return self._json({"coins": out})
        # Coin API: /api/<slug>/<endpoint> (matched before the bare-slug dashboard
        # below, so it can't be mistaken for a coin named "api").
        if clean.startswith("/api/"):
            slug, _, tail = clean[len("/api/"):].partition("/")
            pool = self._by_slug.get(slug)
            if pool is None:
                return self._json({"error": "unknown coin"})
            sub = "/api/" + (tail or "stats") + (("?" + query) if query else "")
            return self._route_for_pool(pool, sub, f"/api/{slug}", coin_base=f"/{slug}", host=host)
        # Coin dashboard: /<slug>[/...] is canonical; legacy /c/<slug> still works as an
        # alias. All global routes above are matched first, so a slug can't shadow them.
        head = clean[3:] if clean.startswith("/c/") else clean.lstrip("/")
        slug, _, tail = head.partition("/")
        pool = self._by_slug.get(slug)
        if pool is not None:
            sub = "/" + tail + (("?" + query) if query else "")
            return self._route_for_pool(pool, sub, f"/api/{slug}", home_url="/",
                                        coin_base=f"/{slug}", host=host)
        # unknown -> hub landing
        return _render_landing(self._landing_payload()).encode(), "text/html; charset=utf-8"

    def _template_summary(self, pool) -> dict:
        """The transactions in the pool's current block template - exactly what the next
        block this pool finds will include (backs the 'every transaction, no filtering'
        claim). monerod assembles its own block, so the list is reported unavailable for
        the Monero engine; a coinbase-only pool reports available with tx_count 0."""
        getter = getattr(pool, "current_job", None)  # Pool.current_job() is a method
        job = getter() if callable(getter) else None
        rows = getattr(job, "tx_summary", None) if job is not None else None
        base = {"coin": pool.cfg.coin, "chain": pool.cfg.chain,
                "height": getattr(pool, "current_height", None)}
        if rows is None:
            return {**base, "available": False}
        txs = [{"txid": t["txid"], "fee": t["fee"], "vsize": (t["weight"] + 3) // 4} for t in rows]
        return {**base, "available": True, "height": job.height,
                "full_block": bool(job.include_transactions),
                "tx_count": len(txs),
                "total_fee": sum(t["fee"] for t in txs),
                "total_vsize": sum(t["vsize"] for t in txs),
                "txs": txs}

    def _route_for_pool(self, pool, path: str, api_base: str, home_url=None,
                        coin_base="", host=None) -> tuple[bytes, str]:
        """Everything for one coin: the JSON API, dashboard, and detail pages."""
        acc = pool.accounting  # None in solo mode
        clean = path.split("?", 1)[0]
        html = lambda s: (s.encode(), "text/html; charset=utf-8")

        if clean in ("/stats.json", "/api/stats"):
            return self._json(pool.stats.snapshot())
        if clean == "/api/chart" and acc:
            q = parse_qs(urlsplit(path).query)
            address = (q.get("address", [""])[0] or "").strip() or None
            span, buckets, _sub = _CHART_RANGE[_chart_range(path)]
            ser = acc.hashrate_series(int(time.time()), span=span, buckets=buckets, address=address)
            bw, mult = ser["bucket_width"], pool.coin.hashes_per_diff1
            return self._json({"bucket_width": bw, "points": [
                {"ts": p["ts"], "hashrate_hs": round(p["diff"] * mult / bw, 2)}
                for p in ser["points"]]})
        if clean.startswith("/api/block/") and acc:
            n = _parse_height(clean[len("/api/block/"):])
            block = acc.block_detail(n) if n is not None else None
            if block is None:
                return self._json({"error": "unknown block"})
            return self._json(block)
        if clean == "/api/miners" and acc:
            # Match the HTML leaderboard: drop the faucet (the fee sink, not a miner) unless
            # it currently has live hashrate. Otherwise the API would expose it while the
            # dashboard hides it.
            return self._json({"miners": acc.miners_overview(exclude=getattr(
                getattr(pool.cfg, "public", None), "faucet_address", "") or "",
                exclude_active_since=int(time.time() - HASHRATE_WINDOW))})
        if clean.startswith("/api/miner/"):
            addr = unquote(clean[len("/api/miner/"):]).strip()
            if acc:
                detail = acc.miner_detail(addr)
                if detail is None:
                    return self._json({"error": "unknown miner"})
                return self._json(self._enrich_miner(pool, detail, addr))
            sd = _solo_detail(pool, addr)  # solo: live-only view, no DB
            return self._json(sd if sd is not None
                              else {"error": "no connected rig for that address"})
        if clean.startswith("/api/worker/") and acc:
            parts = clean[len("/api/worker/"):].split("/", 1)  # <addr>/<worker>, both encoded
            if len(parts) != 2 or not parts[1]:
                return self._json({"error": "usage: /api/worker/<address>/<worker>"})
            address, worker = unquote(parts[0]).strip(), unquote(parts[1]).strip()
            wd = acc.worker_detail(address, worker, int(time.time()))
            if wd is None:
                return self._json({"error": "unknown worker"})
            return self._json(self._enrich_worker(pool, wd, address, worker))
        if clean == "/api/blocks" and acc:
            return self._json({"blocks": acc.recent_blocks()})
        if clean == "/api/payouts" and acc:
            return self._json({"payouts": acc.recent_payouts()})
        if clean == "/api/leaderboard" and acc:
            return self._json({"best_shares": acc.best_shares(50)})
        if clean == "/api/luck" and acc:
            blocks = acc.block_luck()
            matured = [b for b in blocks if b["status"] == "matured" and b["net_diff"]]
            srd = sum(b["round_diff"] for b in matured if b["round_diff"] is not None)
            snd = sum(b["net_diff"] for b in matured)
            return self._json({
                "blocks": blocks,
                "pool_luck_percent": round(srd / snd * 100, 2) if snd else None,
                "counts": acc.block_counts(),  # won / orphaned / stale / orphan_rate
            })
        # The block-template tx list is the next block's contents, not accounting data,
        # so it's served in solo mode too - placed before the public-only guard below.
        if clean == "/api/template":
            return self._json(self._template_summary(pool))
        if clean.startswith("/api/") and not acc:
            return self._json({"error": "API available in public mode only"})

        snap = pool.stats.snapshot()

        # Full, bookmarkable per-address miner page.
        if clean.startswith("/miner/"):
            address = unquote(clean[len("/miner/"):]).strip()
            if acc:
                detail = acc.miner_detail(address)
                if detail is not None:
                    self._enrich_miner(pool, detail, address)
                chart = self._chart_for(pool, address=address, rng=_chart_range(path)) if detail else ""
            else:  # solo: live-only detail, no per-address share history to chart
                detail = _solo_detail(pool, address)
                chart = ""
            return html(_render_miner_page(snap, address, detail, chart,
                                           api_base, home_url, coin_base))

        # Per-rig (worker) drill-down page: /worker/<address>/<worker> (public only;
        # solo keeps no per-worker history to chart).
        if clean.startswith("/worker/") and acc:
            parts = clean[len("/worker/"):].split("/", 1)  # both segments are encoded
            if len(parts) == 2 and parts[1]:
                address, worker = unquote(parts[0]).strip(), unquote(parts[1]).strip()
                wd = acc.worker_detail(address, worker, int(time.time()))
                chart = ""
                if wd is not None:
                    self._enrich_worker(pool, wd, address, worker)
                    chart = self._chart_for(pool, address=address, worker=worker, rng=_chart_range(path))
                return html(_render_worker_page(snap, address, worker, wd, chart,
                                                api_base, home_url, coin_base))

        # Per-block detail page.
        if clean.startswith("/block/"):
            n = _parse_height(clean[len("/block/"):].strip())
            block = acc.block_detail(n) if (acc and n is not None) else None
            confs = None
            if block is not None and pool.current_height is not None:
                # current_height is the height being mined (tip+1), so confirmations =
                # current_height - block height (the block is conf #1 when it is the tip).
                confs = max(0, pool.current_height - block["height"])
            # Per-coin maturity (Monero 60, BTC/LTC 100) - same source the snapshot and
            # "How payouts work" use, not the BTC/LTC default.
            maturity = getattr(pool.coin, "maturity", COINBASE_MATURITY)
            return html(_render_block_page(snap, block, confs, maturity,
                                           api_base, home_url, coin_base,
                                           explorer_url=getattr(pool.cfg, "explorer_url", "")))

        # Current block template's transactions (the "every transaction" view, linked
        # from the dashboard note). Served in solo mode too - it's not accounting data.
        if clean == "/template":
            return html(_render_template_page(self._template_summary(pool), api_base,
                                              home_url, coin_base,
                                              explorer_url=getattr(pool.cfg, "explorer_url", ""),
                                              explorer_tx_url=getattr(pool.cfg, "explorer_tx_url", "")))

        # HTML dashboard (default).
        addr = (parse_qs(urlsplit(path).query).get("address", [""])[0] or "").strip()
        detail = luck_blocks = miners = payouts = leaderboard = None
        if acc:
            if addr:
                detail = acc.miner_detail(addr)
                if detail is not None:
                    self._enrich_miner(pool, detail, addr)
            luck_blocks = acc.block_luck(25)
            # Keep the faucet (the pool's fee sink, 0 shares) out of the miners
            # leaderboard - it still appears in Recent payouts when it's paid - UNLESS it
            # currently has live hashrate (e.g. the operator is topping it up), in which
            # case show it (badged "faucet") for transparency.
            miners = acc.miners_overview(25, exclude=getattr(
                getattr(pool.cfg, "public", None), "faucet_address", "") or "",
                exclude_active_since=int(time.time() - HASHRATE_WINDOW))
            payouts = acc.recent_payouts(25)
            leaderboard = acc.best_shares(10)
        elif addr:  # solo: live-only lookup straight off the connections
            detail = _solo_detail(pool, addr)
        return html(_render_html(snap, detail, addr, luck_blocks, miners, payouts,
                                 api_base=api_base, home_url=home_url, coin_base=coin_base,
                                 chart_html=self._chart_for(pool, rng=_chart_range(path)),
                                 leaderboard=leaderboard))

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
