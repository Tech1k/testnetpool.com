# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Configuration loading and validation (TOML via the stdlib ``tomllib``)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field

from .coin import COINS


@dataclass
class RPCConfig:
    host: str = "127.0.0.1"
    port: int = 0  # 0 -> pick the per-chain default
    user: str = ""
    password: str = ""
    cookie_file: str | None = None
    timeout: float = 30.0


@dataclass
class VardiffConfig:
    enabled: bool = True
    start_difficulty: float = 16.0
    min_difficulty: float = 1.0
    max_difficulty: float = 65536.0
    target_time: float = 15.0  # desired seconds between shares
    retarget_time: float = 90.0  # min seconds between difficulty changes
    variance_percent: float = 30.0  # tolerance band before retargeting


@dataclass
class StatsConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8080
    # Trust X-Forwarded-For from a private (RFC1918/ULA) reverse proxy, not just loopback.
    # Off by default: on a private/overlay bind a client could otherwise spoof XFF to evade
    # the rate limit. Enable only when a trusted proxy sits on a private LAN address.
    trust_private_proxy: bool = False
    # Public URL of the dashboard (e.g. "https://testnetpool.com"). Setting it turns
    # on social/OG meta tags + lets search engines index the site; empty keeps it
    # noindex with no absolute-URL tags (fine behind a private proxy).
    site_url: str = ""
    node_dashboard_url: str = ""  # optional link to an external node-status dashboard
    onion: str = ""              # Tor v3 .onion address/URL for the dashboard mirror
    # Per-IP HTTP rate limit for the dashboard/API (requests/minute; 0 = off). Behind a
    # local reverse proxy the client is taken from X-Forwarded-For. The dashboard polls
    # /api/stats every 30s, so 120/min is generous for browsers + normal API use.
    rate_limit_per_min: int = 120


@dataclass
class DonateConfig:
    """Donation addresses shown on /donate (all optional)."""
    openalias: str = ""   # e.g. donate@testnetpool.com (OpenAlias wallets resolve it)
    bitcoin: str = ""
    litecoin: str = ""
    monero: str = ""

    def any(self) -> bool:
        return bool(self.openalias or self.bitcoin or self.litecoin or self.monero)


@dataclass
class PublicConfig:
    """Settings for multi-miner PPLNS mode (mode = "public")."""
    db_path: str = "pool.db"
    wallet: str = ""             # node wallet name for payouts ("" = default wallet)
    pool_address: str = ""       # coinbase pays here; rewards distributed from it
    faucet_address: str = ""     # pool fee + swept dust go here
    fee_percent: float = 1.0
    min_payout: float = 0.001    # in whole coins
    pplns_window: int = 100_000  # number of most-recent shares in the PPLNS window
    payout_interval: float = 300.0
    sweep_after_days: float = 30.0  # idle miners' balances swept to the faucet
    # Monero payouts go through monero-wallet-rpc (port 0 = payouts disabled).
    monero_wallet_host: str = "127.0.0.1"
    monero_wallet_port: int = 0
    monero_wallet_user: str = ""
    monero_wallet_password: str = ""


@dataclass
class Config:
    coin: str = "litecoin"
    chain: str = "regtest"
    mode: str = "solo"  # "solo" -> mine to one address; "public" -> PPLNS multi-miner
    address: str = ""
    stratum_host: str = "0.0.0.0"
    stratum_port: int = 3333
    coinbase_tag: str = "/testnetpool.com/"
    extranonce2_size: int = 4
    include_transactions: bool = False
    longpoll: bool = True
    # Optional block-explorer URL template for the block page; "{hash}" is filled
    # with the block hash (e.g. "https://litecoinspace.org/testnet/block/{hash}").
    explorer_url: str = ""
    # Optional tx-explorer URL template ("{txid}" is filled) for the payout/transaction
    # links. When empty it is derived from explorer_url by swapping "/block/{hash}" ->
    # "/tx/{txid}" (works for the built-in explorers); set this explicitly for a custom
    # explorer whose transaction path doesn't follow that pattern.
    explorer_tx_url: str = ""
    # Optional node ZMQ block publisher (the node's -zmqpubhashblock=tcp://...) for
    # instant new-block detection. With it set, consider longpoll = false.
    zmq_block_url: str = ""
    # Abuse control. An IP that keeps getting reject-flood-dropped is temp-banned
    # automatically (always on). These cap simultaneous connections; 0 = unlimited.
    # The per-IP cap ships ON by default (a public endpoint should never let one IP
    # open unlimited sockets) at a value generous enough for any real farm/NAT; the
    # total cap is left to the operator (size it to your file-descriptor ulimit).
    max_conns_per_ip: int = 100
    max_conns_total: int = 0
    # Optional: POST a small JSON body (height, hash, reward, coin/chain - no miner
    # data) to this URL when a block is found. Point it anywhere that accepts a POST;
    # best-effort, never blocks mining. Empty = disabled.
    block_webhook_url: str = ""
    block_poll_interval: float = 1.0
    template_refresh: float = 30.0
    # How long (seconds) to cache the node's DISPLAY-only stats (mempool depth, peers, tip age,
    # network hashrate) before refetching. These never affect mining, so raise this to lighten
    # RPC load on a node shared with other services (e.g. a faucet) - 300 = refresh every 5 min.
    node_stats_interval: float = 60.0
    rpc: RPCConfig = field(default_factory=RPCConfig)
    vardiff: VardiffConfig = field(default_factory=VardiffConfig)
    stats: StatsConfig = field(default_factory=StatsConfig)
    public: PublicConfig = field(default_factory=PublicConfig)
    donate: DonateConfig = field(default_factory=DonateConfig)

    @property
    def coinbase_address(self) -> str:
        """The address the coinbase pays: the pool wallet in public mode."""
        return self.public.pool_address if self.mode == "public" else self.address


@dataclass
class HubConfig:
    """Multi-coin hub: one process, one dashboard, N per-coin pools (each its own
    coin/node/stratum port).  Produced when the config has a ``[[coins]]`` array."""
    stats: StatsConfig
    coins: list  # list[Config]; per-coin stats servers are disabled (hub owns one)
    donate: DonateConfig = field(default_factory=DonateConfig)


def _section(data: dict, name: str) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"[{name}] must be a table")
    return value


def _onion_url(v: str) -> str:
    """Normalize a config'd .onion (bare address or full URL) to an http URL."""
    v = (v or "").strip().rstrip("/")
    if v and "://" not in v:
        v = "http://" + v
    return v


def load_config(path: str):
    """Load a config file.  Returns a :class:`Config` (single coin) or a
    :class:`HubConfig` (when the file has a ``[[coins]]`` array)."""
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    if "coins" in data:
        hub = _load_hub(data)
        hub.donate = _donate_from(_section(data, "donate"))
        return hub
    cfg = _config_from_sections(
        _section(data, "network"), _section(data, "pool"), _section(data, "rpc"),
        _section(data, "vardiff"), _section(data, "stats"), _section(data, "public"),
    )
    cfg.donate = _donate_from(_section(data, "donate"))
    return cfg


def _donate_from(d: dict) -> DonateConfig:
    return DonateConfig(
        openalias=str(d.get("openalias", "")),
        bitcoin=str(d.get("bitcoin", "")),
        litecoin=str(d.get("litecoin", "")),
        monero=str(d.get("monero", "")),
    )


def _load_hub(data: dict) -> HubConfig:
    s = _section(data, "stats")
    stats_cfg = StatsConfig(
        enabled=bool(s.get("enabled", StatsConfig.enabled)),
        host=s.get("host", StatsConfig.host),
        port=int(s.get("port", StatsConfig.port)),
        site_url=s.get("site_url", StatsConfig.site_url).rstrip("/"),
        node_dashboard_url=s.get("node_dashboard_url", StatsConfig.node_dashboard_url),
        rate_limit_per_min=int(s.get("rate_limit_per_min", StatsConfig.rate_limit_per_min)),
        onion=_onion_url(s.get("onion", StatsConfig.onion)),
        trust_private_proxy=bool(s.get("trust_private_proxy", StatsConfig.trust_private_proxy)),
    )
    defaults = _section(data, "defaults")
    shared_public = _section(data, "public")
    coins = data.get("coins")
    if not isinstance(coins, list) or not coins:
        raise ValueError("[[coins]] must be a non-empty array of tables")

    configs, ports = [], set()
    for i, c in enumerate(coins):
        if not isinstance(c, dict):
            raise ValueError(f"[[coins]] entry {i} must be a table")
        if c.get("coin") is None:
            raise ValueError(f"[[coins]] entry {i} needs a coin")
        if c.get("stratum_port") is None:
            raise ValueError(f"[[coins]] entry {i} ({c.get('coin')!r}) needs a stratum_port")

        def pick(key, fallback):
            return c.get(key, defaults.get(key, fallback))

        # Omit absent keys so _config_from_sections' per-field defaults apply
        # (a present "chain": None would defeat the default-chain fallback).
        net = {k: c[k] for k in ("coin", "chain") if c.get(k) is not None}
        pool_sec = {
            "mode": pick("mode", "public"),
            "address": c.get("address", ""),
            "stratum_host": pick("stratum_host", Config.stratum_host),
            "stratum_port": c.get("stratum_port"),
            "coinbase_tag": pick("coinbase_tag", Config.coinbase_tag),
            "extranonce2_size": pick("extranonce2_size", Config.extranonce2_size),
            "include_transactions": pick("include_transactions", Config.include_transactions),
            "longpoll": pick("longpoll", Config.longpoll),
            "block_poll_interval": pick("block_poll_interval", Config.block_poll_interval),
            "template_refresh": pick("template_refresh", Config.template_refresh),
            "node_stats_interval": pick("node_stats_interval", Config.node_stats_interval),
            "explorer_url": pick("explorer_url", Config.explorer_url),
            "explorer_tx_url": pick("explorer_tx_url", Config.explorer_tx_url),
            "zmq_block_url": pick("zmq_block_url", Config.zmq_block_url),
            "max_conns_per_ip": pick("max_conns_per_ip", Config.max_conns_per_ip),
            "max_conns_total": pick("max_conns_total", Config.max_conns_total),
            "block_webhook_url": pick("block_webhook_url", Config.block_webhook_url),
        }
        rpc_sec = c.get("rpc", {})
        vardiff_sec = c.get("vardiff", defaults.get("vardiff", {}))
        pub_sec = {}
        for k in ("db_path", "wallet", "pool_address", "faucet_address", "fee_percent",
                  "min_payout", "pplns_window", "payout_interval", "sweep_after_days",
                  "monero_wallet_host", "monero_wallet_port",
                  "monero_wallet_user", "monero_wallet_password"):
            if k in c:
                pub_sec[k] = c[k]
            elif k in shared_public:
                pub_sec[k] = shared_public[k]
            elif k in defaults:
                pub_sec[k] = defaults[k]
        pub_sec.setdefault("db_path", f"{c.get('coin', 'coin')}-{c.get('chain', 'chain')}.db")

        cfg = _config_from_sections(net, pool_sec, rpc_sec, vardiff_sec, {"enabled": False}, pub_sec)
        if cfg.stratum_port in ports:
            raise ValueError(f"duplicate stratum_port {cfg.stratum_port} - each coin needs its own")
        ports.add(cfg.stratum_port)
        configs.append(cfg)

    if len({(c.coin, c.chain) for c in configs}) != len(configs):
        raise ValueError("duplicate coin/chain in [[coins]]")
    # Each coin must own its own database; a shared db_path would let two coins'
    # miners/shares/blocks collide (e.g. monero testnet + stagenet under one file).
    db_paths = [c.public.db_path for c in configs if c.mode == "public"]
    if len(set(db_paths)) != len(db_paths):
        raise ValueError("duplicate db_path in [[coins]] - each coin needs its own database")
    # A shared zmq_block_url would make one coin's block notifications trigger every coin's
    # template refresh (cross-coin churn). Each non-empty url must be unique.
    zmq_urls = [c.zmq_block_url for c in configs if c.zmq_block_url]
    if len(set(zmq_urls)) != len(zmq_urls):
        raise ValueError("duplicate zmq_block_url in [[coins]] - each coin needs its own node endpoint")
    return HubConfig(stats=stats_cfg, coins=configs)


# Vardiff (start, min, max) difficulty per algo. The class defaults (start 16, max 65536)
# suit CPU mining (RandomX, and scrypt cpuminer on testnet), but a SHA-256 ASIC needs a much
# higher floor AND ceiling. At diff 16 it would flood ~millions of shares/sec, so its firmware
# (and rental proxies like MiningRigRentals) just refuses the work and disconnects; and a big
# rented rig's optimal difficulty is in the MILLIONS (MRR flags anything lower as "too low"),
# so the 65536 cap would trap it - vardiff, suggest_difficulty and a "d=" password all clamp to
# max_difficulty - well below where it can mine efficiently. Operators can override in [vardiff].
_ALGO_VARDIFF_FLOOR = {  # algo -> (start, min, max)
    "sha256d": (16384.0, 512.0, 2.0 ** 30),  # Bitcoin: bitaxe (~1.7K) to PH/s rentals (millions)
    "scrypt": (16.0, 1.0, 2.0 ** 26),        # Litecoin: cpuminer (low) up to L7 ASICs (~2M)
}


def _config_from_sections(net, pool, rpc, vardiff, stats, public) -> Config:
    cfg = Config()
    cfg.coin = net.get("coin", cfg.coin)
    if cfg.coin not in COINS:
        raise ValueError(f"network.coin must be one of {tuple(COINS)}, got {cfg.coin!r}")
    coin = COINS[cfg.coin]
    cfg.chain = net.get("chain", cfg.chain)
    if cfg.coin == "monero" and cfg.chain == "mainnet":
        raise ValueError(
            "monero support is TRUST-BASED (shares are credited without RandomX "
            "verification) and is only safe on testnet/stagenet - refusing mainnet")
    if cfg.chain not in coin.networks:
        raise ValueError(
            f"network.chain must be one of {tuple(coin.networks)} for {cfg.coin}, "
            f"got {cfg.chain!r}"
        )

    cfg.mode = pool.get("mode", cfg.mode)
    if cfg.mode not in ("solo", "public"):
        raise ValueError(f"pool.mode must be 'solo' or 'public', got {cfg.mode!r}")
    cfg.address = pool.get("address", "")
    cfg.stratum_host = pool.get("stratum_host", cfg.stratum_host)
    cfg.stratum_port = int(pool.get("stratum_port", cfg.stratum_port))
    cfg.coinbase_tag = pool.get("coinbase_tag", cfg.coinbase_tag)
    cfg.extranonce2_size = int(pool.get("extranonce2_size", cfg.extranonce2_size))
    cfg.include_transactions = bool(
        pool.get("include_transactions", cfg.include_transactions)
    )
    cfg.longpoll = bool(pool.get("longpoll", cfg.longpoll))
    cfg.block_poll_interval = float(pool.get("block_poll_interval", cfg.block_poll_interval))
    cfg.template_refresh = float(pool.get("template_refresh", cfg.template_refresh))
    cfg.node_stats_interval = float(pool.get("node_stats_interval", cfg.node_stats_interval))
    cfg.explorer_url = pool.get("explorer_url", cfg.explorer_url)
    cfg.explorer_tx_url = pool.get("explorer_tx_url", cfg.explorer_tx_url)
    cfg.zmq_block_url = pool.get("zmq_block_url", cfg.zmq_block_url)
    cfg.max_conns_per_ip = int(pool.get("max_conns_per_ip", cfg.max_conns_per_ip))
    cfg.max_conns_total = int(pool.get("max_conns_total", cfg.max_conns_total))
    cfg.block_webhook_url = pool.get("block_webhook_url", cfg.block_webhook_url)

    cfg.rpc = RPCConfig(
        host=rpc.get("host", RPCConfig.host),
        port=int(rpc.get("port", 0)) or coin.network(cfg.chain).rpc_port,
        user=rpc.get("user", ""),
        password=rpc.get("password", ""),
        cookie_file=rpc.get("cookie_file") or None,
        timeout=float(rpc.get("timeout", RPCConfig.timeout)),
    )

    # Default the vardiff floor to suit the coin's algo (ASICs can't mine at the CPU-tuned
    # default of 16) unless the operator set it explicitly in [vardiff].
    d_start, d_min, d_max = _ALGO_VARDIFF_FLOOR.get(
        coin.algo, (VardiffConfig.start_difficulty, VardiffConfig.min_difficulty,
                    VardiffConfig.max_difficulty))
    cfg.vardiff = VardiffConfig(
        enabled=bool(vardiff.get("enabled", VardiffConfig.enabled)),
        start_difficulty=float(vardiff.get("start_difficulty", d_start)),
        min_difficulty=float(vardiff.get("min_difficulty", d_min)),
        max_difficulty=float(vardiff.get("max_difficulty", d_max)),
        target_time=float(vardiff.get("target_time", VardiffConfig.target_time)),
        retarget_time=float(vardiff.get("retarget_time", VardiffConfig.retarget_time)),
        variance_percent=float(vardiff.get("variance_percent", VardiffConfig.variance_percent)),
    )

    cfg.stats = StatsConfig(
        enabled=bool(stats.get("enabled", StatsConfig.enabled)),
        host=stats.get("host", StatsConfig.host),
        port=int(stats.get("port", StatsConfig.port)),
        site_url=stats.get("site_url", StatsConfig.site_url).rstrip("/"),
        node_dashboard_url=stats.get("node_dashboard_url", StatsConfig.node_dashboard_url),
        rate_limit_per_min=int(stats.get("rate_limit_per_min", StatsConfig.rate_limit_per_min)),
        onion=_onion_url(stats.get("onion", StatsConfig.onion)),
        trust_private_proxy=bool(stats.get("trust_private_proxy", StatsConfig.trust_private_proxy)),
    )

    cfg.public = PublicConfig(
        db_path=public.get("db_path", PublicConfig.db_path),
        wallet=public.get("wallet", ""),
        pool_address=public.get("pool_address", ""),
        faucet_address=public.get("faucet_address", ""),
        fee_percent=float(public.get("fee_percent", PublicConfig.fee_percent)),
        min_payout=float(public.get("min_payout", PublicConfig.min_payout)),
        pplns_window=int(public.get("pplns_window", PublicConfig.pplns_window)),
        payout_interval=float(public.get("payout_interval", PublicConfig.payout_interval)),
        sweep_after_days=float(public.get("sweep_after_days", PublicConfig.sweep_after_days)),
        monero_wallet_host=public.get("monero_wallet_host", PublicConfig.monero_wallet_host),
        monero_wallet_port=int(public.get("monero_wallet_port", 0)),
        monero_wallet_user=public.get("monero_wallet_user", ""),
        monero_wallet_password=public.get("monero_wallet_password", ""),
    )

    _validate(cfg)
    return cfg


def _validate(cfg: Config) -> None:
    # Fail closed: the Monero engine credits shares TRUST-BASED (no RandomX
    # verification), which is only safe where coins are worthless.
    if cfg.coin == "monero" and cfg.chain == "mainnet":
        raise ValueError(
            "monero support is TRUST-BASED (shares are credited without RandomX "
            "verification) and is only safe on testnet/stagenet - refusing mainnet")
    if not (1 <= cfg.extranonce2_size <= 8):
        raise ValueError("pool.extranonce2_size must be between 1 and 8")
    # monerod commonly runs without RPC auth on a local testnet/stagenet; only the
    # Bitcoin/Litecoin nodes require credentials here.
    if cfg.coin != "monero" and not cfg.rpc.cookie_file and not (cfg.rpc.user and cfg.rpc.password):
        raise ValueError(
            "set rpc.user + rpc.password, or rpc.cookie_file, to authenticate to the node"
        )
    if cfg.vardiff.min_difficulty <= 0:
        raise ValueError("vardiff.min_difficulty must be > 0")
    if cfg.vardiff.max_difficulty < cfg.vardiff.min_difficulty:
        raise ValueError("vardiff.max_difficulty must be >= min_difficulty")
    # Vardiff timing: target_time/retarget_time of 0 would make every share retarget
    # instantly (ratcheting miners to min); variance_percent >= 100 makes the band
    # one-sided (difficulty can only fall). Reject non-sane values up front.
    for label, val in (("vardiff.target_time", cfg.vardiff.target_time),
                       ("vardiff.retarget_time", cfg.vardiff.retarget_time)):
        if val <= 0:
            raise ValueError(f"{label} must be > 0 (got {val})")
    if not (0 <= cfg.vardiff.variance_percent < 100):
        raise ValueError(
            f"vardiff.variance_percent must be in [0, 100) (got {cfg.vardiff.variance_percent})")
    # Bind ports must be in range. stats.port only matters when the dashboard is enabled;
    # rpc.port == 0 is intentional (falls back to the per-chain default downstream).
    if not (1 <= cfg.stratum_port <= 65535):
        raise ValueError(f"pool.stratum_port must be in 1..65535 (got {cfg.stratum_port})")
    if cfg.stats.enabled and not (1 <= cfg.stats.port <= 65535):
        raise ValueError(f"stats.port must be in 1..65535 (got {cfg.stats.port})")
    # Reject non-positive intervals/timeouts: a negative/zero poll interval makes
    # asyncio.sleep() return immediately, turning a background loop into a tight
    # busy-loop that hammers the node; a non-positive rpc.timeout fails opaquely.
    for label, val in (("pool.block_poll_interval", cfg.block_poll_interval),
                       ("rpc.timeout", cfg.rpc.timeout),
                       ("public.payout_interval", cfg.public.payout_interval)):
        if val <= 0:
            raise ValueError(f"{label} must be > 0 (got {val})")
    # template_refresh == 0 is meaningful: "rebuild only when a block arrives" (skip the idle
    # ntime rebuild); node_stats_interval == 0 means refresh every template. Only NEGATIVE is
    # invalid (a negative poll interval would busy-loop).
    if cfg.template_refresh < 0:
        raise ValueError(f"pool.template_refresh must be >= 0 (got {cfg.template_refresh})")
    if cfg.node_stats_interval < 0:
        raise ValueError(f"pool.node_stats_interval must be >= 0 (got {cfg.node_stats_interval})")
    # Explorer templates must carry their placeholder, else every link would point at one
    # static page (fail closed rather than silently mislink every block/payout).
    if cfg.explorer_url and "{hash}" not in cfg.explorer_url:
        raise ValueError("pool.explorer_url must contain '{hash}' (e.g. "
                         f"https://mempool.space/testnet4/block/{{hash}}); got {cfg.explorer_url!r}")
    if cfg.explorer_tx_url and "{txid}" not in cfg.explorer_tx_url:
        raise ValueError("pool.explorer_tx_url must contain '{txid}' (e.g. "
                         f"https://mempool.space/testnet4/tx/{{txid}}); got {cfg.explorer_tx_url!r}")
    if cfg.public.sweep_after_days <= 0:
        # 0 would set the idle cutoff to "now", sweeping EVERY miner's balance to the
        # faucet on the first hourly tick. Require a positive horizon.
        raise ValueError(f"public.sweep_after_days must be > 0 (got {cfg.public.sweep_after_days})")
    # Caps/limits: 0 = unlimited/off; a NEGATIVE value would silently lock out every
    # miner (the conn caps) or be a confusing no-op (the rate limit), so reject it.
    for label, val in (("pool.max_conns_per_ip", cfg.max_conns_per_ip),
                       ("pool.max_conns_total", cfg.max_conns_total),
                       ("stats.rate_limit_per_min", cfg.stats.rate_limit_per_min)):
        if val < 0:
            raise ValueError(f"{label} must be >= 0 (got {val}; 0 = unlimited/off)")

    # Validate the relevant payout addresses against the coin+chain up-front so we
    # fail loudly at startup instead of when the first block is found.  Monero uses
    # CryptoNote addresses; Bitcoin/Litecoin use the script-encoder check.
    if cfg.coin == "monero":
        from .cryptonote import CryptoNoteError, validate_address

        def _check(addr, label):
            try:
                validate_address(addr, cfg.chain)
            except CryptoNoteError as exc:
                raise ValueError(f"{label}: {exc}")
    else:
        from .address import address_to_script

        net = COINS[cfg.coin].network(cfg.chain)

        def _check(addr, label):
            address_to_script(addr, net)

    if cfg.mode == "solo":
        if not cfg.address:
            raise ValueError("pool.address is required in solo mode (the wallet to mine to)")
        _check(cfg.address, "pool.address")
    else:  # public
        if not cfg.public.pool_address:
            raise ValueError("public.pool_address is required in public mode")
        if not cfg.public.faucet_address:
            raise ValueError("public.faucet_address is required in public mode")
        _check(cfg.public.pool_address, "public.pool_address")
        _check(cfg.public.faucet_address, "public.faucet_address")
        if not (0 <= cfg.public.fee_percent < 100):
            raise ValueError("public.fee_percent must be in [0, 100)")
        if cfg.public.min_payout <= 0:
            raise ValueError("public.min_payout must be > 0")
        if cfg.public.pplns_window < 1:
            raise ValueError("public.pplns_window must be >= 1")
