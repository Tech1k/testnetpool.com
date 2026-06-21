# TestnetPool

A small, self-hostable **Stratum mining pool** for **Bitcoin**, **Litecoin**
(post-MWEB), and **Monero**, the engine behind
[testnetpool.com](https://testnetpool.com). Run it **solo** (mine straight to one
wallet) or **public** (multi-miner PPLNS with carry-forward payouts and a
fee-to-faucet model).

## Features

- Pure Python 3.11+ standard library - **no third-party packages**. PoW is
  `hashlib.scrypt` (Litecoin) / double-SHA256 (Bitcoin), each verified against a
  known block; **Monero/RandomX** is verified by the node (shares are trust-based
  on testnet - see below), so there's still no native dependency.
- **Bitcoin** (`main`/`test`/`testnet4`/`signet`/`regtest`), **Litecoin**
  (`main`/`test`/`regtest`), and **Monero** (`mainnet`/`testnet`/`stagenet`),
  selected by config.
- **Solo mode**: full block reward to your address via `submitblock`.
- **Public mode**: address-as-username, SQLite share accounting, PPLNS split on
  block maturity (orphan-safe), `sendmany` payouts over a threshold, fee + swept
  dust to your faucet, and a JSON API for a front-end.
- Correct on a **post-MWEB** chain; per-miner **self-tuning vardiff** (no
  difficulty config needed - it ramps each miner up or down automatically),
  **version-rolling** (ASICBoost), and **long-poll** instant block updates.
- **Explorer-style dashboard**: bookmarkable
  per-address **miner pages** (`/miner/<addr>`), **block detail** pages
  (`/block/<height>`), a **connect** / getting-started page, inline-SVG **hashrate
  charts** with hover tooltips, **live** in-place stat updates, and a JSON API,
  all zero-dependency and fully offline (no CDN/fonts/images).

**Built for testnets.** The block-construction and payout paths are validated
against real bitcoind/litecoind and real rented hashrate, but always exercise on
**regtest/testnet first**. See [Public mode (PPLNS)](#public-mode-pplns) below for
how multi-miner accounting and payouts work.

## Coins & networks

Pick a coin + chain in `[network]`. Everything else (Stratum, coinbase build,
witness commitment, vardiff, stats) is shared; only the PoW hash, difficulty-1
constant, addresses, GBT rules and default ports differ per coin.

| coin | chains | algo | miners |
| --- | --- | --- | --- |
| `litecoin` | `main`, `test`, `regtest` | scrypt | cgminer/sgminer, cpuminer (`-a scrypt`) |
| `bitcoin` | `main`, `test` (testnet3), `testnet4`, `signet`, `regtest` | sha256d | ASIC/bfgminer/cgminer, cpuminer (`-a sha256d`) |
| `monero` | `mainnet`, `testnet`, `stagenet` | RandomX | xmrig (CryptoNote Stratum) |

**signet** blocks must be signed by the signet challenge key, so a normal pool
can't mine the public signet; use it only with a custom signet you control.

**Monero** is a separate engine (CryptoNote Stratum + monerod RPC, see the Monero
section of [`config.example.toml`](config.example.toml)). RandomX has no Python
implementation, so shares are accepted **trust-based**: the miner's submitted
result is trusted and `monerod` is the final arbiter for real blocks via
`submit_block`. That's fine for a worthless-coin testnet/stagenet faucet pool and
keeps the project pure-Python; **don't run trust-based shares on mainnet.** Payouts
go through `monero-wallet-rpc`.

## Requirements

- Python **3.11+** (uses the stdlib `tomllib`).
- A synced node for your coin with RPC enabled: **litecoind** (Litecoin Core
  0.21.2+ for MWEB), **bitcoind**, or **monerod** (plus **monero-wallet-rpc**
  for Monero payouts).
- A miner that speaks Stratum: `cgminer`/`sgminer`/ASIC, or `cpuminer`/`minerd`
  for CPU testing (`-a scrypt` for LTC, `-a sha256d` for BTC).

## Quick start

```sh
pip install testnetpool          # or: git clone ... && pip install .  (or just run python3 -m testnetpool from a clone)

cp config.example.toml config.toml
# edit config.toml: keep the [[coins]] entry you want (delete the rest), and set
# its rpc credentials + your pool/faucet address. one coin or many - same format.
testnetpool --check -c config.toml      # validate config   (or: python3 -m testnetpool ...)
testnetpool -c config.toml              # run
```

Then point a miner at `stratum+tcp://<host>:3333` and open the status page at
`http://127.0.0.1:8080/`.

## Can I test it on regtest locally? - yes

This is the recommended first step. Regtest has trivial difficulty, so a CPU
miner finds "blocks" in seconds and you can watch the whole pipeline work
(`getblocktemplate` → job → share → `submitblock` → block count increments)
without spending anything.

**1. Run litecoind in regtest** (`~/.litecoin/litecoin.conf` or flags):

```ini
regtest=1
server=1
rpcuser=rpcuser
rpcpassword=rpcpassword
[regtest]
rpcport=19443
```

```sh
litecoind -regtest -daemon
```

**2. Mine some blocks + get a payout address.** Mine ~200 blocks: enough to
mature coinbase outputs (100-block maturity) and activate segwit, but **stay
below height 432** - see the MWEB caveat below.

```sh
litecoin-cli -regtest createwallet poolwallet                 # if you have no wallet
WCLI="litecoin-cli -regtest -rpcwallet=poolwallet"
ADDR=$($WCLI getnewaddress "" bech32)                          # your payout address
$WCLI generatetoaddress 200 "$($WCLI getnewaddress)"          # mine to a throwaway addr
echo "$ADDR"
```

**regtest + MWEB caveat.** MWEB activates on regtest at **height 432**. Once the
tip reaches it, litecoind's own block assembler tries to build a degenerate MWEB
HogEx and `getblocktemplate` starts failing with `bad-txns-vin-empty`, a node-side
regtest quirk, not the pool. So keep your regtest tip under ~430 while testing. If
you blow past it, just start over: `litecoin-cli -regtest stop`,
`rm -rf ~/.litecoin/regtest`, restart, and mine ~200 again. (This only affects
*regtest*; testnet/mainnet have real MWEB state and work fine; use testnet if you
want to exercise the post-MWEB path.)

**3. Configure TestnetPool** (`config.toml`):

```toml
[network]
chain = "regtest"

[pool]
address = "rltc1q...   # the $ADDR from above"
stratum_port = 3333
include_transactions = false

[rpc]
host = "127.0.0.1"
port = 19443
user = "rpcuser"
password = "rpcpassword"

[vardiff]
enabled = false
start_difficulty = 1     # low, so a slow CPU miner finds shares in seconds on regtest

[stats]
enabled = true
host = "127.0.0.1"
port = 8080
```

Validate and run:

```sh
python3 -m testnetpool --check -c config.toml
python3 -m testnetpool -c config.toml --log-level info
```

**4. Point a CPU miner at it.** [pooler/cpuminer](https://github.com/pooler/cpuminer)
(`minerd`) speaks Scrypt + Stratum. The official prebuilt binary works as-is:

```sh
minerd -a scrypt -o stratum+tcp://127.0.0.1:3333 -u myworker -p x -t 2
```

Within seconds minerd prints `accepted: N/N (100.00%) (yay!!!)` and the pool log
shows, per block:

```
*** BLOCK CANDIDATE from myworker (...) height=206 ... ***
################ BLOCK ACCEPTED at height 206! ################
```

Confirm on the node and watch the rewards accrue (immature until 100 confirms):

```sh
litecoin-cli -regtest getblockcount
litecoin-cli -regtest -rpcwallet=poolwallet getbalances   # see "immature"
```

...and the live status page at <http://127.0.0.1:8080/>.

This flow was validated end-to-end against Litecoin Core v0.21.5.5:
pooler-cpuminer 2.5.1 → TestnetPool → `submitblock`, 100% share acceptance,
coinbase paying the configured address.

**Difficulty note.** On regtest the network target is trivially easy, so *every*
accepted share is also a block. Keep `start_difficulty` low (≈1) for a fast CPU
demo; raise it if minerd is flooding blocks too quickly toward height 432.

**Troubleshooting**

- *`getblocktemplate ... bad-txns-vin-empty`* - your regtest tip is at/after the
  MWEB activation height (432). Reset regtest (see the caveat above).
- *`getblocktemplate ... must be called with the segwit & mweb rule sets`* - your
  litecoind predates MWEB; upgrade to 0.21.2+.
- *Miner connects but submits no shares* - `start_difficulty` is too high for the
  miner's hashrate; lower it.
- *Miner says "stratum connection failed"* - check `stratum_host`/port and that
  the pool actually reached the node (the log prints `connected to litecoind`).

## Testnet

**Litecoin testnet:** `coin = "litecoin"`, `chain = "test"`, run
`litecoind -testnet` (default `rpcport = 19332`), `tltc1...`/`m...` address.

**Bitcoin testnet:** `coin = "bitcoin"`, `chain = "test"` (testnet3, rpc 18332) or
`"testnet4"` (rpc 48332, Bitcoin Core 28+), run `bitcoind -testnet`/`-testnet4`,
`tb1...` address. (See the bitcoin entry in [`config.example.toml`](config.example.toml).)

**Reality check on real testnets.** Unlike regtest, testnet/testnet4 PoW is real.
Bitcoin testnet difficulty in particular is often high (then drops to 1 under the
20-minutes-without-a-block rule), so CPU mining lands blocks only sporadically;
point an ASIC at it, or just use a faucet for coins and use the pool as a working
endpoint. Tune `vardiff.start_difficulty` to your hardware.

## Mainnet

Set `chain = "main"`, point at your mainnet node, and use a real `ltc1...`/`L...`
address. You can leave `include_transactions = false`, but note that Litecoin
mainnet is post-MWEB, so the pool automatically builds full MWEB blocks anyway
(see the post-MWEB override below) - a coinbase-only block would be rejected
`mweb-missing`. Flip `include_transactions = true` if you also want fees on any
pre-MWEB chain.

## How it works

Each poll cycle the pool calls `getblocktemplate` (with the required
`["segwit", "mweb"]` rules), builds a coinbase paying your address, splits it
into `coinb1`/`coinb2` around the extranonce, computes the merkle branch, and
broadcasts a `mining.notify` job. Submitted shares are reconstructed into the
80-byte header, hashed with Scrypt(N=1024,r=1,p=1), and checked against both the
miner's vardiff target (accepted share) and the network target (a block →
`submitblock`).

### Two block-construction modes

- **`include_transactions = false` (default)** - the block contains only the
  coinbase. No witness data, no witness commitment, no MWEB suffix; the coinbase
  claims the subsidy only (`coinbasevalue` minus the fees of the dropped txs).
  This keeps the simplest block layout and forfeits the (small) fee portion.

  **Post-MWEB override.** Once MWEB is active (Litecoin testnet/mainnet today),
  consensus requires the MWEB extension block in *every* block; a coinbase-only
  block is rejected by the node as **`mweb-missing`**, losing the found block. So
  whenever a template carries `mweb` data the pool **automatically upgrades that
  block to full mode** (all transactions incl. the HogEx + the `mweb` blob + the
  witness commitment), regardless of this setting, and logs the override once.
  In practice this means: on post-MWEB chains you always mine full blocks.

- **`include_transactions = true`** - include every transaction from the template
  (which already contains the MWEB **HogEx** as its final entry when MWEB txs are
  present), add the segwit witness commitment to the coinbase (from GBT's
  `default_witness_commitment`), serialize the coinbase in BIP144 witness form,
  and append the MWEB extension after the last transaction as Litecoin's `CBlock`
  expects: a `0x01` "present" marker (the `WrapOptionalPtr` flag) followed by the
  template's `mweb` hex. GBT's `mweb` field is only the inner `mw::Block`, so the
  marker byte must be added - omitting it makes the node read the stream as having
  no MWEB block and reject with `mweb-missing`. This collects fees and follows the
  MWEB block layout. Forcing this on is equivalent
  to the post-MWEB override above; on a pre-MWEB chain it additionally collects
  fees. **Test on regtest first.**

The byte layouts were verified against Litecoin Core v0.21.5.5
(`getblocktemplate`/`submitblock` handling, `CBlock` serialization with MWEB
appended after `vtx`, BIP141 optional-commitment rule, BIP34 height push, and
the Scrypt PoW path).

### Addresses

Payout must be a normal **on-chain** address for the chain: legacy
(`L`/`m`/`n`), P2SH (`M`/`Q`/`3`/`2`), or native segwit
(`ltc1`/`tltc1`/`rltc1`). MWEB addresses are **not** valid as a coinbase target -
a coinbase can't pay directly into MWEB. The subsidy lands on-chain; move it to
MWEB from your wallet afterward if you want privacy.

### Public mode (PPLNS)

`mode = "public"` turns the solo daemon into a multi-miner pool: miners connect
with **their own payout address as the Stratum username**, the coinbase pays the
**pool wallet**, and found blocks are split PPLNS with carry-forward. A block flows
through five stages:

1. **Share accepted** - a row in `shares`, weighted by difficulty and keyed to the
   miner's address.
2. **Block found** - the coinbase pays the pool wallet, and the PPLNS split over the
   last `pplns_window` shares is snapshotted into `credits` as `immature`. The fee
   plus the rounding remainder become a faucet credit.
3. **Maturity** (checked every 60 s) - an immature block no longer on the main chain
   is **orphaned** and its credits are dropped (nothing was applied, so there is
   nothing to reverse); at 100 confirmations it **matures** and its credits are
   applied to `balances`.
4. **Payout** (every `payout_interval`) - miners with `owed >= min_payout` are paid
   by one `sendmany` from the pool wallet, bounded by the spendable matured balance.
5. **Sweep** (hourly) - balances of miners idle past `sweep_after_days` move to the
   faucet.

Crediting on maturity rather than on discovery is the money-safety property:
orphans need no balance reversal, and a payout can never exceed what the pool has
actually mined. No reserve, no runaway drain.

**Node wallet.** Payouts come from a node wallet holding your `pool_address` (where
the coinbase pays), so the pool can `sendmany`. Point `[public] wallet` at it, or
leave it blank for the node's default wallet; if the node has several wallets
loaded you must name one, or Bitcoin/Litecoin Core rejects wallet RPCs with
*"Wallet file not specified"*. Coinbase funds are spendable only after 100
confirmations (`getbalance` already excludes immature coinbase), so payouts wait
for maturity; pre-funding the pool wallet from your faucet makes them prompt.

## Configuration

See [`config.example.toml`](config.example.toml) for every option with comments.
Highlights:

| Key | Meaning |
| --- | --- |
| `network.chain` | `main` / `test` / `regtest` |
| `pool.address` | wallet address to mine to (required) |
| `pool.stratum_port` | port miners connect to (default 3333) |
| `pool.include_transactions` | collect fees + MWEB (default `false`) |
| `pool.block_poll_interval` | seconds between new-tip checks |
| `rpc.*` | litecoind host/port + `user`/`password` or `cookie_file` |
| `vardiff.*` | per-miner difficulty targeting |
| `stats.*` | status HTTP page bind + port |

### Running multiple coins (hub mode)

One process, one dashboard, several coins. Give the config a `[[coins]]` array
instead of `[network]`/`[pool]` and TestnetPool starts in **hub mode**: each coin
gets its own node, Stratum port, and database, but they share a single process and
a single dashboard / JSON API. Miners pick a coin by connecting to its port.

```toml
[stats]              # the one shared dashboard
port = 8080

[defaults]           # applied to every coin (override per-coin)
mode = "public"
coinbase_tag = "/testnetpool.com/"

[[coins]]
coin = "bitcoin"
chain = "testnet4"
stratum_port = 3333
pool_address = "tb1q..."
[coins.rpc]
user = "bitcoinrpc"
password = "..."

[[coins]]
coin = "litecoin"
chain = "test"
stratum_port = 3334
pool_address = "tltc1q..."
[coins.rpc]
user = "litecoinrpc"
password = "..."
```

```sh
python3 -m testnetpool -c config.toml          # runs every coin under one dashboard
python3 -m testnetpool -c config.toml --check  # list the coins it will run
```

The dashboard landing page lists every coin and links to each at `/c/<coin>`;
per-coin JSON lives under `/api/<coin>/...`. A connection only ever mines the coin
of the port it connected to - shares and payouts are kept strictly per-coin.
[`config.example.toml`](config.example.toml) **is** this hub format, fully
documented - running a single coin is just one `[[coins]]` entry. (The older
`[network]`/`[pool]` single-coin layout also still works.)

## JSON API

Everything the dashboard shows is a read-only, CORS-open JSON endpoint (no auth, no
keys) - point a front-end, `curl`, or `jq` at it. `GET /api` returns a self-describing
index of every route. In hub mode each coin lives under `/api/<coin>/...`.

| endpoint | what |
| --- | --- |
| `/api` | self-describing list of all routes |
| `/api/info` | the pool's exact rules + version + AGPL source (verify against the code) |
| `/api/stats` | live snapshot: hashrate, blocks, **mempool depth**, **reject reasons**, orphan rate |
| `/api/chart?range=1h\|24h\|1w\|1m` | hashrate time series |
| `/api/miners`, `/api/miner/<address>` | miner overview / one miner's workers + balance |
| `/api/blocks`, `/api/block/<height>` | found blocks (incl. orphaned/**stale**) / one block |
| `/api/payouts`, `/api/luck` | payouts / per-block effort + pool luck + orphan rate |
| `/healthz` | liveness probe (`200` fresh template / `503` stalled node) |

**Privacy:** the API exposes the pool's behaviour, never miners' IPs.

Building a custom public site? Point it at this API; it's the stable contract
(reading `pool.db` directly works too, but the API avoids WAL file-permission
fuss). The exact per-endpoint detail is the self-describing `GET /api` itself,
which also renders as a docs page in a browser.

## Testing

```sh
python3 -m testnetpool --selftest     # consensus-primitive + block-construction checks
python3 tests/integration.py          # full Stratum round-trip with a mocked node (solo)
python3 tests/public.py               # public/PPLNS share recording + payouts
python3 tests/dashboard.py            # stats snapshot + dashboard rendering
python3 tests/hub.py                  # multi-coin hub: routing + coin isolation
python3 tests/vardiff.py             # self-tuning difficulty controller
python3 tests/monero.py              # pure-Python Monero/CryptoNote primitives
python3 tests/monero_pool.py         # Monero engine vs a mocked monerod
python3 tests/dedup.py               # per-connection duplicate-share rejection
python3 tests/zmq.py                 # pure-Python ZMTP block-notify listener
python3 tests/bans.py                # per-IP abuse control (conn caps + temp-ban)
python3 tests/payout.py              # payout-verify: a timed-out sendmany can't double-pay
python3 tests/webhook.py             # generic block-found webhook delivery
python3 tests/qr.py                  # pure-Python QR encoder (donate-page address codes)
python3 tests/find.py                # global address search: classify + route to the right coin
python3 tests/audit.py               # regressions for the final-audit fixes (mainnet guard, orphan/credit)
```

The self-tests cover the Scrypt vector, `bits`→target, BIP34 height encoding, the
Stratum prevhash transform, address decoding (against BIP173/base58 anchors), and
coinbase/merkle/block round-trips for empty, segwit, and MWEB templates. The
integration test drives a real socket through subscribe→authorize→notify→submit
and asserts the miner's header (rebuilt from wire fields only) matches the pool's.

## Deploying

The pool is a long-running **daemon**, not a per-request app: systemd runs it,
miners connect to the **Stratum TCP port directly**, and Apache only ever touches
the **dashboard** (Stratum is raw TCP and never goes behind Apache).

```
miners --TCP:3333--> TestnetPool (systemd) --RPC--> bitcoind / litecoind
                         | writes pool.db (public mode)
                         v
  dashboard: built-in HTTP / JSON API  --(Apache reverse proxy)--> web
```

### Service user + config

```sh
# A locked-down system user (no login, no password; the matching group is created
# with it). You do NOT pre-create /var/lib/testnetpool: the unit's
# StateDirectory=testnetpool makes systemd create it, owned by this user, on start.
sudo useradd --system --home-dir /var/lib/testnetpool --shell /usr/sbin/nologin testnetpool

# Config holds RPC credentials, so lock it to the service user.
sudo mkdir -p /etc/testnetpool
sudo cp config.example.toml /etc/testnetpool/config.toml   # edit: RPC, addresses, ports
sudo chown -R testnetpool:testnetpool /etc/testnetpool
sudo chmod 600 /etc/testnetpool/config.toml
```

Point each coin's `db_path` at the state dir, e.g.
`db_path = "/var/lib/testnetpool/litecoin-test.db"`, so the databases land in the
service's `StateDirectory`. If you authenticate to the node with a **cookie file**
rather than `rpcuser`/`rpcpassword`, the `testnetpool` user must be able to read it
(e.g. add it to the node's group), or RPC fails at startup.

### systemd

The pool runs **every coin in one process** (hub mode), so the default is a single
service reading one config:

```sh
sudo cp contrib/systemd/testnetpool.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now testnetpool          # uses /etc/testnetpool/config.toml
journalctl -u testnetpool -f
```

For a **separate process per coin** (isolation, so one can restart without touching
the others), use the templated unit with one config file per coin, named to match:

```sh
sudo cp contrib/systemd/testnetpool@.service /etc/systemd/system/
sudo systemctl enable --now testnetpool@btc      # uses /etc/testnetpool/btc.toml
sudo systemctl enable --now testnetpool@ltc      # uses /etc/testnetpool/ltc.toml
```

(If you copy-deployed instead of `pip install`, set `WorkingDirectory` to the repo
and keep `ExecStart=/usr/bin/python3 -m testnetpool ...`, or use a venv's python.)

### Firewall

```sh
ufw allow 3333/tcp     # stratum - miners connect here directly
ufw allow 443/tcp      # dashboard (https)
# keep the node RPC bound to 127.0.0.1; never expose it
```

### Dashboard behind Apache

The daemon serves the HTML status page + JSON API on `[stats] port`. Bind it to
`127.0.0.1` and reverse-proxy with Apache (TLS via Let's Encrypt). A complete,
commented vhost ships in
[contrib/apache/testnetpool.conf](contrib/apache/testnetpool.conf); the gist:

```apache
# a2enmod proxy proxy_http ssl headers rewrite
<VirtualHost *:443>
    ServerName testnetpool.com
    ProxyPreserveHost On          # required: the connect page reads the Host header
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

`ProxyPreserveHost On` matters: the "Connect a miner" page builds the miner-facing
stratum host from the `Host` header, so without it miners are told to connect to
`127.0.0.1`. To build a custom front-end instead, point it at the [JSON API](#json-api).
The Stratum port is **never** proxied; it's a direct TCP listen.

### Monitoring (optional)

The dashboard exposes a liveness probe at **`GET /healthz`** (alias `/api/health`):

- **`200`** - the pool is mining on a fresh block template.
- **`503`** - every coin's template has gone stale (node unreachable or wedged); the
  process is up but **not actually working**.

Point an uptime monitor at `https://<yourdomain>/healthz` rather than `/`: a bare
page load returns `200` even while the node is down, but `/healthz` flips to `503` so
you actually get paged. For a local watchdog,
`curl -fsS http://127.0.0.1:8080/healthz` exits non-zero on `503`. Skip it entirely
if you don't run monitoring; nothing depends on it.

### Tor (optional)

Expose the dashboard as a `.onion` hidden service. Point Tor at the dashboard's port
(the daemon directly, or Apache), then tell the pool its onion so it adds a footer
link + an `Onion-Location` header (Tor Browser then offers the mirror automatically
on the clearnet site):

```text
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/testnetpool/
HiddenServicePort 80 127.0.0.1:8080      # the dashboard ([stats] port)
```
```toml
# config.toml, under [stats]
onion = "yourv3address.onion"            # cat /var/lib/tor/testnetpool/hostname
```

That covers **browsing the dashboard** over Tor, which is what the onion is mostly
good for. You can tunnel Stratum too (map each port through the same hidden service,
e.g. `HiddenServicePort 3334 127.0.0.1:3334`), but the work is on the miner's side:
mining software doesn't speak Tor, so a CPU miner needs `torsocks xmrig ...`, and an
ASIC/Bitaxe needs a local `socat` SOCKS forwarder it can point at. Tor also adds
latency, which means more **stale shares**. On testnet the coins are worthless, so
the privacy payoff is mostly principle; the sweet spot is **clearnet Stratum + onion
dashboard**: low-latency mining, private browsing.

## Contributing

Contributions welcome. Ground rules:

- **Pure standard library.** No third-party runtime dependencies (trivial deploy,
  small attack surface); PoW is `hashlib`. If you think you need a dependency, open
  an issue first.
- **Match the surrounding code:** same style, comment density, and naming.
- **Consensus-critical code is verified against known vectors, not vibes.** If you
  touch block construction, share validation, addresses, or PoW, add or extend a
  source-verified vector in `testnetpool/selftest.py`.
- **Testnet first.** This targets testnets; don't add mainnet-only assumptions.

Run the suite before opening a PR (see [Testing](#testing)); for anything touching
block submission or payouts, also exercise it on **regtest** against a real
bitcoind/litecoind. By contributing you agree your work is licensed
**AGPL-3.0-or-later**, the same as the project.

**Source map:**

- `coin.py`, `monero_coin.py` - per-coin params (PoW, diff-1, addresses, GBT rules, maturity)
- `template.py` - GBT to coinbase/job, block serialization
- `stratum.py`, `monero_stratum.py` - Stratum server, share validation, vardiff, version-rolling
- `pool.py`, `monero_pool.py` - orchestration: poll/long-poll, block submit, maturity + payout loops
- `accounting.py` - SQLite: shares, PPLNS credits, balances, payouts (public mode)
- `stats.py` - dashboard + JSON API
- `rpc.py`, `monero_rpc.py` - async JSON-RPC to the node
- `address.py`, `cryptonote.py` - address decode + CryptoNote primitives
- `util.py`, `keccak.py` - serialization, hashing, merkle, difficulty

**Versioning** follows [SemVer](https://semver.org); the contract it protects is the
operator- and miner-facing surface (JSON API, config schema, CLI, Stratum/CryptoNote
protocol, DB schema, `/healthz`), not internal Python symbols. `__version__` lives in
`testnetpool/__init__.py` (pyproject.toml reads it dynamically); `1.0.0` is the first
stable release. Releases are tagged on GitHub, and the Releases page is the changelog.

## Security

Found a vulnerability? Report it privately (see [SECURITY.md](SECURITY.md)); please
don't open a public issue.

## License

**GNU AGPL-3.0-or-later** (see [LICENSE](LICENSE)). AGPL is deliberate: a mining
pool is a network service, and the AGPL's network clause means anyone who runs a
modified TestnetPool as a public service must share their source. Run it, fork it,
modify it; just keep it open.

Copyright (C) 2026 Tech1k

This program is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

### Forking

Per-operator settings (coin/chain, addresses, fee, faucet, RPC credentials,
donation addresses, and your public `site_url`, which drives the dashboard brand
and canonical URLs) live in `config.toml`, documented in
[`config.example.toml`](config.example.toml); `config.toml` is gitignored, so never
commit it. A few branding bits are hardcoded in
[`testnetpool/stats.py`](testnetpool/stats.py) instead: the tagline, the meta
description, the `source` link, the footer attribution, and the contact details in
[SECURITY.md](SECURITY.md). Change those to your own for a public fork. As the AGPL
requires, the `source` link must point at *your* running source.

Built by [Tech1k](https://tech1k.com).
