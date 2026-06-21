# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Command-line entrypoint:  python -m testnetpool -c config.toml"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from .config import HubConfig, load_config
from .hub import Hub, make_pool


_EPILOG = """\
examples:
  python -m testnetpool -c config.toml             run the pool (hub or single coin)
  python -m testnetpool -c config.toml --check     validate the config + list coins
  python -m testnetpool --selftest                 run the internal test suite

  operator admin (local, no auth - operates on the accounting databases):
  python -m testnetpool --list-pending                            show stranded pending payouts
  python -m testnetpool --resolve-payout <id> --unpaid            it didn't send -> re-pay next round
  python -m testnetpool --resolve-payout <id> --paid --txid <hex> it DID send -> debit + mark paid
"""


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def _run(config_path: str) -> int:
    cfg = load_config(config_path)
    runner = Hub(cfg) if isinstance(cfg, HubConfig) else make_pool(cfg)

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # e.g. Windows
            pass

    run_task = asyncio.create_task(runner.run())
    stop_task = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait({run_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)

    if run_task in done:
        # The run loop exited on its own (usually a fatal startup error).
        exc = run_task.exception()
        if exc:
            logging.getLogger("testnetpool").error("fatal: %s", exc)
            return 1
        return 0

    logging.getLogger("testnetpool").info("shutting down...")
    runner.stop()
    try:
        await asyncio.wait_for(run_task, timeout=5)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="testnetpool", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=_EPILOG)
    parser.add_argument("-c", "--config", default="config.toml", help="path to config TOML")
    parser.add_argument("--log-level", default="info", help="debug/info/warning/error")
    parser.add_argument("--check", action="store_true", help="validate config and exit")
    parser.add_argument("--selftest", action="store_true", help="run internal self-tests and exit")
    # Operator admin (local, no auth - ckpmsg-style; operates on the accounting DBs).
    parser.add_argument("--list-pending", action="store_true",
                        help="list unresolved pending payout intents (across coins) and exit")
    parser.add_argument("--resolve-payout", metavar="COMMENT",
                        help="resolve a stranded pending payout by its comment id "
                             "(requires --paid or --unpaid)")
    parser.add_argument("--paid", action="store_true",
                        help="with --resolve-payout: the batch DID broadcast - debit balances + mark paid")
    parser.add_argument("--unpaid", action="store_true",
                        help="with --resolve-payout: it did NOT broadcast - clear so its miners are re-paid")
    parser.add_argument("--force-unpaid", action="store_true",
                        help="with --resolve-payout --unpaid: override the refusal when a txid is "
                             "recorded (ONLY if you are certain the batch never broadcast)")
    parser.add_argument("--txid", default="",
                        help="with --resolve-payout --paid: the real wallet txid, recorded for the books")
    parser.add_argument("--miner", metavar="ADDR",
                        help="show one miner's owed/paid/shares/payouts and exit")
    parser.add_argument("--list-miners", action="store_true",
                        help="list miners per coin (owed/paid/shares) and exit")
    parser.add_argument("--blocks", action="store_true",
                        help="list found blocks per coin (height/status/reward) and exit")
    parser.add_argument("--adjust-balance", nargs=2, metavar=("ADDR", "DELTA"),
                        help="credit(+)/debit(-) a miner's owed balance by DELTA base units "
                             "(DRY RUN unless --yes)")
    parser.add_argument("--coin", default="",
                        help="with --adjust-balance/--resolve-payout: which coin to target "
                             "(disambiguate/create)")
    parser.add_argument("--yes", action="store_true",
                        help="with --adjust-balance: actually apply it (not a dry run)")
    parser.add_argument("--limit", type=int, default=50,
                        help="row cap for --list-miners / --blocks")
    args = parser.parse_args(argv)

    _setup_logging(args.log_level)

    if args.selftest:
        from . import selftest

        return 0 if selftest.run() else 1

    if args.check:
        try:
            cfg = load_config(args.config)
        except Exception as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 1
        if isinstance(cfg, HubConfig):
            print(f"config OK: hub with {len(cfg.coins)} coin(s), dashboard on "
                  f"{cfg.stats.host}:{cfg.stats.port}")
            for c in cfg.coins:
                print(f"  - {c.coin}/{c.chain} mode={c.mode} stratum={c.stratum_host}:{c.stratum_port} "
                      f"coinbase->{c.coinbase_address}")
        else:
            print(f"config OK: coin={cfg.coin} chain={cfg.chain} mode={cfg.mode} "
                  f"coinbase->{cfg.coinbase_address} stratum={cfg.stratum_host}:{cfg.stratum_port}")
        return 0

    if (args.list_pending or args.resolve_payout or args.miner or args.list_miners
            or args.blocks or args.adjust_balance):
        from . import admin

        try:
            cfg = load_config(args.config)
        except Exception as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 1
        if args.list_pending:
            return admin.list_pending(cfg)
        if args.miner:
            return admin.miner_info(cfg, args.miner)
        if args.list_miners:
            return admin.list_miners(cfg, args.limit)
        if args.blocks:
            return admin.list_blocks(cfg, args.limit)
        if args.adjust_balance:
            addr, delta_s = args.adjust_balance
            try:
                delta = int(delta_s)
            except ValueError:
                print(f"--adjust-balance DELTA must be an integer (got {delta_s!r})", file=sys.stderr)
                return 2
            if abs(delta) >= 2 ** 62:  # keep it inside SQLite's signed-64-bit bind range
                print("--adjust-balance DELTA is out of range (must be < 2^62)", file=sys.stderr)
                return 2
            return admin.adjust_balance(cfg, addr, delta, args.coin, apply=args.yes)
        if args.paid == args.unpaid:  # neither, or both
            print("--resolve-payout needs exactly one of --paid / --unpaid", file=sys.stderr)
            return 2
        return admin.resolve_payout(cfg, args.resolve_payout, paid=args.paid, txid=args.txid,
                                    coin=args.coin, force_unpaid=args.force_unpaid)

    try:
        return asyncio.run(_run(args.config))
    except FileNotFoundError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
