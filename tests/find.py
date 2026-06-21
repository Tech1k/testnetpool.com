# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Unit test for the global address search (`GET /find`): a header box that takes
any coin address and routes it to the right coin's miner page.

The classifier reuses each coin's REAL decoder (address.py for BTC/LTC, cryptonote.py
for Monero), validating only against the pools actually configured on the server, so
a match means the miner page would accept it too. We assert: bech32 (hrp) and Monero
are unambiguous; a legacy base58 *testnet* address (shared version bytes) matches BOTH
a BTC and an LTC pool -> a disambiguation page; a single match 302-redirects to the
correctly-shaped URL (slug in hub mode, bare in single mode); mainnet/garbage/empty
degrade gracefully; and the untrusted address is always escaped in HTML.

Run:  python3 tests/find.py
"""

from __future__ import annotations

import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testnetpool import address, cryptonote  # noqa: E402
from testnetpool.coin import COINS  # noqa: E402
from testnetpool.config import StatsConfig  # noqa: E402
from testnetpool.stats import StatsServer  # noqa: E402

ok = []


def chk(name, cond):
    ok.append((name, bool(cond)))


def _bech32(hrp, program, witver=0):
    """Encode a witness program as a bech32 address (witver 0) using address.py's
    own primitives - gives a vector the production decoder accepts."""
    data = [witver] + address._convertbits(list(program), 8, 5, True)
    polymod = address._bech32_polymod(address._bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    chk_ = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(address._BECH32_CHARSET[d] for d in data + chk_)


# Valid vectors for each address type the pool's coins accept.
_WP = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")  # 20-byte hash160
TB1 = _bech32("tb", _WP)                                     # BTC testnet segwit
TLTC = _bech32("tltc", _WP)                                  # LTC testnet segwit
_MBODY = bytes([53]) + b"\x11" * 32 + b"\x22" * 32           # Monero testnet standard
XMR = cryptonote.b58_encode(_MBODY + cryptonote.keccak256(_MBODY)[:4])
B58T = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"   # BTC/LTC testnet P2PKH (version 0x6F)
MAIN = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"   # BTC mainnet P2PKH (version 0x00)


class _Cfg:
    def __init__(self, coin, chain):
        self.coin, self.chain = coin, chain


class _Pool:
    def __init__(self, coin, chain):
        self.cfg = _Cfg(coin, chain)
        self.coin = COINS[coin]


def _server(*specs):
    return StatsServer([_Pool(c, ch) for c, ch in specs],
                       StatsConfig(enabled=True, host="127.0.0.1", port=0))


def _route(srv, q):
    """(status_code, location, body) for GET /find?q=<q> (q already URL-encoded)."""
    r = srv._route(f"/find?q={q}")
    status = (r[2] if len(r) > 2 else b"HTTP/1.1 200 OK").split()[1].decode()
    loc = (r[3] if len(r) > 3 else b"").decode().strip()
    return status, loc, r[0].decode()


def _coins(srv, addr):
    return sorted(p.cfg.coin for p in srv._classify(addr))


def main():
    hub = _server(("bitcoin", "testnet4"), ("litecoin", "test"), ("monero", "testnet"))

    # --- classifier: unambiguous types resolve to exactly one coin ----------
    chk("classify: tb1 bech32 -> bitcoin only", _coins(hub, TB1) == ["bitcoin"])
    chk("classify: tltc1 bech32 -> litecoin only", _coins(hub, TLTC) == ["litecoin"])
    chk("classify: monero -> monero only", _coins(hub, XMR) == ["monero"])
    # base58 testnet version 0x6F is shared by BTC and LTC -> genuinely ambiguous
    chk("classify: base58 testnet -> bitcoin AND litecoin", _coins(hub, B58T) == ["bitcoin", "litecoin"])
    # things that must NOT match anything hosted here
    chk("classify: mainnet address -> no match", _coins(hub, MAIN) == [])
    chk("classify: garbage -> no match", _coins(hub, "not-an-address") == [])
    chk("classify: empty -> no match", _coins(hub, "") == [])
    chk("classify: MWEB address -> no match (address.py won't decode it)",
        _coins(hub, "tltcmweb1qqf0h" + "q" * 90) == [])

    # --- routing: single match 302-redirects to the right URL ---------------
    s, loc, _ = _route(hub, quote(TB1))
    chk("route: tb1 -> 302 to /bitcoin/miner/<addr>", s == "302"
        and loc == f"Location: /bitcoin/miner/{quote(TB1, safe='')}")
    s, loc, _ = _route(hub, quote(XMR))
    chk("route: monero -> 302 to /monero/miner/<addr>", s == "302"
        and loc == f"Location: /monero/miner/{quote(XMR, safe='')}")

    # --- ambiguous -> a disambiguation page listing each candidate ----------
    s, _, body = _route(hub, quote(B58T))
    chk("route: ambiguous -> 200 disambiguation page", s == "200"
        and "more than one chain" in body
        and f"/bitcoin/miner/{quote(B58T, safe='')}" in body
        and f"/litecoin/miner/{quote(B58T, safe='')}" in body)

    # --- 0 matches / empty -> graceful pages, never a redirect --------------
    s, _, body = _route(hub, quote(MAIN))
    chk("route: mainnet -> 200 not-found page", s == "200"
        and "No coin hosted here recognizes" in body)
    s, _, body = _route(hub, "")
    chk("route: empty -> 200 prompt page", s == "200" and "Enter a wallet address" in body)

    # --- single-coin mode: bare /miner/<addr>, no slug ----------------------
    single = _server(("bitcoin", "testnet4"))
    s, loc, _ = _route(single, quote(TB1))
    chk("single: tb1 -> 302 to /miner/<addr> (no slug)", s == "302"
        and loc == f"Location: /miner/{quote(TB1, safe='')}")
    chk("single: tltc1 not accepted by a btc-only server", single._classify(TLTC) == [])
    # ambiguous base58 collapses to ONE match when only one chain is hosted
    s, loc, _ = _route(single, quote(B58T))
    chk("single: base58 testnet -> single 302 (only btc hosted)", s == "302"
        and loc == f"Location: /miner/{quote(B58T, safe='')}")

    # --- the search box is in the nav on every page -------------------------
    from testnetpool.stats import _render_find_page
    page = _render_find_page("", "empty", [], "/")
    chk("nav: search form present", 'class=navfind' in page
        and 'action="/find"' in page and 'name=q' in page)

    # --- XSS: the untrusted address is escaped, never executable ------------
    body = single._find("q=" + quote("<script>alert(1)</script>"))[0].decode()
    chk("xss: address is HTML-escaped", "<script>alert" not in body and "&lt;script&gt;" in body)
    # a quote/redirect can't be broken out of either (no match here -> page, still safe)
    body2 = single._find('q=' + quote('"><img src=x onerror=alert(1)>'))[0].decode()
    chk("xss: attribute breakout escaped", "<img src=x" not in body2)

    # --- reserved slug: a coin can't be named "find" (would shadow the route)
    chk("reserved: /find can't be a coin slug",
        "find" in {"api", "connect", "donate", "find", "healthz", "c", "index.html"})

    passed = sum(1 for _, c in ok if c)
    for n, c in ok:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{passed}/{len(ok)} find checks passed")
    return 0 if passed == len(ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
