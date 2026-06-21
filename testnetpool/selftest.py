# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Internal self-tests: python -m testnetpool --selftest

These exercise every consensus-critical primitive against known-good vectors and
check the block/coinbase construction for internal consistency (the txid of the
witness-serialized coinbase must match its legacy serialization; the merkle root
computed via the branch must match the full-tree root; blocks must parse back to
exactly the bytes we emitted). No litecoind required.
"""

from __future__ import annotations

import struct

from . import util
from .address import AddressError, _b58check_decode, _decode_segwit, address_to_script
from .coin import COINS
from .template import TemplateBuilder

_LTC_REGTEST = COINS["litecoin"].network("regtest")

_results: list[tuple[str, bool, str]] = []


def _check(name: str, cond: bool, detail: str = "") -> None:
    _results.append((name, bool(cond), detail))


# --- helpers for parsing serialized txs/blocks -----------------------------


def _read_compact(b: bytes, pos: int) -> tuple[int, int]:
    v = b[pos]
    pos += 1
    if v < 0xFD:
        return v, pos
    if v == 0xFD:
        return int.from_bytes(b[pos:pos + 2], "little"), pos + 2
    if v == 0xFE:
        return int.from_bytes(b[pos:pos + 4], "little"), pos + 4
    return int.from_bytes(b[pos:pos + 8], "little"), pos + 8


def _parse_tx(raw: bytes, pos: int) -> tuple[bytes, bool, int]:
    """Parse one (possibly witness) tx; return (txid_internal, had_witness, end)."""
    version = raw[pos:pos + 4]
    pos += 4
    has_witness = raw[pos] == 0x00 and raw[pos + 1] == 0x01
    if has_witness:
        pos += 2
    n_in, pos = _read_compact(raw, pos)
    legacy_in = b""
    for _ in range(n_in):
        outpoint = raw[pos:pos + 36]
        pos += 36
        sl, pos = _read_compact(raw, pos)
        script = raw[pos:pos + sl]
        pos += sl
        seq = raw[pos:pos + 4]
        pos += 4
        legacy_in += outpoint + util.ser_compactsize(sl) + script + seq
    n_out, pos = _read_compact(raw, pos)
    legacy_out = b""
    for _ in range(n_out):
        val = raw[pos:pos + 8]
        pos += 8
        sl, pos = _read_compact(raw, pos)
        spk = raw[pos:pos + sl]
        pos += sl
        legacy_out += val + util.ser_compactsize(sl) + spk
    if has_witness:
        for _ in range(n_in):
            wcnt, pos = _read_compact(raw, pos)
            for _ in range(wcnt):
                il, pos = _read_compact(raw, pos)
                pos += il
    locktime = raw[pos:pos + 4]
    pos += 4
    legacy = (
        version
        + util.ser_compactsize(n_in)
        + legacy_in
        + util.ser_compactsize(n_out)
        + legacy_out
        + locktime
    )
    return util.sha256d(legacy), has_witness, pos


# --- individual tests -------------------------------------------------------


def _test_scrypt() -> None:
    header = bytes.fromhex(
        "01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f27"
        "9fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06"
        "b817bb4ea78e011d012d59d4"
    )
    out = util.scrypt_pow(header)
    expected = "0000000110c8357966576df46f3b802ca897deb7ad18b12f1c24ecff6386ebd9"
    _check("scrypt PoW (block 29255)", util.internal_to_display(out) == expected)


def _test_bits_target() -> None:
    t = util.bits_to_target(0x1D00FFFF)
    _check(
        "bits_to_target(1d00ffff)",
        t == 0x00000000FFFF0000000000000000000000000000000000000000000000000000,
        hex(t),
    )


def _test_push_height() -> None:
    cases = {
        0: "00",
        1: "51",
        16: "60",
        17: "0111",
        128: "028000",  # high bit set -> sign byte appended
        100000: "03a08601",
        500000: "0320a107",
    }
    ok = all(util.script_push_height(h).hex() == exp for h, exp in cases.items())
    bad = {h: util.script_push_height(h).hex() for h, exp in cases.items()
           if util.script_push_height(h).hex() != exp}
    _check("script_push_height (BIP34)", ok, str(bad))


def _test_prevhash() -> None:
    d = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    exp = "ccddeeff8899aabb4455667700112233ccddeeff8899aabb4455667700112233"
    _check("stratum_prevhash word-reversal", util.stratum_prevhash(d) == exp)


def _test_addresses() -> None:
    # External anchors (algorithm is identical to Bitcoin's; only prefixes differ).
    payload = _b58check_decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    _check(
        "base58check decode (BTC anchor)",
        payload == bytes.fromhex("0077bff20c60e522dfaa3350c39b030a5d004e839a"),
        payload.hex(),
    )
    witver, prog = _decode_segwit("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    _check(
        "bech32 decode (BIP173 anchor)",
        witver == 0 and prog == bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6"),
    )

    # Round-trip through our own encoders for every coin/network/type.
    h160 = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    for coin_name, chain in (
        ("litecoin", "main"), ("litecoin", "test"), ("litecoin", "regtest"),
        ("bitcoin", "main"), ("bitcoin", "test"), ("bitcoin", "regtest"),
    ):
        net = COINS[coin_name].network(chain)
        tag = f"{coin_name}/{chain}"
        p2pkh = _b58check_encode(bytes([net.pubkey_version]) + h160)
        script = address_to_script(p2pkh, net)
        _check(f"P2PKH {tag}", script == bytes([0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC]))

        p2sh = _b58check_encode(bytes([net.script_versions[0]]) + h160)
        script = address_to_script(p2sh, net)
        _check(f"P2SH {tag}", script == bytes([0xA9, 0x14]) + h160 + bytes([0x87]))

        wpkh = _bech32_encode(net.bech32_hrp, 0, h160)
        script = address_to_script(wpkh, net)
        _check(f"P2WPKH {tag}", script == bytes([0x00, 0x14]) + h160)

    # P2TR (witver 1) must be exactly 32 bytes; a 20-byte v1 program is rejected.
    net = COINS["bitcoin"].network("main")
    h256 = bytes(range(32))
    p2tr = _bech32_encode(net.bech32_hrp, 1, h256)
    _check("P2TR v1 32-byte", address_to_script(p2tr, net) == bytes([0x51, 0x20]) + h256)
    try:
        address_to_script(_bech32_encode(net.bech32_hrp, 1, h160), net)
        _check("P2TR v1 wrong length rejected", False)
    except AddressError:
        _check("P2TR v1 wrong length rejected", True)


def _make_gbt(transactions: list[dict], coinbasevalue: int = 5_000_000_000) -> dict:
    bits = "207fffff"  # regtest: target ~ 2^255, so almost any hash is a "block"
    return {
        "height": 12345,
        "previousblockhash": "f" * 8 + "0" * 56,
        "version": 0x20000000,
        "bits": bits,
        "curtime": 1_700_000_000,
        "mintime": 1_699_999_000,
        "target": f"{util.bits_to_target(int(bits, 16)):064x}",
        "coinbasevalue": coinbasevalue,
        "transactions": transactions,
    }


def _test_empty_block() -> None:
    builder = TemplateBuilder(
        payout_script=address_to_script(_bech32_encode("rltc", 0, b"\x11" * 20), _LTC_REGTEST),
        coinbase_tag="/testnetpool/",
        extranonce1_size=4,
        extranonce2_size=4,
        include_transactions=False,
    )
    fees = [111, 222, 333]
    gbt = _make_gbt([{"txid": "ab" * 32, "data": "00", "fee": f} for f in fees])
    job = builder.build(gbt, "1")

    en1 = bytes.fromhex("deadbeef")
    en2 = bytes.fromhex("00000001")

    # Subsidy = coinbasevalue - dropped fees.
    cb_outs = job.cb_outputs
    value = struct.unpack("<Q", cb_outs[1:9])[0]
    _check("empty-mode subsidy = value - fees", value == 5_000_000_000 - sum(fees), str(value))

    # Single-tx merkle root == coinbase txid; branch is empty.
    txid = job.coinbase_txid(en1, en2)
    _check("empty-mode no merkle branch", job.merkle_branch == [])
    _check("empty-mode root == coinbase txid", job.merkle_root(en1, en2) == txid)

    # Block hex = header || 0x01 || legacy coinbase, nothing else.
    block = bytes.fromhex(job.build_block_hex(en1, en2, job.curtime, 0))
    header, rest = block[:80], block[80:]
    _check("empty-mode header len", len(header) == 80)
    _check("empty-mode tx count == 1", rest[0] == 0x01)
    cb_txid, had_wit, end = _parse_tx(rest, 1)
    _check("empty-mode coinbase legacy (no witness)", not had_wit)
    _check("empty-mode coinbase txid matches", cb_txid == txid)
    _check("empty-mode no trailing bytes", end == len(rest))

    # tx_summary feeds the public /template view: empty when coinbase-only, and in full
    # mode it captures each included tx's txid/fee/weight from the template.
    _check("empty-mode tx_summary empty", job.tx_summary == [])
    full_builder = TemplateBuilder(
        payout_script=address_to_script(_bech32_encode("rltc", 0, b"\x11" * 20), _LTC_REGTEST),
        coinbase_tag="/testnetpool/", extranonce1_size=4, extranonce2_size=4,
        include_transactions=True,
    )
    fjob = full_builder.build(
        _make_gbt([{"txid": "cd" * 32, "data": "00", "fee": 1234, "weight": 561},
                   {"txid": "ef" * 32, "data": "00", "fee": 56, "weight": 440}]), "2")
    _check("full-mode tx_summary captures txid/fee/weight",
           fjob.tx_summary == [{"txid": "cd" * 32, "fee": 1234, "weight": 561},
                               {"txid": "ef" * 32, "fee": 56, "weight": 440}])

    # Coinbase scriptSig must begin with the BIP34 height push.
    legacy = job.coinbase_legacy(en1, en2)
    # version(4)+vin(1)+outpoint(36)+seq-prefix: scriptSig starts at offset 4+1+36+1
    ss_len = legacy[41]
    ss = legacy[42:42 + ss_len]
    _check("coinbase scriptSig starts with height", ss.startswith(util.script_push_height(12345)))
    _check("coinbase scriptSig contains extranonce", en1 + en2 in ss)


def _test_full_block() -> None:
    # One fake non-witness tx: its txid is sha256d(data).
    tx_data = "02000000" + "00" * 40 + "00000000"
    tx_raw = bytes.fromhex(tx_data)
    tx_txid_internal = util.sha256d(tx_raw)
    commitment = "6a24aa21a9ed" + "cd" * 32
    gbt = _make_gbt(
        [{"txid": util.internal_to_display(tx_txid_internal), "data": tx_data, "fee": 500}]
    )
    gbt["default_witness_commitment"] = commitment

    builder = TemplateBuilder(
        payout_script=address_to_script(_bech32_encode("rltc", 0, b"\x22" * 20), _LTC_REGTEST),
        coinbase_tag="/sp/",
        extranonce1_size=4,
        extranonce2_size=4,
        include_transactions=True,
    )
    job = builder.build(gbt, "2")
    en1 = bytes.fromhex("11223344")
    en2 = bytes.fromhex("55667788")

    # Full mode claims the entire template value.
    value = struct.unpack("<Q", job.cb_outputs[1:9])[0]
    _check("full-mode value == coinbasevalue", value == 5_000_000_000, str(value))
    _check("full-mode has commitment output (2 outs)", job.cb_outputs[0] == 0x02)

    # Merkle root via branch must equal the full-tree root over [coinbase, tx].
    cb_txid = job.coinbase_txid(en1, en2)
    via_branch = job.merkle_root(en1, en2)
    full = util.merkle_root_full([cb_txid, tx_txid_internal])
    _check("full-mode merkle branch == full tree", via_branch == full)

    # Witness coinbase must serialize back to the same legacy txid.
    block = bytes.fromhex(job.build_block_hex(en1, en2, job.curtime, 0))
    header, rest = block[:80], block[80:]
    ntx, pos = _read_compact(rest, 0)
    _check("full-mode tx count == 2", ntx == 2)
    parsed_cb_txid, had_wit, pos = _parse_tx(rest, pos)
    _check("full-mode coinbase is witness-serialized", had_wit)
    _check("full-mode coinbase txid round-trips", parsed_cb_txid == cb_txid)
    # The remaining bytes are exactly the appended tx (no MWEB in this template).
    _check("full-mode appended tx bytes", rest[pos:] == tx_raw)


def _test_full_block_mweb() -> None:
    # Template carrying MWEB data: a HogEx-like final tx + an `mweb` blob that we
    # must append verbatim after all transactions.
    tx_data = "02000000" + "00" * 40 + "00000000"
    tx_raw = bytes.fromhex(tx_data)
    mweb_hex = "abcdef0123456789"
    gbt = _make_gbt(
        [{"txid": util.internal_to_display(util.sha256d(tx_raw)), "data": tx_data, "fee": 0}]
    )
    gbt["default_witness_commitment"] = "6a24aa21a9ed" + "00" * 32
    gbt["mweb"] = mweb_hex

    builder = TemplateBuilder(address_to_script(_bech32_encode("rltc", 0, b"\x33" * 20), _LTC_REGTEST),
                              "/sp/", 4, 4, include_transactions=True)
    job = builder.build(gbt, "3")
    block_hex = job.build_block_hex(bytes.fromhex("00000000"), bytes.fromhex("00000000"), job.curtime, 0)
    # Block ends with the 0x01 MWEB-present marker (WrapOptionalPtr) + the mweb blob.
    _check("mweb appended with 0x01 marker at block end", block_hex.endswith("01" + mweb_hex))
    _check("mweb blob is NOT appended without its marker", not block_hex.endswith("00" + mweb_hex))
    _check("mweb stored on job", job.mweb_hex == mweb_hex)


def _test_mweb_forces_full_block() -> None:
    """Regression: a post-MWEB template MUST build a full block even when the
    operator configured include_transactions=false.  A coinbase-only block on a
    post-MWEB chain is rejected by the node as "mweb-missing" (a real found block
    was lost to exactly this).  When the template carries an `mweb` blob the builder
    must auto-upgrade: include the transactions (incl. HogEx), append the mweb blob,
    add the witness commitment, and claim the FULL coinbase value (fees included)."""
    tx_data = "02000000" + "00" * 40 + "00000000"
    tx_raw = bytes.fromhex(tx_data)
    mweb_hex = "abcdef0123456789"
    gbt = _make_gbt(
        [{"txid": util.internal_to_display(util.sha256d(tx_raw)), "data": tx_data, "fee": 777}]
    )
    gbt["default_witness_commitment"] = "6a24aa21a9ed" + "11" * 32
    gbt["mweb"] = mweb_hex

    # NOTE: include_transactions=False - the builder must override it for MWEB.
    builder = TemplateBuilder(address_to_script(_bech32_encode("rltc", 0, b"\x44" * 20), _LTC_REGTEST),
                              "/sp/", 4, 4, include_transactions=False)
    job = builder.build(gbt, "5")
    _check("mweb auto-upgrade: job is full despite include_transactions=false",
           job.include_transactions is True)
    _check("mweb auto-upgrade: tx included (not coinbase-only)", job.tx_data == [tx_data])
    _check("mweb auto-upgrade: claims FULL value incl. fees",
           job.coinbase_value == gbt["coinbasevalue"])
    _check("mweb auto-upgrade: witness commitment present", job.has_witness_commitment is True)
    block_hex = job.build_block_hex(bytes.fromhex("00000000"), bytes.fromhex("00000000"), job.curtime, 0)
    _check("mweb auto-upgrade: mweb blob appended with 0x01 marker",
           block_hex.endswith("01" + mweb_hex))

    # And a BTC-style template (no mweb) with include_transactions=false stays empty.
    gbt2 = _make_gbt([{"txid": util.internal_to_display(util.sha256d(tx_raw)), "data": tx_data, "fee": 777}])
    job2 = builder.build(gbt2, "6")
    _check("no-mweb template stays coinbase-only when configured empty",
           job2.include_transactions is False and job2.tx_data == [])


def _test_full_block_no_commitment() -> None:
    """Regression: a full-mode template WITHOUT a witness commitment (e.g. a
    pre-segwit chain) must serialize a LEGACY coinbase, not a BIP144 witness one.
    A witness-serialized coinbase with no commitment is an invalid block."""
    tx_data = "02000000" + "00" * 40 + "00000000"
    tx_raw = bytes.fromhex(tx_data)
    tx_txid_internal = util.sha256d(tx_raw)
    gbt = _make_gbt(
        [{"txid": util.internal_to_display(tx_txid_internal), "data": tx_data, "fee": 500}]
    )
    # Note: no gbt["default_witness_commitment"].
    builder = TemplateBuilder(
        payout_script=address_to_script(_bech32_encode("rltc", 0, b"\x22" * 20), _LTC_REGTEST),
        coinbase_tag="/sp/", extranonce1_size=4, extranonce2_size=4,
        include_transactions=True,
    )
    job = builder.build(gbt, "4")
    en1, en2 = bytes.fromhex("11223344"), bytes.fromhex("55667788")
    _check("no-commitment: job flag is False", job.has_witness_commitment is False)
    _check("no-commitment: single coinbase output", job.cb_outputs[0] == 0x01)
    block = bytes.fromhex(job.build_block_hex(en1, en2, job.curtime, 0))
    rest = block[80:]
    ntx, pos = _read_compact(rest, 0)
    _check("no-commitment: tx count == 2", ntx == 2)
    parsed_cb_txid, had_wit, pos = _parse_tx(rest, pos)
    _check("no-commitment: coinbase is LEGACY-serialized (no witness marker)", not had_wit)
    _check("no-commitment: coinbase txid round-trips", parsed_cb_txid == job.coinbase_txid(en1, en2))
    _check("no-commitment: appended tx bytes", rest[pos:] == tx_raw)


def _test_coins() -> None:
    from .coin import SCRYPT_DIFF1, SHA256_DIFF1

    header = bytes.fromhex("02000000" + "ab" * 76)  # arbitrary 80-byte header
    btc, ltc = COINS["bitcoin"], COINS["litecoin"]
    _check("bitcoin PoW = double-SHA256", btc.pow_hash(header) == util.sha256d(header))
    _check("litecoin PoW = scrypt", ltc.pow_hash(header) == util.scrypt_pow(header))
    # scrypt diff1 is the sha256 diff1 scaled by the well-known 2^16 factor.
    _check("scrypt diff1 == sha256 diff1 << 16", SCRYPT_DIFF1 == SHA256_DIFF1 << 16)
    _check("bitcoin diff1 target", btc.difficulty_to_target(1) == SHA256_DIFF1)
    _check("litecoin diff1 target", ltc.difficulty_to_target(1) == SCRYPT_DIFF1)
    _check(
        "hashes-per-diff1 (sha256 2^32, scrypt 2^16)",
        btc.hashes_per_diff1 == (1 << 32) and ltc.hashes_per_diff1 == (1 << 16),
    )
    _check("gbt rules (btc segwit-only, ltc +mweb)",
           btc.gbt_rules == ("segwit",) and "mweb" in ltc.gbt_rules)


def _test_accounting() -> None:
    import os
    import tempfile

    from .accounting import Accounting

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        acc = Accounting(path, "bitcoin")
        acc.record_share("tb1qaaa", 1000, 100)
        acc.record_share("tb1qaaa", 2000, 101)   # same miner -> dedup
        acc.record_share("tb1qbbb", 1500, 102)
        s = acc.summary()
        _check("accounting: distinct miners deduped", s["miners_known"] == 2, str(s))
        _check("accounting: shares recorded", s["shares_recorded"] == 3, str(s))
        wsum = acc.conn.execute("SELECT SUM(difficulty) FROM shares").fetchone()[0]
        _check("accounting: share weights persisted", wsum == 4500, str(wsum))
        acc.close()
    finally:
        for p in (path, path + "-wal", path + "-shm"):
            try:
                os.unlink(p)
            except OSError:
                pass


def _test_pplns() -> None:
    import os
    import tempfile

    from .accounting import Accounting

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        acc = Accounting(path, "bitcoin")
        # alice contributes weight 2000, bob 1000 (2:1).
        acc.record_share("tb1qalice", 1000, 100)
        acc.record_share("tb1qalice", 1000, 100)
        acc.record_share("tb1qbob", 1000, 101)
        reward = 1_000_000_000  # 10 coins
        info = acc.credit_block(500, "a" * 64, reward, 10.0, 100_000, "tb1qfaucet", 102)
        cr = dict(acc.conn.execute(
            "SELECT m.address, c.amount FROM credits c JOIN miners m ON m.id=c.miner_id "
            "WHERE c.block_id=?", (info["block_id"],)).fetchall())
        # payable = 900M; alice 2/3 -> 600M, bob 1/3 -> 300M, faucet = fee+remainder = 100M
        _check("pplns: alice 2/3 of payable", cr["tb1qalice"] == 600_000_000, str(cr))
        _check("pplns: bob 1/3 of payable", cr["tb1qbob"] == 300_000_000, str(cr))
        _check("pplns: credits sum to full reward", sum(cr.values()) == reward, str(sum(cr.values())))

        bal0 = acc.conn.execute("SELECT COALESCE(SUM(owed),0) FROM balances").fetchone()[0]
        _check("pplns: immature -> balances still zero", bal0 == 0, str(bal0))
        acc.mature_block(info["block_id"])
        acc.mature_block(info["block_id"])  # idempotent
        owed = dict(acc.conn.execute(
            "SELECT m.address, b.owed FROM balances b JOIN miners m ON m.id=b.miner_id").fetchall())
        _check("pplns: matured credits applied once", owed["tb1qalice"] == 600_000_000, str(owed))

        payable = acc.payable(500_000_000)
        _check("pplns: payable respects threshold",
               {p["address"] for p in payable} == {"tb1qalice"},
               str([p["address"] for p in payable]))
        acc.record_payouts([{"miner_id": p["miner_id"], "amount": p["owed"]} for p in payable], "tx1", 200)
        a_owed = acc.conn.execute(
            "SELECT owed FROM balances b JOIN miners m ON m.id=b.miner_id WHERE m.address='tb1qalice'"
        ).fetchone()[0]
        _check("pplns: payout decremented balance", a_owed == 0, str(a_owed))

        info2 = acc.credit_block(501, "b" * 64, reward, 10.0, 100_000, "tb1qfaucet", 300)
        acc.orphan_block(info2["block_id"])
        left = acc.conn.execute(
            "SELECT COUNT(*) FROM credits WHERE block_id=?", (info2["block_id"],)).fetchone()[0]
        _check("pplns: orphan drops credits", left == 0, str(left))
        acc.close()
    finally:
        for p in (path, path + "-wal", path + "-shm"):
            try:
                os.unlink(p)
            except OSError:
                pass


def _test_password_diff() -> None:
    from .stratum import parse_password_difficulty as p

    cases = {
        "d=1024": 1024.0, "x": None, "": None, "d=512,foo": 512.0,
        "foo;d=2048": 2048.0, "D=256": 256.0, "d=abc": None, "d=-5": None,
        "d=0.5": 0.5,
        "d=2000000": 2000000.0,        # a big rented ASIC asking for a high pin
        "diff=8192": 8192.0, "DIFF=4096": 4096.0,  # the diff= variant some configs use
        "x;diff=16384": 16384.0,
    }
    bad = {k: p(k) for k, v in cases.items() if p(k) != v}
    _check("password difficulty parsing (MRR 'd=' / 'diff=')", not bad, str(bad))


# --- tiny independent encoders (so the decoder tests aren't circular) -------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check_encode(payload: bytes) -> str:
    import hashlib

    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _bech32_encode(hrp: str, witver: int, program: bytes) -> str:
    data = [witver] + _convertbits(list(program), 8, 5, True)
    const = 1 if witver == 0 else 0x2BC830A3
    values = _hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


# --- runner -----------------------------------------------------------------


def run() -> bool:
    _results.clear()
    _test_scrypt()
    _test_bits_target()
    _test_push_height()
    _test_prevhash()
    _test_addresses()
    _test_coins()
    _test_password_diff()
    _test_accounting()
    _test_pplns()
    _test_empty_block()
    _test_full_block()
    _test_full_block_mweb()
    _test_full_block_no_commitment()
    _test_mweb_forces_full_block()

    passed = sum(1 for _, ok, _ in _results if ok)
    for name, ok, detail in _results:
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if not ok and detail:
            line += f"   ({detail})"
        print(line)
    print(f"\n{passed}/{len(_results)} checks passed")
    return passed == len(_results)
