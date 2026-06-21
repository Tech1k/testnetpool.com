# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Block-template handling: turn ``getblocktemplate`` output into a Stratum job
and, given a winning nonce, into a fully-serialized block for ``submitblock``.

Two block-construction modes (selected by ``include_transactions``):

* empty / coinbase-only (default): the block contains only the coinbase.
  No witness data, no witness commitment, no MWEB suffix.  The coinbase claims
  the subsidy only (``coinbasevalue`` minus the fees of the txs we drop).  This
  is the simplest provably-valid block on a post-MWEB chain.

* full: include every transaction from the template (which already contains
  the MWEB HogEx as the final entry when MWEB txs are present), add the segwit
  witness commitment to the coinbase, serialize the coinbase in BIP144 witness
  form, and append the template's ``mweb`` hex after the last transaction.

See ``README.md`` for the source-verified rationale behind both layouts.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import util


@dataclass
class Job:
    job_id: str
    height: int
    prevhash_display: str  # for new-block detection
    prevhash_stratum: str  # for the mining.notify prevhash field
    coinb1: bytes
    coinb2: bytes
    merkle_branch: list[bytes]
    version: int
    nbits: int
    nbits_hex: str
    curtime: int
    mintime: int
    network_target: int
    coinbase_value: int  # base units paid to the coinbase (pool) address
    extranonce1_size: int
    extranonce2_size: int
    # full-block construction inputs
    include_transactions: bool
    cb_version: bytes
    cb_prefix: bytes  # input prefix up to (not incl.) extranonce
    cb_scriptsig_tail: bytes  # scriptSig bytes after the extranonce (the tag)
    cb_input_tail: bytes  # sequence
    cb_outputs: bytes  # txout count + outputs
    cb_locktime: bytes
    tx_data: list[str]  # hex of each non-coinbase tx (incl. HogEx when present)
    tx_summary: list  # [{txid, fee, weight}] per included tx, for the public template view
    mweb_hex: str | None
    # True only when the template carried a segwit witness commitment (so the
    # coinbase must be BIP144 witness-serialized).  Without it, a witness-format
    # coinbase would be invalid, so we fall back to legacy serialization.
    has_witness_commitment: bool = False
    created: float = 0.0  # wall-clock time the job was built (for age-based retention)

    def notify_params(self, clean_jobs: bool) -> list:
        """The ``params`` array for a ``mining.notify`` message."""
        return [
            self.job_id,
            self.prevhash_stratum,
            self.coinb1.hex(),
            self.coinb2.hex(),
            [b.hex() for b in self.merkle_branch],
            util.pack_u32le(self.version)[::-1].hex(),  # version, big-endian hex
            self.nbits_hex,
            util.pack_u32le(self.curtime)[::-1].hex(),  # ntime, big-endian hex
            clean_jobs,
        ]

    def coinbase_legacy(self, extranonce1: bytes, extranonce2: bytes) -> bytes:
        """Non-witness coinbase serialization (used for the txid / merkle root)."""
        return (
            self.coinb1
            + extranonce1
            + extranonce2
            + self.coinb2
        )

    def coinbase_txid(self, extranonce1: bytes, extranonce2: bytes) -> bytes:
        return util.sha256d(self.coinbase_legacy(extranonce1, extranonce2))

    def merkle_root(self, extranonce1: bytes, extranonce2: bytes) -> bytes:
        return util.merkle_root_from_branch(
            self.coinbase_txid(extranonce1, extranonce2), self.merkle_branch
        )

    def build_header(
        self,
        extranonce1: bytes,
        extranonce2: bytes,
        ntime: int,
        nonce: int,
        version: int | None = None,
    ) -> bytes:
        root = self.merkle_root(extranonce1, extranonce2)
        return (
            util.pack_u32le(self.version if version is None else version)
            + util.display_to_internal(self.prevhash_display)
            + root
            + util.pack_u32le(ntime)
            + util.pack_u32le(self.nbits)
            + util.pack_u32le(nonce)
        )

    def _coinbase_witness(self, extranonce1: bytes, extranonce2: bytes) -> bytes:
        """BIP144 witness serialization of the coinbase (segwit / MWEB blocks).

        Adds the 00/01 marker+flag and the single 32-byte all-zero witness
        reserved value that the witness commitment is computed against.
        """
        witness = b"\x01\x20" + b"\x00" * 32  # 1 stack item, 32-byte reserved value
        scriptsig_mid = extranonce1 + extranonce2 + self.cb_scriptsig_tail
        return (
            self.cb_version
            + b"\x00\x01"
            + self.cb_prefix[len(self.cb_version):]  # input prefix without the version
            + scriptsig_mid
            + self.cb_input_tail
            + self.cb_outputs
            + witness
            + self.cb_locktime
        )

    def build_block_hex(
        self,
        extranonce1: bytes,
        extranonce2: bytes,
        ntime: int,
        nonce: int,
        version: int | None = None,
    ) -> str:
        header = self.build_header(extranonce1, extranonce2, ntime, nonce, version)
        if not self.include_transactions:
            # coinbase-only: one tx, legacy serialization, no MWEB suffix.
            coinbase = self.coinbase_legacy(extranonce1, extranonce2)
            return (header + util.ser_compactsize(1) + coinbase).hex()

        # Witness-serialize the coinbase only when the template gave us a witness
        # commitment to honour; otherwise the marker/flag + reserved value would
        # make the coinbase (and block) invalid on a non-segwit template.
        if self.has_witness_commitment:
            coinbase = self._coinbase_witness(extranonce1, extranonce2)
        else:
            coinbase = self.coinbase_legacy(extranonce1, extranonce2)
        n_tx = 1 + len(self.tx_data)
        body = header + util.ser_compactsize(n_tx) + coinbase
        out = body.hex() + "".join(self.tx_data)
        if self.mweb_hex:
            # Litecoin serializes the block as: header + vtx + MWEB::Block, where
            # MWEB::Block = WrapOptionalPtr(mw::Block) - a 0x01 "present" byte then
            # the mw::Block bytes. getblocktemplate's `mweb` field is ONLY the inner
            # mw::Block (m_block->Serialized()), so we must prepend the 0x01 marker;
            # without it the node misreads the stream and the MWEB block comes out
            # null -> "mweb-missing", orphaning the block. (The node only reads this
            # field when the last tx is the HogEx, which full mode always includes.)
            out += "01" + self.mweb_hex
        return out


class TemplateBuilder:
    """Stateless factory that converts a GBT dict into a :class:`Job`."""

    def __init__(
        self,
        payout_script: bytes,
        coinbase_tag: str,
        extranonce1_size: int,
        extranonce2_size: int,
        include_transactions: bool,
    ):
        self.payout_script = payout_script
        self.coinbase_tag = coinbase_tag.encode()
        self.extranonce1_size = extranonce1_size
        self.extranonce2_size = extranonce2_size
        self.include_transactions = include_transactions

    def build(self, gbt: dict, job_id: str) -> Job:
        height = gbt["height"]
        # MWEB-active templates (post-activation Litecoin testnet/mainnet) carry an
        # `mweb` extension block that consensus REQUIRES in every block: a
        # coinbase-only block is rejected by the node as "mweb-missing", losing a
        # real found block. So whenever the template carries MWEB data we MUST build
        # a full block (all transactions incl. the HogEx + the mweb blob + the
        # segwit commitment), regardless of the operator's include_transactions.
        mweb_active = bool(gbt.get("mweb"))
        full = self.include_transactions or mweb_active
        transactions = gbt.get("transactions", []) if full else []

        # --- coinbase value -------------------------------------------------
        # In full mode we claim the whole template value; in empty mode we claim
        # the subsidy only, i.e. value minus the fees of the txs we drop.
        coinbasevalue = gbt["coinbasevalue"]
        if full:
            value = coinbasevalue
        else:
            dropped_fees = sum(t.get("fee", 0) for t in gbt.get("transactions", []))
            value = coinbasevalue - dropped_fees
        if value < 0:
            # pack_u64le would wrap a negative value to ~2^64. Only reachable from an
            # internally-inconsistent template (dropped fees exceed coinbasevalue); fail
            # closed rather than emit a garbage coinbase.
            raise ValueError(f"coinbase value is negative ({value}); inconsistent template")

        # --- coinbase scriptSig (BIP34 height + extranonce + tag) -----------
        push_height = util.script_push_height(height)
        en_total = self.extranonce1_size + self.extranonce2_size
        tag = self.coinbase_tag
        # scriptSig must be <= 100 bytes; trim the tag if necessary.
        max_tag = 100 - len(push_height) - en_total
        if len(tag) > max(max_tag, 0):
            tag = tag[: max(max_tag, 0)]
        scriptsig_len = len(push_height) + en_total + len(tag)
        if scriptsig_len > 100:
            # Extranonce sizes (plus the BIP34 height push) overflow the 100-byte
            # limit on their own; no tag trim can help. Misconfiguration.
            raise ValueError(
                f"coinbase scriptSig is {scriptsig_len} bytes (>100); reduce "
                f"extranonce1_size + extranonce2_size (currently {en_total})"
            )

        cb_version = util.pack_u32le(1)
        cb_prefix = (
            cb_version
            + b"\x01"  # 1 input
            + b"\x00" * 32  # null prevout hash
            + b"\xff\xff\xff\xff"  # prevout index
            + util.ser_compactsize(scriptsig_len)
            + push_height
        )
        cb_input_tail = b"\xff\xff\xff\xff"  # sequence

        # --- coinbase outputs ----------------------------------------------
        outputs = util.pack_u64le(value) + util.ser_string(self.payout_script)
        n_out = 1
        has_commitment = False
        if full:
            commitment = gbt.get("default_witness_commitment")
            if commitment:
                outputs += util.pack_u64le(0) + util.ser_string(bytes.fromhex(commitment))
                n_out += 1
                has_commitment = True
        if mweb_active and not has_commitment:
            # A post-MWEB chain requires the segwit witness commitment in the coinbase; a
            # block without it is rejected ('mweb-missing'/'bad-witness-nonce-size'). Real
            # LTC GBT always supplies default_witness_commitment (segwit predates MWEB), so
            # this only fires on a malformed template - fail closed before we mine a dud.
            raise ValueError("MWEB-active template is missing default_witness_commitment")
        cb_outputs = util.ser_compactsize(n_out) + outputs
        cb_locktime = b"\x00\x00\x00\x00"

        # coinb1 / coinb2 straddle the extranonce inside the scriptSig.
        coinb1 = cb_prefix
        coinb2 = tag + cb_input_tail + cb_outputs + cb_locktime

        # --- merkle branch over non-coinbase txids --------------------------
        txids_internal = [util.display_to_internal(t["txid"]) for t in transactions]
        merkle_branch = util.coinbase_merkle_branch(txids_internal)

        nbits_hex = gbt["bits"]
        return Job(
            job_id=job_id,
            height=height,
            prevhash_display=gbt["previousblockhash"],
            prevhash_stratum=util.stratum_prevhash(gbt["previousblockhash"]),
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branch=merkle_branch,
            version=gbt["version"],
            nbits=int(nbits_hex, 16),
            nbits_hex=nbits_hex,
            curtime=gbt["curtime"],
            mintime=gbt.get("mintime", 0),
            network_target=int(gbt["target"], 16),
            coinbase_value=value,
            extranonce1_size=self.extranonce1_size,
            extranonce2_size=self.extranonce2_size,
            include_transactions=full,
            cb_version=cb_version,
            cb_prefix=cb_prefix,
            cb_scriptsig_tail=tag,
            cb_input_tail=cb_input_tail,
            cb_outputs=cb_outputs,
            cb_locktime=cb_locktime,
            tx_data=[t["data"] for t in transactions],
            # Per-tx summary for the public /template view (txid/fee/weight). Empty when
            # building a coinbase-only block, since no mempool txs are then included.
            tx_summary=[{"txid": t["txid"], "fee": t.get("fee", 0), "weight": t.get("weight", 0)}
                        for t in transactions],
            mweb_hex=gbt.get("mweb") if full else None,
            has_witness_commitment=has_commitment,
        )
