#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Packing experiment on a regtest chain (not part of the test suite).

Builds a chain of large blocks: before activation every payload is random; after activation a
stuffer mines a share of the blocks and fills them with payloads it regenerates from a seed.
Then, with the chain's real block ids and partner sets:
  - verifies that the stuffer's payload chunks are regenerable from the seed;
  - counts, for 0..8 partners, the walk reads the stuffer can serve without a storage read
    (its chunk and every partner regenerable), single tier and with a fast cache tier;
  - times walks (ddpowbench) and packing (ddpowpack) on the node.
Writes the results to --results as JSON.
"""

import hashlib
import json
import os
import random
import time

from test_framework import ddpow
from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

BLAKE2B_HEIGHT = 10
READS = 8
CONSENSUS_PARTNERS = 7
PAYLOAD = 880_000  # bytes per block payload (an OP_RETURN push; block weight stays below 4,000,000)


def keystream(seed, n, size):
    """The stuffer's payload for its n-th block: BLAKE2b-512 in counter mode."""
    out = bytearray()
    i = 0
    while len(out) < size:
        out += hashlib.blake2b(seed + n.to_bytes(4, "little") + i.to_bytes(8, "little"), digest_size=64).digest()
        i += 1
    return bytes(out[:size])


class PackExperiment(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--pre", type=int, default=300, help="payload blocks before activation")
        parser.add_argument("--post", type=int, default=200, help="payload blocks after activation")
        parser.add_argument("--share", type=float, default=0.3, help="stuffer's share of post-activation blocks")
        parser.add_argument("--results", default="ddpow_pack_results.json")
        parser.add_argument("--bench-walks", type=int, default=3000)
        parser.add_argument("--store-only", action="store_true", help="skip the stuffing analysis; time the packed store")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        # Activation after 101 maturing blocks and the pre-activation payload blocks.
        self.ddpow_height = 102 + self.options.pre
        self.extra_args = [[
            f"-testactivationheight=blake2b@{BLAKE2B_HEIGHT}",
            "-blake2b_headline=ddpow packing experiment",
            f"-testactivationheight=ddpow@{self.ddpow_height}",
            f"-ddpowreads={READS}",
            f"-ddpowpartners={CONSENSUS_PARTNERS}",
            "-ddpowblockbits=1",
            "-maxmempool=50",
            "-ddpowpackedstore=1",
        ]]

    def payload_block(self, node, wallet, payload):
        tx = wallet.create_self_transfer()["tx"]
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, payload])))
        block_hash = self.generateblock(node, wallet.get_address(), [tx.serialize().hex()], sync_fun=self.no_op)["hash"]
        wallet.rescan_utxos(include_mempool=False)
        return block_hash

    def run_test(self):
        node = self.nodes[0]
        opts = self.options
        rng = random.Random(20261004)
        seed = b"stuffer seed 2026"
        wallet = MiniWallet(node)
        t0 = time.time()
        DDPOW_HEIGHT = self.ddpow_height
        self.generate(wallet, 101, sync_fun=self.no_op)

        self.log.info(f"{opts.pre} random-payload blocks before activation")
        stuffed = {}  # block hash -> payload counter
        while node.getblockcount() < DDPOW_HEIGHT - 1:
            self.payload_block(node, wallet, os.urandom(PAYLOAD))

        self.log.info(f"{opts.post} payload blocks after activation, stuffer share {opts.share}")
        n_stuffed = 0
        for i in range(opts.post):
            if rng.random() < opts.share:
                h = self.payload_block(node, wallet, keystream(seed, n_stuffed, PAYLOAD))
                stuffed[h] = n_stuffed
                n_stuffed += 1
            else:
                self.payload_block(node, wallet, os.urandom(PAYLOAD))
        tip = node.getbestblockhash()
        self.log.info(f"Chain built in {time.time() - t0:.0f} s: height {node.getblockcount()}")

        if opts.store_only:
            t1 = time.time()
            store = node.getddpowstore()
            self.log.info(f"Packed store built for the whole chain in {time.time() - t1:.1f} s: {store}")
            node.ddpowbench(tip, 200)  # warm the page cache
            node.ddpowbench(tip, 200, CONSENSUS_PARTNERS, True)
            res = {"store": store}
            for label, use_store in (("from raw blocks", False), ("from the packed store", True)):
                bench = node.ddpowbench(tip, opts.bench_walks, CONSENSUS_PARTNERS, use_store)
                res[label] = {"us_per_walk": 1e6 * float(bench["seconds"]) / bench["walks"],
                              "raw_reads_per_walk": bench["raw_reads"] / bench["walks"],
                              "stored_reads_per_walk": bench["stored_reads"] / bench["walks"]}
                self.log.info(f"walks {label}: {res[label]}")
            with open(opts.results, "w") as f:
                json.dump(res, f, indent=1, default=float)
            return

        self.log.info("Reading the chain into the Python model")
        space = ddpow.space_from_node(node, tip)
        regen = bytearray(space.count)
        regen_bytes_checked = 0
        for b, raw in enumerate(space.raw):
            block_hash = space.ids[b][::-1].hex()
            if block_hash not in stuffed:
                continue
            payload = keystream(seed, stuffed[block_hash], PAYLOAD)
            offset = raw.find(payload[:64])
            assert offset > 0
            assert_equal(raw[offset:offset + PAYLOAD], payload)  # regenerable from the seed
            regen_bytes_checked += PAYLOAD
            first = space.first[b]
            for k in range(-(-offset // ddpow.CHUNK), (offset + PAYLOAD) // ddpow.CHUNK):
                regen[first + k] = 1
        n = space.count
        pre_chunks = space.first[DDPOW_HEIGHT]
        self.log.info(f"{n} chunks, {pre_chunks} before activation, {sum(regen)} regenerable ({sum(regen) / n:.4f})")

        self.log.info("Cross-check: the node's packed chunks equal the model's at random positions")
        for position in [rng.randrange(n) for _ in range(20)]:
            got = node.getddpowchunk(tip, position, CONSENSUS_PARTNERS)
            assert_equal(got["packed"], space.packed(position, CONSENSUS_PARTNERS).hex())

        results = {"chunks": n, "pre_activation_chunks": pre_chunks, "regenerable_chunks": sum(regen),
                   "stuffer_share": opts.share, "post_blocks": opts.post, "pre_blocks": opts.pre, "partners": {}}
        # Cumulative regenerable counts, for the per-block expectation the simulation uses.
        cum = [0]
        for r in regen:
            cum.append(cum[-1] + r)
        block_of = []
        for b, first in enumerate(space.first):
            end = space.first[b + 1] if b + 1 < len(space.first) else n
            block_of += [b] * (end - first)
        H = n // 4  # fast tier: a quarter of the chain
        for m in range(0, 9):
            # Exact count with the chain's real partner sets.
            partner_sets = [space.partners_of(j, m) if regen[j] else None for j in range(n)]
            free = sum(1 for j in range(n) if regen[j] and all(regen[p] for p in partner_sets[j]))
            # Expectation with uniform partners (the simulation's formula), on this chain.
            expected = sum(regen[j] * ((cum[space.first[block_of[j]]] / space.first[block_of[j]]) ** m if space.first[block_of[j]] else (1 if m == 0 else 0)) for j in range(n))
            # Fast tier with free fast reads: the stuffer caches the raw prefix [0, H1) and serves
            # prefix chunks and stuffed chunks whose partners lie in regenerable data or the prefix;
            # the rest of its fast capacity holds packed chunks. The honest miner caches packed chunks.
            best_fast = None
            for frac in (0, 0.25, 0.5, 0.75, 1.0):
                H1 = int(H * frac)
                cheap = 0
                stored = 0
                for j in range(n):
                    if j < H1:
                        cheap += 1
                    elif regen[j] and all(regen[p] or p < H1 for p in partner_sets[j]):
                        cheap += 1
                    else:
                        stored += 1
                fast_packed = min(stored, H - H1)
                cost = (stored - fast_packed) / n  # slow reads per read; fast reads cost 0
                honest = (n - H) / n
                speedup = honest / cost if cost else float("inf")
                best_fast = speedup if best_fast is None else max(best_fast, speedup)
            results["partners"][m] = {
                "free_reads": free / n,
                "speedup_single_tier": n / (n - free),
                "speedup_expected_uniform": n / (n - expected),
                "speedup_fast_tier_free_reads": best_fast,
            }
            self.log.info(f"m={m}: free {free}/{n}, single tier {n / (n - free):.4f} (uniform expectation {n / (n - expected):.4f}), fast tier free reads {best_fast:.4f}")

        self.log.info("Timing walks and packing on the node (page cache warm)")
        largest = max(range(DDPOW_HEIGHT, len(space.raw)), key=lambda b: len(space.raw[b]))
        largest_hash = space.ids[largest][::-1].hex()
        node.ddpowbench(tip, 200)  # warm the page cache
        results["timing"] = {}
        for m in (0, 2, 4, 7, 8):
            bench = node.ddpowbench(tip, opts.bench_walks, m)
            pack = node.ddpowpack(largest_hash, m)
            results["timing"][m] = {
                "us_per_walk": 1e6 * float(bench["seconds"]) / bench["walks"],
                "raw_reads_per_walk": bench["raw_reads"] / bench["walks"],
                "pack_block_chunks": pack["chunks"],
                "pack_block_raw_reads": pack["raw_reads"],
                "pack_block_ms": 1e3 * float(pack["seconds"]),
            }
            self.log.info(f"m={m}: {results['timing'][m]}")
        results["regenerable_bytes_checked"] = regen_bytes_checked
        with open(opts.results, "w") as f:
            json.dump(results, f, indent=1)
        self.log.info(f"Results written to {opts.results}")


if __name__ == '__main__':
    PackExperiment(__file__).main()
