#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Data-dependent proof of work with packing (regtest prototype, no proof sections).

From the activation height, a block's work is the walk of its stage-3 digest over packed chunks
of every ancestor (test_framework/ddpow.py). Checked here against that independent
implementation: chunks, partners and packed chunks, final digests, the node's own mining,
blocks solved in Python, blocks that fail the walk, blocks solved for another partner count,
synchronization of a second node, a reorganization and a restart.
"""

import random

from test_framework import ddpow
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlockHeader, blake2b_header_hash_components, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

BLAKE2B_HEIGHT = 10
# After 101 blocks, so the test wallet holds mature coins for blocks of several chunks.
DDPOW_HEIGHT = 120
READS = 8
# Fixed target from the activation height: 2^(256 - 3) - 1, one attempt in 8 succeeds.
BLOCK_BITS = 3


class DdpowTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--partners", type=int, default=7, help="partner count (-ddpowpartners)")
        parser.add_argument("--store", action="store_true", help="keep and mine from a packed store (-ddpowpackedstore)")

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-testactivationheight=blake2b@{BLAKE2B_HEIGHT}",
            "-blake2b_headline=ddpow functional test headline",
            f"-testactivationheight=ddpow@{DDPOW_HEIGHT}",
            f"-ddpowreads={READS}",
            f"-ddpowpartners={self.options.partners}",
            f"-ddpowblockbits={BLOCK_BITS}",
        ] + (["-ddpowpackedstore=1"] if self.options.store else [])] * self.num_nodes

    def setup_network(self):
        # node1 is connected later, to synchronize from headers it cannot check yet.
        self.setup_nodes()

    def header(self, node, block_hash):
        h = CBlockHeader()
        from_hex(h, node.getblockheader(block_hash, False))
        return h

    def bulky_block(self, node, wallet, txs, vsize):
        """A block with `txs` padded transactions (generateblock skips mempool policy)."""
        raw = []
        for _ in range(txs):
            tx = wallet.create_self_transfer(target_vsize=vsize)
            raw.append(tx["hex"])
        block_hash = self.generateblock(node, wallet.get_address(), raw, sync_fun=self.no_op)["hash"]
        wallet.rescan_utxos()
        return block_hash

    def check_block(self, node, block_hash, space=None):
        """The block's walk meets its target in the Python implementation, the node's final digest
        equals Python's, and sampled packed chunks and partners match."""
        m = self.options.partners
        header = self.header(node, block_hash)
        parent = node.getblockheader(block_hash)["previousblockhash"]
        space = space or ddpow.space_from_node(node, parent)
        assert ddpow.check(header, space, READS, m), block_hash
        hash2 = blake2b_header_hash_components(header)["hash2"]
        _, final = ddpow.walk(hash2, READS, m, space)
        assert_equal(node.getddpowfinal(parent, hash2.hex()), final.hex())
        rng = random.Random(block_hash)
        for position in [0, space.count - 1] + [rng.randrange(space.count) for _ in range(6)]:
            got = node.getddpowchunk(parent, position)
            assert_equal(got["partners"], space.partners_of(position, m))
            assert_equal(got["raw"], space.raw_chunk(position).hex())
            assert_equal(got["packed"], space.packed(position, m).hex())
            if self.options.store:
                assert_equal(got["stored"], got["packed"])
            assert_equal(got["count"], space.count)
            assert_equal(got["parent_start"], space.parent_start)

    def python_block(self, node, prev_hash, want_valid, m=None):
        """A block on `prev_hash` whose nonce makes the walk (with `m` partners) meet the target,
        or miss it if not `want_valid`."""
        m = self.options.partners if m is None else m
        tip = node.getblockheader(prev_hash)
        height = tip["height"] + 1
        block = create_block(int(prev_hash, 16), create_coinbase(height), tip["time"] + 1, height=height, header_v2=True)
        block.nBits = int(tip["bits"], 16)  # the fixed target from the activation height
        space = ddpow.space_from_node(node, prev_hash)
        while ddpow.check(block, space, READS, m) != want_valid:
            block.nNonce += 1
        block.rehash()
        return block, space

    def run_test(self):
        node, node1 = self.nodes
        m = self.options.partners
        self.log.info(f"Partners: {m}, reads: {READS}")
        wallet = MiniWallet(node)
        self.generate(wallet, DDPOW_HEIGHT - 6, sync_fun=self.no_op)

        self.log.info("Blocks of several chunks before activation (partners of later chunks)")
        for _ in range(3):
            self.bulky_block(node, wallet, txs=3, vsize=7000)
        assert_equal(node.getblockcount(), DDPOW_HEIGHT - 3)
        self.generate(wallet, 2, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), DDPOW_HEIGHT - 1)

        self.log.info("The node mines across activation; Python checks each block")
        mined = self.generate(wallet, 4, sync_fun=self.no_op)
        mined.append(self.bulky_block(node, wallet, txs=2, vsize=9000))
        mined += self.generate(wallet, 2, sync_fun=self.no_op)
        for block_hash in mined:
            assert node.getblockheader(block_hash)["height"] >= DDPOW_HEIGHT
            self.check_block(node, block_hash)

        self.log.info("A block solved in Python is accepted")
        block, _ = self.python_block(node, node.getbestblockhash(), want_valid=True)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), block.hash)

        self.log.info("A block whose walk misses the target is rejected")
        block, _ = self.python_block(node, node.getbestblockhash(), want_valid=False)
        assert_equal(node.submitblock(block.serialize().hex()), "bad-ddpow-target")
        assert node.getbestblockhash() != block.hash

        other = 0 if m else 7
        self.log.info(f"A block solved for {other} partners but missing the target with {m} is rejected")
        tip = node.getbestblockhash()
        block, space = self.python_block(node, tip, want_valid=True, m=other)
        while ddpow.check(block, space, READS, m):
            block.nNonce += 1
            while not ddpow.check(block, space, READS, other):
                block.nNonce += 1
        block.rehash()
        assert_equal(node.submitblock(block.serialize().hex()), "bad-ddpow-target")

        self.log.info("A second node synchronizes from headers it checks only once their ancestors' data is held")
        self.connect_nodes(1, 0)
        self.sync_blocks()
        assert_equal(node1.getbestblockhash(), node.getbestblockhash())
        self.check_block(node1, node1.getbestblockhash())

        self.log.info("Reorganization: node1 mines a longer branch while disconnected")
        self.disconnect_nodes(1, 0)
        self.generate(node, 2, sync_fun=self.no_op)
        branch = self.generate(node1, 3, sync_fun=self.no_op)
        self.connect_nodes(1, 0)
        self.sync_blocks()
        assert_equal(node.getbestblockhash(), branch[-1])
        for block_hash in branch:
            self.check_block(node, block_hash)

        self.log.info("Restart: the node rebuilds its chunk positions and keeps mining")
        self.restart_node(0, extra_args=self.extra_args[0])
        self.connect_nodes(1, 0)
        mined = self.generate(node, 2)
        for block_hash in mined:
            self.check_block(node1, block_hash)

        if self.options.store:
            self.log.info("Packed store: covers the chain, mining reads it once per step, reloads after restart")
            store = node.getddpowstore()
            self.log.info(f"Store: {store}")
            assert_equal(store["blocks"], node.getblockcount() + 1)
            assert_equal(store["bytes"], store["chunks"] * 4096)
            assert store["blocks_packed"] < store["blocks"]  # the index was reloaded, not rebuilt
            bench = node.ddpowbench(node.getbestblockhash(), 50, m, True)
            assert_equal(bench["raw_reads"], 0)
            assert_equal(bench["stored_reads"], 50 * READS)
            raw = node.ddpowbench(node.getbestblockhash(), 50, m, False)
            assert raw["raw_reads"] >= 50 * READS
            store1 = node1.getddpowstore()
            assert store1["blocks_dropped"] > 0 or store1["blocks_packed"] > 0

        stats = node.getddpowstats()
        self.log.info(f"Counters: {stats}")
        assert stats["walks"] > 0


if __name__ == '__main__':
    DdpowTest(__file__).main()
