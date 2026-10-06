#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent implementation of the data-dependent proof of work with packing (src/ddpow.h).

The chunk space of a block at height h is its ancestors 0..h-1 in height order, each block's
serialization with witness data split into 4,096-byte chunks, the last zero-padded. Chunk k of
block b, whose chunks start at first_b, is hashed packed: XORed with the raw chunks of its
partners (`partners`). The walk: x_0 = hash2; read 0 at S + index(x_0, N - S), S the parent's
first chunk; x_{i+1} = BLAKE2b-256(x_i || packed chunk); read i >= 1 at index(x_i, N);
final = x_reads. The block meets its target if BE-int(final XOR mask) <= target.
"""

import bisect
import hashlib

from .messages import blake2b_header_hash_components, powhash, uint256_from_compact

CHUNK = 4096


def blake2b256(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def index(x, n):
    return int.from_bytes(x[:8], "little") % n


def partners(block_id, k, first, m):
    """Partner positions of chunk `k` of the block with id `block_id` (32 bytes, internal byte
    order) whose chunks start at `first`."""
    if first == 0 or m == 0:
        return []
    if first <= m:
        return list(range(first))
    out = []
    t = 0
    while len(out) < m:
        e = blake2b256(b"\x03" + block_id + k.to_bytes(4, "little") + t.to_bytes(4, "little"))
        for w in range(4):
            if len(out) >= m:
                break
            candidate = int.from_bytes(e[8 * w:8 * w + 8], "little") % first
            if candidate not in out:
                out.append(candidate)
        t += 1
    return out


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class Space:
    """Chunks of a chain: raw serialized blocks with their ids (internal byte order), by height."""

    def __init__(self, blocks=()):
        self.raw = []
        self.ids = []
        self.first = []
        self.count = 0
        for raw, block_id in blocks:
            self.append(raw, block_id)

    def append(self, raw, block_id):
        assert len(block_id) == 32
        self.raw.append(raw)
        self.ids.append(block_id)
        self.first.append(self.count)
        self.count += (len(raw) + CHUNK - 1) // CHUNK

    def truncated(self, blocks):
        """The space of the first `blocks` blocks."""
        return Space(zip(self.raw[:blocks], self.ids[:blocks]))

    @property
    def parent_start(self):
        return self.first[-1]

    def locate(self, position):
        assert 0 <= position < self.count
        b = bisect.bisect_right(self.first, position) - 1
        return b, self.first[b]

    def raw_chunk(self, position):
        b, first = self.locate(position)
        k = position - first
        c = self.raw[b][k * CHUNK:(k + 1) * CHUNK]
        return c + bytes(CHUNK - len(c))

    def partners_of(self, position, m):
        b, first = self.locate(position)
        return partners(self.ids[b], position - first, first, m)

    def packed(self, position, m):
        c = self.raw_chunk(position)
        for p in self.partners_of(position, m):
            c = xor(c, self.raw_chunk(p))
        return c


def walk(hash2, reads, m, space):
    """The positions read and the final digest of `hash2` over `space` (the blocks before the
    block being checked)."""
    count, parent_start = space.count, space.parent_start
    x = hash2
    position = parent_start + index(x, count - parent_start)
    positions = []
    for _ in range(reads):
        positions.append(position)
        x = blake2b256(x + space.packed(position, m))
        position = index(x, count)
    return positions, x


def meets_target(final, mask, nbits):
    return int.from_bytes(xor(final, mask), "big") <= uint256_from_compact(nbits)


def check(header, space, reads, m):
    """Whether `header`, built on the last block of `space`, meets its target."""
    stages = blake2b_header_hash_components(header)
    _, final = walk(stages["hash2"], reads, m, space)
    return meets_target(final, stages["mask"], header.nBits)


def block_id(header):
    """The block hash in internal byte order (as hashPrevBlock serializes it)."""
    return powhash(header)


def solve(block, space, reads, m):
    """Increments the nonce until the walk meets the target."""
    while not check(block, space, reads, m):
        block.nNonce += 1
    block.rehash()


def space_from_node(node, tip_hash):
    """The space of the chain through `tip_hash`, read with getblock (verbosity 0)."""
    hashes = []
    h = tip_hash
    while h is not None:
        hashes.append(h)
        h = node.getblockheader(h).get("previousblockhash")
    hashes.reverse()
    return Space((bytes.fromhex(node.getblock(h, 0)), bytes.fromhex(h)[::-1]) for h in hashes)
