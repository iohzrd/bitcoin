// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DDPOW_H
#define BITCOIN_DDPOW_H

#include <consensus/params.h>
#include <flatfile.h>
#include <util/fs.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <vector>

class CBlockIndex;
namespace node { class BlockManager; }

/**
 * Data-dependent proof of work with packing (regtest prototype; no proof sections).
 *
 * The chunk space of a block at height h is its ancestors 0..h-1 in height order, each block's
 * serialization with witness data split separately into 4,096-byte chunks, the last zero-padded.
 * N is the chunk count of blocks 0..h-1 and S the count of blocks 0..h-2 (the parent starts at S).
 *
 * Packing: chunk k of block b, whose chunks start at first_b, is hashed as
 * packed = chunk XOR the raw chunks of its partners: DdpowPartners distinct positions in
 * [0, first_b), all of them if first_b <= DdpowPartners, none for the genesis block (Partners).
 *
 * Walk: x_0 = hash2 (the v2 header's stage-3 digest); read 0 at S + Index(x_0, N - S);
 * x_{i+1} = BLAKE2b-256(x_i || packed chunk read i); read i >= 1 at Index(x_i, N);
 * final = x_reads. The block is valid if final, masked and reversed as the block hash is,
 * meets the target. The block hash itself is not compared with the target.
 */
namespace ddpow {

static constexpr size_t CHUNK{4096};
using Chunk = std::array<unsigned char, CHUNK>;

/** u64le(x[0..8)) mod n. Requires n > 0. */
uint64_t Index(const uint256& x, uint64_t n);

/** The partners of chunk `k` of the block with id `block_id` (uint256 internal byte order,
 *  as hashPrevBlock serializes it) whose chunks start at `first`: none if first == 0 or
 *  m == 0; every position in [0, first) if first <= m; else m distinct positions drawn in
 *  order from the 8-byte little-endian words of BLAKE2b-256(0x03 || block_id || LE32(k) ||
 *  LE32(t)), t = 0, 1, ..., each reduced mod first, repeats skipped. */
std::vector<uint64_t> Partners(const uint256& block_id, uint32_t k, uint64_t first, unsigned m);

/** Raw chunks of one chain and which block holds a position. */
class ChunkSource
{
public:
    virtual ~ChunkSource() = default;
    /** Chunks of every block in the source. */
    virtual uint64_t Count() const = 0;
    /** The block holding `position`: the position of its first chunk and its id. */
    virtual bool Locate(uint64_t position, uint64_t& first, uint256& block_id) const = 0;
    virtual bool ReadRaw(uint64_t position, Chunk& out) = 0;
};

/** The packed chunk at `position` with `m` partners; false if a read fails. */
bool ReadPacked(ChunkSource& source, uint64_t position, unsigned m, Chunk& out);

/** The walk of `hash2` over `source` (count = source.Count(), parent_start = S); false if a
 *  read fails. Requires count > parent_start. */
bool Walk(const uint256& hash2, unsigned reads, unsigned partners, uint64_t parent_start, ChunkSource& source, uint256& final_out);

/** Whether `final`, masked and reversed as a block hash, meets `nBits`'s target. */
bool MeetsTarget(const uint256& final_digest, const uint256& mask, unsigned nBits, const Consensus::Params& params);

/** Counters for measurements (getddpowstats). */
struct Stats {
    std::atomic<uint64_t> raw_reads{0};
    std::atomic<uint64_t> packed_reads{0};
    std::atomic<uint64_t> walks{0};
    std::atomic<uint64_t> walk_ns{0};
    /** Packed chunks read from a packed store (PackedStore). */
    std::atomic<uint64_t> stored_reads{0};
};
Stats& GetStats();

/** Raw chunks read from the block files along one chain: per block (by height) its file
 *  position, serialized size, id and the chunk count through it. */
class BlockChunkReader : public ChunkSource
{
public:
    void SetBlockManager(const node::BlockManager* blockman) { m_blockman = blockman; }
    uint64_t Count() const override { return m_count_after.empty() ? 0 : m_count_after.back(); }
    bool Locate(uint64_t position, uint64_t& first, uint256& block_id) const override;
    bool ReadRaw(uint64_t position, Chunk& out) override;

    void Push(const FlatFilePos& pos, uint32_t size, const uint256& id);
    void Resize(size_t blocks);
    size_t Blocks() const { return m_count_after.size(); }
    uint64_t CountAfter(size_t height) const { return m_count_after.at(height); }
    uint64_t CountBefore(size_t height) const { return height ? m_count_after.at(height - 1) : 0; }
    const uint256& Id(size_t height) const { return m_id.at(height); }
    /** The same positions without the open files, for reads outside cs_main. */
    BlockChunkReader Copy() const;
    /** Closes the open block files (they are reopened on the next read). */
    void CloseFiles();
    /** The serialized size of the block at `pos` from its record header; nullopt if unreadable. */
    std::optional<uint32_t> ReadSize(const FlatFilePos& pos);

private:
    const node::BlockManager* m_blockman{nullptr};
    std::vector<FlatFilePos> m_pos;
    std::vector<uint32_t> m_size;
    std::vector<uint256> m_id;
    std::vector<uint64_t> m_count_after;
    /** Open block files by file number. */
    std::map<int, std::unique_ptr<AutoFile>> m_files;

    bool ReadAt(int file, uint64_t offset, std::span<std::byte> out);
};

/** A miner's packed copy (regtest prototype): the packed chunks of one chain in position order in
 *  one file, with an index file of (block id, chunk count through it) records. Formed from the
 *  block files with ReadPacked when blocks are added; read with one read per chunk. As a
 *  ChunkSource its chunks are the packed chunks, so a walk over it uses 0 partners. */
class PackedStore : public ChunkSource
{
public:
    PackedStore() = default;
    PackedStore(const PackedStore&) = delete;
    PackedStore& operator=(const PackedStore&) = delete;
    ~PackedStore();

    /** Opens or creates the store at `path` and `path` + ".idx" and loads the index. */
    bool Open(const fs::path& path);
    bool IsOpen() const { return m_fd >= 0; }
    /** Brings the store to the chain of `raw`: truncates it to the longest prefix of blocks it
     *  shares with `raw` (same ids and chunk counts), then packs every later block of `raw` with
     *  `m` partners and appends it. False if a read or write fails. */
    bool SyncTo(BlockChunkReader& raw, unsigned m);
    /** A read-only copy of the index sharing the file (its own descriptor), for walks outside
     *  cs_main. */
    std::shared_ptr<PackedStore> Snapshot() const;

    uint64_t Count() const override { return m_count_after.empty() ? 0 : m_count_after.back(); }
    bool Locate(uint64_t position, uint64_t& first, uint256& block_id) const override;
    /** The stored packed chunk at `position`. */
    bool ReadRaw(uint64_t position, Chunk& out) override;
    size_t Blocks() const { return m_count_after.size(); }

    /** Totals since start: blocks packed, raw chunk reads and seconds spent packing, and blocks
     *  dropped by truncation. */
    struct Totals {
        uint64_t blocks_packed{0};
        uint64_t raw_reads{0};
        double seconds{0};
        uint64_t blocks_dropped{0};
    };
    const Totals& GetTotals() const { return m_totals; }

private:
    int m_fd{-1};
    int m_idx_fd{-1};
    std::vector<uint256> m_id;
    std::vector<uint64_t> m_count_after;
    Totals m_totals;
};

/** The node's packed store; callers hold cs_main. */
PackedStore& NodePackedStore() EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/** What a walk needs for one parent, usable without cs_main (the node's own miner, benchmarks). */
struct Stage {
    uint64_t parent_start{0};
    unsigned reads{8};
    unsigned partners{0};
    BlockChunkReader reader;
    /** If set, the walk reads stored packed chunks (one read per step) instead of forming them. */
    std::shared_ptr<PackedStore> packed;

    bool Final(const uint256& hash2, uint256& out)
    {
        return packed ? Walk(hash2, reads, 0, parent_start, *packed, out) : Walk(hash2, reads, partners, parent_start, reader, out);
    }
};

/** Whether `header`, built on the stage's parent, meets its target. */
bool Valid(const CBlockHeader& header, Stage& stage, const Consensus::Params& params);

/** The chunk positions of the chain the node was last asked about. */
class State
{
public:
    /** Brings the reader to the chain ending at `prev` (blocks 0..prev): truncates to the common
     *  ancestor with the chain it follows and appends from there. False if a block's data is
     *  unavailable; the reader then covers the blocks appended before it. */
    bool SyncTo(const node::BlockManager& blockman, const CBlockIndex* prev) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    uint64_t Count() const { return m_reader.Count(); }
    /** The chunk count before the last block synced to. */
    uint64_t ParentStart() const;
    BlockChunkReader& Reader() { return m_reader; }
    Stage Freeze(const Consensus::Params& params) const;

private:
    std::vector<const CBlockIndex*> m_chain;
    BlockChunkReader m_reader;
    const node::BlockManager* m_blockman{nullptr};

    bool Append(const node::BlockManager& blockman, const CBlockIndex* block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

/** The node's state; callers hold cs_main. */
State& NodeState() EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/** The full check of `header` on `prev` from the node's block files: nullopt if a block's data
 *  is unavailable, else whether the final digest meets the target. */
std::optional<bool> CheckHeader(const CBlockHeader& header, const CBlockIndex* prev, const node::BlockManager& blockman, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

} // namespace ddpow

#endif // BITCOIN_DDPOW_H
