// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ddpow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/blake2b.h>
#include <crypto/common.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <util/check.h>

#include <algorithm>
#include <chrono>

#include <fcntl.h>
#include <unistd.h>

namespace ddpow {

namespace {

uint256 Blake2b256(std::span<const unsigned char> in)
{
    uint256 out;
    Assert(0 == blake2b_nokey(out.begin(), out.size(), in.data(), in.size()));
    return out;
}

} // namespace

uint64_t Index(const uint256& x, uint64_t n)
{
    return ReadLE64(x.begin()) % n;
}

std::vector<uint64_t> Partners(const uint256& block_id, uint32_t k, uint64_t first, unsigned m)
{
    std::vector<uint64_t> out;
    if (first == 0 || m == 0) return out;
    if (first <= m) {
        for (uint64_t p = 0; p < first; ++p) out.push_back(p);
        return out;
    }
    std::array<unsigned char, 1 + 32 + 4 + 4> in;
    in[0] = 0x03;
    std::copy(block_id.begin(), block_id.end(), in.begin() + 1);
    WriteLE32(in.data() + 33, k);
    for (uint32_t t = 0; out.size() < m; ++t) {
        WriteLE32(in.data() + 37, t);
        const uint256 e{Blake2b256(in)};
        for (int w = 0; w < 4 && out.size() < m; ++w) {
            const uint64_t candidate{ReadLE64(e.begin() + 8 * w) % first};
            if (std::find(out.begin(), out.end(), candidate) == out.end()) out.push_back(candidate);
        }
    }
    return out;
}

bool ReadPacked(ChunkSource& source, uint64_t position, unsigned m, Chunk& out)
{
    if (!source.ReadRaw(position, out)) return false;
    GetStats().packed_reads.fetch_add(1, std::memory_order_relaxed);
    if (m == 0) return true;
    uint64_t first;
    uint256 id;
    if (!source.Locate(position, first, id)) return false;
    Chunk partner;
    for (const uint64_t p : Partners(id, uint32_t(position - first), first, m)) {
        if (!source.ReadRaw(p, partner)) return false;
        for (size_t i = 0; i < CHUNK; ++i) out[i] ^= partner[i];
    }
    return true;
}

bool Walk(const uint256& hash2, unsigned reads, unsigned partners, uint64_t parent_start, ChunkSource& source, uint256& final_out)
{
    const uint64_t count{source.Count()};
    Assert(count > parent_start);
    const auto start{std::chrono::steady_clock::now()};
    uint256 x{hash2};
    uint64_t position{parent_start + Index(x, count - parent_start)};
    std::array<unsigned char, 32 + CHUNK> in;
    Chunk chunk;
    bool ok{true};
    for (unsigned i = 0; i < reads; ++i) {
        if (!ReadPacked(source, position, partners, chunk)) {
            ok = false;
            break;
        }
        std::copy(x.begin(), x.end(), in.begin());
        std::copy(chunk.begin(), chunk.end(), in.begin() + 32);
        x = Blake2b256(in);
        position = Index(x, count);
    }
    Stats& stats{GetStats()};
    stats.walks.fetch_add(1, std::memory_order_relaxed);
    stats.walk_ns.fetch_add(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count(), std::memory_order_relaxed);
    if (ok) final_out = x;
    return ok;
}

bool MeetsTarget(const uint256& final_digest, const uint256& mask, unsigned nBits, const Consensus::Params& params)
{
    const auto target{DeriveTarget(nBits, params.powLimit)};
    return target && UintToArith256(CBlockHeader::MaskAndReverse(final_digest, mask)) <= *target;
}

Stats& GetStats()
{
    static Stats stats;
    return stats;
}

// Block files

bool BlockChunkReader::ReadAt(int file, uint64_t offset, std::span<std::byte> out)
{
    // A handle opened before the block file grew can fail past its old end: retry once on a new one.
    for (int attempt = 0; attempt < 2; ++attempt) {
        auto it = m_files.find(file);
        if (it == m_files.end()) {
            // Constructed in place from the returned value: AutoFile can be neither copied nor moved.
            std::unique_ptr<AutoFile> f{new AutoFile{m_blockman->OpenBlockFile(FlatFilePos{file, 0}, /*fReadOnly=*/true)}};
            if (f->IsNull()) return false;
            it = m_files.emplace(file, std::move(f)).first;
        }
        try {
            it->second->seek(int64_t(offset), SEEK_SET);
            it->second->read(out);
            return true;
        } catch (const std::exception& e) {
            m_files.erase(it);
            if (attempt == 1) LogDebug(BCLog::VALIDATION, "ddpow: reading %u bytes at %u in block file %d failed: %s\n", out.size(), offset, file, e.what());
        }
    }
    return false;
}

std::optional<uint32_t> BlockChunkReader::ReadSize(const FlatFilePos& pos)
{
    // The record header before the block data: magic (4 bytes), then the size (4 bytes).
    if (!m_blockman || pos.nPos < 4) return std::nullopt;
    std::array<std::byte, 4> size_bytes;
    if (!ReadAt(pos.nFile, pos.nPos - 4, size_bytes)) return std::nullopt;
    return ReadLE32(reinterpret_cast<const unsigned char*>(size_bytes.data()));
}

void BlockChunkReader::CloseFiles()
{
    m_files.clear();
}

void BlockChunkReader::Push(const FlatFilePos& pos, uint32_t size, const uint256& id)
{
    m_pos.push_back(pos);
    m_size.push_back(size);
    m_id.push_back(id);
    m_count_after.push_back(Count() + (uint64_t{size} + CHUNK - 1) / CHUNK);
}

void BlockChunkReader::Resize(size_t blocks)
{
    m_pos.resize(blocks);
    m_size.resize(blocks);
    m_id.resize(blocks);
    m_count_after.resize(blocks);
}

bool BlockChunkReader::Locate(uint64_t position, uint64_t& first, uint256& block_id) const
{
    if (position >= Count()) return false;
    const size_t h = std::upper_bound(m_count_after.begin(), m_count_after.end(), position) - m_count_after.begin();
    first = h ? m_count_after[h - 1] : 0;
    block_id = m_id[h];
    return true;
}

bool BlockChunkReader::ReadRaw(uint64_t position, Chunk& out)
{
    if (!m_blockman || position >= Count()) return false;
    const size_t h = std::upper_bound(m_count_after.begin(), m_count_after.end(), position) - m_count_after.begin();
    const uint64_t first = h ? m_count_after[h - 1] : 0;
    const uint64_t offset = (position - first) * CHUNK;
    if (offset >= m_size[h]) return false;
    const size_t len = std::min<uint64_t>(CHUNK, m_size[h] - offset);
    out.fill(0);
    GetStats().raw_reads.fetch_add(1, std::memory_order_relaxed);
    return ReadAt(m_pos[h].nFile, m_pos[h].nPos + offset, std::as_writable_bytes(std::span{out.data(), len}));
}

BlockChunkReader BlockChunkReader::Copy() const
{
    BlockChunkReader r;
    r.m_blockman = m_blockman;
    r.m_pos = m_pos;
    r.m_size = m_size;
    r.m_id = m_id;
    r.m_count_after = m_count_after;
    return r;
}

bool Valid(const CBlockHeader& header, Stage& stage, const Consensus::Params& params)
{
    const auto stages{header.GetPowStages()};
    uint256 final_digest;
    return stage.Final(stages.hash2, final_digest) && MeetsTarget(final_digest, stages.mask, header.nBits, params);
}

// Packed store

PackedStore::~PackedStore()
{
    if (m_fd >= 0) close(m_fd);
    if (m_idx_fd >= 0) close(m_idx_fd);
}

static constexpr size_t IDX_RECORD{32 + 8};

bool PackedStore::Open(const fs::path& path)
{
    if (IsOpen()) return true;
    m_fd = open(fs::PathToString(path).c_str(), O_RDWR | O_CREAT, 0644);
    m_idx_fd = open((fs::PathToString(path) + ".idx").c_str(), O_RDWR | O_CREAT, 0644);
    if (m_fd < 0 || m_idx_fd < 0) return false;
    // Index records: block id (32 bytes), chunk count through the block (LE64).
    const off_t idx_bytes{lseek(m_idx_fd, 0, SEEK_END)};
    const off_t data_bytes{lseek(m_fd, 0, SEEK_END)};
    std::array<unsigned char, IDX_RECORD> rec;
    for (off_t off = 0; off + off_t(IDX_RECORD) <= idx_bytes; off += IDX_RECORD) {
        if (pread(m_idx_fd, rec.data(), rec.size(), off) != ssize_t(rec.size())) break;
        const uint64_t count{ReadLE64(rec.data() + 32)};
        // A record whose chunks are not all in the data file (an interrupted append) ends the index.
        if (count * CHUNK > uint64_t(data_bytes) || count < Count()) break;
        uint256 id;
        std::copy(rec.begin(), rec.begin() + 32, id.begin());
        m_id.push_back(id);
        m_count_after.push_back(count);
    }
    if (ftruncate(m_idx_fd, off_t(m_id.size() * IDX_RECORD)) != 0) return false;
    if (ftruncate(m_fd, off_t(Count() * CHUNK)) != 0) return false;
    return true;
}

bool PackedStore::SyncTo(BlockChunkReader& raw, unsigned m)
{
    if (!IsOpen()) return false;
    size_t keep{0};
    while (keep < m_id.size() && keep < raw.Blocks() && m_id[keep] == raw.Id(keep) && m_count_after[keep] == raw.CountAfter(keep)) ++keep;
    if (keep < m_id.size()) {
        m_totals.blocks_dropped += m_id.size() - keep;
        m_id.resize(keep);
        m_count_after.resize(keep);
        if (ftruncate(m_fd, off_t(Count() * CHUNK)) != 0 || ftruncate(m_idx_fd, off_t(keep * IDX_RECORD)) != 0) return false;
    }
    if (keep == raw.Blocks()) return true;
    const auto start{std::chrono::steady_clock::now()};
    Stats& stats{GetStats()};
    const uint64_t raw_before{stats.raw_reads.load()};
    Chunk packed;
    std::array<unsigned char, IDX_RECORD> rec;
    for (size_t h = keep; h < raw.Blocks(); ++h) {
        for (uint64_t p = raw.CountBefore(h); p < raw.CountAfter(h); ++p) {
            if (!ReadPacked(raw, p, m, packed)) return false;
            if (pwrite(m_fd, packed.data(), CHUNK, off_t(p * CHUNK)) != ssize_t(CHUNK)) return false;
        }
        std::copy(raw.Id(h).begin(), raw.Id(h).end(), rec.begin());
        WriteLE64(rec.data() + 32, raw.CountAfter(h));
        if (pwrite(m_idx_fd, rec.data(), rec.size(), off_t(h * IDX_RECORD)) != ssize_t(rec.size())) return false;
        m_id.push_back(raw.Id(h));
        m_count_after.push_back(raw.CountAfter(h));
        ++m_totals.blocks_packed;
    }
    m_totals.raw_reads += stats.raw_reads.load() - raw_before;
    m_totals.seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    return true;
}

std::shared_ptr<PackedStore> PackedStore::Snapshot() const
{
    auto out{std::make_shared<PackedStore>()};
    out->m_fd = dup(m_fd);
    out->m_id = m_id;
    out->m_count_after = m_count_after;
    return out;
}

bool PackedStore::Locate(uint64_t position, uint64_t& first, uint256& block_id) const
{
    if (position >= Count()) return false;
    const size_t h = std::upper_bound(m_count_after.begin(), m_count_after.end(), position) - m_count_after.begin();
    first = h ? m_count_after[h - 1] : 0;
    block_id = m_id[h];
    return true;
}

bool PackedStore::ReadRaw(uint64_t position, Chunk& out)
{
    if (m_fd < 0 || position >= Count()) return false;
    GetStats().stored_reads.fetch_add(1, std::memory_order_relaxed);
    return pread(m_fd, out.data(), CHUNK, off_t(position * CHUNK)) == ssize_t(CHUNK);
}

PackedStore& NodePackedStore()
{
    static PackedStore store;
    return store;
}

// Node state

bool State::Append(const node::BlockManager& blockman, const CBlockIndex* block)
{
    AssertLockHeld(::cs_main);
    if (!(block->nStatus & BLOCK_HAVE_DATA)) return false;
    const FlatFilePos pos{block->GetBlockPos()};
    const auto size{m_reader.ReadSize(pos)};
    if (!size || *size == 0) return false;
    m_reader.Push(pos, *size, block->GetBlockHash());
    m_chain.push_back(block);
    return true;
}

bool State::SyncTo(const node::BlockManager& blockman, const CBlockIndex* prev)
{
    AssertLockHeld(::cs_main);
    if (m_blockman != &blockman) {
        m_blockman = &blockman;
        m_chain.clear();
        m_reader = BlockChunkReader{};
        m_reader.SetBlockManager(&blockman);
    }
    size_t keep{0};
    if (prev && !m_chain.empty()) {
        const CBlockIndex* common{LastCommonAncestor(prev, m_chain.back())};
        if (common && size_t(common->nHeight) < m_chain.size() && m_chain[common->nHeight] == common) keep = common->nHeight + 1;
    }
    m_chain.resize(keep);
    m_reader.Resize(keep);
    if (!prev) return true;
    std::vector<const CBlockIndex*> path;
    for (const CBlockIndex* p = prev; p && size_t(p->nHeight) >= m_chain.size(); p = p->pprev) path.push_back(p);
    // Blocks appended since the files were opened may lie past what the open handles saw.
    if (!path.empty()) m_reader.CloseFiles();
    for (auto it = path.rbegin(); it != path.rend(); ++it) {
        if (!Append(blockman, *it)) {
            LogDebug(BCLog::VALIDATION, "ddpow: block data at height %d is unavailable\n", (*it)->nHeight);
            return false;
        }
    }
    return true;
}

uint64_t State::ParentStart() const
{
    return m_chain.size() >= 2 ? m_reader.CountAfter(m_chain.size() - 2) : 0;
}

Stage State::Freeze(const Consensus::Params& params) const
{
    return Stage{ParentStart(), params.DdpowReads, params.DdpowPartners, m_reader.Copy()};
}

State& NodeState()
{
    static State state;
    return state;
}

std::optional<bool> CheckHeader(const CBlockHeader& header, const CBlockIndex* prev, const node::BlockManager& blockman, const Consensus::Params& params)
{
    AssertLockHeld(::cs_main);
    // A parent without data (headers ahead of the blocks): nothing to walk yet.
    if (!prev || !(prev->nStatus & BLOCK_HAVE_DATA)) return std::nullopt;
    State& dd{NodeState()};
    if (!dd.SyncTo(blockman, prev)) return std::nullopt;
    const auto stages{header.GetPowStages()};
    uint256 final_digest;
    if (!Walk(stages.hash2, params.DdpowReads, params.DdpowPartners, dd.ParentStart(), dd.Reader(), final_digest)) return std::nullopt;
    return MeetsTarget(final_digest, stages.mask, header.nBits, params);
}

} // namespace ddpow
