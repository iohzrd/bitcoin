// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ddpow.h>

#include <crypto/blake2b.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace {

uint256 Blake(const std::string& tag, uint32_t a, std::optional<uint32_t> b = std::nullopt)
{
    std::vector<unsigned char> in(tag.begin(), tag.end());
    in.resize(in.size() + 4);
    WriteLE32(in.data() + in.size() - 4, a);
    if (b) {
        in.resize(in.size() + 4);
        WriteLE32(in.data() + in.size() - 4, *b);
    }
    uint256 out;
    BOOST_REQUIRE(blake2b_nokey(out.begin(), 32, in.data(), in.size()) == 0);
    return out;
}

/** Block `b` of `size` bytes: BLAKE2b-256("blk" || LE32(b) || LE32(i)) for i = 0, 1, ...
 *  concatenated (as test_framework/ddpow.py's vectors are generated). */
std::vector<unsigned char> BlockData(uint32_t b, size_t size)
{
    std::vector<unsigned char> out;
    for (uint32_t i = 0; out.size() < size; ++i) {
        const uint256 h{Blake("blk", b, i)};
        out.insert(out.end(), h.begin(), h.end());
    }
    out.resize(size);
    return out;
}

class VectorSource : public ddpow::ChunkSource
{
public:
    void Append(std::vector<unsigned char> data, const uint256& id)
    {
        m_first.push_back(m_count);
        m_count += (data.size() + ddpow::CHUNK - 1) / ddpow::CHUNK;
        m_data.push_back(std::move(data));
        m_id.push_back(id);
    }
    uint64_t Count() const override { return m_count; }
    bool Locate(uint64_t position, uint64_t& first, uint256& id) const override
    {
        if (position >= m_count) return false;
        const size_t b = std::upper_bound(m_first.begin(), m_first.end(), position) - m_first.begin() - 1;
        first = m_first[b];
        id = m_id[b];
        return true;
    }
    bool ReadRaw(uint64_t position, ddpow::Chunk& out) override
    {
        uint64_t first;
        uint256 id;
        if (!Locate(position, first, id)) return false;
        const size_t b = std::upper_bound(m_first.begin(), m_first.end(), position) - m_first.begin() - 1;
        const size_t offset = (position - first) * ddpow::CHUNK;
        out.fill(0);
        std::copy_n(m_data[b].begin() + offset, std::min(ddpow::CHUNK, m_data[b].size() - offset), out.begin());
        return true;
    }
    uint64_t ParentStart() const { return m_first.back(); }

private:
    std::vector<std::vector<unsigned char>> m_data;
    std::vector<uint256> m_id;
    std::vector<uint64_t> m_first;
    uint64_t m_count{0};
};

VectorSource VectorChain()
{
    VectorSource source;
    const std::vector<size_t> sizes{285, 4095, 4096, 4097, 10000, 1, 9000, 20000};
    for (uint32_t b = 0; b < sizes.size(); ++b) source.Append(BlockData(b, sizes[b]), Blake("id", b));
    return source;
}

std::vector<uint64_t> List(std::initializer_list<uint64_t> l) { return l; }

} // namespace

BOOST_FIXTURE_TEST_SUITE(ddpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(index)
{
    uint256 x;
    WriteLE64(x.begin(), 1000003);
    BOOST_CHECK_EQUAL(ddpow::Index(x, 1000), 3U);
    BOOST_CHECK_EQUAL(ddpow::Index(x, 1), 0U);
}

BOOST_AUTO_TEST_CASE(partners_properties)
{
    const uint256 id{Blake("id", 6)};
    BOOST_CHECK(ddpow::Partners(id, 0, 0, 7).empty());       // genesis: no older chunk
    BOOST_CHECK(ddpow::Partners(id, 0, 1000, 0).empty());    // packing off
    BOOST_CHECK(ddpow::Partners(id, 5, 3, 7) == List({0, 1, 2}));  // fewer older chunks than partners: all
    BOOST_CHECK(ddpow::Partners(id, 1, 1, 2) == List({0}));
    for (unsigned m : {1U, 2U, 3U, 4U, 7U, 8U, 16U}) {
        for (uint64_t first : {uint64_t{m + 1}, uint64_t{17}, uint64_t{1000}, uint64_t{1} << 40}) {
            for (uint32_t k = 0; k < 50; ++k) {
                const auto p{ddpow::Partners(id, k, first, m)};
                BOOST_CHECK_EQUAL(p.size(), m);
                BOOST_CHECK_EQUAL(std::set<uint64_t>(p.begin(), p.end()).size(), m);
                BOOST_CHECK(std::all_of(p.begin(), p.end(), [&](uint64_t x) { return x < first; }));
                BOOST_CHECK(ddpow::Partners(id, k, first, m) == p);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(partners_vectors)
{
    // From test_framework/ddpow.py.
    const uint256 id{Blake("id", 6)};
    BOOST_CHECK(ddpow::Partners(id, 1, 13, 7) == List({11, 7, 0, 5, 10, 3, 12}));
    BOOST_CHECK(ddpow::Partners(id, 0, 1000000, 8) == List({605580, 489461, 862574, 23234, 605162, 652525, 310112, 198775}));
}

BOOST_AUTO_TEST_CASE(packed_and_walk_vectors)
{
    // Blocks of 285, 4095, 4096, 4097, 10000, 1, 9000 and 20000 bytes: 17 chunks, first chunks
    // 0, 1, 2, 3, 5, 8, 9, 12. Expected values from test_framework/ddpow.py.
    VectorSource source{VectorChain()};
    BOOST_CHECK_EQUAL(source.Count(), 17U);
    for (const auto& [position, sha] : {std::pair<uint64_t, std::string>{16, "f4659ad8f5b92c2f5b1b91983549d85a77e676b5029e271608f1aed52574477f"},
                                       {9, "c17ec5a8262725f98e00ea93383b3301dda1ae93f3d8d56386640ea61e85761b"}}) {
        ddpow::Chunk packed;
        BOOST_REQUIRE(ddpow::ReadPacked(source, position, 2, packed));
        uint256 digest;
        CSHA256().Write(packed.data(), packed.size()).Finalize(digest.begin());
        BOOST_CHECK_EQUAL(HexStr(digest), sha);
    }
    uint256 h2;
    const std::string tag{"hash2"};
    BOOST_REQUIRE(blake2b_nokey(h2.begin(), 32, tag.data(), tag.size()) == 0);
    for (const auto& [m, expected] : {std::pair<unsigned, std::string>{0, "fa637d7f2f601d70e1bca12d291e732992756534cabecf0a07233bff578dd071"},
                                     {2, "b5d55311b7cb894454202f81cc733bb5dd717454dcb068ba84aaa5643c6dd0cf"},
                                     {7, "c4c6bd93b81bdb1ef6e8d69f25d3108ebb6d217be8c2ee2c7442eab987851651"}}) {
        uint256 final_digest;
        BOOST_REQUIRE(ddpow::Walk(h2, 8, m, source.ParentStart(), source, final_digest));
        BOOST_CHECK_EQUAL(HexStr(final_digest), expected);
    }
}

BOOST_AUTO_TEST_CASE(walk_fails_on_missing_chunk)
{
    // A source that fails every read after the parent's.
    class Failing : public ddpow::ChunkSource
    {
    public:
        uint64_t Count() const override { return 10; }
        bool Locate(uint64_t, uint64_t& first, uint256& id) const override { first = 9; id.SetNull(); return true; }
        bool ReadRaw(uint64_t position, ddpow::Chunk& out) override { out.fill(0); return position == 9; }
    } failing;
    uint256 final_digest;
    BOOST_CHECK(!ddpow::Walk(uint256::ONE, 8, 0, 9, failing, final_digest));
}

BOOST_AUTO_TEST_CASE(bip_test_vectors)
{
    // bip-strong-ddpow.md, Test vectors: 14 byte strings, m = 7, k = 8.
    VectorSource source;
    const std::vector<size_t> sizes{285, 4095, 4096, 4097, 10000, 1, 9000, 20000, 30000, 4096, 12288, 50000, 7000, 40000};
    for (uint32_t b = 0; b < sizes.size(); ++b) source.Append(BlockData(b, sizes[b]), Blake("id", b));
    BOOST_CHECK_EQUAL(source.Count(), 54U);
    BOOST_CHECK_EQUAL(source.ParentStart(), 44U);
    BOOST_CHECK_EQUAL(HexStr(Blake("id", 0)), "18d727d27284acabf9311e5b0837c37f90e075c449c1dba60adf062da92745bf");
    for (const auto& [position, partners, sha] : {
             std::tuple<uint64_t, std::vector<uint64_t>, std::string>{0, {}, "d7e9cb80c435795a67bdccd18f921b2102ff82cbb977ebd23a2b5d80a78d6f7a"},
             {3, {0, 1, 2}, "e4496d67cf522df1f4f5fb370e223939c8633bb2d94f04a6c8a3388fd0d452af"},
             {5, {0, 1, 2, 3, 4}, "3c122ed6153d05f1686455b617c65a7e2ce2d4c6f637d8960738feeca381bfb1"},
             {12, {1, 9, 2, 10, 3, 0, 11}, "80f59a0fbfe4384ad64cd50b10639dfd16722b6a04a4774f19a99442bda83817"},
             {30, {11, 14, 9, 4, 26, 2, 15}, "42371042fe223513e4c47c6f00850fefc562f58eee272d506807e6924f4af510"},
             {44, {2, 18, 24, 33, 38, 30, 10}, "15b6ef2d39864b1555daad1ba984994bf30eb0726e7805534ef378ea0f4802c9"},
             {53, {13, 36, 38, 4, 35, 6, 5}, "3c67e7c346380a38b3ed5667246ca1589d07303521a6d1c6ac9c926ef70082f4"}}) {
        uint64_t first;
        uint256 id;
        BOOST_REQUIRE(source.Locate(position, first, id));
        BOOST_CHECK(ddpow::Partners(id, uint32_t(position - first), first, 7) == partners);
        ddpow::Chunk packed;
        BOOST_REQUIRE(ddpow::ReadPacked(source, position, 7, packed));
        uint256 digest;
        CSHA256().Write(packed.data(), packed.size()).Finalize(digest.begin());
        BOOST_CHECK_EQUAL(HexStr(digest), sha);
    }
    for (const auto& [tag, expected] : {std::pair<std::string, std::string>{"hash2", "50dfaa122d6d10463baa607b9a836fc085b231d96e2da98ca412090ff05a3c2e"},
                                       {"test vector 2", "e0395a36a2dbfcb7c2978db06fc4b7f15acf194a66116ea2295a741698b0ec86"}}) {
        uint256 h0;
        BOOST_REQUIRE(blake2b_nokey(h0.begin(), 32, tag.data(), tag.size()) == 0);
        uint256 final_digest;
        BOOST_REQUIRE(ddpow::Walk(h0, 8, 7, source.ParentStart(), source, final_digest));
        BOOST_CHECK_EQUAL(HexStr(final_digest), expected);
    }
}

BOOST_AUTO_TEST_SUITE_END()
