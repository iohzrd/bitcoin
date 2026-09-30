// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <hash.h>
#include <policy/unused_data.h>
#include <primitives/transaction.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/strencodings.h>

#include <cassert>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

class AcceptNonEmpty : public BaseSignatureChecker
{
public:
    bool CheckECDSASignature(const valtype& sig, const valtype&, const CScript&, SigVersion, SighashRules) const override { return !sig.empty(); }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char>, SigVersion, ScriptExecutionData&, ScriptError*, SighashRules) const override { return !sig.empty(); }
    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }
};

valtype Key(unsigned char i) { valtype k(33, i); k[0] = 0x02; return k; }
// A canonical low-S DER signature plus SIGHASH_ALL, since standard flags check the encoding.
valtype Sig() { return ParseHex("300602010102010101"); }

CTxIn P2WSHInput(const CScript& script, std::vector<valtype> items, CScript& spk)
{
    CTxIn txin;
    items.emplace_back(script.begin(), script.end());
    txin.scriptWitness.stack = std::move(items);
    spk = GetScriptForDestination(WitnessV0ScriptHash(script));
    return txin;
}

CTxIn TapscriptInput(const CScript& script, std::vector<valtype> items, CScript& spk)
{
    CTxIn txin;
    items.emplace_back(script.begin(), script.end());
    valtype control(33, 0x01);
    control[0] = TAPROOT_LEAF_TAPSCRIPT;
    items.push_back(control);
    txin.scriptWitness.stack = std::move(items);
    spk = CScript() << OP_1 << valtype(32, 0x01);
    return txin;
}

/** DatacarrierBytes of the executed script, then UnusedInputDataBytes, as InputDatacarrierBytes does. */
void Run(benchmark::Bench& bench, const CTxIn& txin, const CScript& spk, const CScript& script)
{
    const AcceptNonEmpty checker;
    bench.run([&] {
        std::vector<std::pair<size_t, size_t>> ranges;
        const auto dcb{script.DatacarrierBytes(0, &txin.scriptWitness, &ranges)};
        const auto unused{UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, checker, ranges).value_or(std::pair<size_t, size_t>{0, 0})};
        ankerl::nanobench::doNotOptimizeAway(dcb.first + dcb.second + unused.first + unused.second);
    });
}

} // namespace

static void UnusedDataMultisig(benchmark::Bench& bench)
{
    const CScript script{CScript() << 2 << Key(1) << Key(2) << Key(3) << 3 << OP_CHECKMULTISIG};
    CScript spk;
    const CTxIn txin{P2WSHInput(script, {{}, Sig(), Sig()}, spk)};
    assert(UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, AcceptNonEmpty{}, {}));
    Run(bench, txin, spk, script);
}

static void UnusedDataHTLC(benchmark::Bench& bench)
{
    // BOLT 3 offered HTLC spent through its HTLC-timeout 2-of-2.
    const valtype revocation_hash(20, 0x11), payment_hash(20, 0x22);
    const CScript script{CScript() << OP_DUP << OP_HASH160 << revocation_hash << OP_EQUAL
                                   << OP_IF << OP_CHECKSIG
                                   << OP_ELSE << Key(2) << OP_SWAP << OP_SIZE << 32 << OP_EQUAL
                                   << OP_NOTIF << OP_DROP << 2 << OP_SWAP << Key(3) << 2 << OP_CHECKMULTISIG
                                   << OP_ELSE << OP_HASH160 << payment_hash << OP_EQUALVERIFY << OP_CHECKSIG
                                   << OP_ENDIF << 1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_ENDIF};
    CScript spk;
    const CTxIn txin{P2WSHInput(script, {{}, Sig(), Sig(), {}}, spk)};
    assert(UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, AcceptNonEmpty{}, {}));
    Run(bench, txin, spk, script);
}

static void UnusedDataWorstHashes(benchmark::Bench& bench)
{
    // 198 of the 201 opcodes a segwit v0 script may execute, hashing a 520 byte item 66 times.
    CScript script;
    for (int i{0}; i < 66; ++i) script << OP_DUP << OP_HASH256 << OP_DROP;
    script << OP_DROP << OP_1;
    CScript spk;
    const CTxIn txin{P2WSHInput(script, {valtype(520, 0xab)}, spk)};
    assert(UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, AcceptNonEmpty{}, {}));
    Run(bench, txin, spk, script);
}

static void UnusedDataWorstTapscript(benchmark::Bench& bench)
{
    // A tapscript has no opcode limit: fill the -maxscriptsize witness with hashes of a 256 byte item.
    CScript script;
    for (int i{0}; i < 440; ++i) script << OP_DUP << OP_SHA256 << OP_DROP;
    script << OP_DROP << OP_1;
    CScript spk;
    const CTxIn txin{TapscriptInput(script, {valtype(256, 0xab)}, spk)};
    assert(UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, AcceptNonEmpty{}, {}));
    Run(bench, txin, spk, script);
}

static void UnusedDataWorstRanges(benchmark::Bench& bench)
{
    // Unused script pushes interleaved with counted ranges, so Count compares every unused push
    // against every range: a tapscript of <2 bytes> OP_DROP <2 bytes> OP_TOALTSTACK.
    CScript script;
    for (int i{0}; i < 190; ++i) script << valtype{0x07, 0x07} << OP_DROP << valtype{0x07, 0x07} << OP_TOALTSTACK;
    script << OP_1;
    CScript spk;
    const CTxIn txin{TapscriptInput(script, {}, spk)};
    assert(UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, AcceptNonEmpty{}, {}));
    Run(bench, txin, spk, script);
}

BENCHMARK(UnusedDataMultisig, benchmark::PriorityLevel::HIGH);
BENCHMARK(UnusedDataHTLC, benchmark::PriorityLevel::HIGH);
BENCHMARK(UnusedDataWorstHashes, benchmark::PriorityLevel::HIGH);
BENCHMARK(UnusedDataWorstTapscript, benchmark::PriorityLevel::HIGH);
BENCHMARK(UnusedDataWorstRanges, benchmark::PriorityLevel::HIGH);
