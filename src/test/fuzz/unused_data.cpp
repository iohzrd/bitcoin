// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <policy/unused_data.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/strencodings.h>

#include <cassert>
#include <vector>

namespace {

/** Accepts exactly the non-empty signatures, as NULLFAIL leaves a valid spend. */
class NonEmptySignatureChecker : public BaseSignatureChecker
{
public:
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>&, const CScript&, SigVersion, SighashRules) const override
    {
        return !sig.empty();
    }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char>, SigVersion, ScriptExecutionData&, ScriptError*, SighashRules) const override
    {
        return !sig.empty();
    }
    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }
};

//! The x coordinate of the secp256k1 generator, a valid taproot internal key.
const XOnlyPubKey INTERNAL_KEY{ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};

} // namespace

FUZZ_TARGET(unused_data)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const CScript script{ConsumeScript(fuzzed_data_provider)};
    CTxIn txin;
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 32) {
        txin.scriptWitness.stack.push_back(ConsumeRandomLengthByteVector(fuzzed_data_provider, 128));
    }
    const std::vector<unsigned char> script_bytes(script.begin(), script.end());

    CScript prev_script_pubkey;
    switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 3)) {
    case 0: // P2WSH
        txin.scriptWitness.stack.push_back(script_bytes);
        prev_script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(script));
        break;
    case 1: { // P2SH-P2WSH
        txin.scriptWitness.stack.push_back(script_bytes);
        const CScript program{GetScriptForDestination(WitnessV0ScriptHash(script))};
        txin.scriptSig << std::vector<unsigned char>(program.begin(), program.end());
        prev_script_pubkey = GetScriptForDestination(ScriptHash(program));
        break;
    }
    case 2: { // P2SH
        for (const auto& item : txin.scriptWitness.stack) txin.scriptSig << item;
        txin.scriptSig << script_bytes;
        txin.scriptWitness.SetNull();
        prev_script_pubkey = GetScriptForDestination(ScriptHash(script));
        break;
    }
    default: { // Tapscript, committed to by the output key so the real interpreter reaches the script.
        const uint256 leaf{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, script_bytes)};
        const auto tweaked{INTERNAL_KEY.CreateTapTweak(&leaf)};
        assert(tweaked);
        std::vector<unsigned char> control{uint8_t(TAPROOT_LEAF_TAPSCRIPT | tweaked->second)};
        control.insert(control.end(), INTERNAL_KEY.begin(), INTERNAL_KEY.end());
        txin.scriptWitness.stack.push_back(script_bytes);
        txin.scriptWitness.stack.push_back(control);
        prev_script_pubkey = CScript() << OP_1 << std::vector<unsigned char>(tweaked->first.begin(), tweaked->first.end());
        break;
    }
    }

    std::vector<std::pair<size_t, size_t>> counted_ranges;
    (void)script.DatacarrierBytes(0, &txin.scriptWitness, &counted_ranges);
    for (const auto& [range_begin, range_end] : counted_ranges) {
        assert(range_begin <= range_end && range_end <= script.size());
    }
    const NonEmptySignatureChecker checker;
    const auto traced{UnusedInputDataBytes(txin, prev_script_pubkey, STANDARD_SCRIPT_VERIFY_FLAGS, checker, counted_ranges)};
    const bool oversized{GetSerializeSize(txin.scriptWitness.stack) > g_script_size_policy_limit};
    if (oversized) assert(!traced);

    // A spend the interpreter accepts under standard flags must be evaluated, or its data would go
    // uncounted. The converse need not hold: script validation rejects the rest.
    const bool valid{VerifyScript(txin.scriptSig, prev_script_pubkey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker)};
    if (valid && !oversized && !script.OPNetWitnessSize(txin.scriptWitness)) {
        assert(traced);
    }
}
