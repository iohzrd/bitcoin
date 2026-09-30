// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/unused_data.h>

#include <policy/settings.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <optional>

namespace {

using valtype = std::vector<unsigned char>;

bool CastToBool(const valtype& vch)
{
    for (size_t i{0}; i < vch.size(); ++i) {
        if (vch[i] != 0) {
            // Negative zero is still zero.
            return !(i == vch.size() - 1 && vch[i] == 0x80);
        }
    }
    return false;
}

/** The script an input executes, the stack it starts from, and what its signatures commit to. */
struct Spend {
    CScript script;
    std::vector<valtype> stack;
    SigVersion sigversion;
    ScriptExecutionData execdata;
};

/** Finds the executed script as GetScriptForTransactionInput does. */
std::optional<Spend> GetSpend(const CTxIn& txin, CScript prev_script)
{
    std::vector<valtype> stack;
    bool p2sh{false};
    if (prev_script.IsPayToScriptHash()) {
        if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE) || stack.empty()) {
            return std::nullopt;
        }
        prev_script = CScript(stack.back().begin(), stack.back().end());
        stack.pop_back();
        p2sh = true;
    }

    int witness_version;
    valtype program;
    if (!prev_script.IsWitnessProgram(witness_version, program)) {
        if (!p2sh) return std::nullopt;
        return Spend{std::move(prev_script), std::move(stack), SigVersion::BASE, {}};
    }
    // Consensus requires a wrapped witness program's scriptSig to be its push alone.
    if (!stack.empty()) return std::nullopt;

    stack = txin.scriptWitness.stack;
    if (witness_version == 0 && program.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
        if (stack.empty()) return std::nullopt;
        CScript script(stack.back().begin(), stack.back().end());
        stack.pop_back();
        return Spend{std::move(script), std::move(stack), SigVersion::WITNESS_V0, {}};
    }
    if (witness_version == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
        // An annex is non-standard, and a key path spend executes no script.
        if (stack.size() < 2 || (!stack.back().empty() && stack.back()[0] == ANNEX_TAG)) return std::nullopt;
        const valtype control{stack.back()};
        stack.pop_back();
        if (control.empty() || (control[0] & TAPROOT_LEAF_MASK) != TAPROOT_LEAF_TAPSCRIPT) return std::nullopt;
        CScript script(stack.back().begin(), stack.back().end());
        stack.pop_back();
        // As VerifyWitnessProgram sets it up for a tapscript.
        ScriptExecutionData execdata;
        execdata.m_tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, script);
        execdata.m_tapleaf_hash_init = true;
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        execdata.m_validation_weight_left = ::GetSerializeSize(txin.scriptWitness.stack) + VALIDATION_WEIGHT_OFFSET;
        execdata.m_validation_weight_left_init = true;
        return Spend{std::move(script), std::move(stack), SigVersion::TAPSCRIPT, std::move(execdata)};
    }
    return std::nullopt;
}

/**
 * Checks signatures against the unaltered script, which is what they commit to, and records them.
 *
 * An altered push keeps its length, so a script code is the same suffix of the unaltered script.
 * Standard flags include CONST_SCRIPTCODE, so no signature is deleted from a legacy script code.
 */
class UnalteredScriptChecker : public BaseSignatureChecker
{
public:
    UnalteredScriptChecker(const BaseSignatureChecker& checker, const CScript& script, std::vector<valtype>* signatures)
        : m_checker{checker}, m_script{script}, m_signatures{signatures} {}

    bool CheckECDSASignature(const valtype& sig, const valtype& pubkey, const CScript& script_code, SigVersion sigversion, SighashRules sighash_rules) const override
    {
        if (m_signatures && !sig.empty()) m_signatures->push_back(sig);
        if (script_code.size() > m_script.size()) return false;
        const CScript unaltered(m_script.end() - script_code.size(), m_script.end());
        return m_checker.CheckECDSASignature(sig, pubkey, unaltered, sigversion, sighash_rules);
    }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror, SighashRules sighash_rules) const override
    {
        if (m_signatures && !sig.empty()) m_signatures->emplace_back(sig.begin(), sig.end());
        return m_checker.CheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror, sighash_rules);
    }
    bool CheckLockTime(const CScriptNum& lock_time) const override { return m_checker.CheckLockTime(lock_time); }
    bool CheckSequence(const CScriptNum& sequence) const override { return m_checker.CheckSequence(sequence); }

private:
    const BaseSignatureChecker& m_checker;
    const CScript& m_script;
    std::vector<valtype>* m_signatures;
};

/** An item whose bytes are altered: a witness item, or the data of a script push. */
struct Candidate {
    bool in_script;
    size_t position; //!< stack index, or script offset of the push data
    size_t size;
};

/** Executes the spend with the chosen candidates' bytes altered; true if it is still valid. */
bool Valid(const Spend& spend, const std::vector<Candidate>& candidates, const std::vector<bool>& alter,
           unsigned int flags, const BaseSignatureChecker& checker, std::vector<valtype>* signatures)
{
    std::vector<valtype> stack{spend.stack};
    CScript script{spend.script};
    for (size_t i{0}; i < alter.size(); ++i) {
        if (!alter[i]) continue;
        const Candidate& c{candidates[i]};
        unsigned char* data{c.in_script ? script.data() + c.position : stack[c.position].data()};
        for (size_t j{0}; j < c.size; ++j) data[j] ^= 0x01;
    }
    ScriptExecutionData execdata{spend.execdata};
    const UnalteredScriptChecker unaltered{checker, spend.script, signatures};
    // CLEANSTACK: segwit requires it by consensus, and standard flags for P2SH.
    return EvalScript(stack, script, flags, unaltered, spend.sigversion, execdata) &&
           stack.size() == 1 && CastToBool(stack.back());
}

} // namespace

std::optional<std::pair<size_t, size_t>> UnusedInputDataBytes(const CTxIn& txin, const CScript& prev_script_pubkey, unsigned int flags,
                                                              const BaseSignatureChecker& checker,
                                                              const std::vector<std::pair<size_t, size_t>>& counted_ranges)
{
    const std::optional<Spend> spend{GetSpend(txin, prev_script_pubkey)};
    if (!spend) return std::nullopt;
    // DatacarrierBytes counts an OPNet witness whole.
    if (spend->sigversion != SigVersion::BASE && spend->script.OPNetWitnessSize(txin.scriptWitness)) return std::nullopt;
    // IsWitnessStandard rejects a witness over -maxscriptsize; that also bounds the executions here.
    if (::GetSerializeSize(txin.scriptWitness.stack) > g_script_size_policy_limit) return std::nullopt;

    // The unaltered spend, recording its signatures so they are not altered: each would cost a
    // signature verification to find what is already known.
    std::vector<valtype> signatures;
    std::vector<Candidate> candidates;
    if (!Valid(*spend, candidates, {}, flags, checker, &signatures)) return std::nullopt;

    for (size_t i{0}; i < spend->stack.size(); ++i) {
        const valtype& item{spend->stack[i]};
        // Zero bytes carry no payload, e.g. miniscript's dissatisfaction of a hash fragment.
        if (std::all_of(item.begin(), item.end(), [](unsigned char c) { return c == 0; })) continue;
        if (std::find(signatures.begin(), signatures.end(), item) != signatures.end()) continue;
        candidates.push_back({false, i, item.size()});
    }

    // DatacarrierBytes reports its ranges without overlap, so the last one to begin at or before
    // an offset is the only one that can hold it.
    std::vector<std::pair<size_t, size_t>> ranges{counted_ranges};
    std::sort(ranges.begin(), ranges.end());
    const auto counted = [&](size_t offset) {
        const auto it{std::upper_bound(ranges.begin(), ranges.end(), std::pair<size_t, size_t>{offset, SIZE_MAX})};
        return it != ranges.begin() && offset < std::prev(it)->second;
    };
    opcodetype opcode;
    valtype push;
    for (CScript::const_iterator pc{spend->script.begin()}; pc < spend->script.end();) {
        const size_t offset(pc - spend->script.begin());
        if (!spend->script.GetOp(pc, opcode, push)) break;
        if (opcode > OP_PUSHDATA4 || counted(offset)) continue;
        const size_t size{push.size()};
        // Numbers, hash commitments and keys are spending conditions even where unused, e.g. in a
        // branch the witness does not select. Unmatched script keys are not counted here.
        if (size <= 5 || size == 20 || size == 32 || size == CPubKey::COMPRESSED_SIZE ||
            (size == CPubKey::SIZE && spend->sigversion == SigVersion::BASE)) {
            continue;
        }
        candidates.push_back({true, size_t(pc - spend->script.begin()) - size, size});
    }
    if (candidates.empty()) return std::pair<size_t, size_t>{0, 0};

    // Alter all candidates at once, which settles an input that carries only data in one execution
    // and alters copies compared for equality together; then each alone, up to a bound.
    std::vector<bool> unused(candidates.size(), true);
    if (!Valid(*spend, candidates, unused, flags, checker, nullptr)) {
        if (candidates.size() <= MAX_UNUSED_DATA_EXECUTIONS) {
            for (size_t i{0}; i < candidates.size(); ++i) {
                std::vector<bool> alter(candidates.size(), false);
                alter[i] = true;
                unused[i] = Valid(*spend, candidates, alter, flags, checker, nullptr);
            }
        }
        // Past the bound every candidate counts, which no ordinary spend reaches.
    }

    size_t key_bytes{0}, witness_bytes{0}, script_bytes{0};
    for (size_t i{0}; i < candidates.size(); ++i) {
        if (!unused[i]) continue;
        const Candidate& c{candidates[i]};
        if (c.in_script) {
            script_bytes += c.size;
        } else if (c.size == CPubKey::COMPRESSED_SIZE && (spend->stack[c.position][0] == 0x02 || spend->stack[c.position][0] == 0x03)) {
            // An unexamined key the witness supplies.
            key_bytes += c.size;
        } else {
            witness_bytes += c.size;
        }
    }
    return std::pair<size_t, size_t>{key_bytes, witness_bytes + (script_bytes > MAX_UNUSED_SCRIPT_BYTES ? script_bytes - MAX_UNUSED_SCRIPT_BYTES : 0)};
}
