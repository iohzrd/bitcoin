// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <hash.h>
#include <policy/policy.h>
#include <policy/unused_data.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

/**
 * Accepts a signature from Sig or SchnorrSig only for the key it names, as a real checker binds a
 * signature to one key: otherwise an altered item could make the same witness valid by another path.
 */
class KeyBoundChecker : public BaseSignatureChecker
{
public:
    bool CheckECDSASignature(const valtype& sig, const valtype& pubkey, const CScript&, SigVersion, SighashRules) const override
    {
        return sig.size() == 9 && pubkey.size() > 1 && sig[4] == pubkey[1];
    }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion, ScriptExecutionData&, ScriptError*, SighashRules) const override
    {
        return sig.size() == 64 && !pubkey.empty() && sig[0] == pubkey[0];
    }
    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }
};

valtype Key(unsigned char i) { valtype k(33, i); k[0] = 0x02; return k; }
valtype XKey(unsigned char i) { return valtype(32, i); }
// A canonical low-S DER signature plus SIGHASH_ALL, as STANDARD flags check the encoding, whose R
// names the key i it signs for.
valtype Sig(unsigned char i) { return {0x30, 0x06, 0x02, 0x01, i, 0x02, 0x01, 0x01, 0x01}; }
valtype SchnorrSig(unsigned char i) { return valtype(64, i); }
valtype Data(size_t size, unsigned char fill = 0xab) { return valtype(size, fill); }
valtype Hash160Of(const valtype& v) { valtype h(20); CHash160().Write(v).Finalize(h); return h; }
const valtype TRUE_ITEM{1};

std::string Result(const CTxIn& txin, const CScript& spk, const CScript& script)
{
    std::vector<std::pair<size_t, size_t>> ranges;
    script.DatacarrierBytes(0, &txin.scriptWitness, &ranges);
    // "fail" tells a spend that does not execute to its end from one with nothing unused.
    const auto result{UnusedInputDataBytes(txin, spk, STANDARD_SCRIPT_VERIFY_FLAGS, KeyBoundChecker{}, ranges)};
    if (!result) return "fail";
    return std::to_string(result->first) + "+" + std::to_string(result->second);
}

std::string P2WSH(const CScript& script, std::vector<valtype> items)
{
    CTxIn txin;
    items.emplace_back(script.begin(), script.end());
    txin.scriptWitness.stack = std::move(items);
    return Result(txin, GetScriptForDestination(WitnessV0ScriptHash(script)), script);
}

std::string P2SH(const CScript& redeem, const std::vector<valtype>& items)
{
    CTxIn txin;
    for (const valtype& item : items) txin.scriptSig << item;
    txin.scriptSig << valtype(redeem.begin(), redeem.end());
    return Result(txin, GetScriptForDestination(ScriptHash(redeem)), redeem);
}

std::string Tapscript(const CScript& script, std::vector<valtype> items)
{
    CTxIn txin;
    items.emplace_back(script.begin(), script.end());
    valtype control(33, 0x01);
    control[0] = 0xc0;
    items.push_back(control);
    txin.scriptWitness.stack = std::move(items);
    return Result(txin, CScript() << OP_1 << valtype(32, 0x01), script);
}

CScript Cat(CScript a, const CScript& b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

CScript Multisig(int m, const std::vector<valtype>& keys)
{
    CScript s;
    s << m;
    for (const valtype& k : keys) s << k;
    s << int(keys.size()) << OP_CHECKMULTISIG;
    return s;
}

// BOLT 3 offered HTLC, anchor variant.
CScript OfferedHTLC(const valtype& revocation, const valtype& payment_hash160)
{
    return CScript() << OP_DUP << OP_HASH160 << Hash160Of(revocation) << OP_EQUAL
                     << OP_IF << OP_CHECKSIG
                     << OP_ELSE << Key(2) << OP_SWAP << OP_SIZE << 32 << OP_EQUAL
                     << OP_NOTIF << OP_DROP << 2 << OP_SWAP << Key(3) << 2 << OP_CHECKMULTISIG
                     << OP_ELSE << OP_HASH160 << payment_hash160 << OP_EQUALVERIFY << OP_CHECKSIG
                     << OP_ENDIF << 1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_ENDIF;
}

// BOLT 3 received HTLC, anchor variant.
CScript ReceivedHTLC(const valtype& revocation, const valtype& payment_hash160)
{
    return CScript() << OP_DUP << OP_HASH160 << Hash160Of(revocation) << OP_EQUAL
                     << OP_IF << OP_CHECKSIG
                     << OP_ELSE << Key(2) << OP_SWAP << OP_SIZE << 32 << OP_EQUAL
                     << OP_IF << OP_HASH160 << payment_hash160 << OP_EQUALVERIFY
                     << 2 << OP_SWAP << Key(3) << 2 << OP_CHECKMULTISIG
                     << OP_ELSE << OP_DROP << 800000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_CHECKSIG
                     << OP_ENDIF << 1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_ENDIF;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(unused_data_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(honest_spends)
{
    // Multisig, both kinds of wrapping.
    BOOST_CHECK_EQUAL("0+0", P2WSH(Multisig(2, {Key(1), Key(2), Key(3)}), {{}, Sig(1), Sig(2)}));
    BOOST_CHECK_EQUAL("0+0", P2SH(Multisig(2, {Key(1), Key(2), Key(3)}), {{}, Sig(1), Sig(2)}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(Multisig(11, {Key(1), Key(2), Key(3), Key(4), Key(5), Key(6), Key(7), Key(8), Key(9), Key(10), Key(11), Key(12), Key(13), Key(14), Key(15)}),
                                   {{}, Sig(1), Sig(2), Sig(3), Sig(4), Sig(5), Sig(6), Sig(7), Sig(8), Sig(9), Sig(10), Sig(11)}));

    // A key from the witness checked against its hash.
    const CScript pkh{CScript() << OP_DUP << OP_HASH160 << Hash160Of(Key(1)) << OP_EQUALVERIFY << OP_CHECKSIG};
    BOOST_CHECK_EQUAL("0+0", P2WSH(pkh, {Sig(1), Key(1)}));

    // A hashlock with a 32 byte preimage.
    const valtype preimage(32, 0x42);
    valtype sha(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(sha.data());
    const CScript hashlock{CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_SHA256 << sha << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG};
    BOOST_CHECK_EQUAL("0+0", P2WSH(hashlock, {Sig(1), preimage}));

    // Lightning to_local, both branches.
    const CScript to_local{CScript() << OP_IF << Key(1) << OP_ELSE << 144 << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key(2) << OP_ENDIF << OP_CHECKSIG};
    BOOST_CHECK_EQUAL("0+0", P2WSH(to_local, {Sig(1), TRUE_ITEM}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(to_local, {Sig(2), {}}));

    // Lightning anchor, keyed and after 16 blocks without a signature.
    const CScript anchor{CScript() << Key(1) << OP_CHECKSIG << OP_IFDUP << OP_NOTIF << OP_16 << OP_CHECKSEQUENCEVERIFY << OP_ENDIF};
    BOOST_CHECK_EQUAL("0+0", P2WSH(anchor, {Sig(1)}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(anchor, {{}}));

    // Lightning HTLCs on every path. The revocation hash, a payment hash and the size constant go
    // unused on some paths, within MAX_UNUSED_SCRIPT_BYTES.
    const valtype revocation{Key(1)};
    const CScript offered{OfferedHTLC(revocation, Hash160Of(preimage))};
    BOOST_CHECK_EQUAL("0+0", P2WSH(offered, {Sig(1), revocation}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(offered, {Sig(2), preimage}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(offered, {{}, Sig(2), Sig(3), {}}));
    const CScript received{ReceivedHTLC(revocation, Hash160Of(preimage))};
    BOOST_CHECK_EQUAL("0+0", P2WSH(received, {Sig(1), revocation}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(received, {{}, Sig(2), Sig(3), preimage}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(received, {Sig(2), {}}));

    // Miniscript or_d(pk(A),pk(B)), satisfied by B.
    const CScript or_d{CScript() << Key(1) << OP_CHECKSIG << OP_IFDUP << OP_NOTIF << Key(2) << OP_CHECKSIG << OP_ENDIF};
    BOOST_CHECK_EQUAL("0+0", P2WSH(or_d, {Sig(2), {}}));

    // Miniscript or_d(sha256(H),pk(B)), dissatisfying the hash with 32 zero bytes.
    const CScript or_d_hash{CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_SHA256 << sha << OP_EQUAL
                                      << OP_IFDUP << OP_NOTIF << Key(2) << OP_CHECKSIG << OP_ENDIF};
    BOOST_CHECK_EQUAL("0+0", P2WSH(or_d_hash, {Sig(2), valtype(32, 0)}));
    BOOST_CHECK_EQUAL("0+32", P2WSH(or_d_hash, {Sig(2), valtype(32, 1)}));

    // A federation with a timelocked emergency branch, spent by the federation.
    const CScript federation{Cat(Cat(Cat(CScript() << OP_IF, Multisig(2, {Key(1), Key(2), Key(3)})),
                                     Cat(CScript() << OP_ELSE << 4032 << OP_CHECKSEQUENCEVERIFY << OP_DROP, Multisig(1, {Key(4), Key(5)}))),
                                 CScript() << OP_ENDIF)};
    BOOST_CHECK_EQUAL("0+0", P2WSH(federation, {{}, Sig(1), Sig(2), TRUE_ITEM}));

    // Shapes flagged on mainnet by an earlier version, which counted every push in a branch the
    // witness did not select: a selector over pairs of hash commitments (P2SH-P2WSH, 152
    // transactions from height 961687), and a primary 2-of-2 with three timelocked key-hash
    // recovery paths (P2WSH, height 966389).
    const valtype preimage2(32, 0x43);
    const CScript selector{CScript() << OP_DUP << 1 << OP_EQUAL << OP_IF << OP_DROP << Data(20, 1) << Data(20, 2)
                                     << OP_ELSE << OP_DUP << 2 << OP_EQUAL << OP_IF << OP_DROP << Data(20, 3) << Data(20, 4)
                                     << OP_ELSE << OP_DUP << 3 << OP_EQUAL << OP_IF << OP_DROP << Data(20, 5) << Data(20, 6)
                                     << OP_ELSE << 4 << OP_EQUALVERIFY << Hash160Of(Key(1)) << Hash160Of(preimage2)
                                     << OP_ENDIF << OP_ENDIF << OP_ENDIF
                                     << OP_ROT << OP_HASH160 << OP_EQUALVERIFY << OP_OVER << OP_HASH160 << OP_EQUALVERIFY << OP_CHECKSIG};
    BOOST_CHECK_EQUAL("0+0", P2WSH(selector, {Sig(1), Key(1), preimage2, {4}}));
    CScript recovery;
    for (unsigned char i{1}; i <= 3; ++i) {
        recovery << OP_IF << OP_DUP << OP_HASH160 << Data(20, i) << OP_EQUALVERIFY << OP_CHECKSIGVERIFY << 4032 + i << OP_CHECKSEQUENCEVERIFY << OP_ELSE;
    }
    recovery << Key(1) << OP_CHECKSIGVERIFY << Key(2) << OP_CHECKSIG << OP_ENDIF << OP_ENDIF << OP_ENDIF;
    BOOST_CHECK_EQUAL("0+0", P2WSH(recovery, {Sig(2), Sig(1), {}, {}, {}}));

    // Tapscript multi_a 2-of-3 with the middle key not signing.
    const CScript multi_a{CScript() << XKey(1) << OP_CHECKSIG << XKey(2) << OP_CHECKSIGADD << XKey(3) << OP_CHECKSIGADD << OP_2 << OP_NUMEQUAL};
    BOOST_CHECK_EQUAL("0+0", Tapscript(multi_a, {SchnorrSig(3), {}, SchnorrSig(1)}));
}

BOOST_AUTO_TEST_CASE(discarded_data)
{
    const CScript checksig{CScript() << Key(1) << OP_CHECKSIG};

    // Witness items the script drops.
    BOOST_CHECK_EQUAL("0+160", P2WSH(CScript() << OP_2DROP << Key(1) << OP_CHECKSIG, {Sig(1), Data(80), Data(80)}));
    BOOST_CHECK_EQUAL("0+80", P2WSH(CScript() << OP_NIP << Key(1) << OP_CHECKSIG, {Data(80), Sig(1)}));
    BOOST_CHECK_EQUAL("0+80", P2WSH(CScript() << OP_TOALTSTACK << Key(1) << OP_CHECKSIG, {Sig(1), Data(80)}));

    // Witness items that only a condition, a digest or an equality with another witness item reads.
    BOOST_CHECK_EQUAL("0+80", P2WSH(CScript() << OP_SHA256 << OP_VERIFY << Key(1) << OP_CHECKSIG, {Sig(1), Data(80)}));
    BOOST_CHECK_EQUAL("0+160", P2WSH(CScript() << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG, {Sig(1), Data(80), Data(80)}));
    BOOST_CHECK_EQUAL("0+80", P2WSH(CScript() << 1 << OP_EQUAL << OP_NOT << OP_VERIFY << Key(1) << OP_CHECKSIG, {Sig(1), Data(80)}));
    BOOST_CHECK_EQUAL("0+80", P2WSH(CScript() << OP_SIZE << OP_2DROP << Key(1) << OP_CHECKSIG, {Sig(1), Data(80)}));
    // P2SH has no MINIMALIF, so a condition can be any truthy push.
    BOOST_CHECK_EQUAL("0+75", P2SH(CScript() << OP_IF << Key(1) << OP_CHECKSIG << OP_ELSE << OP_0 << OP_ENDIF, {Sig(1), Data(75)}));

    // Script pushes moved away or examined only for their size, past the tolerance.
    CScript altstack, sized;
    for (int i{0}; i < 10; ++i) {
        altstack << Data(75) << OP_TOALTSTACK;
        sized << Data(75) << OP_SIZE << OP_2DROP;
    }
    BOOST_CHECK_EQUAL("0+686", P2WSH(Cat(altstack, checksig), {Sig(1)}));
    BOOST_CHECK_EQUAL("0+686", P2WSH(Cat(sized, checksig), {Sig(1)}));

    // Pushes of no number, hash or key size in a branch the witness does not select.
    CScript untaken{CScript() << OP_IF << Key(1) << OP_CHECKSIG << OP_ELSE};
    for (int i{0}; i < 10; ++i) untaken << Data(75);
    untaken << OP_ENDIF;
    BOOST_CHECK_EQUAL("0+686", P2WSH(untaken, {Sig(1), TRUE_ITEM}));

    // A branch no spend executes is not told from one the witness did not select: pushes of no
    // number, hash or key size count, less the tolerance. The first is the shape of
    // 23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a.
    BOOST_CHECK_EQUAL("0+446", P2WSH(CScript() << OP_1 << OP_NOTIF << Data(255) << Data(255) << OP_ENDIF << OP_1, {}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << OP_2 << OP_2 << OP_SUB << OP_IF << Data(20) << Data(20) << Data(20) << Data(20) << OP_ENDIF << Key(1) << OP_CHECKSIG, {Sig(1)}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << OP_2 << OP_1 << OP_SUB << OP_NOTIF << Data(32) << Data(32) << OP_ENDIF << Key(1) << OP_CHECKSIG, {Sig(1)}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << OP_1 << OP_IF << Key(1) << OP_CHECKSIG << OP_ELSE << Data(32) << Data(32) << OP_ENDIF, {Sig(1)}));
}

BOOST_AUTO_TEST_CASE(multisig_keys)
{
    std::vector<valtype> fakes;

    // Keys CHECKMULTISIG cannot match, since examining one fails: any size but a valid key's.
    for (int i{0}; i < 14; ++i) fakes.push_back(Data(34));
    fakes.push_back(Key(1));
    BOOST_CHECK_EQUAL("0+412", P2WSH(Multisig(1, fakes), {{}, Sig(1)}));
    fakes.clear();
    for (int i{0}; i < 6; ++i) fakes.push_back(Data(240));
    fakes.push_back(Key(1));
    BOOST_CHECK_EQUAL("0+1376", P2WSH(Multisig(1, fakes), {{}, Sig(1)}));
    // Segwit accepts only compressed keys.
    fakes.clear();
    for (int i{0}; i < 14; ++i) { valtype k(65, 0xab); k[0] = 0x04; fakes.push_back(k); }
    fakes.push_back(Key(1));
    BOOST_CHECK_EQUAL("0+846", P2WSH(Multisig(1, fakes), {{}, Sig(1)}));

    // Keys supplied by the witness: invalid ones are discarded, valid unmatched ones are counted
    // separately as keys.
    std::vector<valtype> witness{{}, Sig(1), {1}};
    for (int i{0}; i < 14; ++i) witness.push_back(Data(80));
    BOOST_CHECK_EQUAL("0+1120", P2WSH(CScript() << Key(1) << 15 << OP_CHECKMULTISIG, witness));
    witness = {{}, Sig(1), {1}};
    for (int i{0}; i < 14; ++i) witness.push_back(Key(10 + i));
    BOOST_CHECK_EQUAL("462+0", P2WSH(CScript() << Key(1) << 15 << OP_CHECKMULTISIG, witness));

    // Unmatched script keys of key size are not counted here.
    fakes.clear();
    for (int i{0}; i < 15; ++i) fakes.push_back(Key(i + 1));
    BOOST_CHECK_EQUAL("0+0", P2WSH(Multisig(1, fakes), {{}, Sig(1)}));
}

BOOST_AUTO_TEST_CASE(counted_elsewhere)
{
    // DatacarrierBytes already counts dropped pushes and envelopes.
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << Data(75) << OP_DROP << Key(1) << OP_CHECKSIG, {Sig(1)}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << OP_FALSE << OP_IF << Data(75) << Data(75) << OP_ENDIF << Key(1) << OP_CHECKSIG, {Sig(1)}));
    // Spends that fail under standard flags are left to script validation.
    BOOST_CHECK_EQUAL("fail", P2WSH(CScript() << OP_2DROP << Key(1) << OP_CHECKSIG, {Sig(1), Data(80)}));
    BOOST_CHECK_EQUAL("fail", P2WSH(CScript() << OP_DROP << Key(1) << OP_CHECKSIG, {Sig(1), Data(80), Data(80)}));
    BOOST_CHECK_EQUAL("fail", P2WSH(CScript() << OP_IF << Key(1) << OP_CHECKSIG << OP_ENDIF, {Sig(1), {2}}));
    BOOST_CHECK_EQUAL("fail", P2WSH(Multisig(2, {Key(1), Key(2)}), {{}, Sig(1), {}}));
    // A true result is the one byte 0x01, which a script can compare against.
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << Key(1) << OP_CHECKSIG << 1 << OP_EQUAL, {Sig(1)}));
    BOOST_CHECK_EQUAL("0+0", P2WSH(CScript() << OP_0 << OP_0 << OP_EQUAL << 1 << OP_EQUAL, {}));
}

BOOST_AUTO_TEST_SUITE_END()
