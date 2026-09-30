#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that bytes a P2WSH spend never uses count as datacarrier bytes.

Each spend is valid by consensus. The rejected ones carry data where no signature, hash
commitment, timelock or condition depends on it; the accepted ones are ordinary scripts,
including Lightning outputs on the paths that leave some of their script unused.
"""
from random import randbytes

from test_framework.key import ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    CScript,
    OP_2DROP,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_IFDUP,
    OP_NOTIF,
    OP_SIZE,
    OP_SWAP,
    OP_TOALTSTACK,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
    hash160,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

FUND = 100_000


def new_key():
    key = ECKey()
    key.generate(compressed=True)
    return key


class MempoolUnusedDataTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The framework passes -corepolicy, which turns datacarrier counting off.
        self.extra_args = [["-corepolicy=0"]]

    def fund(self, script, num_inputs=1):
        spk = script_to_p2wsh_script(script)
        funding = [self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=FUND)
                   for _ in range(num_inputs)]
        self.generate(self.nodes[0], 1)
        return funding

    def spend(self, script, witness_fn, *, num_inputs=1, sequence=0, blocks=0):
        """witness_fn(sighash) -> witness stack without the trailing witnessScript."""
        funding = self.fund(script, num_inputs)
        if blocks:
            self.generate(self.nodes[0], blocks)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(f['txid'], 16), f['sent_vout']), nSequence=sequence) for f in funding]
        tx.vout = [CTxOut(FUND * num_inputs - 20_000, script_to_p2wsh_script(script))]
        tx.wit.vtxinwit = [CTxInWitness() for _ in funding]
        for i in range(num_inputs):
            sighash = SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, FUND)
            tx.wit.vtxinwit[i].scriptWitness.stack = witness_fn(sighash) + [bytes(script)]
        return self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]

    def check(self, desc, result, reason=None):
        self.log.info(f"{desc}: {'accepted' if result['allowed'] else result['reject-reason']}")
        if reason is None:
            assert result['allowed'], result
        else:
            assert_equal(result['reject-reason'], reason)

    def sig(self, key, sighash):
        return key.sign_ecdsa(sighash) + bytes([SIGHASH_ALL])

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 110)
        key = new_key()
        pub = key.get_pubkey().get_bytes()
        sign = lambda h: self.sig(key, h)

        def multisig_real_last(fakes):
            return CScript([1] + fakes + [pub, len(fakes) + 1, OP_CHECKMULTISIG])

        self.log.info("Keys CHECKMULTISIG cannot match, and keys supplied by the witness")
        self.check("1-of-15 with 34 byte keys",
                   self.spend(multisig_real_last([randbytes(34) for _ in range(14)]), lambda h: [b'', sign(h)]),
                   "txn-datacarrier-nonstandard")
        self.check("1-of-7 with 240 byte keys",
                   self.spend(multisig_real_last([randbytes(240) for _ in range(6)]), lambda h: [b'', sign(h)]),
                   "txn-datacarrier-nonstandard")
        self.check("1-of-15 with 65 byte keys",
                   self.spend(multisig_real_last([b'\x04' + randbytes(64) for _ in range(14)]), lambda h: [b'', sign(h)]),
                   "txn-datacarrier-nonstandard")
        padded = CScript([1] + sum([[randbytes(34), OP_DUP, OP_DROP] for _ in range(14)], []) + [pub, 15, OP_CHECKMULTISIG])
        self.check("1-of-15 with 34 byte keys padded by OP_DUP OP_DROP", self.spend(padded, lambda h: [b'', sign(h)]),
                   "txn-datacarrier-nonstandard")
        items = [randbytes(80) for _ in range(14)]
        self.check("1-of-15 with keys in witness items",
                   self.spend(CScript([pub, 15, OP_CHECKMULTISIG]), lambda h: [b'', sign(h), b'\x01'] + items),
                   "txn-datacarrier-nonstandard")
        items = [b'\x02' + randbytes(32) for _ in range(14)]
        self.check("1-of-15 with valid-looking keys in witness items",
                   self.spend(CScript([pub, 15, OP_CHECKMULTISIG]), lambda h: [b'', sign(h), b'\x01'] + items),
                   "txn-datacarrier-exceeded")

        self.log.info("Data the script discards")
        items = [randbytes(80) for _ in range(18)]
        self.check("witness items dropped",
                   self.spend(CScript([OP_2DROP] * 9 + [pub, OP_CHECKSIG]), lambda h: [sign(h)] + items),
                   "txn-datacarrier-nonstandard")
        script = CScript(sum([[randbytes(75), OP_TOALTSTACK] for _ in range(18)], []) + [pub, OP_CHECKSIG])
        self.check("script pushes moved to the altstack", self.spend(script, lambda h: [sign(h)]),
                   "txn-datacarrier-nonstandard")
        script = CScript([OP_IF, pub, OP_CHECKSIG, OP_ELSE] + [randbytes(75) for _ in range(10)] + [OP_ENDIF])
        self.check("pushes in a branch not taken", self.spend(script, lambda h: [sign(h), b'\x01']),
                   "txn-datacarrier-nonstandard")

        self.log.info("Ordinary scripts")
        keys = [new_key() for _ in range(3)]
        script = CScript([2] + [k.get_pubkey().get_bytes() for k in keys] + [3, OP_CHECKMULTISIG])
        self.check("2-of-3 multisig", self.spend(script, lambda h: [b'', self.sig(keys[0], h), self.sig(keys[1], h)]))

        revocation, delayed = new_key(), new_key()
        to_local = CScript([OP_IF, revocation.get_pubkey().get_bytes(), OP_ELSE, 144, OP_CHECKSEQUENCEVERIFY, OP_DROP,
                            delayed.get_pubkey().get_bytes(), OP_ENDIF, OP_CHECKSIG])
        self.check("to_local, revocation path", self.spend(to_local, lambda h: [self.sig(revocation, h), b'\x01']))
        self.check("to_local, delayed path",
                   self.spend(to_local, lambda h: [self.sig(delayed, h), b''], sequence=144, blocks=144))

        # BOLT 3 offered HTLC (anchor variant), spent through the HTLC-timeout 2-of-2: the revocation
        # hash, the size constant and the payment hash all go unused on this path.
        remote, local = new_key(), new_key()
        offered = CScript([OP_DUP, OP_HASH160, hash160(revocation.get_pubkey().get_bytes()), OP_EQUAL,
                           OP_IF, OP_CHECKSIG,
                           OP_ELSE, remote.get_pubkey().get_bytes(), OP_SWAP, OP_SIZE, 32, OP_EQUAL,
                           OP_NOTIF, OP_DROP, 2, OP_SWAP, local.get_pubkey().get_bytes(), 2, OP_CHECKMULTISIG,
                           OP_ELSE, OP_HASH160, hash160(randbytes(32)), OP_EQUALVERIFY, OP_CHECKSIG,
                           OP_ENDIF, 1, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_ENDIF])
        self.check("offered HTLC, timeout path",
                   self.spend(offered, lambda h: [b'', self.sig(remote, h), self.sig(local, h), b''], sequence=1, blocks=1))

        anchor = CScript([pub, OP_CHECKSIG, OP_IFDUP, OP_NOTIF, 16, OP_CHECKSEQUENCEVERIFY, OP_ENDIF])
        self.check("anchor, keyed", self.spend(anchor, lambda h: [sign(h)]))
        self.check("anchor, unkeyed after 16 blocks", self.spend(anchor, lambda h: [b''], sequence=16, blocks=16))


if __name__ == '__main__':
    MempoolUnusedDataTest(__file__).main()
