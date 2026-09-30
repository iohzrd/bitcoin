// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_UNUSED_DATA_H
#define BITCOIN_POLICY_UNUSED_DATA_H

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

class BaseSignatureChecker;
class CScript;
class CTxIn;

/**
 * Unused script pushes of no number, hash or key size may total this many bytes per input before
 * the rest count as data.
 */
static constexpr size_t MAX_UNUSED_SCRIPT_BYTES{64};

/** Executions with a single item altered, per input, before every candidate counts as data. */
static constexpr size_t MAX_UNUSED_DATA_EXECUTIONS{32};

/**
 * Bytes of a P2SH, P2WSH or tapscript spend that it would still be valid without.
 *
 * Executes the spend's script with the script interpreter, again with each witness item (or P2SH
 * scriptSig push) and each script push of no number, hash or key size altered in place; an item
 * whose alteration leaves the spend valid is unused. Signatures are checked against the unaltered
 * script, which is what they commit to, so checker should be the one that validated the spend,
 * with its signature cache. Signatures, all-zero items and pushes in counted_ranges (the second
 * count of CScript::DatacarrierBytes) are not altered.
 *
 * Returns {unused keys the witness supplies, other unused bytes, less MAX_UNUSED_SCRIPT_BYTES of
 * script pushes}, or std::nullopt for an input that executes no script or does not validate.
 */
std::optional<std::pair<size_t, size_t>> UnusedInputDataBytes(const CTxIn& txin, const CScript& prev_script_pubkey, unsigned int flags,
                                                              const BaseSignatureChecker& checker,
                                                              const std::vector<std::pair<size_t, size_t>>& counted_ranges);

#endif // BITCOIN_POLICY_UNUSED_DATA_H
