//! Response identity and serialization checks, not chain/consensus validation.
//! Pinned librustzcash decodes structures and computes identifiers. A prefix
//! guard applies its version/branch rule before full transaction decoding.
use serde_json::Value;
use std::io::Read;
use zcash_primitives::{
    block::BlockHeader,
    transaction::{Transaction, TxVersion},
};
use zcash_protocol::consensus::{BranchId, NetworkUpgrade, Parameters, TEST_NETWORK};
use zrpc_protocol::{MAX_RESPONSE_BYTES, SafeError};

use super::{invalid_response, is_hash, too_large};

fn decode_hex(value: &Value) -> Result<Vec<u8>, SafeError> {
    let encoded = value.as_str().ok_or_else(invalid_response)?;
    // Reuse the design's existing decoded JSON response limit. Network bodies
    // are bounded before this point; keep direct/internal callers bounded too.
    if encoded.len() > MAX_RESPONSE_BYTES {
        return Err(too_large());
    }
    if encoded.is_empty() {
        return Err(invalid_response());
    }
    hex::decode(encoded).map_err(|_| invalid_response())
}

pub(super) fn header(raw: &Value, expected: &str) -> Result<BlockHeader, SafeError> {
    let bytes = decode_hex(raw)?;
    let mut remaining = bytes.as_slice();
    let header = BlockHeader::read(&mut remaining).map_err(|_| invalid_response())?;
    if !remaining.is_empty() || !header.hash().to_string().eq_ignore_ascii_case(expected) {
        return Err(invalid_response());
    }
    Ok(header)
}

pub(super) fn transaction(raw: &Value, expected: &str) -> Result<Transaction, SafeError> {
    let bytes = decode_hex(raw)?;
    // 0.30.1 computes the identifier during Transaction::read without enforcing
    // version/branch compatibility. Check the embedded V5/V6 branch first,
    // using the maintained version decoder and compatibility rule. Earlier
    // formats carry no branch field; the metadata branch below is not evidence
    // of their mined height or consensus validity.
    let mut prefix = bytes.as_slice();
    let version = TxVersion::read(&mut prefix).map_err(|_| invalid_response())?;
    if matches!(version, TxVersion::V5 | TxVersion::V6) {
        let mut encoded_branch = [0; 4];
        prefix
            .read_exact(&mut encoded_branch)
            .map_err(|_| invalid_response())?;
        let branch = BranchId::try_from(u32::from_le_bytes(encoded_branch))
            .map_err(|_| invalid_response())?;
        if !version.valid_in_branch(branch) {
            return Err(invalid_response());
        }
    }
    let mut remaining = bytes.as_slice();
    // For pre-v5 identity, this branch is stored metadata, not a hash input or
    // a statement of mined height. V5+ reads its branch from the wire itself.
    let tx = Transaction::read(&mut remaining, BranchId::Canopy).map_err(|_| invalid_response())?;
    if !remaining.is_empty() || !tx.txid().to_string().eq_ignore_ascii_case(expected) {
        return Err(invalid_response());
    }
    Ok(tx)
}

pub(super) fn verbose_transaction(result: &Value, expected: &str) -> Result<(), SafeError> {
    if !matches_hex(result, "txid", expected) {
        return Err(invalid_response());
    }
    transaction(result.get("hex").ok_or_else(invalid_response)?, expected)?;
    // A v5 txid commits to effecting data, not signatures/proofs/scriptSig.
    // JSON metadata, decoded vin/vout, inclusion, and validity remain unverified.
    Ok(())
}

fn matches_hex(result: &Value, field: &str, expected: &str) -> bool {
    result
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn reversed_hex(mut bytes: [u8; 32]) -> String {
    bytes.reverse();
    hex::encode(bytes)
}

/// Match pinned Zebra v6.3.0's JSON rendering of serialized header fields.
/// Reported height selects formatting only; it is not authenticated chain
/// position. Confirmations, difficulty, next hash and tree metadata are not
/// committed by this header and are not authenticated here.
pub(super) fn verbose_header(result: &Value, header: &BlockHeader) -> Result<(), SafeError> {
    let height = result
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(invalid_response)?;
    let sapling = u32::from(
        TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .ok_or_else(invalid_response)?,
    );
    let heartwood = u32::from(
        TEST_NETWORK
            .activation_height(NetworkUpgrade::Heartwood)
            .ok_or_else(invalid_response)?,
    );
    // librustzcash's historical field name denotes the serialized commitment
    // slot, whose semantics changed after Sapling. Zebra displays pre-Sapling
    // reserved bytes directly and later commitments in reversed byte order.
    let commitment = if height < sapling {
        hex::encode(header.final_sapling_root)
    } else {
        reversed_hex(header.final_sapling_root)
    };
    if height == heartwood && header.final_sapling_root != [0; 32] {
        // Zebra's activation-reserved rendering requires a zero commitment.
        return Err(invalid_response());
    }
    let sapling_root_matches = if height < sapling {
        matches_hex(result, "finalsaplingroot", &hex::encode([0; 32]))
    } else if height < heartwood {
        matches_hex(result, "finalsaplingroot", &commitment)
    } else {
        // After Heartwood this is a separate state-tree root, not the header
        // slot. Check representation only; never claim it is authenticated.
        result.get("finalsaplingroot").is_some_and(is_hash)
    };
    let valid = matches_hex(result, "hash", &header.hash().to_string())
        && result.get("version").and_then(Value::as_u64) == Some(u64::from(header.version as u32))
        && matches_hex(result, "previousblockhash", &header.prev_block.to_string())
        && matches_hex(result, "merkleroot", &reversed_hex(header.merkle_root))
        && matches_hex(result, "blockcommitments", &commitment)
        && sapling_root_matches
        && result.get("time").and_then(Value::as_u64) == Some(u64::from(header.time))
        && matches_hex(result, "bits", &hex::encode(header.bits.to_be_bytes()))
        && matches_hex(result, "nonce", &reversed_hex(header.nonce))
        && matches_hex(result, "solution", &hex::encode(&header.solution));
    if valid {
        Ok(())
    } else {
        Err(invalid_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zcash_primitives::block::BlockHeaderData;

    const HEADER: &str = include_str!("../../../../tests/fixtures/zcash/testnet-header.hex");
    const HEADER_JSON: &str =
        include_str!("../../../../tests/fixtures/zcash/testnet-header-verbose.json");
    const HEADER_HASH: &str = "025579869bcf52a989337342f5f57a84f3a28b968f7d6a8307902b065a668d23";
    const V4: &str = include_str!("../../../../tests/fixtures/zcash/testnet-v4-tx.hex");
    const V4_ID: &str = "64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639";
    const V5: &str = include_str!("../../../../tests/fixtures/zcash/zip244-v5-0.hex");
    const V5_ID: &str = "d0854b7070bb168392e7cf3d3a558711b49c2c0ad8eca3a8a14b8333bd962c55";
    const V5_SMALL: &str = include_str!("../../../../tests/fixtures/zcash/zip244-v5-2.hex");
    const V5_MUTATED: &str =
        include_str!("../../../../tests/fixtures/zcash/zip244-v5-2-auth-mutated.hex");
    const V5_SMALL_ID: &str = "6427874598e3877e9f28aad8e3c6634e4c7617841b1ab1507a6b8ad73c6cd128";

    fn header_data() -> BlockHeaderData {
        let h = header(&json!(HEADER.trim()), HEADER_HASH).unwrap();
        BlockHeaderData {
            version: h.version,
            prev_block: h.prev_block,
            merkle_root: h.merkle_root,
            final_sapling_root: h.final_sapling_root,
            time: h.time,
            bits: h.bits,
            nonce: h.nonce,
            solution: h.solution.clone(),
        }
    }

    #[test]
    fn immutable_public_vectors_match_maintained_identifiers() {
        let h = header(&json!(HEADER.trim()), HEADER_HASH).unwrap();
        verbose_header(&serde_json::from_str(HEADER_JSON).unwrap(), &h).unwrap();
        for (raw, id) in [(V4, V4_ID), (V5, V5_ID), (V5_SMALL, V5_SMALL_ID)] {
            transaction(&json!(raw.trim()), id).unwrap();
            verbose_transaction(&json!({"txid":id, "hex":raw.trim()}), id).unwrap();
        }
    }

    // Synthetic empty bundles exercise parsing only, not consensus validity.
    fn empty_transaction(version: TxVersion, branch: BranchId) -> Vec<u8> {
        let mut bytes = Vec::new();
        version.write(&mut bytes).unwrap();
        bytes.extend_from_slice(&u32::from(branch).to_le_bytes());
        bytes.extend_from_slice(&[0; 8]); // lock time and expiry height
        bytes.extend_from_slice(&[0; 5]); // transparent, Sapling and Orchard counts
        if version == TxVersion::V6 {
            bytes.push(0); // Ironwood count
        }
        bytes
    }

    #[test]
    fn matching_identifier_does_not_admit_invalid_embedded_branch() {
        for (version, branch) in [
            (TxVersion::V6, BranchId::Sprout),
            (TxVersion::V6, BranchId::Overwinter),
            (TxVersion::V6, BranchId::Sapling),
            (TxVersion::V6, BranchId::Blossom),
            (TxVersion::V6, BranchId::Heartwood),
            (TxVersion::V6, BranchId::Canopy),
            (TxVersion::V6, BranchId::Nu5),
            (TxVersion::V6, BranchId::Nu6),
            (TxVersion::V6, BranchId::Nu6_1),
            (TxVersion::V6, BranchId::Nu6_2),
            (TxVersion::V5, BranchId::Sprout),
            (TxVersion::V5, BranchId::Overwinter),
            (TxVersion::V5, BranchId::Sapling),
            (TxVersion::V5, BranchId::Blossom),
            (TxVersion::V5, BranchId::Heartwood),
            (TxVersion::V5, BranchId::Canopy),
        ] {
            let bytes = empty_transaction(version, branch);
            // The pinned codec accepts this empty form and calculates an ID.
            // A matching ID must not bypass version/branch rejection.
            let decoded = Transaction::read(bytes.as_slice(), BranchId::Canopy).unwrap();
            let id = decoded.txid().to_string();
            let raw = json!(hex::encode(bytes));
            assert!(transaction(&raw, &id).is_err(), "{version:?} / {branch:?}");
            assert!(verbose_transaction(&json!({"txid": id, "hex": raw}), &id).is_err());
        }
    }

    #[test]
    fn supported_embedded_branches_keep_the_full_decode_and_identity_checks() {
        for (version, branch) in [
            (TxVersion::V5, BranchId::Nu5),
            (TxVersion::V5, BranchId::Nu6_3),
            (TxVersion::V6, BranchId::Nu6_3),
        ] {
            let bytes = empty_transaction(version, branch);
            let decoded = Transaction::read(bytes.as_slice(), BranchId::Canopy).unwrap();
            let id = decoded.txid().to_string();
            let raw = json!(hex::encode(&bytes));
            transaction(&raw, &id).unwrap();
            verbose_transaction(&json!({"txid": id, "hex": raw}), &id).unwrap();
            assert!(transaction(&raw, &"00".repeat(32)).is_err());
            for malformed in [bytes[..bytes.len() - 1].to_vec(), [bytes, vec![0]].concat()] {
                assert!(transaction(&json!(hex::encode(malformed)), &id).is_err());
            }
        }
    }

    #[test]
    fn incomplete_unknown_and_invalid_branch_prefixes_are_rejected() {
        for version in [TxVersion::V5, TxVersion::V6] {
            let mut prefix = Vec::new();
            version.write(&mut prefix).unwrap();
            prefix.extend_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
            for end in 0..prefix.len() {
                assert!(transaction(&json!(hex::encode(&prefix[..end])), V5_ID).is_err());
            }
            for branch in [u32::MAX, u32::from(BranchId::Canopy)] {
                let mut prefix = Vec::new();
                version.write(&mut prefix).unwrap();
                prefix.extend_from_slice(&branch.to_le_bytes());
                assert!(transaction(&json!(hex::encode(prefix)), V5_ID).is_err());
            }
        }
    }

    #[test]
    fn malformed_truncated_trailing_and_wrong_identity_are_rejected() {
        for bad in [json!(null), json!(""), json!("0"), json!("zz"), json!("00")] {
            assert!(header(&bad, HEADER_HASH).is_err());
            assert!(transaction(&bad, V4_ID).is_err());
        }
        let raw = HEADER.trim();
        for bad in [
            raw[..raw.len() - 2].to_owned(),
            format!("{raw}00"),
            format!("{raw}{raw}"),
        ] {
            assert!(header(&json!(bad), HEADER_HASH).is_err());
        }
        assert!(header(&json!(raw), &"ab".repeat(32)).is_err());
        for (raw, id) in [(V4.trim(), V4_ID), (V5.trim(), V5_ID)] {
            for bad in [
                raw[..raw.len() - 2].to_owned(),
                format!("{raw}00"),
                format!("{raw}{raw}"),
            ] {
                assert!(transaction(&json!(bad), id).is_err());
            }
            assert!(transaction(&json!(raw), &"ab".repeat(32)).is_err());
            assert!(verbose_transaction(&json!({"txid":id, "hex":"abcd"}), id).is_err());
            assert!(verbose_transaction(&json!({"txid":"ab".repeat(32), "hex":raw}), id).is_err());
        }
        let mut changed = header_data();
        changed.time ^= 1;
        let changed = changed.freeze().unwrap();
        let mut bytes = Vec::new();
        changed.write(&mut bytes).unwrap();
        assert!(header(&json!(hex::encode(bytes)), HEADER_HASH).is_err());
    }

    #[test]
    fn verbose_header_rejects_fabricated_serialized_fields() {
        let h = header(&json!(HEADER.trim()), HEADER_HASH).unwrap();
        let original: Value = serde_json::from_str(HEADER_JSON).unwrap();
        for (field, bad) in [
            ("hash", json!("ab".repeat(32))),
            ("version", json!(5)),
            ("previousblockhash", json!("ab".repeat(32))),
            ("merkleroot", json!("ab".repeat(32))),
            ("blockcommitments", json!("ab".repeat(32))),
            ("finalsaplingroot", json!("ab".repeat(32))),
            ("time", json!(0)),
            ("bits", json!("00000000")),
            ("nonce", json!("ab".repeat(32))),
            ("solution", json!("00")),
            ("height", json!(-1)),
        ] {
            let mut changed = original.clone();
            changed[field] = bad;
            assert!(verbose_header(&changed, &h).is_err(), "{field}");
            let mut missing = original.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(verbose_header(&missing, &h).is_err(), "missing {field}");
        }
    }

    #[test]
    fn synthetic_rendering_only_commitment_boundaries_do_not_prove_height() {
        let mut data = header_data();
        data.final_sapling_root = std::array::from_fn(|i| i as u8);
        let h = data.freeze().unwrap();
        let sapling = u32::from(
            TEST_NETWORK
                .activation_height(NetworkUpgrade::Sapling)
                .unwrap(),
        );
        let heartwood = u32::from(
            TEST_NETWORK
                .activation_height(NetworkUpgrade::Heartwood)
                .unwrap(),
        );
        let mut rendered: Value = serde_json::from_str(HEADER_JSON).unwrap();
        rendered["hash"] = json!(h.hash().to_string());
        for height in [sapling - 1, sapling, heartwood - 1, heartwood + 1] {
            rendered["height"] = json!(height);
            rendered["blockcommitments"] = json!(if height < sapling {
                hex::encode(h.final_sapling_root)
            } else {
                reversed_hex(h.final_sapling_root)
            });
            rendered["finalsaplingroot"] = json!(if height < sapling {
                hex::encode([0; 32])
            } else if height < heartwood {
                reversed_hex(h.final_sapling_root)
            } else {
                "ab".repeat(32)
            }); // Uncommitted tree metadata after Heartwood.
            verbose_header(&rendered, &h).unwrap();
            let mut swapped = rendered.clone();
            let mut bytes = hex::decode(swapped["blockcommitments"].as_str().unwrap()).unwrap();
            bytes.reverse();
            swapped["blockcommitments"] = json!(hex::encode(bytes));
            assert!(verbose_header(&swapped, &h).is_err());
        }
        rendered["height"] = json!(heartwood);
        assert!(verbose_header(&rendered, &h).is_err());
        let zero = header(&json!(HEADER.trim()), HEADER_HASH).unwrap();
        rendered["hash"] = json!(HEADER_HASH);
        rendered["blockcommitments"] = json!("00".repeat(32));
        verbose_header(&rendered, &zero).unwrap();
    }

    #[test]
    fn malformed_compact_sizes_stop_at_eof_without_declared_count_allocation() {
        let mut data = header_data();
        data.solution.clear();
        let mut empty_header = Vec::new();
        data.freeze().unwrap().write(&mut empty_header).unwrap();
        assert_eq!(empty_header.pop(), Some(0)); // Maintained writer's empty vector prefix.
        let tx = transaction(&json!(V5_SMALL.trim()), V5_SMALL_ID).unwrap();
        let mut tx_header = Vec::new();
        tx.write_v5_header(&mut tx_header).unwrap();
        // Codec's maximum, above maximum, noncanonical, and truncated counts.
        // Values come from zcash_encoding's CompactSize contract, not a new cap.
        for count in [
            &[0xfe, 0, 0, 0, 2][..],
            &[0xfe, 1, 0, 0, 2][..],
            &[0xfd, 1, 0][..],
            &[0xfd][..],
        ] {
            let mut malformed = empty_header.clone();
            malformed.extend_from_slice(count);
            assert!(header(&json!(hex::encode(malformed)), HEADER_HASH).is_err());
            let mut malformed = tx_header.clone();
            malformed.extend_from_slice(count);
            assert!(transaction(&json!(hex::encode(malformed)), V5_SMALL_ID).is_err());
        }
    }

    #[test]
    fn zip244_authorizing_mutation_does_not_authenticate_every_returned_byte() {
        let original = transaction(&json!(V5_SMALL.trim()), V5_SMALL_ID).unwrap();
        let altered = transaction(&json!(V5_MUTATED.trim()), V5_SMALL_ID).unwrap();
        assert_eq!(
            hex::encode(
                &original.transparent_bundle().unwrap().vin[0]
                    .script_sig()
                    .0
                    .0
            ),
            "0468984d0200"
        );
        assert_eq!(
            hex::encode(
                &altered.transparent_bundle().unwrap().vin[0]
                    .script_sig()
                    .0
                    .0
            ),
            "0468984d0251"
        );
        assert_eq!(original.txid(), altered.txid());
        assert_eq!(
            hex::encode(original.auth_commitment().as_bytes()),
            "332155b1cc23a2571e86e49e06010cd25321dcfcca34ae14e8b3f4f00270d287"
        );
        assert_ne!(original.auth_commitment(), altered.auth_commitment());
        // Neither vector's signatures, scripts, inclusion or validity are checked.
    }

    #[test]
    fn maintained_writer_effecting_mutation_changes_v4_and_v5_identity() {
        use zcash_primitives::transaction::TransactionData;
        for (raw, expected) in [(V4, V4_ID), (V5, V5_ID)] {
            let original = transaction(&json!(raw.trim()), expected).unwrap();
            let altered = TransactionData::from_parts(
                original.version(),
                original.consensus_branch_id(),
                original.lock_time() ^ 1,
                original.expiry_height(),
                original.transparent_bundle().cloned(),
                original.sprout_bundle().cloned(),
                original.sapling_bundle().cloned(),
                original.orchard_bundle().cloned(),
            )
            .freeze()
            .unwrap();
            assert_ne!(original.txid(), altered.txid());
            let mut bytes = Vec::new();
            altered.write(&mut bytes).unwrap();
            let raw = json!(hex::encode(bytes));
            transaction(&raw, &altered.txid().to_string()).unwrap();
            assert!(transaction(&raw, expected).is_err());
        }
    }
}
