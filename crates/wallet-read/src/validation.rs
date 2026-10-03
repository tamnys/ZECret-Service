use super::{ReadMethod, wire};
use prost::Message;
use std::collections::HashSet;
use tonic::Status;
use zrpc_protocol::TestnetTransparentAddress;

fn invalid() -> Status {
    Status::invalid_argument("Invalid testnet wallet read request.")
}

fn decode<T: Message + Default>(payload: &[u8]) -> Result<T, Status> {
    T::decode(payload).map_err(|_| invalid())
}

fn address(value: &str) -> Result<(), Status> {
    TestnetTransparentAddress::parse(value)
        .map(|_| ())
        .map_err(|_| invalid())
}

fn addresses(values: &[String]) -> Result<(), Status> {
    // Zebra v6.4.2's lightwalletd service enforces MAX_REQUEST_ADDRESSES=10_000.
    if values.is_empty() || values.len() > 10_000 {
        return Err(invalid());
    }
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        address(value)?;
        if !seen.insert(value.as_str()) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn block_id(id: &wire::BlockId) -> Result<(), Status> {
    if id.height > u32::MAX as u64 || (!id.hash.is_empty() && id.hash.len() != 32) {
        return Err(invalid());
    }
    if !id.hash.is_empty() && id.height != 0 {
        return Err(invalid());
    }
    Ok(())
}

fn height_range(range: Option<wire::BlockRange>) -> Result<(), Status> {
    let range = range.ok_or_else(invalid)?;
    let start = range.start.ok_or_else(invalid)?;
    let end = range.end.ok_or_else(invalid)?;
    block_id(&start)?;
    block_id(&end)?;
    if !start.hash.is_empty() || !end.hash.is_empty() || start.height > end.height {
        return Err(invalid());
    }
    Ok(())
}

/// Decode and re-encode before forwarding. Unknown protobuf fields are dropped,
/// so a future service revision cannot add a privileged selector implicitly.
/// The caller bounds the incoming gRPC message before calling this function.
pub fn validate_unary_request(method: ReadMethod, payload: &[u8]) -> Result<Vec<u8>, Status> {
    match method {
        ReadMethod::GetLatestBlock => Ok(decode::<wire::ChainSpec>(payload)?.encode_to_vec()),
        ReadMethod::GetBlock | ReadMethod::GetBlockNullifiers | ReadMethod::GetTreeState => {
            let request = decode::<wire::BlockId>(payload)?;
            block_id(&request)?;
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetBlockRange | ReadMethod::GetBlockRangeNullifiers => {
            let request = decode::<wire::BlockRange>(payload)?;
            height_range(Some(request.clone()))?;
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetTransaction => {
            let request = decode::<wire::TxFilter>(payload)?;
            if request.hash.len() != 32 || request.block.is_some() || request.index != 0 {
                return Err(invalid());
            }
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetTaddressTxids | ReadMethod::GetTaddressTransactions => {
            let request = decode::<wire::TransparentAddressBlockFilter>(payload)?;
            address(&request.address)?;
            height_range(request.range.clone())?;
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetTaddressBalance => {
            let request = decode::<wire::AddressList>(payload)?;
            addresses(&request.addresses)?;
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetTaddressBalanceStream => Err(invalid()),
        ReadMethod::GetMempoolTx => {
            let request = decode::<wire::Exclude>(payload)?;
            // Match Zebra's request-count limit and the 32-byte txid format.
            if request.txid.len() > 20_000
                || request
                    .txid
                    .iter()
                    .any(|suffix| suffix.is_empty() || suffix.len() > 32)
            {
                return Err(invalid());
            }
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetMempoolStream
        | ReadMethod::GetLatestTreeState
        | ReadMethod::GetLightdInfo => Ok(decode::<wire::Empty>(payload)?.encode_to_vec()),
        ReadMethod::GetSubtreeRoots => {
            let request = decode::<wire::GetSubtreeRootsArg>(payload)?;
            if wire::ShieldedProtocol::try_from(request.shielded_protocol).is_err() {
                return Err(invalid());
            }
            Ok(request.encode_to_vec())
        }
        ReadMethod::GetAddressUtxos | ReadMethod::GetAddressUtxosStream => {
            let request = decode::<wire::GetAddressUtxosArg>(payload)?;
            addresses(&request.addresses)?;
            if request.start_height > u32::MAX as u64 {
                return Err(invalid());
            }
            Ok(request.encode_to_vec())
        }
    }
}

/// Each address in the one client-streaming method is validated independently;
/// callers must also enforce Zebra's total address count before transmission.
pub fn validate_client_stream_address(payload: &[u8]) -> Result<Vec<u8>, Status> {
    let request = decode::<wire::Address>(payload)?;
    address(&request.address)?;
    Ok(request.encode_to_vec())
}

fn malformed_response() -> Status {
    Status::data_loss("Invalid wallet chain data from the backend.")
}

/// Check structural invariants that the wallet scanner relies on. This does
/// not turn a node response into an independently validated Zcash consensus
/// proof; a maintained wallet scanner still performs its own protocol checks.
pub fn validate_compact_block(block: &wire::CompactBlock) -> Result<(), Status> {
    if block.proto_version != 0
        || block.height > u32::MAX as u64
        || block.hash.len() != 32
        || block.prev_hash.len() != 32
        || block.chain_metadata.is_none()
        || !block.header.is_empty()
    {
        return Err(malformed_response());
    }
    let mut previous_index = None;
    for tx in &block.vtx {
        validate_compact_tx(tx)?;
        if previous_index.is_some_and(|index| tx.index <= index) {
            return Err(malformed_response());
        }
        previous_index = Some(tx.index);
    }
    Ok(())
}

pub fn validate_compact_tx(tx: &wire::CompactTx) -> Result<(), Status> {
    if tx.hash.len() != 32
        || tx.spends.iter().any(|spend| spend.nf.len() != 32)
        || tx.outputs.iter().any(|output| {
            output.cmu.len() != 32
                || output.ephemeral_key.len() != 32
                || output.ciphertext.len() != 52
        })
        || tx
            .actions
            .iter()
            .chain(tx.ironwood_actions.iter())
            .any(|action| {
                action.nullifier.len() != 32
                    || action.cmx.len() != 32
                    || action.ephemeral_key.len() != 32
                    || action.ciphertext.len() != 52
            })
    {
        return Err(malformed_response());
    }
    Ok(())
}

/// Validates a complete ordered block-range stream, including its terminal
/// status. An interrupted stream cannot be reported as a complete scan.
pub struct RangeContinuity {
    next_height: Option<u32>,
    end: u32,
    ascending: bool,
    previous_hash: Option<[u8; 32]>,
    previous_parent: Option<[u8; 32]>,
    first_anchor: Option<[u8; 32]>,
}

impl RangeContinuity {
    pub fn new(start: u32, end: u32, first_anchor: Option<[u8; 32]>) -> Self {
        Self {
            next_height: Some(start),
            end,
            ascending: start <= end,
            previous_hash: None,
            previous_parent: None,
            first_anchor,
        }
    }

    pub fn observe(&mut self, block: &wire::CompactBlock) -> Result<(), Status> {
        validate_compact_block(block)?;
        let expected = self.next_height.ok_or_else(malformed_response)?;
        if block.height != u64::from(expected) {
            return Err(malformed_response());
        }
        let hash: [u8; 32] = block
            .hash
            .as_slice()
            .try_into()
            .map_err(|_| malformed_response())?;
        let parent: [u8; 32] = block
            .prev_hash
            .as_slice()
            .try_into()
            .map_err(|_| malformed_response())?;
        let linked = match (self.previous_hash, self.previous_parent) {
            (Some(prior_hash), _) if self.ascending => parent == prior_hash,
            (_, Some(prior_parent)) => hash == prior_parent,
            _ => self.first_anchor.is_none_or(|anchor| {
                if self.ascending {
                    parent == anchor
                } else {
                    hash == anchor
                }
            }),
        };
        if !linked {
            return Err(Status::aborted(
                "Wallet block range changed or is disconnected.",
            ));
        }
        self.previous_hash = Some(hash);
        self.previous_parent = Some(parent);
        self.next_height = if expected == self.end {
            None
        } else if self.ascending {
            expected.checked_add(1)
        } else {
            expected.checked_sub(1)
        };
        Ok(())
    }

    pub fn finish(self) -> Result<(), Status> {
        if self.next_height.is_some() {
            Err(Status::aborted(
                "Wallet block range ended before completion.",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zrpc_protocol::PREVIEW_TESTNET_ADDRESS;

    #[test]
    fn transparent_selection_is_testnet_only_and_unique() {
        let valid = wire::AddressList {
            addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned()],
        };
        assert!(
            validate_unary_request(ReadMethod::GetTaddressBalance, &valid.encode_to_vec()).is_ok()
        );
        let duplicate = wire::AddressList {
            addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned(); 2],
        };
        assert!(
            validate_unary_request(ReadMethod::GetTaddressBalance, &duplicate.encode_to_vec())
                .is_err()
        );
        let mainnet = wire::AddressList {
            addresses: vec!["t1Yzt1YSjHd8gdn6zaraWSpnbK7Sx9eWZ4u".into()],
        };
        assert!(
            validate_unary_request(ReadMethod::GetTaddressBalance, &mainnet.encode_to_vec())
                .is_err()
        );
    }

    #[test]
    fn historical_range_needs_two_heights() {
        let range = wire::BlockRange {
            start: Some(wire::BlockId {
                height: 10,
                hash: vec![],
            }),
            end: Some(wire::BlockId {
                height: 9,
                hash: vec![],
            }),
        };
        assert!(validate_unary_request(ReadMethod::GetBlockRange, &range.encode_to_vec()).is_err());
        let ascending = wire::BlockRange {
            end: Some(wire::BlockId {
                height: 10,
                hash: vec![],
            }),
            ..range.clone()
        };
        assert!(
            validate_unary_request(ReadMethod::GetBlockRange, &ascending.encode_to_vec()).is_ok()
        );
        let missing_end = wire::BlockRange {
            end: None,
            ..range.clone()
        };
        assert!(
            validate_unary_request(ReadMethod::GetBlockRange, &missing_end.encode_to_vec())
                .is_err()
        );
        let hash_end = wire::BlockRange {
            end: Some(wire::BlockId {
                height: 0,
                hash: vec![7; 32],
            }),
            ..range
        };
        assert!(
            validate_unary_request(ReadMethod::GetBlockRange, &hash_end.encode_to_vec()).is_err()
        );
    }

    #[test]
    fn transaction_request_cannot_select_an_unsupported_form() {
        let valid = wire::TxFilter {
            block: None,
            index: 0,
            hash: vec![1; 32],
        };
        assert!(validate_unary_request(ReadMethod::GetTransaction, &valid.encode_to_vec()).is_ok());
        let invalid = wire::TxFilter {
            block: Some(wire::BlockId {
                height: 1,
                hash: vec![],
            }),
            ..valid
        };
        assert!(
            validate_unary_request(ReadMethod::GetTransaction, &invalid.encode_to_vec()).is_err()
        );
    }

    fn block(height: u64, hash: u8, parent: u8) -> wire::CompactBlock {
        wire::CompactBlock {
            proto_version: 0,
            height,
            hash: vec![hash; 32],
            prev_hash: vec![parent; 32],
            chain_metadata: Some(wire::ChainMetadata::default()),
            ..Default::default()
        }
    }

    #[test]
    fn range_requires_complete_linked_blocks() {
        let mut range = RangeContinuity::new(8, 10, Some([7; 32]));
        range.observe(&block(8, 8, 7)).unwrap();
        range.observe(&block(9, 9, 8)).unwrap();
        assert!(range.finish().is_err());
        let mut range = RangeContinuity::new(8, 10, Some([7; 32]));
        range.observe(&block(8, 8, 7)).unwrap();
        assert!(range.observe(&block(9, 9, 6)).is_err());
        let mut range = RangeContinuity::new(10, 8, Some([10; 32]));
        range.observe(&block(10, 10, 9)).unwrap();
        range.observe(&block(9, 9, 8)).unwrap();
        range.observe(&block(8, 8, 7)).unwrap();
        range.finish().unwrap();
    }

    #[test]
    fn malformed_compact_note_bytes_are_rejected() {
        let mut block = block(8, 8, 7);
        block.vtx.push(wire::CompactTx {
            index: 1,
            hash: vec![1; 32],
            outputs: vec![wire::CompactSaplingOutput {
                cmu: vec![1; 32],
                ephemeral_key: vec![2; 32],
                ciphertext: vec![3; 51],
            }],
            ..Default::default()
        });
        assert!(validate_compact_block(&block).is_err());
    }
}
