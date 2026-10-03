//! Process the maintained wallet backend's raw-transaction enhancement,
//! status, and mined transparent-history requests. Other transparent filters
//! remain explicit in the report until their full protocol contract is met.

use rusqlite::Connection;
use std::error::Error;
use zcash_client_backend::{
    data_api::wallet::decrypt_and_store_transaction,
    data_api::{
        OutputStatusFilter, TransactionDataRequest, TransactionStatus, TransactionStatusFilter,
        TransactionsInvolvingAddress, WalletRead, WalletWrite,
    },
    proto::service::{
        BlockId, BlockRange, RawTransaction, TransparentAddressBlockFilter, TxFilter,
    },
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::encoding::encode_transparent_address_p;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, BranchId, Network},
};
use zrpc_wallet_sdk::bridge::MaintainedScannerClient;

#[derive(Default)]
pub struct EnhancementReport {
    pub enhanced: u64,
    pub status_checks: u64,
    pub mined_transparent_checks: u64,
    pub unresolved_transparent_history: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainTxState {
    Pending,
    Mined(BlockHeight),
    Orphaned,
}

impl ChainTxState {
    fn from_wire_height(height: u64) -> Result<Self, &'static str> {
        match height {
            0 => Ok(Self::Pending),
            u64::MAX => Ok(Self::Orphaned),
            other => u32::try_from(other)
                .map(|value| Self::Mined(BlockHeight::from_u32(value)))
                .map_err(|_| "transaction height is invalid"),
        }
    }

    fn wallet_status(self) -> TransactionStatus {
        match self {
            Self::Pending | Self::Orphaned => TransactionStatus::NotInMainChain,
            Self::Mined(height) => TransactionStatus::Mined(height),
        }
    }

    fn mined_height(self) -> Option<BlockHeight> {
        match self {
            Self::Mined(height) => Some(height),
            Self::Pending | Self::Orphaned => None,
        }
    }
}

type LocalWallet = WalletDb<Connection, Network, SystemClock, rand_core::OsRng>;

fn decode_checked_transaction(
    raw: &RawTransaction,
    requested: TxId,
    parse_height: BlockHeight,
) -> Result<Transaction, &'static str> {
    let transaction = decode_transaction(raw, parse_height)?;
    if transaction.txid() != requested {
        return Err("node returned a transaction with the wrong identifier");
    }
    Ok(transaction)
}

fn decode_transaction(
    raw: &RawTransaction,
    parse_height: BlockHeight,
) -> Result<Transaction, &'static str> {
    let branch = BranchId::for_height(&Network::TestNetwork, parse_height);
    let mut encoded = raw.data.as_slice();
    let transaction = Transaction::read(&mut encoded, branch)
        .map_err(|_| "node returned an invalid Zcash transaction")?;
    if !encoded.is_empty() {
        return Err("node returned a transaction with trailing data");
    }
    Ok(transaction)
}

fn mined_history_bounds(
    start: BlockHeight,
    end_exclusive: Option<BlockHeight>,
    tx_status: &TransactionStatusFilter,
    output_status: &OutputStatusFilter,
) -> Option<(BlockHeight, BlockHeight)> {
    if tx_status != &TransactionStatusFilter::Mined || output_status != &OutputStatusFilter::All {
        return None;
    }
    let end_exclusive = end_exclusive?;
    let end_inclusive = u32::from(end_exclusive).checked_sub(1)?;
    if u32::from(start) > end_inclusive {
        return None;
    }
    Some((start, BlockHeight::from_u32(end_inclusive)))
}

async fn process_mined_transparent_history(
    client: &mut MaintainedScannerClient,
    wallet: &mut LocalWallet,
    request: TransactionsInvolvingAddress,
) -> Result<bool, Box<dyn Error>> {
    let Some((start, end)) = mined_history_bounds(
        request.block_range_start(),
        request.block_range_end(),
        request.tx_status_filter(),
        request.output_status_filter(),
    ) else {
        return Ok(false);
    };
    let tip = wallet
        .chain_height()?
        .ok_or("wallet chain tip unavailable")?;
    if end > tip {
        return Err("transparent history extends beyond the scanned wallet tip".into());
    }
    let anchor_selector = BlockId {
        height: u64::from(u32::from(end)),
        hash: vec![],
    };
    let before = client
        .get_block(anchor_selector.clone())
        .await?
        .into_inner();
    if before.height != anchor_selector.height || before.hash.len() != 32 {
        return Err("invalid transparent history anchor".into());
    }
    let mut stream = client
        .get_taddress_transactions(TransparentAddressBlockFilter {
            address: encode_transparent_address_p(&Network::TestNetwork, &request.address()),
            range: Some(BlockRange {
                start: Some(BlockId {
                    height: u64::from(u32::from(start)),
                    hash: vec![],
                }),
                end: Some(anchor_selector.clone()),
                pool_types: vec![],
            }),
        })
        .await?
        .into_inner();
    let mut had_transactions = false;
    let mut previous_height = None;
    while let Some(raw) = stream.message().await? {
        let ChainTxState::Mined(height) = ChainTxState::from_wire_height(raw.height)? else {
            return Err("transparent history contained a non-main-chain transaction".into());
        };
        if height < start || height > end || previous_height.is_some_and(|prior| height < prior) {
            return Err("transparent history violated the requested block order".into());
        }
        let transaction = decode_transaction(&raw, height)?;
        decrypt_and_store_transaction(&Network::TestNetwork, wallet, &transaction, Some(height))?;
        had_transactions = true;
        previous_height = Some(height);
    }
    // The stream reaching EOF does not prove the chain stayed on the same
    // branch while transactions arrived. Recheck the scanned range's tip before
    // marking an empty range complete. On any error, the wallet is retryable;
    // no full-history result is reported to the caller.
    let after = client.get_block(anchor_selector).await?.into_inner();
    if after.height != before.height || after.hash != before.hash {
        return Err("transparent history changed during retrieval".into());
    }
    if !had_transactions {
        wallet.notify_address_checked(request, end)?;
    }
    Ok(true)
}

pub async fn process_snapshot(
    client: &mut MaintainedScannerClient,
    wallet: &mut LocalWallet,
) -> Result<EnhancementReport, Box<dyn Error>> {
    let mut report = EnhancementReport::default();
    let requests = wallet.transaction_data_requests()?;
    for request in requests {
        let (txid, enhance) = match request {
            TransactionDataRequest::GetStatus(txid) => (txid, false),
            TransactionDataRequest::Enhancement(txid) => (txid, true),
            TransactionDataRequest::TransactionsInvolvingAddress(history) => {
                if process_mined_transparent_history(client, wallet, history).await? {
                    report.mined_transparent_checks += 1;
                } else {
                    report.unresolved_transparent_history += 1;
                }
                continue;
            }
        };
        let raw = match client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid.as_ref().to_vec(),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) if error.code() == tonic::Code::NotFound => {
                wallet.set_transaction_status(txid, TransactionStatus::TxidNotRecognized)?;
                report.status_checks += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let state = ChainTxState::from_wire_height(raw.height)?;
        let parse_height = if let Some(height) = state.mined_height() {
            height
        } else {
            let tip = wallet
                .chain_height()?
                .ok_or("wallet chain tip unavailable")?;
            let next = u32::from(tip)
                .checked_add(1)
                .ok_or("wallet chain height overflow")?;
            BlockHeight::from_u32(next)
        };
        let transaction = decode_checked_transaction(&raw, txid, parse_height)?;
        if enhance {
            decrypt_and_store_transaction(
                &Network::TestNetwork,
                wallet,
                &transaction,
                state.mined_height(),
            )?;
            report.enhanced += 1;
        }
        wallet.set_transaction_status(txid, state.wallet_status())?;
        report.status_checks += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_testnet_transaction_requires_exact_id_and_no_trailing_data() {
        let data =
            hex::decode(include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex").trim())
                .unwrap();
        let txid =
            TxId::from_hex("64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639")
                .unwrap();
        let height = BlockHeight::from_u32(280_003);
        let raw = RawTransaction {
            data,
            height: u64::from(u32::from(height)),
        };
        assert_eq!(
            decode_checked_transaction(&raw, txid, height)
                .unwrap()
                .txid(),
            txid
        );
        assert!(decode_checked_transaction(&raw, TxId::NULL, height).is_err());
        let mut trailing = raw;
        trailing.data.push(0);
        assert!(decode_checked_transaction(&trailing, txid, height).is_err());
    }

    #[test]
    fn transaction_status_sentinels_are_not_heights() {
        assert_eq!(ChainTxState::from_wire_height(0), Ok(ChainTxState::Pending));
        assert_eq!(
            ChainTxState::from_wire_height(u64::MAX),
            Ok(ChainTxState::Orphaned)
        );
        assert_eq!(
            ChainTxState::from_wire_height(42),
            Ok(ChainTxState::Mined(BlockHeight::from_u32(42)))
        );
        assert!(ChainTxState::from_wire_height(u64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn transaction_id_bytes_are_protocol_order_not_display_order() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 7;
        let id = TxId::from_bytes(bytes);
        assert_eq!(id.as_ref()[0], 7);
        assert!(id.to_string().starts_with("00"));
    }

    #[test]
    fn mined_history_is_inclusive_on_wire_and_rejects_other_filters() {
        let start = BlockHeight::from_u32(100);
        let end_exclusive = Some(BlockHeight::from_u32(103));
        assert_eq!(
            mined_history_bounds(
                start,
                end_exclusive,
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::All,
            ),
            Some((start, BlockHeight::from_u32(102)))
        );
        assert!(
            mined_history_bounds(
                start,
                Some(start),
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::All,
            )
            .is_none()
        );
        assert!(
            mined_history_bounds(
                start,
                end_exclusive,
                &TransactionStatusFilter::All,
                &OutputStatusFilter::All,
            )
            .is_none()
        );
        assert!(
            mined_history_bounds(
                start,
                end_exclusive,
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::Unspent,
            )
            .is_none()
        );
    }
}
