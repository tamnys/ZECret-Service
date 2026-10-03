//! Typed, read-only adapter for Zebra's loopback lightwalletd service.
//! Constructing this service does not expose it on a socket: the attested
//! wrapper must still authorize each remote call before invoking it.

use crate::{
    RangeContinuity, ReadMethod, validate_client_stream_address, validate_compact_block,
    validate_compact_tx, validate_unary_request, wire,
};
use futures_util::{StreamExt, stream};
use prost::Message;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tonic::{
    Request, Response, Status,
    transport::{Channel, Endpoint},
};

type ReadStream<T> = futures_util::stream::BoxStream<'static, Result<T, Status>>;

fn unavailable() -> Status {
    Status::unavailable("Wallet node is unavailable.")
}

fn sanitize(error: Status) -> Status {
    Status::new(error.code(), "Wallet node request failed.")
}

fn invalid_data() -> Status {
    Status::data_loss("Invalid testnet wallet data from the node.")
}

fn check_block_id(id: &wire::BlockId) -> Result<(), Status> {
    if id.height > u32::MAX as u64 || id.hash.len() != 32 {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_raw_transaction(tx: &wire::RawTransaction) -> Result<(), Status> {
    if tx.data.is_empty() || (tx.height != u64::MAX && tx.height > u32::MAX as u64) {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_balance(balance: &wire::Balance) -> Result<(), Status> {
    if balance.value_zat < 0 {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_tree_state(tree: &wire::TreeState) -> Result<(), Status> {
    if tree.network != "test"
        || tree.height > u32::MAX as u64
        || tree.hash.len() != 64
        || !tree.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_subtree(root: &wire::SubtreeRoot) -> Result<(), Status> {
    if root.root_hash.len() != 32
        || root.completing_block_hash.len() != 32
        || root.completing_block_height > u32::MAX as u64
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_utxo(utxo: &wire::GetAddressUtxosReply) -> Result<(), Status> {
    if utxo.txid.len() != 32
        || utxo.index < 0
        || utxo.value_zat < 0
        || utxo.height > u32::MAX as u64
        || validate_client_stream_address(
            &wire::Address {
                address: utxo.address.clone(),
            }
            .encode_to_vec(),
        )
        .is_err()
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_utxos(list: &wire::GetAddressUtxosReplyList) -> Result<(), Status> {
    for utxo in &list.address_utxos {
        check_utxo(utxo)?;
    }
    Ok(())
}

fn check_info(info: &wire::LightdInfo) -> Result<(), Status> {
    if info.chain_name != "test" || !info.taddr_support || info.block_height > u32::MAX as u64 {
        return Err(invalid_data());
    }
    Ok(())
}

/// A numeric loopback endpoint is the only accepted backend destination. It
/// never uses a resolver, public URL, Unix socket supplied by a caller, or
/// credentials from request metadata.
#[derive(Clone)]
pub struct ZebraReadOnly {
    endpoint: Endpoint,
}

impl ZebraReadOnly {
    pub fn new(addr: SocketAddr) -> Result<Self, Status> {
        if !addr.ip().is_loopback() || addr.port() == 0 {
            return Err(Status::invalid_argument("Wallet backend must be loopback."));
        }
        let endpoint = Endpoint::from_shared(format!("http://{addr}"))
            .map_err(|_| Status::invalid_argument("Invalid wallet backend."))?;
        Ok(Self { endpoint })
    }

    async fn client(
        &self,
    ) -> Result<wire::compact_tx_streamer_client::CompactTxStreamerClient<Channel>, Status> {
        let channel = self.endpoint.connect().await.map_err(|_| unavailable())?;
        let mut client = wire::compact_tx_streamer_client::CompactTxStreamerClient::new(channel);
        // No caller selection reaches a misconfigured mainnet or other node.
        // This public request contains no address, txid, or wallet state.
        let info = client
            .get_lightd_info(wire::Empty {})
            .await
            .map_err(sanitize)?
            .into_inner();
        check_info(&info)?;
        Ok(client)
    }
}

fn checked_blocks(
    input: tonic::Streaming<wire::CompactBlock>,
    start: u32,
    end: u32,
) -> ReadStream<wire::CompactBlock> {
    let continuity = Arc::new(Mutex::new(Some(RangeContinuity::new(start, end, None))));
    let check_each = continuity.clone();
    let blocks = input.map(move |item| {
        let block = item.map_err(sanitize)?;
        let mut state = check_each.lock().map_err(|_| invalid_data())?;
        state.as_mut().ok_or_else(invalid_data)?.observe(&block)?;
        Ok(block)
    });
    // A transport EOF before the requested end height is an error item. A
    // consumer must observe the terminal gRPC status before accepting a range.
    let terminal = stream::once(async move {
        let mut state = continuity.lock().map_err(|_| invalid_data())?;
        state.take().ok_or_else(invalid_data)?.finish()
    })
    .filter_map(|result| async move { result.err().map(Err) });
    Box::pin(blocks.chain(terminal))
}

#[tonic::async_trait]
impl wire::compact_tx_streamer_server::CompactTxStreamer for ZebraReadOnly {
    async fn get_latest_block(
        &self,
        request: Request<wire::ChainSpec>,
    ) -> Result<Response<wire::BlockId>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetLatestBlock, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_latest_block(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_block_id(&response)?;
        Ok(Response::new(response))
    }
    async fn get_block(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::CompactBlock>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetBlock, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_block(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        validate_compact_block(&response)?;
        Ok(Response::new(response))
    }
    async fn get_block_nullifiers(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::CompactBlock>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetBlockNullifiers, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_block_nullifiers(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        validate_compact_block(&response)?;
        Ok(Response::new(response))
    }

    type GetBlockRangeStream = ReadStream<wire::CompactBlock>;
    async fn get_block_range(
        &self,
        request: Request<wire::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetBlockRange, &request.encode_to_vec())?;
        let start = request.start.as_ref().ok_or_else(invalid_data)?.height as u32;
        let end = request.end.as_ref().ok_or_else(invalid_data)?.height as u32;
        let mut client = self.client().await?;
        let input = client
            .get_block_range(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        Ok(Response::new(checked_blocks(input, start, end)))
    }

    type GetBlockRangeNullifiersStream = ReadStream<wire::CompactBlock>;
    async fn get_block_range_nullifiers(
        &self,
        request: Request<wire::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(
            ReadMethod::GetBlockRangeNullifiers,
            &request.encode_to_vec(),
        )?;
        let start = request.start.as_ref().ok_or_else(invalid_data)?.height as u32;
        let end = request.end.as_ref().ok_or_else(invalid_data)?.height as u32;
        let mut client = self.client().await?;
        let input = client
            .get_block_range_nullifiers(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        Ok(Response::new(checked_blocks(input, start, end)))
    }

    async fn get_transaction(
        &self,
        request: Request<wire::TxFilter>,
    ) -> Result<Response<wire::RawTransaction>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTransaction, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_transaction(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_raw_transaction(&response)?;
        Ok(Response::new(response))
    }
    async fn send_transaction(
        &self,
        _: Request<wire::RawTransaction>,
    ) -> Result<Response<wire::SendResponse>, Status> {
        Err(Status::permission_denied(
            "Transaction submission is unavailable.",
        ))
    }
    type GetTaddressTxidsStream = ReadStream<wire::RawTransaction>;
    async fn get_taddress_txids(
        &self,
        request: Request<wire::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTaddressTxids, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let input = client
            .get_taddress_txids(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_raw_transaction(&value)?;
            Ok(value)
        });
        Ok(Response::new(Box::pin(output)))
    }
    type GetTaddressTransactionsStream = ReadStream<wire::RawTransaction>;
    async fn get_taddress_transactions(
        &self,
        request: Request<wire::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(
            ReadMethod::GetTaddressTransactions,
            &request.encode_to_vec(),
        )?;
        let mut client = self.client().await?;
        let input = client
            .get_taddress_transactions(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_raw_transaction(&value)?;
            Ok(value)
        });
        Ok(Response::new(Box::pin(output)))
    }
    async fn get_taddress_balance(
        &self,
        request: Request<wire::AddressList>,
    ) -> Result<Response<wire::Balance>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTaddressBalance, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_taddress_balance(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_balance(&response)?;
        Ok(Response::new(response))
    }

    async fn get_taddress_balance_stream(
        &self,
        request: Request<tonic::Streaming<wire::Address>>,
    ) -> Result<Response<wire::Balance>, Status> {
        let mut incoming = request.into_inner();
        let mut addresses = Vec::new();
        let mut seen = HashSet::new();
        while let Some(value) = incoming.message().await.map_err(sanitize)? {
            validate_client_stream_address(&value.encode_to_vec())?;
            if addresses.len() >= 10_000 || !seen.insert(value.address.clone()) {
                return Err(Status::invalid_argument(
                    "Invalid testnet wallet read request.",
                ));
            }
            addresses.push(value);
        }
        if addresses.is_empty() {
            return Err(Status::invalid_argument(
                "Invalid testnet wallet read request.",
            ));
        }
        let mut client = self.client().await?;
        let response = client
            .get_taddress_balance_stream(stream::iter(addresses))
            .await
            .map_err(sanitize)?
            .into_inner();
        check_balance(&response)?;
        Ok(Response::new(response))
    }

    type GetMempoolTxStream = ReadStream<wire::CompactTx>;
    async fn get_mempool_tx(
        &self,
        request: Request<wire::Exclude>,
    ) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetMempoolTx, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let input = client
            .get_mempool_tx(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            validate_compact_tx(&value)?;
            Ok(value)
        });
        Ok(Response::new(Box::pin(output)))
    }
    type GetMempoolStreamStream = ReadStream<wire::RawTransaction>;
    async fn get_mempool_stream(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetMempoolStream, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let input = client
            .get_mempool_stream(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_raw_transaction(&value)?;
            Ok(value)
        });
        Ok(Response::new(Box::pin(output)))
    }
    async fn get_tree_state(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::TreeState>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTreeState, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_tree_state(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_tree_state(&response)?;
        Ok(Response::new(response))
    }
    async fn get_latest_tree_state(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<wire::TreeState>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetLatestTreeState, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_latest_tree_state(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_tree_state(&response)?;
        Ok(Response::new(response))
    }
    type GetSubtreeRootsStream = ReadStream<wire::SubtreeRoot>;
    async fn get_subtree_roots(
        &self,
        request: Request<wire::GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetSubtreeRoots, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let input = client
            .get_subtree_roots(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_subtree(&value)?;
            Ok(value)
        });
        Ok(Response::new(Box::pin(output)))
    }
    async fn get_address_utxos(
        &self,
        request: Request<wire::GetAddressUtxosArg>,
    ) -> Result<Response<wire::GetAddressUtxosReplyList>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetAddressUtxos, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_address_utxos(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_utxos(&response)?;
        Ok(Response::new(response))
    }
    type GetAddressUtxosStreamStream = ReadStream<wire::GetAddressUtxosReply>;
    async fn get_address_utxos_stream(
        &self,
        request: Request<wire::GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetAddressUtxosStream, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let input = client
            .get_address_utxos_stream(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_utxo(&value)?;
            Ok(value)
        });
        Ok(Response::new(Box::pin(output)))
    }
    async fn get_lightd_info(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<wire::LightdInfo>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetLightdInfo, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_lightd_info(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_info(&response)?;
        Ok(Response::new(response))
    }
    async fn ping(
        &self,
        _: Request<wire::Duration>,
    ) -> Result<Response<wire::PingResponse>, Status> {
        Err(Status::permission_denied(
            "Testing methods are unavailable.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::compact_tx_streamer_server::CompactTxStreamer;

    #[test]
    fn backend_requires_numeric_loopback() {
        assert!(ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).is_ok());
        assert!(ZebraReadOnly::new("[::1]:9067".parse().unwrap()).is_ok());
        assert!(ZebraReadOnly::new("0.0.0.0:9067".parse().unwrap()).is_err());
        assert!(ZebraReadOnly::new("192.0.2.1:9067".parse().unwrap()).is_err());
        assert!(ZebraReadOnly::new("127.0.0.1:0".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn submission_and_ping_cannot_reach_backend() {
        let backend = ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).unwrap();
        assert_eq!(
            backend
                .send_transaction(Request::new(wire::RawTransaction::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            backend
                .ping(Request::new(wire::Duration::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
}
