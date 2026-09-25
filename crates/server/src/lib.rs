//! Fixture wrapper and internal loopback-only node adapter. No public listener.
#![forbid(unsafe_code)]

pub mod node;

use serde_json::{Value, json};
use std::io::{self, Write};
use zrpc_protocol::{
    ErrorCode, MAX_RESPONSE_BYTES, Method, Request, SafeError, Verbosity, parse_request,
};

const NODE_FIXTURE: &str = include_str!("../../../tests/fixtures/node.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    FixtureAvailable,
    Unavailable,
}

pub struct FixtureServer;

impl FixtureServer {
    /// A fixture request never reaches a node or any network.
    pub fn handle(bytes: &[u8], state: NodeState) -> Result<Value, SafeError> {
        let request = parse_request(bytes)?;
        Self::dispatch(&request, state)
    }

    pub fn dispatch(request: &Request, state: NodeState) -> Result<Value, SafeError> {
        if state == NodeState::Unavailable {
            return Err(SafeError::new(
                ErrorCode::NodeUnavailable,
                "The simulated node is unavailable.",
            ));
        }
        let fixture: Value = serde_json::from_str(NODE_FIXTURE).map_err(|_| {
            SafeError::new(
                ErrorCode::NodeUnavailable,
                "Bundled fixture cannot be read.",
            )
        })?;
        let missing = || {
            SafeError::new(
                ErrorCode::FixtureNotFound,
                "Selection is absent from the bundled synthetic fixture.",
            )
        };
        let result = match request.method() {
            Method::GetBlockchainInfo => fixture["blockchain_info"].clone(),
            Method::GetBlockCount => fixture["height"].clone(),
            Method::GetBlockHash { height } => {
                if Some(u64::from(*height)) != fixture["height"].as_u64() {
                    return Err(missing());
                }
                fixture["block_hash"].clone()
            }
            Method::GetBlockHeader { hash, verbosity } => {
                if Some(hash.as_str()) != fixture["block_hash"].as_str() {
                    return Err(missing());
                }
                match verbosity {
                    Verbosity::Raw => fixture["raw_header"].clone(),
                    Verbosity::Verbose => fixture["block_header"].clone(),
                }
            }
            Method::GetRawTransaction { txid, verbosity } => {
                if Some(txid.as_str()) != fixture["transaction_id"].as_str() {
                    return Err(missing());
                }
                match verbosity {
                    Verbosity::Raw => fixture["raw_transaction"].clone(),
                    Verbosity::Verbose => fixture["transaction"].clone(),
                }
            }
        };
        let response = json!({"jsonrpc":"2.0","id":request.id(),"result":result});
        check_response_bound(&response)?;
        Ok(response)
    }
}

/// Counts serialized output without making a second response-sized allocation.
pub fn check_response_bound(response: &Value) -> Result<(), SafeError> {
    let mut sink = BoundedCounter { bytes: 0 };
    serde_json::to_writer(&mut sink, response).map_err(|_| {
        SafeError::new(
            ErrorCode::ResponseTooLarge,
            "RPC response exceeds the configured decoded response limit.",
        )
    })
}

struct BoundedCounter {
    bytes: usize,
}
impl Write for BoundedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.bytes) {
            return Err(io::Error::other("response limit"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixture_request_has_a_synthetic_response() {
        let requests: Vec<Value> =
            serde_json::from_str(include_str!("../../../tests/fixtures/requests.json")).unwrap();
        for request in requests {
            let response = FixtureServer::handle(
                &serde_json::to_vec(&request).unwrap(),
                NodeState::FixtureAvailable,
            )
            .unwrap();
            assert_eq!(response["id"], request["id"]);
            assert!(response.get("result").is_some());
        }
    }

    #[test]
    fn fixture_selection_is_not_arbitrary_forwarding() {
        let bytes = br#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[43]}"#;
        assert_eq!(
            FixtureServer::handle(bytes, NodeState::FixtureAvailable)
                .unwrap_err()
                .code,
            ErrorCode::FixtureNotFound
        );
        let forbidden = br#"{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["SYNTHETIC_QUERY_MARKER"]}"#;
        let error = FixtureServer::handle(forbidden, NodeState::FixtureAvailable).unwrap_err();
        assert_eq!(error.code, ErrorCode::MethodNotAllowed);
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("SYNTHETIC_QUERY_MARKER")
        );
    }

    #[test]
    fn unavailable_node_returns_sanitized_error() {
        let bytes = br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount"}"#;
        assert_eq!(
            FixtureServer::handle(bytes, NodeState::Unavailable)
                .unwrap_err()
                .code,
            ErrorCode::NodeUnavailable
        );
    }

    #[test]
    fn decoded_response_size_is_enforced() {
        assert_eq!(
            check_response_bound(&Value::String("x".repeat(MAX_RESPONSE_BYTES)))
                .unwrap_err()
                .code,
            ErrorCode::ResponseTooLarge
        );
    }
}
