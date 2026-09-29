//! The M0 fixture protocol. No wallet, write, forwarding, or generic RPC method.
#![forbid(unsafe_code)]

mod attestation;
pub use attestation::*;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Release-policy starting limits from the design, section 9; not Zebra limits.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const EXECUTING_QUERIES: usize = 2;
pub const QUEUED_QUERIES: usize = 4;
pub const BACKEND_TIMEOUT_SECONDS: u64 = 15;
/// Public Zebra testnet fixture shown as the preview's initial example.
pub const PREVIEW_TESTNET_ADDRESS: &str = "tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3";

/// A checksum-validated Zcash testnet transparent P2PKH or P2SH address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestnetTransparentAddress(String);

struct TransparentReceiver;

impl zcash_address::TryFromAddress for TransparentReceiver {
    type Error = ();

    fn try_from_transparent_p2pkh(
        _network: zcash_protocol::consensus::NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self)
    }

    fn try_from_transparent_p2sh(
        _network: zcash_protocol::consensus::NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self)
    }
}

impl TestnetTransparentAddress {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let address = zcash_address::ZcashAddress::try_from_encoded(value)
            .map_err(|_| invalid_parameters())?;
        address
            .clone()
            .convert_if_network::<TransparentReceiver>(zcash_protocol::consensus::NetworkType::Test)
            .map_err(|_| invalid_parameters())?;
        if address.encode() != value {
            return Err(invalid_parameters());
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Testnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    RequestTooLarge,
    MethodNotAllowed,
    InvalidParameters,
    ResponseTooLarge,
    NodeUnavailable,
    BackendBusy,
    BackendTimeout,
    InvalidBackendResponse,
    WrongNetwork,
    FixtureNotFound,
    PrivateModeUnavailable,
    SimulationRejected,
    UnknownRelease,
    WrongKey,
    InvalidNonce,
    StaleNonce,
    AlteredEventLog,
    ExpiredCollateral,
    UnacceptableTcb,
    DebugImage,
    TorUnavailable,
    InvalidPolicy,
}

/// Static messages only: parser/backend diagnostics must not echo query data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafeError {
    pub code: ErrorCode,
    pub message: &'static str,
}

impl SafeError {
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for SafeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for SafeError {}
pub type ProtocolError = SafeError;

/// Strings and unsigned integer request IDs are supported; null is a notification.
/// The request-body limit bounds string IDs without an invented secondary limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(u64),
    Text(String),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Hash32(String);

impl Hash32 {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(value: &Value) -> Result<Self, ProtocolError> {
        let text = value.as_str().ok_or_else(invalid_parameters)?;
        // A 32-byte transaction/block identifier is exactly 64 hexadecimal digits.
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_parameters());
        }
        Ok(Self(text.to_ascii_lowercase()))
    }
}

// Do not accidentally disclose transaction selections through Debug logging.
impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash32([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Raw,
    Verbose,
}

impl Verbosity {
    fn parse(value: &Value) -> Result<Self, ProtocolError> {
        match value {
            Value::Bool(false) => Ok(Self::Raw),
            Value::Bool(true) => Ok(Self::Verbose),
            _ => Err(invalid_parameters()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    GetBlockchainInfo,
    GetBlockCount,
    /// u32 is this typed fixture model's height representation, not a node claim.
    GetBlockHash {
        height: u32,
    },
    GetBlockHeader {
        hash: Hash32,
        verbosity: Verbosity,
    },
    GetRawTransaction {
        txid: Hash32,
        verbosity: Verbosity,
    },
    GetPreviewAddressBalance {
        address: TestnetTransparentAddress,
    },
}

impl Method {
    pub fn name(&self) -> &'static str {
        match self {
            Self::GetBlockchainInfo => "getblockchaininfo",
            Self::GetBlockCount => "getblockcount",
            Self::GetBlockHash { .. } => "getblockhash",
            Self::GetBlockHeader { .. } => "getblockheader",
            Self::GetRawTransaction { .. } => "getrawtransaction",
            Self::GetPreviewAddressBalance { .. } => "getaddressbalance",
        }
    }
}

/// Intentionally not Serialize: private wire serialization belongs after verification.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    id: RequestId,
    method: Method,
}

impl Request {
    pub fn id(&self) -> &RequestId {
        &self.id
    }
    pub fn method(&self) -> &Method {
        &self.method
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method.name())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    jsonrpc: String,
    id: RequestId,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

/// Keep duplicate nested keys visible for the single transparent address selector.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressBalanceWireRequest {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    #[serde(rename = "id")]
    _id: RequestId,
    #[serde(rename = "method")]
    _method: String,
    params: [AddressBalanceSelection; 1],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressBalanceSelection {
    addresses: [String; 1],
}

fn invalid_parameters() -> ProtocolError {
    SafeError::new(
        ErrorCode::InvalidParameters,
        "Parameters are not allowed by the fixture protocol.",
    )
}

/// Rejects duplicate/unknown fields, batches, notifications, named parameters,
/// trailing data, forbidden methods, and bodies above the design's bound.
pub fn parse_request(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(SafeError::new(
            ErrorCode::RequestTooLarge,
            "RPC request exceeds the configured body limit.",
        ));
    }
    // Serde structs can also deserialize positional arrays. JSON-RPC requests
    // must be objects, so reject that alternate representation explicitly.
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err(SafeError::new(
            ErrorCode::InvalidRequest,
            "Expected one JSON-RPC request object.",
        ));
    }
    let raw: WireRequest = serde_json::from_slice(bytes).map_err(|_| {
        SafeError::new(
            ErrorCode::InvalidRequest,
            "Expected one strict JSON-RPC 2.0 request with an ID.",
        )
    })?;
    if raw.jsonrpc != "2.0" {
        return Err(SafeError::new(
            ErrorCode::InvalidRequest,
            "JSON-RPC version must be 2.0.",
        ));
    }
    let method = match (raw.method.as_str(), raw.params.as_slice()) {
        ("getblockchaininfo", []) => Method::GetBlockchainInfo,
        ("getblockcount", []) => Method::GetBlockCount,
        ("getblockhash", [height]) => Method::GetBlockHash {
            height: height
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(invalid_parameters)?,
        },
        ("getblockheader", [hash, verbosity]) => Method::GetBlockHeader {
            hash: Hash32::parse(hash)?,
            verbosity: Verbosity::parse(verbosity)?,
        },
        ("getrawtransaction", [txid, verbosity]) => Method::GetRawTransaction {
            txid: Hash32::parse(txid)?,
            verbosity: Verbosity::parse(verbosity)?,
        },
        ("getaddressbalance", _) => {
            let strict: AddressBalanceWireRequest =
                serde_json::from_slice(bytes).map_err(|_| invalid_parameters())?;
            Method::GetPreviewAddressBalance {
                address: TestnetTransparentAddress::parse(&strict.params[0].addresses[0])?,
            }
        }
        (
            "getblockchaininfo" | "getblockcount" | "getblockhash" | "getblockheader"
            | "getrawtransaction",
            _,
        ) => {
            return Err(invalid_parameters());
        }
        _ => {
            return Err(SafeError::new(
                ErrorCode::MethodNotAllowed,
                "RPC method is not allowlisted.",
            ));
        }
    };
    Ok(Request { id: raw.id, method })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainReadiness {
    Synthetic,
    Unavailable,
    NotChecked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allowed_requests_are_typed() {
        for method in ["getblockcount", "getblockchaininfo"] {
            let bytes =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}))
                    .unwrap();
            assert_eq!(parse_request(&bytes).unwrap().method().name(), method);
        }
        let request =
            parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[42]}"#)
                .unwrap();
        assert_eq!(request.method(), &Method::GetBlockHash { height: 42 });
    }

    #[test]
    fn forbidden_shapes_and_methods_fail_without_echoing_markers() {
        let invalid = [
            r#"[{"jsonrpc":"2.0","id":1,"method":"getblockcount"}]"#,
            r#"["2.0",1,"getblockcount",[]]"#,
            r#"{"jsonrpc":"2.0","method":"getblockcount"}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"getblockcount"}"#,
            r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","method":"sendrawtransaction"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","seed":"SYNTHETIC_SECRET_MARKER"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["SYNTHETIC_SECRET_MARKER"]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getbalance"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[1]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[-1]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[4294967296]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[1.5]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getrawtransaction","params":["bad",true]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":{"url":"http://outside"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","upstream_url":"http://outside"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount"} {}"#,
        ];
        for bytes in invalid {
            let error = parse_request(bytes.as_bytes()).unwrap_err();
            assert!(
                !serde_json::to_string(&error)
                    .unwrap()
                    .contains("SYNTHETIC_SECRET_MARKER")
            );
        }
    }

    #[test]
    fn request_bound_is_checked_before_json_decode() {
        assert_eq!(
            parse_request(&vec![b' '; MAX_REQUEST_BYTES + 1])
                .unwrap_err()
                .code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn transaction_and_block_hashes_and_verbosity_are_strict() {
        for method in ["getrawtransaction", "getblockheader"] {
            for verbosity in [json!(true), json!(false)] {
                let bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":["ab".repeat(32),verbosity]})).unwrap();
                assert!(parse_request(&bytes).is_ok());
            }
            for params in [
                json!(["ab".repeat(32)]),
                json!(["ab".repeat(32), 2]),
                json!(["zz".repeat(32), true]),
                json!(["ab".repeat(33), true]),
            ] {
                let bytes = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
                )
                .unwrap();
                assert_eq!(
                    parse_request(&bytes).unwrap_err().code,
                    ErrorCode::InvalidParameters
                );
            }
        }
    }

    #[test]
    fn address_balance_accepts_only_one_valid_testnet_transparent_address() {
        let request = |params: Value| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "getaddressbalance", "params": params
            }))
            .unwrap()
        };
        assert_eq!(
            parse_request(&request(json!([{"addresses": [PREVIEW_TESTNET_ADDRESS]}])))
                .unwrap()
                .method(),
            &Method::GetPreviewAddressBalance {
                address: TestnetTransparentAddress::parse(PREVIEW_TESTNET_ADDRESS).unwrap(),
            }
        );
        for address in [
            "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
        ] {
            assert_eq!(
                parse_request(&request(json!([{"addresses": [address]}])))
                    .unwrap()
                    .method(),
                &Method::GetPreviewAddressBalance {
                    address: TestnetTransparentAddress::parse(address).unwrap(),
                }
            );
        }
        for params in [
            json!([]),
            json!([{"addresses": ["tmArbitraryAddress"]}]),
            json!([{"addresses": ["t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"]}]),
            json!([{"addresses": ["zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya"]}]),
            json!([{"addresses": [PREVIEW_TESTNET_ADDRESS, PREVIEW_TESTNET_ADDRESS]}]),
            json!([{"addresses": [PREVIEW_TESTNET_ADDRESS], "extra": true}]),
            json!([[PREVIEW_TESTNET_ADDRESS]]),
        ] {
            assert_eq!(
                parse_request(&request(params)).unwrap_err().code,
                ErrorCode::InvalidParameters
            );
        }
        let duplicate_address_key = br#"{"jsonrpc":"2.0","id":1,"method":"getaddressbalance","params":[{"addresses":["tmArbitraryAddress"],"addresses":["tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3"]}]}"#;
        assert_eq!(
            parse_request(duplicate_address_key).unwrap_err().code,
            ErrorCode::InvalidParameters
        );
    }
}
