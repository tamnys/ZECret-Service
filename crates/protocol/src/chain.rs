//! Node-reported block context, not an independent consensus or freshness proof.
use super::{ErrorCode, Hash32, Method, Request, SafeError};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockRef {
    pub height: u32,
    pub hash: Hash32,
}

impl BlockRef {
    pub fn from_parts(height: &Value, hash: &Value) -> Result<Self, SafeError> {
        Ok(Self {
            height: height
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(invalid_context)?,
            hash: Hash32::parse(hash).map_err(|_| invalid_context())?,
        })
    }
}

// Require a JSON object and preserve duplicate-field rejection at the boundary.
impl<'de> Deserialize<'de> for BlockRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BlockVisitor;
        impl<'de> Visitor<'de> for BlockVisitor {
            type Value = BlockRef;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a block height/hash object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<BlockRef, M::Error> {
                let (mut height, mut hash) = (None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "height" if height.is_none() => height = Some(map.next_value::<u32>()?),
                        "hash" if hash.is_none() => {
                            let text = map.next_value::<String>()?;
                            hash = Some(
                                Hash32::parse(&Value::String(text))
                                    .map_err(|_| de::Error::custom("invalid block hash"))?,
                            );
                        }
                        _ => return Err(de::Error::custom("unknown or duplicate block field")),
                    }
                }
                Ok(BlockRef {
                    height: height.ok_or_else(|| de::Error::missing_field("height"))?,
                    hash: hash.ok_or_else(|| de::Error::missing_field("hash"))?,
                })
            }
        }
        deserializer.deserialize_map(BlockVisitor)
    }
}

#[derive(Debug, Serialize)]
pub struct RpcResult {
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_context: Option<BlockRef>,
}

fn invalid_context() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidBackendResponse,
        "RPC block context or result is invalid.",
    )
}

/// Used independently by the server and native client before returning a result.
pub fn validate_chain_context(
    request: &Request,
    result: &Value,
    context: Option<&BlockRef>,
) -> Result<(), SafeError> {
    if !request.method().requires_chain_context() {
        return if context.is_none() {
            Ok(())
        } else {
            Err(invalid_context())
        };
    }
    let context = context.ok_or_else(|| {
        SafeError::new(
            ErrorCode::ChainContextUnavailable,
            "Server response lacks required block context; update the server and client together.",
        )
    })?;
    let consistent = match request.method() {
        Method::GetBlockchainInfo => {
            BlockRef::from_parts(&result["blocks"], &result["bestblockhash"])? == *context
        }
        Method::GetBlockCount => result.as_u64() == Some(u64::from(context.height)),
        Method::GetPreviewAddressBalance { .. } => {
            result.get("balance").and_then(Value::as_u64).is_some()
                && result.get("received").is_none()
        }
        _ => unreachable!(),
    };
    if !consistent {
        return Err(invalid_context());
    }
    if request
        .expected_block()
        .is_some_and(|expected| expected != context)
    {
        return Err(SafeError::new(
            ErrorCode::BlockMismatch,
            "Result block does not match the requested block.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PREVIEW_TESTNET_ADDRESS, parse_request};
    use serde_json::json;

    #[test]
    fn expected_block_is_typed_strict_and_limited_to_supported_methods() {
        for (method, params) in [
            ("getblockcount", json!([])),
            ("getblockchaininfo", json!([])),
            (
                "getaddressbalance",
                json!([{"addresses":[PREVIEW_TESTNET_ADDRESS]}]),
            ),
        ] {
            let wire = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params,
                "expected_block":{"height":42,"hash":"AB".repeat(32)}});
            let req = parse_request(&serde_json::to_vec(&wire).unwrap()).unwrap();
            assert_eq!(req.expected_block().unwrap().hash.as_str(), "ab".repeat(32));
            for bad in [
                json!({"height":42}),
                json!({"height":-1,"hash":"ab".repeat(32)}),
                json!({"height":42,"hash":"bad"}),
                json!([42, "ab".repeat(32)]),
                json!({"height":42,"hash":"ab".repeat(32),"unknown":true}),
            ] {
                let mut bad_wire = wire.clone();
                bad_wire["expected_block"] = bad;
                assert!(parse_request(&serde_json::to_vec(&bad_wire).unwrap()).is_err());
            }
        }
        let duplicate = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"getblockcount","expected_block":{{"height":42,"height":43,"hash":"{}"}}}}"#,
            "ab".repeat(32)
        );
        assert!(parse_request(duplicate.as_bytes()).is_err());
        let unsupported = json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[42],
            "expected_block":{"height":42,"hash":"ab".repeat(32)}});
        assert!(parse_request(&serde_json::to_vec(&unsupported).unwrap()).is_err());
    }

    #[test]
    fn exact_match_rejects_old_height_and_same_height_reorg() {
        let wire = json!({"jsonrpc":"2.0","id":1,"method":"getblockcount",
            "expected_block":{"height":42,"hash":"ab".repeat(32)}});
        let req = parse_request(&serde_json::to_vec(&wire).unwrap()).unwrap();
        let matched = req.expected_block().unwrap();
        assert!(validate_chain_context(&req, &json!(42), Some(matched)).is_ok());
        for (height, hash) in [(41, "ab"), (42, "cd")] {
            let context = BlockRef::from_parts(&json!(height), &json!(hash.repeat(32))).unwrap();
            assert_eq!(
                validate_chain_context(&req, &json!(height), Some(&context))
                    .unwrap_err()
                    .code,
                ErrorCode::BlockMismatch
            );
        }
        assert_eq!(
            validate_chain_context(&req, &json!(42), None)
                .unwrap_err()
                .code,
            ErrorCode::ChainContextUnavailable
        );
        assert_eq!(
            validate_chain_context(&req, &json!(43), Some(matched))
                .unwrap_err()
                .code,
            ErrorCode::InvalidBackendResponse
        );
    }
}
