//! Confirmed balance and block identity from one complete Zebra UTXO response.
use super::{invalid_response, is_hash};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use zrpc_protocol::{BlockRef, SafeError, TestnetTransparentAddress};

#[derive(Deserialize)]
struct Utxo {
    address: String,
    txid: String,
    #[serde(rename = "outputIndex")]
    output_index: u32,
    satoshis: u64,
    height: u32,
}

pub(super) fn balance(
    value: &Value,
    address: &TestnetTransparentAddress,
) -> Result<(u64, BlockRef), SafeError> {
    let context = BlockRef::from_parts(&value["height"], &value["hash"])?;
    let utxos = value
        .get("utxos")
        .and_then(Value::as_array)
        .ok_or_else(invalid_response)?;
    let mut outpoints = HashSet::new();
    let mut balance = 0u64;
    for value in utxos {
        let utxo = Utxo::deserialize(value).map_err(|_| invalid_response())?;
        if utxo.address != address.as_str()
            || !is_hash(&value["txid"])
            || utxo.height > context.height
            || !outpoints.insert((utxo.txid.to_ascii_lowercase(), utxo.output_index))
        {
            return Err(invalid_response());
        }
        balance = balance
            .checked_add(utxo.satoshis)
            .ok_or_else(invalid_response)?;
    }
    Ok((balance, context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zrpc_protocol::PREVIEW_TESTNET_ADDRESS;

    fn output(index: u32, amount: Value) -> Value {
        json!({"address":PREVIEW_TESTNET_ADDRESS,"txid":"ab".repeat(32),"outputIndex":index,"satoshis":amount,"height":40})
    }
    fn response(utxos: Value) -> Value {
        json!({"height":42,"hash":"cd".repeat(32),"utxos":utxos})
    }
    fn check(value: &Value) -> Result<(u64, BlockRef), SafeError> {
        balance(
            value,
            &TestnetTransparentAddress::parse(PREVIEW_TESTNET_ADDRESS).unwrap(),
        )
    }
    #[test]
    fn sums_complete_set_including_empty_balance_at_actual_tip() {
        let (total, tip) = check(&response(json!([
            output(0, json!(7)),
            output(1, json!(11))
        ])))
        .unwrap();
        assert_eq!(total, 18);
        assert_eq!(tip.height, 42);
        assert_eq!(tip.hash.as_str(), "cd".repeat(32));
        assert_eq!(check(&response(json!([]))).unwrap().0, 0);
    }
    #[test]
    fn malformed_partial_duplicate_or_overflowing_data_never_becomes_a_balance() {
        let mut bad = vec![
            response(Value::Null),
            response(json!([output(0, json!(u64::MAX)), output(1, json!(1))])),
            response(json!([output(0, json!(7)), output(0, json!(7))])),
        ];
        for amount in [json!(-1), json!(0.5), json!("7"), Value::Null] {
            bad.push(response(json!([output(0, amount)])));
        }
        for (field, value) in [
            ("txid", json!("bad")),
            ("address", json!("wrong")),
            ("height", json!(43)),
            ("outputIndex", json!(-1)),
        ] {
            let mut item = output(0, json!(1));
            item[field] = value;
            bad.push(response(json!([item])));
        }
        let mut missing_tip = response(json!([]));
        missing_tip.as_object_mut().unwrap().remove("hash");
        bad.push(missing_tip);
        for value in bad {
            assert!(check(&value).is_err(), "accepted malformed synthetic UTXOs");
        }
    }
}
