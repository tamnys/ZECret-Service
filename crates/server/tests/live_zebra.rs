//! Opt-in check of the production node adapter against a locally running
//! Zebra Testnet process. This does not exercise a TEE, TLS, Tor, or a client.

use std::{net::SocketAddrV4, path::PathBuf};

use zrpc_protocol::PREVIEW_TESTNET_ADDRESS;
use zrpc_server::node::{CookieAuth, LocalNode};

#[tokio::test]
#[ignore = "requires a live local Zebra Testnet RPC and its tmpfs cookie"]
async fn adapter_reads_live_testnet_status_and_transparent_balance() {
    let endpoint: SocketAddrV4 = std::env::var("ZRPC_LIVE_ZEBRA_RPC")
        .expect("set ZRPC_LIVE_ZEBRA_RPC to a numeric loopback address")
        .parse()
        .expect("ZRPC_LIVE_ZEBRA_RPC must be numeric IPv4");
    let cookie = PathBuf::from(
        std::env::var_os("ZRPC_LIVE_ZEBRA_COOKIE")
            .expect("set ZRPC_LIVE_ZEBRA_COOKIE to the tmpfs cookie path"),
    );
    let auth = CookieAuth::from_tmpfs_file(&cookie).expect("valid owned tmpfs Zebra cookie");
    let node = LocalNode::new(endpoint, auth).expect("loopback node RPC");

    let status = node
        .handle(br#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)
        .await
        .expect("live Testnet status through the production adapter");
    assert_eq!(status["result"]["chain"], "test");
    assert!(status["result"]["blocks"].as_u64().is_some());
    assert_eq!(
        status["chain_context"]["height"],
        status["result"]["blocks"]
    );
    assert_eq!(
        status["chain_context"]["hash"],
        status["result"]["bestblockhash"]
    );

    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "getaddressbalance",
        "params": [{"addresses": [PREVIEW_TESTNET_ADDRESS]}]
    });
    let response = node
        .handle(&serde_json::to_vec(&request).expect("bounded public request"))
        .await
        .expect("live transparent balance through the production adapter");
    assert_eq!(response["id"], 2);
    assert!(response["result"]["balance"].as_u64().is_some());
    assert!(response["result"].get("received").is_none());
    assert!(
        serde_json::from_value::<zrpc_protocol::BlockRef>(response["chain_context"].clone())
            .is_ok()
    );
}
