//! Measured-guest-only quote bridge. The guest image must install the fixed
//! systemd unit/group and keep the dstack agent socket root-only.

use std::path::Path;
use zrpc_server::quote_proxy::{QUOTE_SOCKET_PATH, QuoteOnlyBridge};

const DSTACK_SOCKET: &str = "/run/dstack.sock";

async fn run() -> Result<(), &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("quote bridge takes no runtime options");
    }
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "shutdown signal unavailable")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "shutdown signal unavailable")?;

    // The measured service runs root:zrpc-wrapper. The library publishes only
    // after the root-only backend and socket permissions have been validated.
    let quote_dir = Path::new(QUOTE_SOCKET_PATH)
        .parent()
        .ok_or("quote bridge path unavailable")?;
    let bridge = QuoteOnlyBridge::bind_private(quote_dir, Path::new(DSTACK_SOCKET))
        .map_err(|_| "private quote socket unavailable")?;
    bridge
        .run(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
        .await
        .map_err(|_| "quote bridge stopped unexpectedly")
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
