//! Local diagnostic launcher. No cloud deployment, RPC or imported TLS keys.
use serde_json::json;
use std::{
    io::{self, Write},
    net::SocketAddr,
    num::NonZeroUsize,
    path::PathBuf,
    time::Duration,
};
use zrpc_server::{attestation::BootstrapLimits, bootstrap::BoundPublicListener};

const USAGE: &str = "zrpc-wrapper --listen LOOPBACK_IP:PORT --dstack-socket ABSOLUTE_PATH --max-connections COUNT --max-quotes COUNT --quote-spacing-ms INTEGER\nLocal public attestation only. Every option is required; no private RPC or deployment is enabled.";

fn take(args: &mut Vec<String>, name: &str) -> Result<String, &'static str> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .ok_or("required option missing; run zrpc-wrapper --help")?;
    if index + 1 >= args.len() {
        return Err("required option value missing");
    }
    args.remove(index);
    Ok(args.remove(index))
}

struct Config {
    address: SocketAddr,
    socket: PathBuf,
    limits: BootstrapLimits,
}
fn parse(mut args: Vec<String>) -> Result<Config, &'static str> {
    let address: SocketAddr = take(&mut args, "--listen")?
        .parse()
        .map_err(|_| "invalid numeric listen address")?;
    if !address.ip().is_loopback() {
        return Err("the diagnostic listener requires a loopback address");
    }
    let socket = PathBuf::from(take(&mut args, "--dstack-socket")?);
    let connections: NonZeroUsize = take(&mut args, "--max-connections")?
        .parse()
        .map_err(|_| "a nonzero connection limit is required")?;
    let quotes: NonZeroUsize = take(&mut args, "--max-quotes")?
        .parse()
        .map_err(|_| "a nonzero quote limit is required")?;
    let spacing: u64 = take(&mut args, "--quote-spacing-ms")?
        .parse()
        .map_err(|_| "invalid quote spacing")?;
    if !args.is_empty() {
        return Err("unknown or repeated option; run zrpc-wrapper --help");
    }
    let limits = BootstrapLimits::new(connections, quotes, Duration::from_millis(spacing))
        .map_err(|_| "invalid explicit bootstrap limits")?;
    Ok(Config {
        address,
        socket,
        limits,
    })
}

fn report(state: &str, address: SocketAddr) -> Result<(), &'static str> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(
        &mut stdout,
        &json!({
            "mode":"local_public_attestation", "state":state, "listen":address.to_string(),
            "tls_identity":"fresh_process_local_key", "evidence_status":"unverified",
            "approved_release":null, "private_accepted":false, "query_sent":false,
            "private_rpc_enabled":false, "deployment_enabled":false
        }),
    )
    .map_err(|_| "status output unavailable")?;
    stdout
        .write_all(b"\n")
        .and_then(|_| stdout.flush())
        .map_err(|_| "status output unavailable")
}

async fn run() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let config = parse(args)?;
    // Register both handlers before opening the listening socket. Cancellation
    // owns and closes every accepted connection; no detached service survives.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "shutdown signal registration failed")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "shutdown signal registration failed")?;
    let listener = BoundPublicListener::bind(config.address, &config.socket, config.limits)
        .await
        .map_err(|_| "local public listener could not start")?;
    let address = listener
        .local_addr()
        .map_err(|_| "listener address unavailable")?;
    report("listening", address)?;
    listener
        .run(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
        .await
        .map_err(|_| "local public listener failed")?;
    report("stopped", address)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let mut stdout = io::stdout().lock();
        let _ = serde_json::to_writer(
            &mut stdout,
            &json!({"error":error,"private_accepted":false,"query_sent":false,"private_rpc_enabled":false,"deployment_enabled":false}),
        );
        let _ = stdout.write_all(b"\n");
        std::process::exit(1);
    }
}
