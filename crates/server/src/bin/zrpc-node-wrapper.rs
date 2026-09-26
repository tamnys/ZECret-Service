//! Node-backed guest launcher candidate. The image must install it in a
//! measured, non-root container with only a tmpfs Zebra cookie mount and the
//! quote-only bridge socket. This binary grants no client release approval.

use std::{
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroUsize,
    path::Path,
    time::Duration,
};
use zrpc_server::{
    attestation::BootstrapLimits,
    bootstrap::BoundNodeListener,
    node::{CookieAuth, LocalNode},
};

const COOKIE_PATH: &str = "/run/zrpc-node/.cookie";
const USAGE: &str = "zrpc-node-wrapper --listen NUMERIC_IP:PORT --node LOOPBACK_IPV4:PORT --max-connections COUNT --max-quotes COUNT --quote-spacing-ms INTEGER\nMeasured guest only. The Zebra cookie must be at /run/zrpc-node/.cookie on tmpfs; the quote-only socket path is compiled in. This launcher does not approve client private mode.";

struct Config {
    listen: SocketAddr,
    node: SocketAddrV4,
    limits: BootstrapLimits,
}

fn take(args: &mut Vec<String>, name: &str) -> Result<String, &'static str> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .ok_or("required option missing")?;
    if index + 1 >= args.len() {
        return Err("required option value missing");
    }
    args.remove(index);
    Ok(args.remove(index))
}

fn parse(mut args: Vec<String>) -> Result<Config, &'static str> {
    let listen: SocketAddr = take(&mut args, "--listen")?
        .parse()
        .map_err(|_| "invalid numeric listen address")?;
    if listen.port() == 0 || !matches!(listen, SocketAddr::V4(_)) {
        return Err("IPv4 listen address with nonzero port required");
    }
    let node: SocketAddrV4 = take(&mut args, "--node")?
        .parse()
        .map_err(|_| "invalid numeric node address")?;
    if !node.ip().is_loopback() || node.port() == 0 {
        return Err("node RPC must use IPv4 loopback");
    }
    let connections: NonZeroUsize = take(&mut args, "--max-connections")?
        .parse()
        .map_err(|_| "nonzero connection limit required")?;
    let quotes: NonZeroUsize = take(&mut args, "--max-quotes")?
        .parse()
        .map_err(|_| "nonzero quote limit required")?;
    let spacing: u64 = take(&mut args, "--quote-spacing-ms")?
        .parse()
        .map_err(|_| "invalid quote spacing")?;
    if !args.is_empty() {
        return Err("unknown or repeated option");
    }
    let limits = BootstrapLimits::new(connections, quotes, Duration::from_millis(spacing))
        .map_err(|_| "invalid explicit bootstrap limits")?;
    Ok(Config {
        listen,
        node,
        limits,
    })
}

async fn run() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let config = parse(args)?;
    if rustix::process::geteuid().as_raw() == 0 {
        return Err("node wrapper must run as a non-root user");
    }
    let cookie = CookieAuth::from_tmpfs_file(Path::new(COOKIE_PATH))
        .map_err(|_| "memory-backed Zebra cookie unavailable")?;
    let node = LocalNode::new(config.node, cookie).map_err(|_| "invalid node configuration")?;

    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "shutdown signal unavailable")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "shutdown signal unavailable")?;
    // The production constructor has no caller-supplied quote socket: it
    // probes only the local quote-only bridge before binding TCP.
    let listener = BoundNodeListener::bind(config.listen, config.limits, node)
        .await
        .map_err(|_| "node listener unavailable")?;
    listener
        .run(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
        .await
        .map_err(|_| "node listener stopped unexpectedly")
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("node wrapper unavailable");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Vec<String> {
        [
            "--listen",
            "127.0.0.1:8443",
            "--node",
            "127.0.0.1:18232",
            "--max-connections",
            "2",
            "--max-quotes",
            "1",
            "--quote-spacing-ms",
            "1000",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn launcher_needs_explicit_bounded_numeric_configuration() {
        assert!(parse(valid()).is_ok());
        for (name, replacement) in [
            ("--node", "192.0.2.1:18232"),
            ("--node", "127.0.0.1:0"),
            ("--listen", "localhost:8443"),
            ("--listen", "[::1]:8443"),
            ("--max-connections", "0"),
            ("--max-quotes", "0"),
            ("--quote-spacing-ms", "invalid"),
        ] {
            let mut args = valid();
            let position = args.iter().position(|arg| arg == name).unwrap();
            args[position + 1] = replacement.into();
            assert!(parse(args).is_err(), "{name}={replacement}");
        }
        let mut repeated = valid();
        repeated.extend(["--node".into(), "127.0.0.1:18232".into()]);
        assert!(parse(repeated).is_err());
        let mut missing = valid();
        missing.truncate(2);
        assert!(parse(missing).is_err());
    }
}
