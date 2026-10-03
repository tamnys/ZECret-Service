//! Node-backed guest launcher candidate. The image must install it in a
//! measured, non-root container with only a tmpfs Zebra cookie mount and the
//! quote-only bridge socket. This binary grants no client release approval.

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroUsize,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zrpc_payments::{IssuerPublic, PrivateDirectory, Redeemer, RedeemerStore};
use zrpc_server::{
    attestation::BootstrapLimits,
    bootstrap::BoundNodeListener,
    node::{CookieAuth, LocalNode},
};
use zrpc_wallet_read::backend::ZebraReadOnly;

const COOKIE_PATH: &str = "/run/zrpc-node/.cookie";
const USAGE: &str = "zrpc-node-wrapper --listen NUMERIC_IP:PORT --node LOOPBACK_IPV4:PORT --max-connections COUNT --max-quotes COUNT --quote-spacing-ms INTEGER --access free-demo|ticket-required [--wallet-backend LOOPBACK_IPV4:PORT]\nTicket-required mode also needs --issuer-public-der ROOT_OWNED_FILE --issuer-name COMMON_NAME --crypto-helper ROOT_OWNED_EXECUTABLE --spent-store PRIVATE_DIR. The wallet backend is Phala ticket-required only. Measured guest only; the Zebra cookie remains on tmpfs. This launcher does not approve client private mode.";

enum PaymentAccess {
    FreeDemo,
    TicketRequired {
        public_der: PathBuf,
        issuer_name: String,
        helper: PathBuf,
        spent_store: PathBuf,
    },
}

struct Config {
    gcp: bool,
    listen: SocketAddr,
    node: SocketAddrV4,
    limits: BootstrapLimits,
    payment: PaymentAccess,
    wallet_backend: Option<SocketAddrV4>,
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
    let payment = match take(&mut args, "--access")?.as_str() {
        "free-demo" => PaymentAccess::FreeDemo,
        "ticket-required" => PaymentAccess::TicketRequired {
            public_der: PathBuf::from(take(&mut args, "--issuer-public-der")?),
            issuer_name: take(&mut args, "--issuer-name")?,
            helper: PathBuf::from(take(&mut args, "--crypto-helper")?),
            spent_store: PathBuf::from(take(&mut args, "--spent-store")?),
        },
        _ => return Err("invalid RPC access policy"),
    };
    let gcp = if args.iter().any(|arg| arg == "--platform") {
        match take(&mut args, "--platform")?.as_str() {
            "gcp-tdx" => true,
            "phala-dstack" => false,
            _ => return Err("unsupported quote platform"),
        }
    } else {
        false
    };
    let wallet_backend = if args.iter().any(|arg| arg == "--wallet-backend") {
        let address: SocketAddrV4 = take(&mut args, "--wallet-backend")?
            .parse()
            .map_err(|_| "wallet backend must use IPv4 loopback")?;
        if gcp
            || !matches!(payment, PaymentAccess::TicketRequired { .. })
            || !address.ip().is_loopback()
            || address.port() == 0
        {
            return Err("wallet backend requires Phala ticketed loopback mode");
        }
        Some(address)
    } else {
        None
    };
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
        gcp,
        listen,
        node,
        limits,
        payment,
        wallet_backend,
    })
}

fn reviewed_file(path: &Path, executable: bool) -> Result<File, &'static str> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("payment configuration unavailable");
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| "payment configuration unavailable")?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("payment configuration unavailable");
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "payment configuration unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "payment configuration unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || (executable && metadata.mode() & 0o111 == 0)
    {
        return Err("payment configuration unavailable");
    }
    Ok(file)
}

fn paid_redeemer(payment: PaymentAccess) -> Result<Option<Arc<Redeemer>>, &'static str> {
    let PaymentAccess::TicketRequired {
        public_der,
        issuer_name,
        helper,
        spent_store,
    } = payment
    else {
        return Ok(None);
    };
    let public_file = reviewed_file(&public_der, false)?;
    reviewed_file(&helper, true)?;
    let mut public_bytes = Vec::new();
    public_file
        .take(u16::MAX as u64 + 1)
        .read_to_end(&mut public_bytes)
        .map_err(|_| "payment configuration unavailable")?;
    if public_bytes.is_empty() || public_bytes.len() > u16::MAX as usize {
        return Err("payment configuration unavailable");
    }
    let issuer = IssuerPublic::from_public_der(&helper, &public_bytes, &issuer_name)
        .map_err(|_| "payment configuration unavailable")?;
    let directory =
        PrivateDirectory::open(&spent_store).map_err(|_| "payment state unavailable")?;
    let spent = RedeemerStore::open(&directory).map_err(|_| "payment state unavailable")?;
    Ok(Some(Arc::new(Redeemer::new(issuer, helper, spent))))
}

async fn run() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let Config {
        gcp,
        listen,
        node: node_address,
        limits,
        payment,
        wallet_backend,
    } = parse(args)?;
    if rustix::process::geteuid().as_raw() == 0 {
        return Err("node wrapper must run as a non-root user");
    }
    let payment = paid_redeemer(payment)?;
    let wallet_backend = wallet_backend
        .map(|address| {
            ZebraReadOnly::new(SocketAddr::V4(address)).map_err(|_| "wallet backend unavailable")
        })
        .transpose()?;
    let cookie_path = if gcp {
        "/run/zrpc-wrapper/.cookie"
    } else {
        COOKIE_PATH
    };
    let cookie = CookieAuth::from_tmpfs_file(Path::new(cookie_path))
        .map_err(|_| "memory-backed Zebra cookie unavailable")?;
    let node = LocalNode::new(node_address, cookie).map_err(|_| "invalid node configuration")?;

    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "shutdown signal unavailable")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "shutdown signal unavailable")?;
    // The production constructor has no caller-supplied quote socket: it
    // probes only the local quote-only bridge before binding TCP.
    let listener = match (gcp, payment, wallet_backend) {
        (false, Some(payment), Some(wallet_backend)) => {
            BoundNodeListener::bind_paid_wallet(listen, limits, node, payment, wallet_backend).await
        }
        (_, _, Some(_)) => return Err("wallet backend requires Phala ticketed mode"),
        (true, Some(payment), None) => {
            BoundNodeListener::bind_gcp_paid(listen, limits, node, payment).await
        }
        (false, Some(payment), None) => {
            BoundNodeListener::bind_paid(listen, limits, node, payment).await
        }
        (true, None, None) => BoundNodeListener::bind_gcp(listen, limits, node).await,
        (false, None, None) => BoundNodeListener::bind(listen, limits, node).await,
    }
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
            "--access",
            "free-demo",
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

    #[test]
    fn platform_is_explicit_and_never_falls_back() {
        let mut args = valid();
        args.extend(["--platform".into(), "gcp-tdx".into()]);
        assert!(parse(args).unwrap().gcp);
        let mut args = valid();
        args.extend(["--platform".into(), "unknown".into()]);
        assert!(parse(args).is_err());
    }

    #[test]
    fn ticket_required_policy_needs_complete_explicit_configuration() {
        let mut args = valid();
        let access = args.iter().position(|arg| arg == "--access").unwrap();
        args[access + 1] = "ticket-required".into();
        args.extend([
            "--issuer-public-der".into(),
            "/etc/zrpc/issuer.der".into(),
            "--issuer-name".into(),
            "issuer.example".into(),
            "--crypto-helper".into(),
            "/usr/local/bin/zrpc-payment-crypto".into(),
            "--spent-store".into(),
            "/var/lib/zrpc-spent".into(),
        ]);
        assert!(matches!(
            parse(args.clone()).unwrap().payment,
            PaymentAccess::TicketRequired { .. }
        ));
        let mut wallet = args.clone();
        wallet.extend(["--wallet-backend".into(), "127.0.0.1:9067".into()]);
        assert_eq!(
            parse(wallet.clone()).unwrap().wallet_backend,
            Some("127.0.0.1:9067".parse().unwrap())
        );
        for bad in ["0.0.0.0:9067", "127.0.0.1:0", "localhost:9067"] {
            let mut changed = wallet.clone();
            let index = changed
                .iter()
                .position(|arg| arg == "--wallet-backend")
                .unwrap();
            changed[index + 1] = bad.into();
            assert!(parse(changed).is_err(), "{bad}");
        }
        wallet.extend(["--platform".into(), "gcp-tdx".into()]);
        assert!(parse(wallet).is_err());
        let mut free_wallet = valid();
        free_wallet.extend(["--wallet-backend".into(), "127.0.0.1:9067".into()]);
        assert!(parse(free_wallet).is_err());
        for option in [
            "--issuer-public-der",
            "--issuer-name",
            "--crypto-helper",
            "--spent-store",
        ] {
            let mut incomplete = args.clone();
            let index = incomplete.iter().position(|arg| arg == option).unwrap();
            incomplete.drain(index..index + 2);
            assert!(parse(incomplete).is_err(), "{option}");
        }
        let mut invalid_free = valid();
        invalid_free.extend(["--issuer-name".into(), "issuer.example".into()]);
        assert!(parse(invalid_free).is_err());
        assert!(matches!(
            parse(valid()).unwrap().payment,
            PaymentAccess::FreeDemo
        ));
        let mut missing = valid();
        missing.truncate(missing.len() - 2);
        assert!(parse(missing).is_err());
        let mut invalid = valid();
        let access = invalid.iter().position(|arg| arg == "--access").unwrap();
        invalid[access + 1] = "unknown".into();
        assert!(parse(invalid).is_err());
    }
}
