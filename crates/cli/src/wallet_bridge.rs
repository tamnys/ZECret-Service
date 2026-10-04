use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

use serde_json::json;
use tokio::net::TcpListener;
use zrpc_payments::PrivateDirectory;
use zrpc_wallet_sdk::{WalletReader, bridge::WalletBridge};

use super::{
    exhausted, payments::QueryTicketConfig, phala_trusted_inputs, print_json, required, take_flag,
};

pub(super) async fn run(mut args: Vec<String>) -> Result<(), String> {
    let show_dashboard = take_flag(&mut args, "--dashboard");
    if required(&mut args, "--privacy-profile")? != "phala-trusted" {
        return Err("wallet bridge requires the explicit phala-trusted profile".into());
    }
    let bind: SocketAddr = required(&mut args, "--bind")?
        .parse()
        .map_err(|_| "wallet bridge requires a numeric loopback bind address")?;
    if !bind.ip().is_loopback() || bind.port() == 0 {
        return Err("wallet bridge requires a nonzero loopback port".into());
    }
    let capability_dir = PathBuf::from(required(&mut args, "--capability-dir")?);
    let ticket_config = QueryTicketConfig::parse(&mut args)?
        .ok_or("wallet bridge requires a private ticket store")?;
    let live = phala_trusted_inputs(&mut args)?;
    exhausted(&args)?;

    // Bind before publishing a capability file or reporting readiness.
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| "wallet bridge loopback bind unavailable")?;
    let (issuer, tickets) = ticket_config.open()?;
    let reader = WalletReader::new(
        live.config,
        live.collateral,
        live.compose,
        live.policy,
        issuer,
        tickets,
    );
    let (bridge, capability) =
        WalletBridge::new(reader).map_err(|_| "wallet bridge unavailable")?;
    let dashboard = if show_dashboard {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| "wallet dashboard loopback bind unavailable")?;
        let address = listener
            .local_addr()
            .map_err(|_| "wallet dashboard address unavailable")?;
        let session = zrpc_cli::LocalSession::new_wallet_bridge(address, bridge.clone())?;
        Some((listener, session))
    } else {
        None
    };
    PrivateDirectory::create(&capability_dir)
        .map_err(|_| "new private capability directory required")?;
    let capability_path = capability_dir.join("capability");
    let setup = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&capability_path)
            .map_err(|_| "capability file unavailable")?;
        file.write_all(capability.expose())
            .and_then(|_| file.sync_all())
            .map_err(|_| "capability file unavailable")
    })();
    if let Err(error) = setup {
        let _ = fs::remove_file(&capability_path);
        let _ = fs::remove_dir(&capability_dir);
        return Err(error.into());
    }
    drop(capability);
    if let Some((_, session)) = dashboard.as_ref() {
        let delivered = (|| {
            let url = session.bootstrap_url()?;
            let mut tty = OpenOptions::new()
                .write(true)
                .open("/dev/tty")
                .map_err(|_| "interactive terminal required for wallet dashboard")?;
            writeln!(
                tty,
                "Open this one-time local wallet status link privately:\n{url}"
            )
            .map_err(|_| "wallet dashboard terminal unavailable")
        })();
        if let Err(error) = delivered {
            let _ = fs::remove_file(&capability_path);
            let _ = fs::remove_dir(&capability_dir);
            return Err(error.into());
        }
    }
    let address = listener
        .local_addr()
        .map_err(|_| "wallet bridge address unavailable")?;
    let announcement = print_json(json!({
        "wallet_bridge":"listening",
        "bind":address.to_string(),
        "capability_file":capability_path,
        "privacy_profile":"phala_trusted",
        "wallet_data_retained":false,
        "public_reflection":false
    }));
    if let Err(error) = announcement {
        let _ = fs::remove_file(&capability_path);
        let _ = fs::remove_dir(&capability_dir);
        return Err(error);
    }
    let shutdown = async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        if let Some(signal) = terminate.as_mut() {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = signal.recv() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    let result = if let Some((dashboard_listener, dashboard_session)) = dashboard {
        tokio::select! {
            result = bridge.serve_on(listener, shutdown) => result,
            _ = axum::serve(dashboard_listener, zrpc_cli::dashboard(dashboard_session)) => {
                Err(zrpc_protocol::SafeError::new(
                    zrpc_protocol::ErrorCode::NodeUnavailable,
                    "Local wallet dashboard stopped.",
                ))
            }
        }
    } else {
        bridge.serve_on(listener, shutdown).await
    };
    let removed = fs::remove_file(&capability_path).is_ok();
    let _ = fs::remove_dir(&capability_dir);
    if !removed {
        return Err("wallet bridge capability cleanup failed".into());
    }
    result.map_err(|_| "wallet bridge stopped unexpectedly".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bridge_rejects_public_and_zero_ports_before_loading_private_inputs() {
        for bind in ["0.0.0.0:9067", "192.0.2.1:9067", "127.0.0.1:0"] {
            let result = run(vec![
                "--privacy-profile".into(),
                "phala-trusted".into(),
                "--bind".into(),
                bind.into(),
            ])
            .await;
            assert_eq!(
                result,
                Err("wallet bridge requires a nonzero loopback port".into()),
                "{bind}"
            );
        }
    }
}
