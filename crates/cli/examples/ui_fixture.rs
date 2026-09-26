//! Browser-test harness, never included in the release binary. The runner gives
//! fd 3 exclusively to this child and reads its ephemeral URL without logging it.
use std::{io::Write, os::fd::FromRawFd};
#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let session = if std::env::var_os("ZRPC_BROWSER_LIVE").is_some() {
        let config = zrpc_client::inspection::PublicInspectionConfig::new(
            "fixture.invalid",
            443,
            "127.0.0.1:9",
        )
        .unwrap();
        zrpc_cli::LocalSession::new_live(
            listener.local_addr().unwrap(),
            zrpc_cli::LiveConfiguration::new(
                config,
                b"{}".to_vec(),
                b"{}".to_vec(),
                zrpc_verifier::ReleasePolicy::default(),
            ),
        )
        .unwrap()
    } else {
        zrpc_cli::LocalSession::new(listener.local_addr().unwrap()).unwrap()
    };
    // SAFETY: the test runner creates fd 3 for this child; this File takes sole
    // ownership. It is a pipe, never a path or persistent capability artifact.
    let mut pipe = unsafe { std::fs::File::from_raw_fd(3) };
    writeln!(pipe, "{}", session.bootstrap_url().unwrap()).unwrap();
    drop(pipe);
    axum::serve(listener, zrpc_cli::dashboard(session))
        .await
        .unwrap();
}
