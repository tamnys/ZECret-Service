//! Browser-test harness, never included in the release binary. The runner gives
//! fd 3 exclusively to this child and reads its ephemeral URL without logging it.
use std::{io::Write, os::fd::FromRawFd};
#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let session = zrpc_cli::LocalSession::new(listener.local_addr().unwrap()).unwrap();
    // SAFETY: the test runner creates fd 3 for this child; this File takes sole
    // ownership. It is a pipe, never a path or persistent capability artifact.
    let mut pipe = unsafe { std::fs::File::from_raw_fd(3) };
    writeln!(pipe, "{}", session.bootstrap_url().unwrap()).unwrap();
    drop(pipe);
    axum::serve(listener, zrpc_cli::dashboard(session))
        .await
        .unwrap();
}
