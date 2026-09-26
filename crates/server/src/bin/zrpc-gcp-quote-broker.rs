//! Immutable guest service; no paths or report bytes are accepted as options.
use zrpc_server::gcp_quote::GcpQuoteBroker;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("TDX quote broker unavailable");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let notify = std::env::var_os("NOTIFY_SOCKET").ok_or(())?;
    if !std::path::Path::new(&notify).is_absolute() {
        return Err(());
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ())?;
    let broker = GcpQuoteBroker::bind().map_err(|_| ())?;
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).map_err(|_| ())?;
    broker
        .run(async move {
            terminate.recv().await;
        })
        .await
        .map_err(|_| ())
}
