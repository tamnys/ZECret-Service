//! One-boot memory-only handoff; no caller-selected source or destination.
fn identity(passwd: &str, name: &str) -> Result<(u32, u32), ()> {
    let entries: Vec<_> = passwd
        .lines()
        .filter(|line| line.split(':').next() == Some(name))
        .collect();
    let [entry] = entries.as_slice() else {
        return Err(());
    };
    let fields: Vec<_> = entry.split(':').collect();
    if fields.len() != 7 || fields[6] != "/usr/sbin/nologin" {
        return Err(());
    }
    Ok((
        fields[2].parse().map_err(|_| ())?,
        fields[3].parse().map_err(|_| ())?,
    ))
}
async fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [timeout_flag, timeout, poll_flag, poll] = args.as_slice() else {
        return Err(());
    };
    if timeout_flag != "--startup-timeout-secs" || poll_flag != "--poll-interval-ms" {
        return Err(());
    }
    let timeout = timeout.parse::<u64>().ok().filter(|v| *v > 0).ok_or(())?;
    let poll = poll.parse::<u64>().ok().filter(|v| *v > 0).ok_or(())?;
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|_| ())?;
    let (node, _) = identity(&passwd, "zrpc-node")?;
    let (wrapper, group) = identity(&passwd, "zrpc-wrapper")?;
    let wait = async {
        loop {
            if zrpc_server::node::stage_gcp_cookie(node, wrapper, group).is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(poll)).await;
        }
    };
    // Timing inputs belong to the measured startup configuration, with no
    // guessed production default or unbounded wait after failed node startup.
    tokio::time::timeout(std::time::Duration::from_secs(timeout), wait)
        .await
        .map_err(|_| ())
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("memory-only node cookie unavailable");
        std::process::exit(1);
    }
}
