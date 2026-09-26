//! Google TDX quote broker. The only external input is one 64-byte REPORTDATA.
//! ConfigFS is the kernel ABI, not a verifier. Client approval is independent.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use zrpc_protocol::{
    ErrorCode, MAX_ATTESTATION_RESPONSE_BYTES, MAX_CONNECTION_LIFETIME_SECONDS, SafeError,
};

pub const GCP_QUOTE_DIRECTORY: &str = "/run/zrpc-gcp-quote";
pub const GCP_QUOTE_SOCKET: &str = "/run/zrpc-gcp-quote/quote.sock";
pub const GCP_WATCH_SOCKET: &str = "/run/zrpc-gcp-quote/watch.sock";
const REPORT: &str = "/sys/kernel/config/tsm/report/zrpc";
const CCEL: &str = "/sys/firmware/acpi/tables/data/CCEL";

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "TDX quote broker is unavailable.",
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GcpQuoteEvidence {
    pub quote: String,
    pub ccel: String,
}

fn read_bound(path: &Path, maximum: usize) -> Result<Vec<u8>, SafeError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| unavailable())?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > maximum {
        return Err(unavailable());
    }
    Ok(bytes)
}

fn generation(report: &Path) -> Result<u64, SafeError> {
    let bytes = read_bound(&report.join("generation"), MAX_ATTESTATION_RESPONSE_BYTES)?;
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.trim_end_matches('\n').parse().ok())
        .ok_or_else(unavailable)
}

/// One private, never-reused report directory. An existing path denies startup.
struct TsmReport {
    path: PathBuf,
    ccel: String,
}
impl TsmReport {
    fn open() -> Result<Self, SafeError> {
        let root = File::open("/sys/kernel/config/tsm/report").map_err(|_| unavailable())?;
        if rustix::fs::fstatfs(&root)
            .map_err(|_| unavailable())?
            .f_type as u64
            // Linux fs/configfs/mount.c CONFIGFS_MAGIC, not exported by libc.
            != 0x6265_6570
        {
            return Err(unavailable());
        }
        let ccel = read_bound(Path::new(CCEL), MAX_ATTESTATION_RESPONSE_BYTES / 2)?;
        if ccel.is_empty() {
            return Err(unavailable());
        }
        let path = PathBuf::from(REPORT);
        fs::create_dir(&path).map_err(|_| unavailable())?;
        if read_bound(&path.join("provider"), MAX_ATTESTATION_RESPONSE_BYTES)? != b"tdx_guest\n" {
            return Err(unavailable());
        }
        Ok(Self {
            path,
            ccel: hex::encode(ccel),
        })
    }
    fn quote(&self, input: [u8; 64]) -> Result<GcpQuoteEvidence, SafeError> {
        let before = generation(&self.path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.join("inblob"))
            .map_err(|_| unavailable())?;
        // A single write must provide the complete kernel attribute value.
        if file.write(&input).map_err(|_| unavailable())? != input.len() {
            return Err(unavailable());
        }
        let quote = read_bound(
            &self.path.join("outblob"),
            MAX_ATTESTATION_RESPONSE_BYTES / 2,
        )?;
        if quote.is_empty() || before.checked_add(1) != Some(generation(&self.path)?) {
            return Err(unavailable());
        }
        Ok(GcpQuoteEvidence {
            quote: hex::encode(quote),
            ccel: self.ccel.clone(),
        })
    }
}

fn wrapper_uid(passwd: &str) -> Result<u32, SafeError> {
    let matches: Vec<_> = passwd
        .lines()
        .filter(|line| line.split(':').next() == Some("zrpc-wrapper"))
        .collect();
    let [entry] = matches.as_slice() else {
        return Err(unavailable());
    };
    let fields: Vec<_> = entry.split(':').collect();
    if fields.len() != 7 || fields[6] != "/usr/sbin/nologin" {
        return Err(unavailable());
    }
    fields[2]
        .parse::<u32>()
        .ok()
        .filter(|uid| *uid != 0)
        .ok_or_else(unavailable)
}

fn allowed_peer(socket: &UnixStream, uid: u32) -> bool {
    socket.peer_cred().is_ok_and(|peer| peer.uid() == uid)
}

pub struct GcpQuoteBroker {
    listener: UnixListener,
    watch: UnixListener,
    report: TsmReport,
    wrapper_uid: u32,
}
impl GcpQuoteBroker {
    pub fn bind() -> Result<Self, SafeError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(unavailable());
        }
        let uid = wrapper_uid(
            std::str::from_utf8(&read_bound(
                Path::new("/etc/passwd"),
                MAX_ATTESTATION_RESPONSE_BYTES,
            )?)
            .map_err(|_| unavailable())?,
        )?;
        let report = TsmReport::open()?;
        let directory = Path::new(GCP_QUOTE_DIRECTORY);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|_| unavailable())?;
        let listener = UnixListener::bind(GCP_QUOTE_SOCKET).map_err(|_| unavailable())?;
        let watch = UnixListener::bind(GCP_WATCH_SOCKET).map_err(|_| unavailable())?;
        for path in [GCP_QUOTE_SOCKET, GCP_WATCH_SOCKET] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o660))
                .map_err(|_| unavailable())?;
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))
            .map_err(|_| unavailable())?;
        Ok(Self {
            listener,
            watch,
            report,
            wrapper_uid: uid,
        })
    }

    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), SafeError> {
        let Self {
            listener,
            watch,
            report,
            wrapper_uid,
        } = self;
        let watch = async move {
            let (mut socket, _) = watch.accept().await.map_err(|_| unavailable())?;
            if !allowed_peer(&socket, wrapper_uid) {
                return Err(unavailable());
            }
            socket.write_all(b"W").await.map_err(|_| unavailable())?;
            let mut byte = [0];
            let _ = socket.read(&mut byte).await;
            Err::<(), _>(unavailable())
        };
        let report = std::sync::Arc::new(report);
        let work = async move {
            loop {
                let (mut socket, _) = listener.accept().await.map_err(|_| unavailable())?;
                if !allowed_peer(&socket, wrapper_uid) {
                    continue;
                }
                let operation = async {
                    let mut input = [0; 64];
                    if socket.read_exact(&mut input).await.is_err() {
                        return Ok::<_, SafeError>(());
                    }
                    let mut extra = [0];
                    if socket.read(&mut extra).await.map_err(|_| unavailable())? != 0 {
                        return Err(unavailable());
                    }
                    // The kernel read may block; don't stall liveness/shutdown
                    // observation. A cancelled blocking operation is terminated
                    // with this service process by systemd's control-group kill.
                    let report = report.clone();
                    let evidence = tokio::task::spawn_blocking(move || report.quote(input))
                        .await
                        .map_err(|_| unavailable())??;
                    let encoded = serde_json::to_vec(&evidence).map_err(|_| unavailable())?;
                    if encoded.len() > MAX_ATTESTATION_RESPONSE_BYTES {
                        return Err(unavailable());
                    }
                    socket
                        .write_u32(u32::try_from(encoded.len()).map_err(|_| unavailable())?)
                        .await
                        .map_err(|_| unavailable())?;
                    socket
                        .write_all(&encoded)
                        .await
                        .map_err(|_| unavailable())?;
                    Ok(())
                };
                // Serialization provides the broker's concurrency bound. The
                // wrapper retains its separately reviewed quote-rate policy.
                let result = tokio::time::timeout(
                    Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS),
                    operation,
                )
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    return Err(unavailable());
                }
            }
        };
        tokio::pin!(shutdown, watch, work);
        tokio::select! { biased; _ = &mut shutdown => Ok(()), result = &mut watch => result, result = &mut work => result }
    }
}

pub(crate) async fn request_gcp_quote(
    path: &Path,
    report_data: [u8; 64],
) -> Result<GcpQuoteEvidence, SafeError> {
    let mut socket = UnixStream::connect(path).await.map_err(|_| unavailable())?;
    socket
        .write_all(&report_data)
        .await
        .map_err(|_| unavailable())?;
    socket.shutdown().await.map_err(|_| unavailable())?;
    let length = socket.read_u32().await.map_err(|_| unavailable())? as usize;
    if length == 0 || length > MAX_ATTESTATION_RESPONSE_BYTES {
        return Err(unavailable());
    }
    let mut bytes = vec![0; length];
    socket
        .read_exact(&mut bytes)
        .await
        .map_err(|_| unavailable())?;
    let mut extra = [0];
    if socket.read(&mut extra).await.map_err(|_| unavailable())? != 0 {
        return Err(unavailable());
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_identity_requires_unique_nonroot_locked_account() {
        assert_eq!(
            wrapper_uid("zrpc-wrapper:x:612:612::/:/usr/sbin/nologin\n").unwrap(),
            612
        );
        for input in [
            "",
            "zrpc-wrapper:x:0:612::/:/usr/sbin/nologin",
            "zrpc-wrapper:x:612:612::/:/bin/sh",
            "zrpc-wrapper:x:612:612::/:/usr/sbin/nologin\nzrpc-wrapper:x:613:613::/:/usr/sbin/nologin",
        ] {
            assert!(wrapper_uid(input).is_err());
        }
    }
    #[test]
    fn raw_fixture_is_not_accepted_as_configfs() {
        // No injected filesystem or alternate quote path exists in production.
        if !Path::new(REPORT).exists() {
            assert!(TsmReport::open().is_err());
        }
    }

    #[tokio::test]
    async fn peer_uid_is_checked_from_kernel_credentials() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        assert!(allowed_peer(&socket, uid));
        assert!(!allowed_peer(&socket, uid.wrapping_add(1)));
    }

    #[tokio::test]
    async fn broker_response_framing_is_bounded_and_strict() {
        for case in [
            "valid",
            "oversize",
            "truncated",
            "unknown",
            "duplicate",
            "trailing",
        ] {
            let path = std::env::temp_dir()
                .join(format!("zrpc-gcp-frame-{}-{case}.sock", std::process::id()));
            let listener = UnixListener::bind(&path).unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut input = [0; 64];
                socket.read_exact(&mut input).await.unwrap();
                assert_eq!(input, [42; 64]);
                let mut extra = [0];
                assert_eq!(socket.read(&mut extra).await.unwrap(), 0);
                let body: &[u8] = match case {
                    "unknown" => br#"{"quote":"00","ccel":"00","verified":true}"#,
                    "duplicate" => br#"{"quote":"00","ccel":"00","quote":"00"}"#,
                    _ => br#"{"quote":"00","ccel":"00"}"#,
                };
                let length = if case == "oversize" {
                    MAX_ATTESTATION_RESPONSE_BYTES + 1
                } else if case == "truncated" {
                    body.len() + 1
                } else {
                    body.len()
                };
                socket.write_u32(length as u32).await.unwrap();
                if case != "oversize" {
                    socket.write_all(body).await.unwrap();
                }
                if case == "trailing" {
                    socket.write_all(b"X").await.unwrap();
                }
            });
            assert_eq!(
                request_gcp_quote(&path, [42; 64]).await.is_ok(),
                case == "valid",
                "{case}"
            );
            server.await.unwrap();
            fs::remove_file(path).unwrap();
        }
    }
}
