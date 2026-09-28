//! A private session owns the local Tor child that owns its SOCKS socket.
//!
//! Launching a locally installed executable is an operator/host trust decision,
//! not cryptographic proof of Tor's source or network path. Diagnostic TCP SOCKS
//! connections deliberately cannot construct this capability.

use crate::{
    IsolationLabel, ProxySocket, RemoteEndpoint, TransportOrigin, UnverifiedChannel,
    negotiate_socks,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UnixStream;
use zrpc_protocol::{ErrorCode, SafeError};

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::TorUnavailable,
        "The managed local Tor process or its private SOCKS socket is unavailable.",
    )
}

#[derive(Clone)]
pub struct ManagedTor(Arc<ManagedTorState>);

struct ManagedTorState {
    child: Mutex<Child>,
    root: PathBuf,
    socket: PathBuf,
    root_identity: (u64, u64),
    socket_identity: Mutex<Option<(u64, u64)>>,
}

impl std::fmt::Debug for ManagedTor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagedTor([local process and socket redacted])")
    }
}

impl ManagedTor {
    /// Spawn one foreground process from an explicitly selected local Tor
    /// installation. The client calls this only after a reviewed release is
    /// selected; no endpoint or query material enters argv or torrc.
    pub fn launch(executable: &Path) -> Result<Self, SafeError> {
        if !executable.is_absolute() {
            return Err(unavailable());
        }
        let executable = fs::canonicalize(executable).map_err(|_| unavailable())?;
        if !fs::metadata(&executable)
            .map_err(|_| unavailable())?
            .is_file()
        {
            return Err(unavailable());
        }

        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| unavailable())?;
        // Keep this below Unix-domain socket path limits on both Linux and
        // macOS. An exclusive 0700 directory makes other users unable to
        // inspect or replace the socket; same-UID code remains trusted.
        // Resolve macOS's /tmp -> /private/tmp alias before recording the
        // directory identity and passing paths to Tor. This also removes an
        // alias from the Unix socket path without following our new root.
        let temp_root = fs::canonicalize("/tmp").map_err(|_| unavailable())?;
        let root = temp_root.join(format!("zrpc-tor-{}", hex::encode(random)));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|_| unavailable())?;
        let root_identity = identity(&root).ok_or_else(unavailable)?;
        let mut cleanup = RootOnFailure {
            root: root.clone(),
            identity: root_identity,
            active: true,
        };
        if fs::symlink_metadata(&root)
            .map_err(|_| unavailable())?
            .mode()
            & 0o777
            != 0o700
        {
            return Err(unavailable());
        }
        let socket = root.join("s");
        let data = root.join("data");
        let torrc = root.join("torrc");
        let defaults = root.join("defaults-torrc");
        // The selected fixed base and random hex component have no torrc
        // metacharacters. Never interpolate operator input into this file.
        let socket_path = safe_torrc_path(&socket)?;
        let data_path = safe_torrc_path(&data)?;
        let mut config = private_file(&torrc).map_err(|_| unavailable())?;
        write!(
            config,
            "DataDirectory {data_path}\nSocksPort unix:{socket_path} IsolateSOCKSAuth\nControlPort 0\nDNSPort 0\nTransPort 0\nHTTPTunnelPort 0\nClientOnly 1\nRunAsDaemon 0\nNoExec 1\nSafeLogging 1\nLog err stdout\n"
        )
        .map_err(|_| unavailable())?;
        config.sync_all().map_err(|_| unavailable())?;
        private_file(&defaults)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())?;

        let child = Command::new(executable)
            .arg("--defaults-torrc")
            .arg(&defaults)
            .arg("-f")
            .arg(&torrc)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| unavailable())?;
        cleanup.active = false;
        Ok(Self(Arc::new(ManagedTorState {
            child: Mutex::new(child),
            root,
            socket,
            root_identity,
            socket_identity: Mutex::new(None),
        })))
    }

    pub(crate) fn ensure_live(&self) -> Result<(), SafeError> {
        self.0.ensure_live()
    }

    /// Local test lease only. `/bin/sleep` is not Tor and never establishes
    /// private-mode acceptance; this constructor is absent from release builds.
    #[cfg(test)]
    pub(crate) fn synthetic_live() -> io::Result<(Self, tokio::net::UnixListener)> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("OS randomness unavailable"))?;
        let root = fs::canonicalize("/tmp")?.join(format!("zrpc-tor-test-{}", hex::encode(random)));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let root_identity = identity(&root).ok_or_else(|| io::Error::other("missing test root"))?;
        let mut cleanup = RootOnFailure {
            root: root.clone(),
            identity: root_identity,
            active: true,
        };
        let socket = root.join("s");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        let metadata = fs::symlink_metadata(&socket)?;
        let socket_identity = Some((metadata.dev(), metadata.ino()));
        let child = Command::new("/bin/sleep")
            .arg(zrpc_protocol::MAX_CONNECTION_LIFETIME_SECONDS.to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        cleanup.active = false;
        Ok((
            Self(Arc::new(ManagedTorState {
                child: Mutex::new(child),
                root,
                socket,
                root_identity,
                socket_identity: Mutex::new(socket_identity),
            })),
            listener,
        ))
    }

    #[cfg(test)]
    pub(crate) fn terminate_synthetic_child(&self) {
        let mut child = self.0.child.lock().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(test)]
    pub(crate) fn synthetic_socket_path(&self) -> &Path {
        &self.0.socket
    }

    /// Wait for this child's private Unix listener, then use the same
    /// maintained SOCKS negotiation as public diagnostics. The surrounding
    /// five-minute connection deadline bounds readiness and the exchange.
    pub async fn connect_bootstrap(
        &self,
        endpoint: &RemoteEndpoint,
        isolation: IsolationLabel,
    ) -> Result<UnverifiedChannel, SafeError> {
        loop {
            self.0.ensure_child_and_root()?;
            match self.0.ensure_socket_identity() {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(_) => return Err(unavailable()),
            }
        }
        let socket = UnixStream::connect(&self.0.socket)
            .await
            .map_err(|_| unavailable())?;
        self.ensure_live()?;
        negotiate_socks(
            ProxySocket::Unix(socket),
            endpoint,
            isolation,
            TransportOrigin::Managed(self.clone()),
        )
        .await
    }
}

impl ManagedTorState {
    fn ensure_child_and_root(&self) -> Result<(), SafeError> {
        if self
            .child
            .lock()
            .map_err(|_| unavailable())?
            .try_wait()
            .map_err(|_| unavailable())?
            .is_some()
            || identity(&self.root) != Some(self.root_identity)
            || fs::symlink_metadata(&self.root)
                .map_err(|_| unavailable())?
                .mode()
                & 0o777
                != 0o700
        {
            return Err(unavailable());
        }
        Ok(())
    }

    fn ensure_socket_identity(&self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.socket)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a socket"));
        }
        let observed = (metadata.dev(), metadata.ino());
        let mut expected = self
            .socket_identity
            .lock()
            .map_err(|_| io::Error::other("socket state unavailable"))?;
        match *expected {
            Some(pinned) if pinned != observed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socket replaced",
            )),
            Some(_) => Ok(()),
            None => {
                *expected = Some(observed);
                Ok(())
            }
        }
    }

    fn ensure_live(&self) -> Result<(), SafeError> {
        self.ensure_child_and_root()?;
        self.ensure_socket_identity().map_err(|_| unavailable())
    }
}

impl Drop for ManagedTorState {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Only delete the exact directory created by this process. A changed
        // path is left untouched rather than recursively deleting a substitute.
        if identity(&self.root) == Some(self.root_identity) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct RootOnFailure {
    root: PathBuf,
    identity: (u64, u64),
    active: bool,
}

impl Drop for RootOnFailure {
    fn drop(&mut self) {
        if self.active && identity(&self.root) == Some(self.identity) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    let metadata = fs::symlink_metadata(path).ok()?;
    metadata
        .file_type()
        .is_dir()
        .then_some((metadata.dev(), metadata.ino()))
}

fn safe_torrc_path(path: &Path) -> Result<&str, SafeError> {
    let text = path.to_str().ok_or_else(unavailable)?;
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
    {
        return Err(unavailable());
    }
    Ok(text)
}

fn private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(test)]
mod real_tor_smoke {
    use super::*;
    use std::{io::ErrorKind, net::TcpListener};

    /// Opt-in integration check using an independently authenticated Tor
    /// executable. A loopback destination would be reachable by a direct
    /// fallback, but Tor must reject it without touching the local listener.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires an authenticated local Tor executable"]
    async fn managed_child_rejects_loopback_destination_without_direct_fallback() {
        let executable = std::env::var_os("ZRPC_REAL_TOR_EXECUTABLE")
            .expect("set ZRPC_REAL_TOR_EXECUTABLE to the authenticated Tor binary");
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint =
            RemoteEndpoint::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
        let tor = ManagedTor::launch(Path::new(&executable)).unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(zrpc_protocol::MAX_CONNECTION_LIFETIME_SECONDS),
            tor.connect_bootstrap(&endpoint, IsolationLabel::new("real-tor-smoke").unwrap()),
        )
        .await
        .expect("Tor SOCKS negotiation did not finish within the connection lifetime");
        assert_eq!(outcome.unwrap_err().code, ErrorCode::TorUnavailable);
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        tor.ensure_live().unwrap();
    }
}
