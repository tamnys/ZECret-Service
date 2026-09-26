//! Measured-guest-only quote bridge. The guest image must install the fixed
//! systemd unit/group and keep the dstack agent socket root-only.

use std::path::Path;
use zrpc_server::quote_proxy::{QUOTE_SOCKET_PATH, QuoteOnlyBridge};

const DSTACK_SOCKET: &str = "/run/dstack.sock";

fn bind_ready_bridge(quote_dir: &Path, backend: &Path) -> Result<QuoteOnlyBridge, &'static str> {
    // sd-notify 0.4.5 treats an absent variable as success and supports only
    // pathname sockets. The measured guest must supply a compatible absolute
    // NOTIFY_SOCKET; abstract addresses fail closed in this source candidate.
    let notify_socket =
        std::env::var_os("NOTIFY_SOCKET").ok_or("systemd notification socket unavailable")?;
    if !Path::new(&notify_socket).is_absolute() {
        return Err("systemd notification socket must be an absolute pathname");
    }
    let bridge = QuoteOnlyBridge::bind_private(quote_dir, backend)
        .map_err(|_| "private quote socket unavailable")?;
    // This process owns both published listeners before reporting readiness.
    // Do not unset process-wide environment after Tokio has started threads.
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready])
        .map_err(|_| "systemd readiness notification failed")?;
    Ok(bridge)
}

async fn run() -> Result<(), &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("quote bridge takes no runtime options");
    }
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "shutdown signal unavailable")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "shutdown signal unavailable")?;

    // The measured service runs root:zrpc-wrapper. The library publishes only
    // after the root-only backend and socket permissions have been validated.
    let quote_dir = Path::new(QUOTE_SOCKET_PATH)
        .parent()
        .ok_or("quote bridge path unavailable")?;
    let bridge = bind_ready_bridge(quote_dir, Path::new(DSTACK_SOCKET))?;
    bridge
        .run(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
        .await
        .map_err(|_| "quote bridge stopped unexpectedly")
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::ErrorKind,
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixDatagram, UnixListener},
        },
        path::PathBuf,
        process::Command,
    };

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(case: &str) -> Self {
            // These tiny Unix socket fixtures require local socket chmod,
            // which the managed workspace volume does not provide.
            let path =
                std::env::temp_dir().join(format!("zrpc-notify-{}-{case}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for name in [
                "bridge/quote.sock",
                "bridge/watch.sock",
                "backend.sock",
                "notify.sock",
            ] {
                let _ = fs::remove_file(self.0.join(name));
            }
            let _ = fs::remove_dir(self.0.join("bridge"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn readiness_requires_published_sockets_and_successful_notification() {
        for case in [
            "ready",
            "absent",
            "empty",
            "relative",
            "abstract",
            "unreachable",
            "bind-failure",
        ] {
            let fixture = Fixture::new(case);
            let receiver = UnixDatagram::bind(fixture.0.join("notify.sock")).unwrap();
            receiver.set_nonblocking(true).unwrap();
            let _backend = UnixListener::bind(fixture.0.join("backend.sock")).unwrap();
            fs::set_permissions(
                fixture.0.join("backend.sock"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", "tests::readiness_child", "--nocapture"])
                .env("ZRPC_TEST_READINESS_DIR", &fixture.0)
                .env("ZRPC_TEST_READINESS_CASE", case)
                .env_remove("NOTIFY_SOCKET");
            match case {
                "absent" => {}
                "empty" => {
                    child.env("NOTIFY_SOCKET", "");
                }
                "relative" => {
                    child.env("NOTIFY_SOCKET", "notify.sock");
                }
                "abstract" => {
                    child.env("NOTIFY_SOCKET", "@zrpc-notify");
                }
                "unreachable" => {
                    child.env("NOTIFY_SOCKET", fixture.0.join("missing.sock"));
                }
                _ => {
                    child.env("NOTIFY_SOCKET", fixture.0.join("notify.sock"));
                }
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{case}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let mut packet = [0; b"READY=1\n".len() + 1];
            if case == "ready" {
                let length = receiver.recv(&mut packet).unwrap();
                assert_eq!(&packet[..length], b"READY=1\n");
            }
            assert_eq!(
                receiver.recv(&mut packet).unwrap_err().kind(),
                ErrorKind::WouldBlock
            );
        }
    }

    // Run the production bind-and-notify path in a child so tests neither
    // mutate their shared environment nor require unsafe environment writes.
    #[test]
    fn readiness_child() {
        let Some(root) = std::env::var_os("ZRPC_TEST_READINESS_DIR") else {
            return;
        };
        let root = PathBuf::from(root);
        let case = std::env::var("ZRPC_TEST_READINESS_CASE").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _entered = runtime.enter();
        let backend = root.join(if case == "bind-failure" {
            "missing.sock"
        } else {
            "backend.sock"
        });
        let bridge = bind_ready_bridge(&root.join("bridge"), &backend);
        if case == "ready" {
            let _bridge = bridge.expect("published bridge must notify");
            for name in ["quote.sock", "watch.sock"] {
                let metadata = fs::symlink_metadata(root.join("bridge").join(name)).unwrap();
                assert!(metadata.file_type().is_socket());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
            }
            assert_eq!(
                fs::metadata(root.join("bridge"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
        } else {
            assert!(bridge.is_err(), "startup must fail closed");
        }
    }
}
