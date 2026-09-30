//! Quote-only Unix bridge. It grants no key, signing, exec, update or TCP API.
//! The client must still verify every returned quote and its TLS exporter.

use crate::attestation::request_dstack_quote;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, Version, body::Incoming, header};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{
    convert::Infallible,
    fs::{self, DirBuilder, Permissions},
    future::Future,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    task::JoinSet,
};
use zrpc_protocol::{
    ErrorCode, MAX_ATTESTATION_REQUEST_BYTES, MAX_ATTESTATION_RESPONSE_BYTES,
    MAX_CONNECTION_LIFETIME_SECONDS, SafeError,
};

/// The only quote socket accepted by the production node-backed listener.
pub const QUOTE_SOCKET_PATH: &str = "/run/zrpc-quote/quote.sock";
/// A second Unix socket carries only a one-byte liveness acknowledgement.
/// Its held connection closes if either the bridge or wrapper exits.
pub const QUOTE_WATCH_SOCKET_PATH: &str = "/run/zrpc-quote/watch.sock";
/// Stock Phala's host `/run/dstack.sock` is bind-mounted only into the quote
/// container at this path, outside the runtime tmpfs shared with the app.
pub const STOCK_DSTACK_SOCKET_PATH: &str = "/dstack.sock";

#[derive(Clone, Copy)]
enum BackendAccess {
    Private,
    StockPreview,
}

fn backend_permissions_ok(path: &Path, mode: u32, uid: u32, access: BackendAccess) -> bool {
    match access {
        BackendAccess::Private => mode & 0o077 == 0,
        BackendAccess::StockPreview => path == Path::new(STOCK_DSTACK_SOCKET_PATH) && uid == 0,
    }
}

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "Quote bridge is unavailable.",
    )
}

/// Accepts an already-bound Unix listener. The image launcher owns its path,
/// mode and group; no backend socket or listener is ever exposed over TCP.
pub struct QuoteOnlyBridge {
    listener: UnixListener,
    watch_listener: Option<UnixListener>,
    backend: Arc<PathBuf>,
}

impl QuoteOnlyBridge {
    /// Publish a group-accessible quote socket only after every preparation
    /// step succeeds. A fresh owner-only directory hides bind/chmod races and
    /// its continued existence denies a same-boot restart after any failure.
    pub fn bind_private(directory: &Path, backend: &Path) -> Result<Self, SafeError> {
        Self::bind_with_access(directory, backend, BackendAccess::Private)
    }

    /// Stock Phala's root-owned dstack socket is world-accessible inside the
    /// quote container. This explicit preview path cannot be used to approve
    /// private operation; deployment must isolate that mount from the app.
    pub fn bind_stock_preview(directory: &Path) -> Result<Self, SafeError> {
        Self::bind_with_access(
            directory,
            Path::new(STOCK_DSTACK_SOCKET_PATH),
            BackendAccess::StockPreview,
        )
    }

    fn bind_with_access(
        directory: &Path,
        backend: &Path,
        access: BackendAccess,
    ) -> Result<Self, SafeError> {
        if !directory.is_absolute()
            || directory
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(unavailable());
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(directory).map_err(|_| unavailable())?;
        let socket_path = directory.join("quote.sock");
        let listener = UnixListener::bind(&socket_path).map_err(|_| unavailable())?;
        let watch_path = directory.join("watch.sock");
        let watch_listener = UnixListener::bind(&watch_path).map_err(|_| unavailable())?;
        fs::set_permissions(&socket_path, Permissions::from_mode(0o660))
            .map_err(|_| unavailable())?;
        fs::set_permissions(&watch_path, Permissions::from_mode(0o660))
            .map_err(|_| unavailable())?;
        let mut bridge = Self::new_with_access(listener, backend, access)?;
        bridge.watch_listener = Some(watch_listener);
        fs::set_permissions(directory, Permissions::from_mode(0o750)).map_err(|_| unavailable())?;
        Ok(bridge)
    }

    pub fn new(listener: UnixListener, backend: &Path) -> Result<Self, SafeError> {
        Self::new_with_access(listener, backend, BackendAccess::Private)
    }

    fn new_with_access(
        listener: UnixListener,
        backend: &Path,
        access: BackendAccess,
    ) -> Result<Self, SafeError> {
        let listener_address = listener.local_addr().map_err(|_| unavailable())?;
        let listener_path = listener_address.as_pathname().ok_or_else(unavailable)?;
        let listener_metadata =
            std::fs::symlink_metadata(listener_path).map_err(|_| unavailable())?;
        let backend_metadata = std::fs::symlink_metadata(backend).map_err(|_| unavailable())?;
        if !listener_path.is_absolute()
            || !listener_metadata.file_type().is_socket()
            || listener_metadata.mode() & 0o007 != 0
            || !backend.is_absolute()
            || backend
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || !backend_metadata.file_type().is_socket()
            || !backend_permissions_ok(
                backend,
                backend_metadata.mode(),
                backend_metadata.uid(),
                access,
            )
            || listener_path == backend
        {
            return Err(unavailable());
        }
        Ok(Self {
            listener,
            watch_listener: None,
            backend: Arc::new(backend.to_owned()),
        })
    }

    /// An accepted connection gets the existing five-minute lifetime and one
    /// quote request. Shutdown aborts all owned connections and backend calls.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), SafeError> {
        let Self {
            listener,
            watch_listener,
            backend,
        } = self;
        let mut tasks = JoinSet::new();
        let watch = async move {
            let Some(listener) = watch_listener else {
                return std::future::pending::<Result<(), SafeError>>().await;
            };
            // Only the first accepted wrapper gets the acknowledgement. Any
            // second contender cannot authorize a listener without that byte.
            let (mut socket, _) = listener.accept().await.map_err(|_| unavailable())?;
            socket.write_all(b"W").await.map_err(|_| unavailable())?;
            let mut byte = [0u8; 1];
            let _ = socket.read(&mut byte).await;
            Err(unavailable())
        };
        tokio::pin!(watch);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    tasks.shutdown().await;
                    return Ok(());
                }
                _ = &mut watch => {
                    tasks.shutdown().await;
                    return Err(unavailable());
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
                accepted = listener.accept() => {
                    let (socket, _) = accepted.map_err(|_| unavailable())?;
                    let backend = backend.clone();
                    tasks.spawn(async move {
                        let used = Arc::new(AtomicBool::new(false));
                        let service = hyper::service::service_fn(move |request| {
                            let backend = backend.clone();
                            let used = used.clone();
                            async move {
                                Ok::<_, Infallible>(handle(request, &backend, &used).await)
                            }
                        });
                        let connection = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(socket), service);
                        let _ = tokio::time::timeout(
                            Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS), connection
                        ).await;
                    });
                }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest {
    report_data: String,
}

fn reply(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn failure(status: StatusCode) -> Response<Full<Bytes>> {
    reply(
        status,
        Bytes::from_static(br#"{"error":"quote_unavailable"}"#),
    )
}

async fn handle(
    request: Request<Incoming>,
    backend: &Path,
    used: &AtomicBool,
) -> Response<Full<Bytes>> {
    if request.method() != hyper::Method::POST
        || request.version() != Version::HTTP_11
        || request.uri().authority().is_some()
        || request.uri().path_and_query().map(|part| part.as_str()) != Some("/GetQuote")
    {
        return failure(StatusCode::NOT_FOUND);
    }
    if used.swap(true, Ordering::SeqCst) {
        return failure(StatusCode::CONFLICT);
    }
    if request.headers().contains_key(header::CONTENT_ENCODING)
        || request.headers().get_all(header::HOST).iter().count() != 1
        || request
            .headers()
            .get(header::HOST)
            .is_none_or(|host| host != "dstack")
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|content_type| content_type != "application/json")
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let body = match Limited::new(request.into_body(), MAX_ATTESTATION_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return failure(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let QuoteRequest { report_data } = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    let mut report_data_bytes = [0u8; 64];
    if hex::decode_to_slice(&report_data, &mut report_data_bytes).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let evidence = match request_dstack_quote(backend, report_data_bytes).await {
        Ok(evidence) => evidence,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut output = BoundedOutput(Vec::new());
    if serde_json::to_writer(&mut output, &evidence).is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    reply(StatusCode::OK, Bytes::from(output.0))
}

struct BoundedOutput(Vec<u8>);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_ATTESTATION_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("quote response bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
