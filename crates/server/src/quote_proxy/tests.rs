//! Unix-only quote bridge tests; all backend quote material is synthetic.
use super::*;
use dstack_sdk_types::dstack::GetQuoteResponse;
use hyper::{Request as HttpRequest, body::Incoming};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::atomic::{AtomicU64, AtomicUsize},
};
use tokio::{net::UnixStream, sync::oneshot};

struct SocketPaths {
    backend: PathBuf,
    proxy: PathBuf,
}

#[test]
fn stock_preview_socket_exception_is_exact_and_private_path_stays_strict() {
    assert_eq!(STOCK_DSTACK_SOCKET_PATH, "/dstack.sock");
    let stock = Path::new(STOCK_DSTACK_SOCKET_PATH);
    assert!(backend_permissions_ok(
        stock,
        0o777,
        0,
        BackendAccess::StockPreview
    ));
    assert!(!backend_permissions_ok(
        stock,
        0o777,
        0,
        BackendAccess::Private
    ));
    assert!(!backend_permissions_ok(
        stock,
        0o777,
        10002,
        BackendAccess::StockPreview
    ));
    assert!(!backend_permissions_ok(
        Path::new("/run/other.sock"),
        0o777,
        0,
        BackendAccess::StockPreview
    ));
    assert!(backend_permissions_ok(
        stock,
        0o600,
        0,
        BackendAccess::Private
    ));
}

impl SocketPaths {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // The managed workspace volume supports Unix sockets but not chmod on
        // them; these tiny ephemeral socket fixtures need a local tmpfs.
        let root = std::env::temp_dir();
        let stem = format!(
            "quote-bridge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        Self {
            backend: root.join(format!("{stem}-backend.sock")),
            proxy: root.join(format!("{stem}-proxy.sock")),
        }
    }
}

impl Drop for SocketPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.backend);
        let _ = std::fs::remove_file(&self.proxy);
    }
}

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

async fn client(path: &Path) -> (Sender, tokio::task::JoinHandle<()>) {
    let socket = UnixStream::connect(path).await.unwrap();
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

fn request(method: hyper::Method, path: &str, body: Vec<u8>) -> HttpRequest<Full<Bytes>> {
    HttpRequest::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "dstack")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn send(path: &Path, request: HttpRequest<Full<Bytes>>) -> StatusCode {
    let (mut sender, driver) = client(path).await;
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    response.into_body().collect().await.unwrap();
    drop(sender);
    driver.abort();
    status
}

#[tokio::test]
async fn only_one_valid_quote_request_reaches_the_root_only_backend() {
    let paths = SocketPaths::new();
    let backend = UnixListener::bind(&paths.backend).unwrap();
    std::fs::set_permissions(&paths.backend, std::fs::Permissions::from_mode(0o600)).unwrap();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let calls = backend_calls.clone();
    let backend_task = tokio::spawn(async move {
        let (socket, _) = backend.accept().await.unwrap();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.method(), hyper::Method::POST);
                assert_eq!(request.uri(), "/GetQuote");
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let report_data = body["report_data"].as_str().unwrap().to_owned();
                assert_eq!(hex::decode(&report_data).unwrap(), [31u8; 64]);
                let quote = GetQuoteResponse {
                    quote: "SYNTHETIC_NOT_A_TDX_QUOTE".into(),
                    event_log: "[]".into(),
                    report_data,
                    vm_config: "{}".into(),
                };
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                    serde_json::to_vec(&quote).unwrap(),
                ))))
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(socket), service)
            .await;
    });

    let listener = UnixListener::bind(&paths.proxy).unwrap();
    std::fs::set_permissions(&paths.proxy, std::fs::Permissions::from_mode(0o660)).unwrap();
    let bridge = QuoteOnlyBridge::new(listener, &paths.backend).unwrap();
    let (stop, shutdown) = oneshot::channel();
    let bridge_task = tokio::spawn(bridge.run(async {
        let _ = shutdown.await;
    }));
    let valid = serde_json::to_vec(&serde_json::json!({
        "report_data":hex::encode([31u8; 64])
    }))
    .unwrap();
    for (method, route, body, expected) in [
        (
            hyper::Method::POST,
            "/GetKey",
            valid.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            hyper::Method::POST,
            "/Sign",
            valid.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            hyper::Method::POST,
            "/rpc",
            valid.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            hyper::Method::POST,
            "/GetQuote?x=1",
            valid.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            hyper::Method::GET,
            "/GetQuote",
            valid.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            hyper::Method::POST,
            "/GetQuote",
            br#"{"report_data":"00","key_path":"private"}"#.to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            hyper::Method::POST,
            "/GetQuote",
            br#"{"report_data":"00"}"#.to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            hyper::Method::POST,
            "/GetQuote",
            br#"{"report_data":"00","report_data":"11"}"#.to_vec(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            send(&paths.proxy, request(method, route, body)).await,
            expected
        );
    }
    assert_eq!(backend_calls.load(Ordering::SeqCst), 0);

    let (mut sender, driver) = client(&paths.proxy).await;
    let response = sender
        .send_request(request(hyper::Method::POST, "/GetQuote", valid.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["quote"], "SYNTHETIC_NOT_A_TDX_QUOTE");
    assert_eq!(value["report_data"], hex::encode([31u8; 64]));
    assert!(value.get("private_accepted").is_none());
    let repeated = sender
        .send_request(request(hyper::Method::POST, "/GetQuote", valid))
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::CONFLICT);
    repeated.into_body().collect().await.unwrap();
    assert_eq!(backend_calls.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    bridge_task.await.unwrap().unwrap();
    driver.abort();
    backend_task.await.unwrap();
}

#[tokio::test]
async fn bridge_rejects_relative_and_self_backend_paths() {
    let paths = SocketPaths::new();
    let proxy = UnixListener::bind(&paths.proxy).unwrap();
    std::fs::set_permissions(&paths.proxy, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(QuoteOnlyBridge::new(proxy, Path::new("relative.sock")).is_err());
    let proxy = UnixListener::bind(&paths.backend).unwrap();
    std::fs::set_permissions(&paths.backend, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(QuoteOnlyBridge::new(proxy, &paths.backend).is_err());
}

#[tokio::test]
async fn private_socket_publication_requires_backend_and_refuses_same_boot_retry() {
    let paths = SocketPaths::new();
    let _backend = UnixListener::bind(&paths.backend).unwrap();
    std::fs::set_permissions(&paths.backend, std::fs::Permissions::from_mode(0o600)).unwrap();
    let directory = paths.proxy.with_extension("private-dir");
    let bridge = QuoteOnlyBridge::bind_private(&directory, &paths.backend).unwrap();
    assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o750);
    assert_eq!(
        std::fs::metadata(directory.join("quote.sock"))
            .unwrap()
            .mode()
            & 0o777,
        0o660
    );
    assert_eq!(
        std::fs::metadata(directory.join("watch.sock"))
            .unwrap()
            .mode()
            & 0o777,
        0o660
    );
    assert!(QuoteOnlyBridge::bind_private(&directory, &paths.backend).is_err());
    drop(bridge);
    std::fs::remove_file(directory.join("quote.sock")).unwrap();
    std::fs::remove_file(directory.join("watch.sock")).unwrap();
    std::fs::remove_dir(&directory).unwrap();

    let failed_directory = paths.proxy.with_extension("failed-dir");
    assert!(QuoteOnlyBridge::bind_private(&failed_directory, Path::new("missing.sock")).is_err());
    assert_eq!(
        std::fs::metadata(&failed_directory).unwrap().mode() & 0o777,
        0o700
    );
    std::fs::remove_file(failed_directory.join("quote.sock")).unwrap();
    std::fs::remove_file(failed_directory.join("watch.sock")).unwrap();
    std::fs::remove_dir(failed_directory).unwrap();
}

#[tokio::test]
async fn lost_wrapper_watch_terminates_the_bridge_and_prevents_same_boot_retry() {
    use tokio::io::AsyncReadExt;
    let paths = SocketPaths::new();
    let _backend = UnixListener::bind(&paths.backend).unwrap();
    std::fs::set_permissions(&paths.backend, std::fs::Permissions::from_mode(0o600)).unwrap();
    let directory = paths.proxy.with_extension("watch-dir");
    let bridge = QuoteOnlyBridge::bind_private(&directory, &paths.backend).unwrap();
    let task = tokio::spawn(bridge.run(std::future::pending()));
    let mut watch = UnixStream::connect(directory.join("watch.sock"))
        .await
        .unwrap();
    let mut acknowledgement = [0u8; 1];
    watch.read_exact(&mut acknowledgement).await.unwrap();
    assert_eq!(acknowledgement, *b"W");
    drop(watch);
    assert!(task.await.unwrap().is_err());
    assert!(QuoteOnlyBridge::bind_private(&directory, &paths.backend).is_err());
    std::fs::remove_file(directory.join("quote.sock")).unwrap();
    std::fs::remove_file(directory.join("watch.sock")).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
