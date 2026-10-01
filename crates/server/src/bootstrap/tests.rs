//! Real local TLS/Unix-socket plumbing; all quote evidence is synthetic.
use super::*;
use crate::node::CookieAuth;
use bytes::Bytes;
use dstack_sdk_types::dstack::GetQuoteResponse;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, header};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, HandshakeKind,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{convert::Infallible, io, num::NonZeroUsize, path::PathBuf, sync::Mutex};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
    sync::oneshot,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use zrpc_protocol::{
    ATTESTATION_EXPORTER_LABEL, PublicAttestationRequest, parse_attestation_response,
};

#[tokio::test]
async fn node_startup_rejects_missing_stale_symlinked_and_public_quote_sockets() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "zrpc-private-quote-probe-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    assert!(probe_private_quote_socket(&path).await.is_err());
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(probe_private_quote_socket(&path).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(probe_private_quote_socket(&path).await.is_ok());
    let alias = path.with_extension("alias");
    symlink(&path, &alias).unwrap();
    assert!(probe_private_quote_socket(&alias).await.is_err());
    std::fs::remove_file(alias).unwrap();
    drop(listener);
    assert!(probe_private_quote_socket(&path).await.is_err());
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn node_startup_requires_private_live_watch_and_exact_acknowledgement() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "zrpc-watch-probe-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    assert!(connect_quote_watch(&path).await.is_err());
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(connect_quote_watch(&path).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let alias = path.with_extension("alias");
    symlink(&path, &alias).unwrap();
    assert!(connect_quote_watch(&alias).await.is_err());
    std::fs::remove_file(alias).unwrap();

    let incorrect = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        peer.write_all(b"X").await.unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        drop(peer);
        let (mut peer, _) = listener.accept().await.unwrap();
        peer.write_all(b"W").await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    });
    assert!(connect_quote_watch(&path).await.is_err());
    assert!(connect_quote_watch(&path).await.is_err());
    let watch = connect_quote_watch(&path).await.unwrap();
    drop(watch);
    incorrect.await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[derive(Debug)]
struct NoPki(Arc<CryptoProvider>);
impl ServerCertVerifier for NoPki {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        rustls::server::ParsedCertificate::try_from(cert)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS13 required by test".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoPki(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // Allow the test client to seek resumption/early data; server must forbid it.
    config.enable_early_data = true;
    Arc::new(config)
}

// These explicit values exercise boundaries, not production defaults.
fn limits(connections: usize) -> BootstrapLimits {
    BootstrapLimits::new(
        NonZeroUsize::new(connections).unwrap(),
        NonZeroUsize::new(1).unwrap(),
        Duration::from_nanos(1),
    )
    .unwrap()
}

struct Running {
    address: SocketAddr,
    service: AttestationService,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), SafeError>>>,
}
impl Running {
    async fn start(socket: &Path, connections: usize) -> Self {
        let listener =
            BoundPublicListener::bind("127.0.0.1:0".parse().unwrap(), socket, limits(connections))
                .await
                .unwrap();
        let address = listener.local_addr().unwrap();
        let service = listener.service.clone();
        assert!(!format!("{listener:?}").contains(&address.to_string()));
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(listener.run(async {
            let _ = shutdown.await;
        }));
        Self {
            address,
            service,
            stop: Some(stop),
            task: Some(task),
        }
    }
    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.task.take().unwrap().await.unwrap().unwrap();
    }
    async fn cancel(mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn connect(address: SocketAddr, config: Arc<ClientConfig>) -> TlsStream<TcpStream> {
    let socket = TcpStream::connect(address).await.unwrap();
    TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap()
}
async fn wait_admitted(service: &AttestationService) {
    loop {
        match service.admit_connection() {
            Ok(permit) => drop(permit),
            Err(_) => return,
        }
        tokio::task::yield_now().await;
    }
}
async fn wait_released(service: &AttestationService) {
    loop {
        if let Ok(permit) = service.admit_connection() {
            drop(permit);
            return;
        }
        tokio::task::yield_now().await;
    }
}
async fn assert_closed_without_application_bytes(stream: &mut (impl AsyncRead + Unpin)) {
    let mut bytes = Vec::new();
    let result = stream.read_to_end(&mut bytes).await;
    assert!(bytes.is_empty());
    assert!(
        result.is_ok()
            || result.as_ref().err().is_some_and(|error| matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ))
    );
}

#[test]
fn generated_config_has_no_resumption_early_data_or_key_logger() {
    let config = ephemeral_config().unwrap();
    assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
    assert_eq!(config.send_tls13_tickets, 0);
    assert!(!config.ticketer.enabled());
    assert!(!config.session_storage.can_cache());
    assert_eq!(config.max_early_data_size, 0);
    assert!(!config.send_half_rtt_data);
    assert!(!config.enable_secret_extraction);
    assert!(!config.key_log.will_log("CLIENT_RANDOM"));
    assert!(!config.key_log.will_log("SERVER_TRAFFIC_SECRET_0"));
}

#[tokio::test]
async fn fresh_listener_keys_and_full_signature_checked_tls_are_public_only() {
    let first = Running::start(Path::new("/SYNTHETIC_MISSING_DSTACK_SOCKET"), 2).await;
    let config = client_config();
    let mut tls = connect(first.address, config.clone()).await;
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    assert!(matches!(
        tls.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
    ));
    assert!(tls.get_mut().1.early_data().is_none());
    let certificate = &tls.get_ref().1.peer_certificates().unwrap()[0];
    let first_key = rustls::server::ParsedCertificate::try_from(certificate)
        .unwrap()
        .subject_public_key_info();
    let mut second_connection = connect(first.address, config.clone()).await;
    assert!(matches!(
        second_connection.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
    ));
    assert!(second_connection.get_mut().1.early_data().is_none());
    let second = Running::start(Path::new("/SYNTHETIC_MISSING_DSTACK_SOCKET"), 1).await;
    let other_tls = connect(second.address, config).await;
    let other_certificate = &other_tls.get_ref().1.peer_certificates().unwrap()[0];
    let other_key = rustls::server::ParsedCertificate::try_from(other_certificate)
        .unwrap()
        .subject_public_key_info();
    assert_ne!(first_key, other_key);
    first.stop().await;
    second.stop().await;
    assert_closed_without_application_bytes(&mut tls).await;
    assert_closed_without_application_bytes(&mut second_connection).await;
}

#[tokio::test]
async fn admission_precedes_handshake_and_excess_socket_has_no_tls_bytes() {
    let running = Running::start(Path::new("/SYNTHETIC_MISSING_DSTACK_SOCKET"), 1).await;
    let first = TcpStream::connect(running.address).await.unwrap();
    wait_admitted(&running.service).await;
    let mut excess = TcpStream::connect(running.address).await.unwrap();
    assert_closed_without_application_bytes(&mut excess).await;
    drop(first);
    wait_released(&running.service).await;
    let _tls = connect(running.address, client_config()).await;
    running.stop().await;
}

#[tokio::test]
async fn original_accepted_socket_deadline_includes_handshake_and_http() {
    let running = Running::start(Path::new("/SYNTHETIC_MISSING_DSTACK_SOCKET"), 1).await;
    let socket = TcpStream::connect(running.address).await.unwrap();
    wait_admitted(&running.service).await;
    // Split the design's existing lifetime into handshake and HTTP phases.
    let phase = Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS / 2);
    tokio::time::pause();
    tokio::time::advance(phase).await;
    tokio::time::resume();
    let mut tls = TlsConnector::from(client_config())
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(phase).await;
    assert_closed_without_application_bytes(&mut tls).await;
    tokio::time::resume();
    wait_released(&running.service).await;
    running.stop().await;
}

#[tokio::test]
async fn stalled_handshake_expires_and_other_alpn_is_rejected() {
    let running = Running::start(Path::new("/SYNTHETIC_MISSING_DSTACK_SOCKET"), 1).await;
    let mut socket = TcpStream::connect(running.address).await.unwrap();
    wait_admitted(&running.service).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS)).await;
    assert_closed_without_application_bytes(&mut socket).await;
    tokio::time::resume();
    wait_released(&running.service).await;
    let mut config = (*client_config()).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let socket = TcpStream::connect(running.address).await.unwrap();
    assert!(
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .is_err()
    );
    running.stop().await;
}

#[tokio::test]
async fn shutdown_and_future_cancellation_close_stalled_handshakes() {
    for cancel in [false, true] {
        let running = Running::start(Path::new("/SYNTHETIC_MISSING_DSTACK_SOCKET"), 1).await;
        let service = running.service.clone();
        let mut socket = TcpStream::connect(running.address).await.unwrap();
        wait_admitted(&service).await;
        if cancel {
            running.cancel().await;
        } else {
            running.stop().await;
        }
        assert_closed_without_application_bytes(&mut socket).await;
        wait_released(&service).await;
    }
}

struct SocketPath(PathBuf);
impl SocketPath {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // Match the existing test socket convention; no key/certificate files.
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.codex-tmp");
        std::fs::create_dir_all(&directory).unwrap();
        Self(std::fs::canonicalize(directory).unwrap().join(format!(
            "bootstrap-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn request(path: &str, nonce: [u8; 32]) -> Request<Full<Bytes>> {
    Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&PublicAttestationRequest { nonce }).unwrap(),
        )))
        .unwrap()
}

#[tokio::test]
async fn listener_serves_only_public_attestation_bound_to_its_generated_tls_session() {
    let path = SocketPath::new();
    let guest = UnixListener::bind(&path.0).unwrap();
    let (observed, received) = oneshot::channel();
    let guest_task = tokio::spawn(async move {
        let (stream, _) = guest.accept().await.unwrap();
        let observed = std::sync::Mutex::new(Some(observed));
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let observed = observed.lock().unwrap().take().unwrap();
            async move {
                assert_eq!(request.uri(), "/GetQuote");
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body.as_object().unwrap().len(), 1);
                let report_data = body["report_data"].as_str().unwrap().to_owned();
                observed.send(report_data.clone()).unwrap();
                let body = serde_json::to_vec(&GetQuoteResponse {
                    quote: "SYNTHETIC_NOT_A_HARDWARE_QUOTE".into(),
                    event_log: "[]".into(),
                    report_data,
                    vm_config: "{}".into(),
                })
                .unwrap();
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let running = Running::start(&path.0, 1).await;
    let tls = connect(running.address, client_config()).await;
    let nonce = [7; 32];
    let expected = tls
        .get_ref()
        .1
        .export_keying_material([0; 64], ATTESTATION_EXPORTER_LABEL, Some(&nonce))
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let rejected = sender.send_request(request("/rpc", nonce)).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
    rejected.into_body().collect().await.unwrap();
    let response = sender
        .send_request(request("/attestation", nonce))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let evidence = parse_attestation_response(&body).unwrap();
    assert_eq!(evidence.quote, "SYNTHETIC_NOT_A_HARDWARE_QUOTE");
    assert_eq!(evidence.nonce, nonce);
    assert_eq!(hex::decode(received.await.unwrap()).unwrap(), expected);
    assert_eq!(
        sender
            .send_request(request("/attestation", [8; 32]))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    running.stop().await;
    let _ = driver.await;
    guest_task.await.unwrap();
}

#[tokio::test]
async fn node_listener_uses_same_tls_session_and_only_typed_loopback_rpc() {
    let quote_path = SocketPath::new();
    let guest = UnixListener::bind(&quote_path.0).unwrap();
    let quote_task = tokio::spawn(async move {
        let (stream, _) = guest.accept().await.unwrap();
        let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
            assert_eq!(request.uri(), "/GetQuote");
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let report_data = value["report_data"].as_str().unwrap().to_owned();
            let reply = GetQuoteResponse {
                quote: "SYNTHETIC_NOT_A_HARDWARE_QUOTE".into(),
                event_log: "[]".into(),
                report_data,
                vm_config: "{}".into(),
            };
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                serde_json::to_vec(&reply).unwrap(),
            ))))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let zebra = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let zebra_address = match zebra.local_addr().unwrap() {
        SocketAddr::V4(address) => address,
        _ => unreachable!(),
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_by_node = seen.clone();
    let zebra_task = tokio::spawn(async move {
        // This test sends a successful query and an exact-block mismatch.
        for _ in 0..2 {
            let seen_by_node = seen_by_node.clone();
            let (stream, _) = zebra.accept().await.unwrap();
            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                let seen = seen_by_node.clone();
                async move {
                    assert_eq!(request.uri(), "/");
                    assert!(request.headers().contains_key(header::AUTHORIZATION));
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let method = value["method"].as_str().unwrap();
                    seen.lock().unwrap().push(method.to_owned());
                    let result = match method {
                        "getblockchaininfo" => serde_json::json!({
                            "chain":"test", "blocks":42, "bestblockhash":"ab".repeat(32)
                        }),
                        _ => panic!("unapproved method reached the node"),
                    };
                    let reply = serde_json::json!({
                        "jsonrpc":"2.0", "id":value["id"], "result":result
                    });
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from(serde_json::to_vec(&reply).unwrap())))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    });

    let node = LocalNode::new(
        zebra_address,
        CookieAuth::from_cookie(b"__cookie__:SYNTHETIC_ONLY").unwrap(),
    )
    .unwrap();
    let (bridge_watch, bridge_peer) = UnixStream::pair().unwrap();
    let listener = BoundNodeListener::bind_fixture(
        "127.0.0.1:0".parse().unwrap(),
        &quote_path.0,
        limits(1),
        node,
        Some(bridge_watch),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    assert!(!format!("{listener:?}").contains(&address.to_string()));
    let listener_task = tokio::spawn(listener.run(std::future::pending()));
    let tls = connect(address, client_config()).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let rpc_body =
        br#"{"jsonrpc":"2.0","id":"SYNTHETIC_REQUEST","method":"getblockcount","params":[]}"#;
    let rpc = || {
        Request::post("/rpc")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(rpc_body)))
            .unwrap()
    };
    let denied = sender.send_request(rpc()).await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    denied.into_body().collect().await.unwrap();
    let attestation = sender
        .send_request(request("/attestation", [17; 32]))
        .await
        .unwrap();
    assert_eq!(attestation.status(), StatusCode::OK);
    let evidence = attestation.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        parse_attestation_response(&evidence).unwrap().quote,
        "SYNTHETIC_NOT_A_HARDWARE_QUOTE"
    );
    let allowed = sender.send_request(rpc()).await.unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let body = allowed.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], "SYNTHETIC_REQUEST");
    assert_eq!(response["result"], 42);
    assert_eq!(*seen.lock().unwrap(), ["getblockchaininfo"]);
    let mismatch = Request::post("/rpc")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc":"2.0","id":"SYNTHETIC_REQUEST","method":"getblockcount",
                "expected_block":{"height":42,"hash":"cd".repeat(32)}
            }))
            .unwrap(),
        )))
        .unwrap();
    let rejected = sender.send_request(mismatch).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::OK);
    let rejected: serde_json::Value =
        serde_json::from_slice(&rejected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(rejected["error"]["code"], "block_mismatch");
    assert!(rejected.get("result").is_none());
    drop(bridge_peer);
    assert!(listener_task.await.unwrap().is_err());
    let _ = driver.await;
    assert!(sender.send_request(rpc()).await.is_err());
    assert_eq!(
        *seen.lock().unwrap(),
        ["getblockchaininfo", "getblockchaininfo"]
    );
    quote_task.await.unwrap();
    zebra_task.await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live local Zebra Testnet RPC and its tmpfs cookie; quote is synthetic"]
async fn node_listener_reaches_live_zebra_after_synthetic_attestation() {
    let zebra_address: std::net::SocketAddrV4 = std::env::var("ZRPC_LIVE_ZEBRA_RPC")
        .expect("set ZRPC_LIVE_ZEBRA_RPC to a numeric loopback address")
        .parse()
        .expect("ZRPC_LIVE_ZEBRA_RPC must be numeric IPv4");
    let cookie = PathBuf::from(
        std::env::var_os("ZRPC_LIVE_ZEBRA_COOKIE")
            .expect("set ZRPC_LIVE_ZEBRA_COOKIE to the tmpfs cookie path"),
    );
    let node = LocalNode::new(
        zebra_address,
        CookieAuth::from_tmpfs_file(&cookie).expect("valid owned tmpfs Zebra cookie"),
    )
    .expect("loopback node RPC");

    let quote_path = SocketPath::new();
    let guest = UnixListener::bind(&quote_path.0).unwrap();
    let quote_task = tokio::spawn(async move {
        let (stream, _) = guest.accept().await.unwrap();
        let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
            assert_eq!(request.uri(), "/GetQuote");
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let reply = GetQuoteResponse {
                quote: "SYNTHETIC_NOT_A_HARDWARE_QUOTE".into(),
                event_log: "[]".into(),
                report_data: value["report_data"].as_str().unwrap().to_owned(),
                vm_config: "{}".into(),
            };
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                serde_json::to_vec(&reply).unwrap(),
            ))))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let (bridge_watch, bridge_peer) = UnixStream::pair().unwrap();
    let listener = BoundNodeListener::bind_fixture(
        "127.0.0.1:0".parse().unwrap(),
        &quote_path.0,
        limits(1),
        node,
        Some(bridge_watch),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let listener_task = tokio::spawn(listener.run(std::future::pending()));
    let tls = connect(address, client_config()).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);

    let status_body = br#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#;
    let rpc = |body: Vec<u8>| {
        Request::post("/rpc")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    };
    let denied = sender
        .send_request(rpc(status_body.to_vec()))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    denied.into_body().collect().await.unwrap();

    let attestation = sender
        .send_request(request("/attestation", [21; 32]))
        .await
        .unwrap();
    assert_eq!(attestation.status(), StatusCode::OK);
    let evidence = attestation.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        parse_attestation_response(&evidence).unwrap().quote,
        "SYNTHETIC_NOT_A_HARDWARE_QUOTE"
    );

    let status = sender
        .send_request(rpc(status_body.to_vec()))
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let body = status.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["result"]["chain"], "test");
    assert!(response["result"]["blocks"].as_u64().is_some());

    let balance_body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "getaddressbalance",
        "params": [{"addresses": [zrpc_protocol::PREVIEW_TESTNET_ADDRESS]}]
    }))
    .unwrap();
    let balance = sender.send_request(rpc(balance_body)).await.unwrap();
    assert_eq!(balance.status(), StatusCode::OK);
    let body = balance.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(response["result"]["balance"].as_u64().is_some());
    assert!(response["result"]["received"].as_u64().is_some());

    drop(bridge_peer);
    assert!(listener_task.await.unwrap().is_err());
    let _ = driver.await;
    quote_task.await.unwrap();
}

#[tokio::test]
async fn shutdown_cancels_pending_quote_and_closes_its_unix_connection() {
    let path = SocketPath::new();
    let guest = UnixListener::bind(&path.0).unwrap();
    let running = Running::start(&path.0, 1).await;
    let tls = connect(running.address, client_config()).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let query =
        tokio::spawn(async move { sender.send_request(request("/attestation", [0; 32])).await });
    let (mut guest_socket, _) = guest.accept().await.unwrap();
    let mut first = [0];
    guest_socket.read_exact(&mut first).await.unwrap();
    running.stop().await;
    let mut remainder = Vec::new();
    guest_socket.read_to_end(&mut remainder).await.unwrap();
    assert!(query.await.unwrap().is_err());
    let _ = driver.await;
}
