//! Real local TLS/Unix-socket plumbing; all quote evidence is synthetic.
use super::*;
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
use std::{convert::Infallible, io, num::NonZeroUsize, path::PathBuf};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::{TcpStream, UnixListener},
    sync::oneshot,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use zrpc_protocol::{
    ATTESTATION_EXPORTER_LABEL, PublicAttestationRequest, parse_attestation_response,
};

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
