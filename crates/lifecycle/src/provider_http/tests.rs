//! Synthetic CA, API key, account responses and loopback server only. The
//! production hostname is retained for real WebPKI name verification; its DNS
//! is never consulted by these tests.
use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
use tokio_rustls::TlsAcceptor;

const WORKSPACE: &str = "wks_synthetic_only";
const KEY: &str = "SYNTHETIC_API_KEY_MUST_NOT_ESCAPE";
const AUTH: &str = r#"{"workspace":{"id":"wks_synthetic_only"},"user":{"email":"ACCOUNT_MARKER"}}"#;
const INVENTORY: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/inventory.json");
const DETAIL: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/cvm-detail.json");
const USAGE: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/usage.json");

// An explicit synthetic interval is advanced by the timeout tests. It is not a
// production timeout or a claim about provider latency.
const TEST_BUDGET: Duration = Duration::from_secs(60);

fn material(name: &str) -> (Arc<ServerConfig>, CertificateDer<'static>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![name.into()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
            )
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // The fixture offers tickets so the client, rather than the fixture, must
    // ensure a fresh full handshake on every read.
    (Arc::new(config), ca.der().clone())
}

fn response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

struct Server {
    address: SocketAddr,
    root: CertificateDer<'static>,
    requests: Arc<Mutex<Vec<String>>>,
    handshakes: Arc<Mutex<Vec<rustls::HandshakeKind>>>,
    closed: Arc<AtomicUsize>,
    activity: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(replies: Vec<Vec<u8>>, name: &str) -> Self {
        let (tls, root) = material(name);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicUsize::new(0));
        let activity = Arc::new(Notify::new());
        let (record, handshake_record, closed_count, notify) = (
            requests.clone(),
            handshakes.clone(),
            closed.clone(),
            activity.clone(),
        );
        let task = tokio::spawn(async move {
            let mut replies: VecDeque<_> = replies.into();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = match TlsAcceptor::from(tls.clone()).accept(socket).await {
                    Ok(tls) => tls,
                    Err(_) => {
                        closed_count.fetch_add(1, Ordering::SeqCst);
                        notify.notify_one();
                        continue;
                    }
                };
                handshake_record
                    .lock()
                    .unwrap()
                    .push(tls.get_ref().1.handshake_kind().unwrap());
                let mut request = Vec::new();
                loop {
                    let mut byte = [0u8];
                    match tls.read(&mut byte).await {
                        Ok(1) => request.extend_from_slice(&byte),
                        _ => break,
                    }
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if !request.is_empty() {
                    record
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    notify.notify_one();
                    let reply = replies
                        .pop_front()
                        .expect("unexpected extra provider request");
                    // A rejected over-bound body may close while this fixture
                    // is writing; that is an expected transport cancellation.
                    let _ = tls.write_all(&reply).await;
                    let _ = tls.flush().await;
                }
                let mut extra = Vec::new();
                let _ = tls.read_to_end(&mut extra).await;
                assert!(
                    extra.is_empty(),
                    "read-only requests must contain no body or pipelined operation"
                );
                closed_count.fetch_add(1, Ordering::SeqCst);
                notify.notify_one();
            }
        });
        Self {
            address,
            root,
            requests,
            handshakes,
            closed,
            activity,
            task,
        }
    }

    fn client(&self, bound: usize) -> ProviderClient {
        let mut client = ProviderClient::new(
            ApiKey::new(KEY.as_bytes().to_vec()).unwrap(),
            WORKSPACE.into(),
            vec![self.root.clone()],
            TEST_BUDGET,
            NonZeroUsize::new(bound).unwrap(),
        )
        .unwrap();
        client.test_address = Some(self.address);
        client
    }

    async fn wait_requests(&self, count: usize) {
        while self.requests.lock().unwrap().len() < count {
            self.activity.notified().await;
        }
    }

    async fn wait_closed(&self, count: usize) {
        while self.closed.load(Ordering::SeqCst) < count {
            self.activity.notified().await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find_map(|(field, value)| field.eq_ignore_ascii_case(name).then_some(value.trim()))
}

#[tokio::test]
async fn authenticated_reads_use_fixed_get_routes_scope_and_exact_version() {
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", INVENTORY),
            response("404 Not Found", "PROVIDER_ERROR_MARKER"),
            response("200 OK", USAGE),
        ],
        HOST,
    )
    .await;
    let bound = [AUTH.len(), INVENTORY.len(), USAGE.len()]
        .into_iter()
        .max()
        .unwrap();
    let mut reads = server.client(bound).authenticate().await.ok().unwrap();
    assert_eq!(reads.workspace_id(), WORKSPACE);
    assert_eq!(reads.inventory_page(1, 30).await.unwrap().items.len(), 2);
    assert_eq!(
        reads.cvm_detail("cvm?x=y#z").await.unwrap(),
        CvmDetail::NotFound
    );
    assert_eq!(
        reads.usage_page("app_1", 0, 1, 500, 0).await.unwrap().total,
        2
    );
    server.wait_closed(4).await;
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests.iter() {
        assert!(request.starts_with("GET /api/v1/"));
        assert_eq!(header_value(request, "host"), Some(HOST));
        assert_eq!(header_value(request, "x-api-key"), Some(KEY));
        assert_eq!(header_value(request, "x-phala-workspace"), Some(WORKSPACE));
        assert_eq!(header_value(request, "x-phala-version"), Some("2026-06-23"));
        assert_eq!(header_value(request, "connection"), Some("close"));
        assert!(header_value(request, "authorization").is_none());
        assert!(header_value(request, "cookie").is_none());
    }
    assert!(requests[0].starts_with("GET /api/v1/auth/me HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /api/v1/cvms/paginated?page=1&page_size=30 HTTP/1.1\r\n"));
    assert!(requests[2].starts_with("GET /api/v1/cvms/cvm%3Fx%3Dy%23z HTTP/1.1\r\n"));
    assert!(requests[3].starts_with("GET /api/v1/apps/app%5F1/usage?start_date=1970%2D01%2D01T00%3A00%3A00Z&end_date=1970%2D01%2D01T00%3A00%3A01Z&limit=500&offset=0 HTTP/1.1\r\n"));
    assert!(
        server
            .handshakes
            .lock()
            .unwrap()
            .iter()
            .all(|kind| *kind == rustls::HandshakeKind::Full)
    );
}

#[tokio::test]
async fn wrong_ca_or_server_name_receives_no_api_key_application_bytes() {
    for wrong_name in [false, true] {
        let server = Server::start(vec![], if wrong_name { "wrong.example" } else { HOST }).await;
        let mut client = server.client(AUTH.len());
        if !wrong_name {
            let (_, unrelated_root) = material(HOST);
            client = ProviderClient::new(
                ApiKey::new(KEY.as_bytes().to_vec()).unwrap(),
                WORKSPACE.into(),
                vec![unrelated_root],
                TEST_BUDGET,
                NonZeroUsize::new(AUTH.len()).unwrap(),
            )
            .unwrap();
            client.test_address = Some(server.address);
        }
        assert_eq!(
            client.authenticate().await.err(),
            Some(ProviderHttpError::TlsRejected)
        );
        server.wait_closed(1).await;
        assert!(server.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn wrong_workspace_or_malformed_auth_never_creates_scoped_reads() {
    for body in [
        AUTH.replace(WORKSPACE, "wks_other"),
        r#"{"workspace":{"id":"wks_synthetic_only","id":"wks_synthetic_only"}}"#.into(),
    ] {
        let server = Server::start(vec![response("200 OK", &body)], HOST).await;
        let error = server
            .client(body.len())
            .authenticate()
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error,
            ProviderHttpError::WorkspaceMismatch | ProviderHttpError::InvalidResponse
        ));
        server.wait_closed(1).await;
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn error_statuses_are_static_and_redirects_are_not_followed() {
    for (status, expected) in [
        ("302 Found", ProviderHttpError::RedirectRejected),
        ("401 Unauthorized", ProviderHttpError::Unauthorized),
        ("403 Forbidden", ProviderHttpError::Forbidden),
        ("404 Not Found", ProviderHttpError::NotFound),
        ("429 Too Many Requests", ProviderHttpError::RateLimited),
        (
            "503 Service Unavailable",
            ProviderHttpError::ProviderUnavailable,
        ),
        ("204 No Content", ProviderHttpError::UnexpectedStatus),
    ] {
        let mut reply = response(status, "PROVIDER_ERROR_MARKER");
        if status.starts_with("302") {
            reply = format!("HTTP/1.1 {status}\r\nLocation: https://different.invalid/secret\r\nContent-Length: 0\r\n\r\n").into_bytes();
        }
        let server = Server::start(vec![reply], HOST).await;
        let error = server
            .client(AUTH.len())
            .authenticate()
            .await
            .err()
            .unwrap();
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains("MARKER"));
        assert!(!format!("{error:?} {error}").contains(KEY));
        server.wait_closed(1).await;
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn content_length_and_streamed_body_limits_include_authentication() {
    let over = format!("{AUTH} ");
    let cases = [response("200 OK", &over),
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{AUTH}\r\n1\r\n \r\n0\r\n\r\n", AUTH.len()).into_bytes()];
    for reply in cases {
        let server = Server::start(vec![reply], HOST).await;
        assert_eq!(
            server.client(AUTH.len()).authenticate().await.err(),
            Some(ProviderHttpError::BodyLimitExceeded)
        );
        server.wait_closed(1).await;
    }
    let exact = Server::start(vec![response("200 OK", AUTH)], HOST).await;
    assert!(exact.client(AUTH.len()).authenticate().await.is_ok());
    exact.wait_closed(1).await;
}

#[tokio::test]
async fn conflicting_resource_workspace_identity_and_page_are_rejected() {
    for (body, expected) in [
        (
            INVENTORY.replace(WORKSPACE, "wks_other"),
            ProviderHttpError::WorkspaceMismatch,
        ),
        (
            INVENTORY.replace("\"page\": 1", "\"page\": 2"),
            ProviderHttpError::InvalidResponse,
        ),
    ] {
        let server = Server::start(
            vec![response("200 OK", AUTH), response("200 OK", &body)],
            HOST,
        )
        .await;
        let mut reads = server
            .client(body.len().max(AUTH.len()))
            .authenticate()
            .await
            .ok()
            .unwrap();
        assert_eq!(reads.inventory_page(1, 30).await.err(), Some(expected));
        server.wait_closed(2).await;
    }
    let server = Server::start(
        vec![response("200 OK", AUTH), response("200 OK", DETAIL)],
        HOST,
    )
    .await;
    let mut reads = server
        .client(DETAIL.len().max(AUTH.len()))
        .authenticate()
        .await
        .ok()
        .unwrap();
    assert_eq!(
        reads.cvm_detail("different_canonical_id").await.err(),
        Some(ProviderHttpError::InvalidResponse)
    );
    server.wait_closed(2).await;
}

#[tokio::test]
async fn invalid_request_configuration_never_opens_another_socket() {
    let server = Server::start(vec![response("200 OK", AUTH)], HOST).await;
    let mut reads = server.client(AUTH.len()).authenticate().await.ok().unwrap();
    assert_eq!(
        reads.inventory_page(0, 30).await.err(),
        Some(ProviderHttpError::InvalidConfiguration)
    );
    assert_eq!(
        reads.cvm_detail("../auth/me").await.err(),
        Some(ProviderHttpError::InvalidConfiguration)
    );
    assert_eq!(
        reads.usage_page("app", 1, 0, 500, 0).await.err(),
        Some(ProviderHttpError::InvalidConfiguration)
    );
    server.wait_closed(1).await;
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn original_deadline_includes_body_and_later_pages_without_renewal() {
    let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".to_vec();
    let server = Server::start(vec![response("200 OK", AUTH), partial], HOST).await;
    let mut reads = server.client(AUTH.len()).authenticate().await.ok().unwrap();
    let deadline = reads.0.deadline;
    let task = tokio::spawn(async move { reads.inventory_page(1, 30).await });
    server.wait_requests(2).await;
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    assert_eq!(
        task.await.unwrap().err(),
        Some(ProviderHttpError::DeadlineExceeded)
    );
    tokio::time::resume();
    server.wait_closed(2).await;
}

#[tokio::test]
async fn invocation_expiry_and_postparse_check_never_renew_or_release_results() {
    let server = Server::start(vec![response("200 OK", AUTH)], HOST).await;
    let mut reads = server.client(AUTH.len()).authenticate().await.ok().unwrap();
    tokio::time::pause();
    tokio::time::advance(TEST_BUDGET).await;
    assert_eq!(
        reads.0.finish(Ok("already parsed")),
        Err(ProviderHttpError::DeadlineExceeded)
    );
    assert_eq!(
        reads.inventory_page(1, 30).await.err(),
        Some(ProviderHttpError::DeadlineExceeded)
    );
    assert_eq!(
        reads.usage_page("app", 0, 1, 500, 0).await.err(),
        Some(ProviderHttpError::DeadlineExceeded)
    );
    tokio::time::resume();
    server.wait_closed(1).await;
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancellation_aborts_the_http_driver_and_closes_the_socket() {
    let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".to_vec();
    let server = Server::start(vec![partial], HOST).await;
    let client = server.client(AUTH.len());
    let task = tokio::spawn(client.authenticate());
    server.wait_requests(1).await;
    task.abort();
    assert!(task.await.is_err());
    server.wait_closed(1).await;
}

#[test]
fn configuration_validates_roots_budget_headers_and_disables_secret_logging() {
    let (_, root) = material(HOST);
    let create = |roots, workspace, budget| {
        ProviderClient::new(
            ApiKey::new(KEY.as_bytes().to_vec()).unwrap(),
            workspace,
            roots,
            budget,
            NonZeroUsize::new(AUTH.len()).unwrap(),
        )
    };
    assert!(create(vec![], WORKSPACE.into(), TEST_BUDGET).is_err());
    assert!(
        create(
            vec![CertificateDer::from(vec![0u8])],
            WORKSPACE.into(),
            TEST_BUDGET
        )
        .is_err()
    );
    assert!(create(vec![root.clone()], WORKSPACE.into(), Duration::ZERO).is_err());
    assert!(
        create(
            vec![root.clone()],
            "header\r\ninjection".into(),
            TEST_BUDGET
        )
        .is_err()
    );
    assert!(create(vec![root.clone()], " ".into(), TEST_BUDGET).is_err());
    for bytes in [
        Vec::new(),
        b"key\r\nother: value".to_vec(),
        b"key\0".to_vec(),
    ] {
        assert!(ApiKey::new(bytes).is_err());
    }
    let client = create(vec![root], WORKSPACE.into(), TEST_BUDGET)
        .ok()
        .unwrap();
    assert!(client.api_key.0.is_sensitive());
    assert!(!format!("{:?}", client.api_key.0).contains(KEY));
    assert!(!client.tls.enable_early_data);
    assert!(!client.tls.key_log.will_log("CLIENT_RANDOM"));
    assert!(!client.tls.key_log.will_log("SERVER_TRAFFIC_SECRET_0"));
}
