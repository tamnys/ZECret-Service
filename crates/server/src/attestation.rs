//! Session-owned public attestation. There is no RPC route or private acceptance.
use bytes::Bytes;
use dstack_sdk_types::dstack::GetQuoteResponse;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, Version, body::Incoming, header};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    future::Future,
    io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UnixStream},
    sync::Semaphore,
};
use tokio_rustls::server::TlsStream;
use zrpc_protocol::{
    ATTESTATION_EXPORTER_LABEL, ErrorCode, MAX_ATTESTATION_REQUEST_BYTES,
    MAX_ATTESTATION_RESPONSE_BYTES, MAX_CONNECTION_LIFETIME_SECONDS, PublicAttestationResponse,
    SafeError, parse_attestation_request,
};

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "Public attestation is unavailable.",
    )
}

/// Values must come from an independently reviewed release configuration.
/// No deployment defaults or experimentally guessed production quotas exist.
pub struct BootstrapLimits {
    connections: NonZeroUsize,
    quotes: NonZeroUsize,
    quote_spacing: Duration,
}
impl BootstrapLimits {
    pub fn new(
        connections: NonZeroUsize,
        quotes: NonZeroUsize,
        quote_spacing: Duration,
    ) -> Result<Self, SafeError> {
        if quote_spacing.is_zero()
            || connections.get() > Semaphore::MAX_PERMITS
            || quotes.get() > Semaphore::MAX_PERMITS
        {
            return Err(unavailable());
        }
        Ok(Self {
            connections,
            quotes,
            quote_spacing,
        })
    }
}

/// Local, explicit guest socket only. No environment endpoint, URL, TCP fallback,
/// generic forwarding, secret-key derivation or signing operation is exposed.
struct DstackQuoteSource {
    socket: PathBuf,
}
trait QuoteSource: Send + Sync + 'static {
    fn quote(
        &self,
        report_data: [u8; 64],
    ) -> impl Future<Output = Result<GetQuoteResponse, SafeError>> + Send;
}
impl QuoteSource for DstackQuoteSource {
    async fn quote(&self, report_data: [u8; 64]) -> Result<GetQuoteResponse, SafeError> {
        let socket = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| unavailable())?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| unavailable())?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        // Exact SDK v0.1.2 DstackClient::get_quote wire operation. The maintained
        // response type is reused; HTTP body collection is independently bounded.
        let body = serde_json::to_vec(&serde_json::json!({"report_data":hex::encode(report_data)}))
            .map_err(|_| unavailable())?;
        let request = Request::post("/GetQuote")
            .header(header::HOST, "dstack")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| unavailable())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| unavailable())?;
        if response.status() != StatusCode::OK
            || response.headers().contains_key(header::CONTENT_ENCODING)
        {
            return Err(unavailable());
        }
        let body = Limited::new(response.into_body(), MAX_ATTESTATION_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| unavailable())?
            .to_bytes();
        // Parse directly: don't normalize through Value and erase duplicate fields.
        if body.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
            return Err(unavailable());
        }
        let response: GetQuoteResponse =
            serde_json::from_slice(&body).map_err(|_| unavailable())?;
        // This unauthenticated echo only detects a malformed guest reply. The
        // native client must authenticate the quote and compare actual REPORTDATA.
        if hex::decode(&response.report_data).ok().as_deref() != Some(report_data.as_slice()) {
            return Err(unavailable());
        }
        Ok(response)
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Shared<Q> {
    source: Q,
    connections: Semaphore,
    quotes: Semaphore,
    quote_spacing: Duration,
    last_quote: Mutex<Option<Instant>>,
}
impl<Q: QuoteSource> Shared<Q> {
    fn new(source: Q, limits: BootstrapLimits) -> Self {
        Self {
            source,
            connections: Semaphore::new(limits.connections.get()),
            quotes: Semaphore::new(limits.quotes.get()),
            quote_spacing: limits.quote_spacing,
            last_quote: Mutex::new(None),
        }
    }
}

/// A library endpoint for already-negotiated TLS streams. No listener, key import,
/// certificate generation, deployment or private-RPC activation is provided.
/// A future listener must generate ephemeral keys inside the approved workload
/// and apply global admission before TLS handshakes as well.
#[derive(Clone)]
pub struct AttestationService {
    shared: Arc<Shared<DstackQuoteSource>>,
}
impl AttestationService {
    pub fn new(socket: &Path, limits: BootstrapLimits) -> Result<Self, SafeError> {
        if !socket.is_absolute()
            || socket
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(unavailable());
        }
        Ok(Self {
            shared: Arc::new(Shared::new(
                DstackQuoteSource {
                    socket: socket.to_owned(),
                },
                limits,
            )),
        })
    }
    /// Call immediately after the server handshake. This checks TLS1.3, full
    /// handshake and ALPN; it does not certify the caller's key-generation policy.
    pub async fn serve_connection(&self, stream: TlsStream<TcpStream>) -> Result<(), SafeError> {
        serve(self.shared.clone(), stream).await
    }
}

// Both Hyper I/O and the exporter use the same Rustls session. Locks are held
// only during one synchronous poll/exporter operation, never across await.
#[derive(Clone)]
struct SessionIo(Arc<Mutex<TlsStream<TcpStream>>>);
impl AsyncRead for SessionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_read(cx, buf),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
}
impl AsyncWrite for SessionIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_write(cx, buf),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_flush(cx),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_shutdown(cx),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
}
struct Session {
    io: SessionIo,
    challenged: AtomicBool,
}

async fn serve<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    stream: TlsStream<TcpStream>,
) -> Result<(), SafeError> {
    let _connection = shared
        .connections
        .try_acquire()
        .map_err(|_| unavailable())?;
    let (_, tls) = stream.get_ref();
    if tls.is_handshaking()
        || tls.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || tls.alpn_protocol() != Some(b"http/1.1")
        || !matches!(
            tls.handshake_kind(),
            Some(rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest)
        )
    {
        return Err(unavailable());
    }
    let io = SessionIo(Arc::new(Mutex::new(stream)));
    let session = Arc::new(Session {
        io: io.clone(),
        challenged: AtomicBool::new(false),
    });
    let service = hyper::service::service_fn(|request| {
        let shared = shared.clone();
        let session = session.clone();
        async move { Ok::<_, Infallible>(handle(shared, session, request).await) }
    });
    // Dropping the connection future also drops an in-progress quote future.
    tokio::time::timeout(
        Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS),
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(io), service),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
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
        Bytes::from_static(br#"{"error":"public_attestation_unavailable"}"#),
    )
}
async fn handle<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    session: Arc<Session>,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    if request.method() != hyper::Method::POST
        || request.uri().path_and_query().map(|p| p.as_str()) != Some("/attestation")
        || request.uri().authority().is_some()
        || request.version() != Version::HTTP_11
    {
        return failure(StatusCode::NOT_FOUND);
    }
    if request.headers().contains_key(header::CONTENT_ENCODING)
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|h| h != "application/json")
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
    let request = match parse_attestation_request(&body) {
        Ok(request) => request,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    // Every connection can attempt just its one challenge. Failure does not make
    // it reusable with another nonce, nor does any status grant RPC permission.
    if session.challenged.swap(true, Ordering::SeqCst) {
        return failure(StatusCode::CONFLICT);
    }
    let _quote = match shared.quotes.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return failure(StatusCode::TOO_MANY_REQUESTS),
    };
    {
        let mut last = match shared.last_quote.lock() {
            Ok(last) => last,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        let now = Instant::now();
        if last
            .is_some_and(|previous| now.saturating_duration_since(previous) < shared.quote_spacing)
        {
            return failure(StatusCode::TOO_MANY_REQUESTS);
        }
        *last = Some(now);
    }
    let exporter = {
        let stream = match session.io.0.lock() {
            Ok(stream) => stream,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        match stream.get_ref().1.export_keying_material(
            [0u8; 64],
            ATTESTATION_EXPORTER_LABEL,
            Some(&request.nonce),
        ) {
            Ok(exporter) => exporter,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        }
    };
    let evidence = match shared.source.quote(exporter).await {
        Ok(evidence) => evidence,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
    };
    let response = PublicAttestationResponse {
        nonce: request.nonce,
        quote: evidence.quote,
        event_log: evidence.event_log,
        report_data: evidence.report_data,
        vm_config: evidence.vm_config,
    };
    // Bound while serializing, avoiding a second unbounded response allocation.
    let mut output = BoundedOutput(Vec::new());
    if serde_json::to_writer(&mut output, &response).is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    reply(StatusCode::OK, Bytes::from(output.0))
}
struct BoundedOutput(Vec<u8>);
impl io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_ATTESTATION_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("public evidence bound"));
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
