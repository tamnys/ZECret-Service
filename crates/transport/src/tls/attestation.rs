//! One nonce-only public request on the challenge's original TLS connection.

use super::{BootstrapStream, MAX_CONNECTION_LIFETIME, PendingChallenge, unavailable};
use crate::TransportOrigin;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, Version, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zrpc_protocol::{
    ATTESTATION_EXPORTER_LABEL, ErrorCode, GcpAttestationResponse, MAX_ATTESTATION_REQUEST_BYTES,
    MAX_ATTESTATION_RESPONSE_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Method,
    PublicAttestationRequest, PublicAttestationResponse, Request as RpcRequest, RequestId,
    SafeError, TestnetTransparentAddress, Verbosity, parse_attestation_response,
    parse_gcp_attestation_response, parse_request,
};

mod inspection;
pub use inspection::{EndpointInspection, EndpointInspectionIssue};
mod gcp;

fn invalid_response() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidBackendResponse,
        "Public attestation response is malformed; evidence remains unverified.",
    )
}

fn too_large() -> SafeError {
    SafeError::new(
        ErrorCode::ResponseTooLarge,
        "Public attestation response exceeds the release-policy limit.",
    )
}

fn expired() -> SafeError {
    SafeError::new(
        ErrorCode::StaleNonce,
        "TLS bootstrap lifetime expired; establish a new connection.",
    )
}

fn collateral_expired() -> SafeError {
    SafeError::new(
        ErrorCode::ExpiredCollateral,
        "Verified quote collateral expired; establish a new connection with fresh evidence.",
    )
}

/// The QVL-authenticated expiration is anchored to the local monotonic clock
/// during inspection. A later wall-clock rollback cannot extend the session;
/// a forward jump still closes it immediately.
#[derive(Debug, Clone, Copy)]
struct PrivateDeadline {
    monotonic: Instant,
    collateral_expiration_unix_seconds: u64,
}

impl PrivateDeadline {
    fn from_inspection_snapshot(
        expiration: u64,
        wall_now: SystemTime,
        monotonic_before_wall_now: Instant,
    ) -> Option<Self> {
        let elapsed = wall_now.duration_since(UNIX_EPOCH).ok()?;
        let remaining = Duration::from_secs(expiration).checked_sub(elapsed)?;
        if remaining.is_zero() {
            return None;
        }
        Some(Self {
            monotonic: monotonic_before_wall_now.checked_add(remaining)?,
            collateral_expiration_unix_seconds: expiration,
        })
    }

    fn is_expired(self) -> bool {
        Instant::now() >= self.monotonic
            || SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(true, |now| {
                    now >= Duration::from_secs(self.collateral_expiration_unix_seconds)
                })
    }
}

struct OwnedHttpSession {
    // Retain ownership but never expose this application-writing capability.
    sender: http1::SendRequest<Full<Bytes>>,
    driver: tokio::task::JoinHandle<()>,
    private_deadline: Arc<OnceLock<PrivateDeadline>>,
    origin: TransportOrigin,
}

// The timer around an HTTP future is not a write barrier: Tokio polls the
// future before checking its timeout. Guard the actual TLS I/O so a delayed
// Hyper driver cannot transmit a private body after the connection expires.
struct DeadlineIo {
    stream: BootstrapStream,
    deadline: Instant,
    private_deadline: Arc<OnceLock<PrivateDeadline>>,
    origin: TransportOrigin,
}

impl DeadlineIo {
    fn check_deadline(&self) -> io::Result<()> {
        if self.origin.ensure_usable().is_err()
            || Instant::now() >= self.deadline
            || self
                .private_deadline
                .get()
                .is_some_and(|deadline| deadline.is_expired())
        {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Verified session expired",
            ))
        } else {
            Ok(())
        }
    }
}

impl AsyncRead for DeadlineIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DeadlineIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Drop for OwnedHttpSession {
    fn drop(&mut self) {
        // Also applies on cancellation, parse failure and connection expiry.
        self.driver.abort();
    }
}

impl PendingChallenge {
    /// Send the sole public request allowed by this type: POST /attestation with
    /// this session's 32-byte nonce. No caller payload, selector or key is accepted.
    /// The nonce is consumed once, and the response is explicitly unverified.
    pub async fn request_attestation(self) -> Result<UnverifiedPublicEvidence, SafeError> {
        let received = self.receive_evidence().await?;
        let evidence = parse_attestation_response(&received.body)?;
        if evidence.nonce != received.nonce {
            return Err(challenge_mismatch());
        }
        Ok(UnverifiedPublicEvidence {
            evidence,
            _session: received.session,
            authority: received.authority,
            expected_report_data: received.expected_report_data,
            established: received.established,
            deadline: received.deadline,
            nonce: received.nonce,
        })
    }

    /// Explicit GCP decoding on the same nonce-only exchange. Never retries with
    /// another provider when the selected evidence schema does not match.
    pub async fn request_gcp_attestation(self) -> Result<UnverifiedGcpEvidence, SafeError> {
        let mut received = self.receive_evidence().await?;
        let evidence = parse_gcp_attestation_response(&received.body)?;
        if evidence.nonce != received.nonce {
            return Err(challenge_mismatch());
        }
        received.body = Bytes::new();
        Ok(UnverifiedGcpEvidence {
            evidence,
            connection: received,
        })
    }

    async fn receive_evidence(self) -> Result<ReceivedEvidence, SafeError> {
        self.tls.ensure_live()?;
        let deadline = self
            .tls
            .established
            .checked_add(MAX_CONNECTION_LIFETIME)
            .ok_or_else(expired)?;
        // This is the original connection's existing five-minute lifetime, not
        // a fresh timeout or an extension starting at request time.
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), self.exchange())
            .await
            .map_err(|_| expired())?
    }

    async fn exchange(self) -> Result<ReceivedEvidence, SafeError> {
        let nonce = self.nonce;
        let established = self.tls.established;
        let authority = self.tls.authority.clone();
        let origin = self.tls.origin.clone();
        let deadline = established
            .checked_add(MAX_CONNECTION_LIFETIME)
            .ok_or_else(expired)?;
        // Capture from this original completed TLS session before handing it to
        // Hyper. Keeping these private inputs is not quote acceptance: a future
        // verifier must authenticate REPORTDATA before comparing it to them.
        let expected_report_data = self
            .tls
            .stream
            .get_ref()
            .1
            .export_keying_material([0; 64], ATTESTATION_EXPORTER_LABEL, Some(&nonce))
            .map_err(|_| unavailable())?;
        let body =
            serde_json::to_vec(&PublicAttestationRequest { nonce }).map_err(|_| unavailable())?;
        if body.len() > MAX_ATTESTATION_REQUEST_BYTES {
            return Err(SafeError::new(
                ErrorCode::RequestTooLarge,
                "Public attestation request exceeds the release-policy limit.",
            ));
        }
        let request = Request::post("/attestation")
            .header(header::HOST, self.tls.authority)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| unavailable())?;
        // Hyper receives the owned TLS stream. This API neither opens a socket
        // nor resolves a host, follows a redirect, retries, or consults proxies.
        let private_deadline = Arc::new(OnceLock::new());
        let (sender, connection) = http1::handshake(TokioIo::new(DeadlineIo {
            stream: self.tls.stream,
            deadline,
            private_deadline: Arc::clone(&private_deadline),
            origin: origin.clone(),
        }))
        .await
        .map_err(|_| unavailable())?;
        let mut session = OwnedHttpSession {
            sender,
            driver: tokio::spawn(async move {
                let _ = connection.await;
            }),
            private_deadline,
            origin,
        };
        let response = session
            .sender
            .send_request(request)
            .await
            .map_err(|_| unavailable())?;
        if response.status() != StatusCode::OK || response.version() != Version::HTTP_11 {
            return Err(invalid_response());
        }
        let headers = response.headers();
        if headers.contains_key(header::CONTENT_ENCODING)
            || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
            || headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                != Some("application/json")
            || headers.get_all(header::CONNECTION).iter().any(|value| {
                value.to_str().map_or(true, |value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"))
                })
            })
        {
            return Err(invalid_response());
        }
        if headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_ATTESTATION_RESPONSE_BYTES as u64)
        {
            return Err(too_large());
        }
        let body = Limited::new(response.into_body(), MAX_ATTESTATION_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| {
                if error.is::<http_body_util::LengthLimitError>() {
                    too_large()
                } else {
                    unavailable()
                }
            })?
            .to_bytes();
        if Instant::now()
            .checked_duration_since(established)
            .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            return Err(expired());
        }
        if session.sender.is_closed() || session.driver.is_finished() {
            return Err(unavailable());
        }
        Ok(ReceivedEvidence {
            body,
            session,
            authority,
            expected_report_data,
            established,
            deadline,
            nonce,
        })
    }
}

fn challenge_mismatch() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidNonce,
        "Public attestation response does not match this challenge.",
    )
}

struct ReceivedEvidence {
    body: Bytes,
    session: OwnedHttpSession,
    authority: String,
    expected_report_data: [u8; 64],
    established: Instant,
    deadline: Instant,
    nonce: [u8; 32],
}

/// GCP quote material retained with its original connection. There is no raw
/// socket, serializer, or query capability on this unauthenticated type.
///
/// ```compile_fail
/// async fn cannot_query(evidence: zrpc_transport::UnverifiedGcpEvidence, request: &zrpc_protocol::Request) {
///     evidence.query(request).await.unwrap();
/// }
/// ```
/// ```compile_fail
/// use tokio::io::AsyncWriteExt;
/// async fn cannot_write(mut evidence: zrpc_transport::UnverifiedGcpEvidence) {
///     evidence.write_all(b"private query").await.unwrap();
/// }
/// ```
pub struct UnverifiedGcpEvidence {
    evidence: GcpAttestationResponse,
    connection: ReceivedEvidence,
}

impl fmt::Debug for UnverifiedGcpEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnverifiedGcpEvidence([unverified public evidence])")
    }
}

/// Raw peer-supplied quote material received over the challenge's TLS session.
/// Nonce equality establishes correlation only: no hardware, workload, quote
/// freshness, report-data binding or approval policy has been authenticated.
/// The retained socket is opaque; this type has no private-query capability.
///
/// ```compile_fail
/// fn cannot_authorize(evidence: zrpc_transport::UnverifiedPublicEvidence) {
///     let _: zrpc_verifier::VerifiedChannel = evidence.into();
/// }
/// ```
/// ```compile_fail
/// use tokio::io::AsyncWriteExt;
/// async fn cannot_write(mut evidence: zrpc_transport::UnverifiedPublicEvidence) {
///     evidence.write_all(b"private query").await.unwrap();
/// }
/// ```
/// ```compile_fail
/// async fn cannot_supply_query(challenge: zrpc_transport::PendingChallenge) {
///     challenge.request_attestation(b"private query").await.unwrap();
/// }
/// ```
pub struct UnverifiedPublicEvidence {
    evidence: PublicAttestationResponse,
    _session: OwnedHttpSession,
    authority: String,
    // Retained for the future authenticated verifier boundary, never exported
    // through the raw evidence accessor or treated as acceptance in this API.
    expected_report_data: [u8; 64],
    established: Instant,
    deadline: Instant,
    nonce: [u8; 32],
}

/// The original TLS connection, retained only after local hardware, workload,
/// collateral, freshness, reviewed-release and exporter-binding checks pass.
/// It is neither serializable nor constructible from caller-supplied evidence.
/// One query consumes it; reconnects must obtain a new quote and fresh approval.
pub struct VerifiedRpcSession {
    session: OwnedHttpSession,
    deadline: Instant,
    authority: String,
}

/// A diagnostic-attested, managed-Tor session for two typed public testnet
/// reads. This type is distinct from `VerifiedRpcSession`, has no arbitrary
/// request method, and cannot establish reviewed-release or private approval.
pub struct PreviewRpcSession {
    session: OwnedHttpSession,
    deadline: Instant,
    authority: String,
}

impl fmt::Debug for PreviewRpcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreviewRpcSession([typed public testnet reads only])")
    }
}

#[derive(Debug, Serialize)]
pub struct PublicTestnetPreview {
    pub reported_chain: &'static str,
    pub blocks: u32,
    pub best_block_hash: String,
    pub transparent_address: String,
    pub transparent_balance_zatoshis: u64,
}

impl VerifiedRpcSession {
    fn from_authenticated_inspection(
        session: OwnedHttpSession,
        deadline: Instant,
        authority: String,
        collateral_deadline: PrivateDeadline,
    ) -> Result<Self, SafeError> {
        session.origin.require_managed()?;
        session
            .private_deadline
            .set(collateral_deadline)
            .map_err(|_| unavailable())?;
        let verified = Self {
            session,
            deadline,
            authority,
        };
        verified.ensure_private_ready()?;
        Ok(verified)
    }

    fn ensure_lifetimes(&self) -> Result<(), SafeError> {
        if Instant::now() >= self.deadline {
            return Err(expired());
        }
        match self.session.private_deadline.get() {
            Some(deadline) if !deadline.is_expired() => Ok(()),
            Some(_) => Err(collateral_expired()),
            None => Err(unavailable()),
        }
    }

    fn ensure_private_ready(&self) -> Result<(), SafeError> {
        self.session.origin.require_managed()?;
        self.ensure_lifetimes()?;
        if self.session.sender.is_closed() || self.session.driver.is_finished() {
            return Err(expired());
        }
        Ok(())
    }

    fn private_operation_deadline(&self) -> Result<Instant, SafeError> {
        let collateral_deadline = self
            .session
            .private_deadline
            .get()
            .ok_or_else(unavailable)?;
        Ok(self.deadline.min(collateral_deadline.monotonic))
    }

    /// Read a caller-supplied body only while the verified connection remains
    /// live, then parse the typed allowlist and recheck before sending it.
    pub async fn query_from_body(
        self,
        body: impl FnOnce() -> Result<Vec<u8>, SafeError>,
    ) -> Result<Value, SafeError> {
        self.query_from_body_async(|| async move { body() }).await
    }

    /// Async local body sources, such as the dashboard's HTTP request stream,
    /// are polled only while the managed Tor lease is still usable. A second
    /// check in `query` guards the wire write after body collection.
    pub async fn query_from_body_async<F, Fut>(self, body: F) -> Result<Value, SafeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>, SafeError>>,
    {
        self.ensure_private_ready()?;
        let deadline = self.private_operation_deadline()?;
        let bytes = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), body())
            .await
            .map_err(|_| self.ensure_lifetimes().err().unwrap_or_else(expired))??;
        self.ensure_private_ready()?;
        let request = parse_request(&bytes)?;
        self.query(&request).await
    }

    pub async fn query(mut self, request: &RpcRequest) -> Result<Value, SafeError> {
        self.ensure_private_ready()?;
        ensure_private_method(request)?;
        let operation_deadline = self.private_operation_deadline()?;
        // The only sender here is the one retained from POST /attestation.
        let operation = send_rpc(&mut self.session, self.authority.as_str(), request);
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(operation_deadline),
            operation,
        )
        .await;
        // A peer may close after a complete response; only expiry must still
        // be checked before returning the decoded result.
        self.ensure_lifetimes()?;
        let result = result.map_err(|_| expired())?;
        // Tokio cannot preempt synchronous JSON decoding inside the timeout.
        // Check again before a result escapes the original TLS session deadline.
        finish_before_deadline(self.deadline, result)
    }
}

fn ensure_private_method(request: &RpcRequest) -> Result<(), SafeError> {
    if matches!(request.method(), Method::GetPreviewAddressBalance { .. }) {
        return Err(SafeError::new(
            ErrorCode::MethodNotAllowed,
            "Transparent address balance is available only in the public preview.",
        ));
    }
    Ok(())
}

impl PreviewRpcSession {
    fn from_public_preview_inspection(
        session: OwnedHttpSession,
        deadline: Instant,
        authority: String,
        collateral_deadline: PrivateDeadline,
    ) -> Result<Self, SafeError> {
        session.origin.require_managed()?;
        session
            .private_deadline
            .set(collateral_deadline)
            .map_err(|_| unavailable())?;
        let preview = Self {
            session,
            deadline,
            authority,
        };
        preview.ensure_ready()?;
        Ok(preview)
    }

    fn ensure_ready(&self) -> Result<(), SafeError> {
        self.session.origin.require_managed()?;
        if Instant::now() >= self.deadline {
            return Err(expired());
        }
        match self.session.private_deadline.get() {
            Some(deadline) if !deadline.is_expired() => {}
            Some(_) => return Err(collateral_expired()),
            None => return Err(unavailable()),
        }
        if self.session.sender.is_closed() || self.session.driver.is_finished() {
            return Err(expired());
        }
        Ok(())
    }

    async fn fixed_request(&mut self, request: &RpcRequest) -> Result<Value, SafeError> {
        self.ensure_ready()?;
        let collateral_deadline = self
            .session
            .private_deadline
            .get()
            .ok_or_else(unavailable)?;
        let deadline = self.deadline.min(collateral_deadline.monotonic);
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            send_rpc(&mut self.session, self.authority.as_str(), request),
        )
        .await
        .map_err(|_| expired())?;
        self.ensure_ready()?;
        finish_before_deadline(self.deadline, result)
    }

    /// The method sequence is fixed in native code. The only caller input is a
    /// locally validated testnet transparent address. Both RPCs use the same
    /// Tor/TLS connection that supplied the inspected live quote.
    pub async fn public_testnet_preview(
        mut self,
        address: &TestnetTransparentAddress,
    ) -> Result<PublicTestnetPreview, SafeError> {
        let info =
            parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)?;
        let result = self.fixed_request(&info).await?;
        if result.get("chain").and_then(Value::as_str) != Some("test") {
            return Err(SafeError::new(
                ErrorCode::WrongNetwork,
                "The node did not report Zcash testnet.",
            ));
        }
        let blocks = result
            .get("blocks")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(invalid_response)?;
        let best_block_hash = result
            .get("bestblockhash")
            .and_then(Value::as_str)
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(invalid_response)?
            .to_ascii_lowercase();
        let balance_body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":2, "method":"getaddressbalance",
            "params":[{"addresses":[address.as_str()]}]
        }))
        .map_err(|_| unavailable())?;
        let balance_request = parse_request(&balance_body)?;
        let balance = self.fixed_request(&balance_request).await?;
        let transparent_balance_zatoshis = balance
            .get("balance")
            .and_then(Value::as_u64)
            .ok_or_else(invalid_response)?;
        Ok(PublicTestnetPreview {
            reported_chain: "test",
            blocks,
            best_block_hash,
            transparent_address: address.as_str().to_owned(),
            transparent_balance_zatoshis,
        })
    }
}

async fn send_rpc(
    session: &mut OwnedHttpSession,
    authority: &str,
    request: &RpcRequest,
) -> Result<Value, SafeError> {
    session.origin.require_managed()?;
    let body = encode_request(request)?;
    let http = Request::post("/rpc")
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header(header::ACCEPT_ENCODING, "identity")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| unavailable())?;
    let response = session
        .sender
        .send_request(http)
        .await
        .map_err(|_| unavailable())?;
    if response.status() != StatusCode::OK || response.version() != Version::HTTP_11 {
        return Err(unavailable());
    }
    let headers = response.headers();
    if headers.contains_key(header::CONTENT_ENCODING)
        || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .is_none_or(|h| h != "application/json")
        || headers.get_all(header::CONTENT_LENGTH).iter().count() > 1
        || headers
            .get(header::CONTENT_LENGTH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(invalid_response());
    }
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|_| too_large())?
        .to_bytes();
    if body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err(invalid_response());
    }
    let response: WireRpcResponse =
        serde_json::from_slice(&body).map_err(|_| invalid_response())?;
    if response.jsonrpc != "2.0"
        || response.id != *request.id()
        || response.result.is_none()
        || response.error.is_some()
    {
        return Err(invalid_response());
    }
    Ok(response.result.unwrap())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRpcResponse {
    jsonrpc: String,
    id: RequestId,
    result: Option<Value>,
    error: Option<Value>,
}

fn finish_before_deadline<T>(
    deadline: Instant,
    result: Result<T, SafeError>,
) -> Result<T, SafeError> {
    if Instant::now() >= deadline {
        Err(expired())
    } else {
        result
    }
}

fn encode_request(request: &RpcRequest) -> Result<Vec<u8>, SafeError> {
    let params = match request.method() {
        Method::GetBlockchainInfo | Method::GetBlockCount => json!([]),
        Method::GetPreviewAddressBalance { address } => json!([{"addresses":[address.as_str()]}]),
        Method::GetBlockHash { height } => json!([height]),
        Method::GetBlockHeader { hash, verbosity } => {
            json!([hash.as_str(), matches!(verbosity, Verbosity::Verbose)])
        }
        Method::GetRawTransaction { txid, verbosity } => {
            json!([txid.as_str(), matches!(verbosity, Verbosity::Verbose)])
        }
    };
    let body = serde_json::to_vec(&json!({
        "jsonrpc":"2.0", "id":request.id(), "method":request.method().name(), "params":params
    }))
    .map_err(|_| unavailable())?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(SafeError::new(
            ErrorCode::RequestTooLarge,
            "Typed RPC request exceeds the configured body limit.",
        ));
    }
    Ok(body)
}

impl UnverifiedPublicEvidence {
    pub fn raw_unverified(&self) -> &PublicAttestationResponse {
        &self.evidence
    }
    pub fn private_rpc_allowed(&self) -> bool {
        false
    }

    #[cfg(test)]
    pub(super) fn assert_retained_binding_for_test(
        &self,
        expected: [u8; 64],
        nonce: [u8; 32],
        established: Instant,
    ) {
        assert_eq!(self.expected_report_data, expected);
        assert_eq!(self.nonce, nonce);
        assert_eq!(self.established, established);
        assert_eq!(self.deadline, established + MAX_CONNECTION_LIFETIME);
    }
}

impl fmt::Debug for UnverifiedPublicEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedPublicEvidence")
            .field("evidence_authenticated", &false)
            .field("private_rpc_allowed", &false)
            .finish()
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use crate::tls::{
        ALPN,
        tests::{assert_no_application_bytes, connect_pair, server_config},
    };
    use tokio::io::AsyncWriteExt;

    #[test]
    fn preview_address_method_cannot_enter_private_session() {
        let preview = parse_request(format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getaddressbalance\",\"params\":[{{\"addresses\":[\"{}\"]}}]}}",
            zrpc_protocol::PREVIEW_TESTNET_ADDRESS,
        ).as_bytes()).unwrap();
        assert_eq!(
            ensure_private_method(&preview).unwrap_err().code,
            ErrorCode::MethodNotAllowed
        );
        let status =
            parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)
                .unwrap();
        assert!(ensure_private_method(&status).is_ok());
    }

    #[test]
    fn collateral_snapshot_uses_subsecond_remaining_time_and_rejects_expiry() {
        let instant = Instant::now();
        let wall = UNIX_EPOCH + Duration::from_millis(1_500);
        let deadline = PrivateDeadline::from_inspection_snapshot(2, wall, instant).unwrap();
        assert_eq!(
            deadline.monotonic.duration_since(instant),
            Duration::from_millis(500)
        );
        assert!(
            PrivateDeadline::from_inspection_snapshot(
                2,
                UNIX_EPOCH + Duration::from_secs(2),
                instant
            )
            .is_none()
        );
        assert!(
            PrivateDeadline::from_inspection_snapshot(
                2,
                UNIX_EPOCH + Duration::from_secs(3),
                instant
            )
            .is_none()
        );
    }

    #[test]
    fn decoded_private_result_cannot_escape_expired_session() {
        // Synthetic wire data exercises the final gate without approving any
        // release or constructing a private-capable connection.
        let response: WireRpcResponse =
            serde_json::from_slice(br#"{"jsonrpc":"2.0","id":7,"result":42}"#).unwrap();
        let result = response.result.unwrap();
        let expired_deadline = Instant::now();
        assert_eq!(
            finish_before_deadline(expired_deadline, Ok(result.clone()))
                .unwrap_err()
                .code,
            ErrorCode::StaleNonce
        );
        assert_eq!(
            finish_before_deadline(Instant::now() + MAX_CONNECTION_LIFETIME, Ok(result)).unwrap(),
            json!(42)
        );
    }

    #[tokio::test]
    async fn expired_tls_write_is_rejected_before_application_bytes() {
        let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
        let mut io = DeadlineIo {
            stream: client.unwrap().stream,
            deadline: Instant::now(),
            private_deadline: Arc::new(OnceLock::new()),
            origin: TransportOrigin::DiagnosticTcp,
        };
        assert_eq!(
            io.write_all(b"SYNTHETIC_PRIVATE_CANARY")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        drop(io);
        assert_no_application_bytes(server.unwrap()).await;
    }

    #[tokio::test]
    async fn expired_http_driver_cannot_write_private_body() {
        let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
        let io = DeadlineIo {
            stream: client.unwrap().stream,
            deadline: Instant::now(),
            private_deadline: Arc::new(OnceLock::new()),
            origin: TransportOrigin::DiagnosticTcp,
        };
        let (mut sender, connection) = http1::handshake(TokioIo::new(io)).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = Request::post("/rpc")
            .body(Full::new(Bytes::from_static(b"SYNTHETIC_PRIVATE_CANARY")))
            .unwrap();
        assert!(sender.send_request(request).await.is_err());
        drop(sender);
        let _ = driver.await.unwrap();
        assert_no_application_bytes(server.unwrap()).await;
    }

    #[tokio::test]
    async fn collateral_expiry_closes_tls_write_barrier_before_private_bytes() {
        let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
        let private_deadline = Arc::new(OnceLock::new());
        let mut io = DeadlineIo {
            stream: client.unwrap().stream,
            deadline: Instant::now() + MAX_CONNECTION_LIFETIME,
            private_deadline: Arc::clone(&private_deadline),
            origin: TransportOrigin::DiagnosticTcp,
        };
        // Synthetic deadline injected after the TLS connection exists. This
        // tests the I/O barrier, not quote validity or release approval.
        private_deadline
            .set(PrivateDeadline {
                monotonic: Instant::now(),
                collateral_expiration_unix_seconds: u64::MAX,
            })
            .unwrap();
        assert_eq!(
            io.write_all(b"SYNTHETIC_PRIVATE_CANARY")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        drop(io);
        assert_no_application_bytes(server.unwrap()).await;
    }
}
