//! Narrow operator control-plane reads over ordinarily authenticated HTTPS.
//!
//! This transport cannot create, alter, stop, or delete resources. It is separate
//! from the Tor/private-query transport and never accepts an endpoint URL. A
//! completed read is neither an atomic inventory nor a disk/billing receipt.

use crate::{provider_request::ReadRequest, provider_wire};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use std::{fmt, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::Instant};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const HOST: &str = "cloud-api.phala.com";
const PORT: u16 = 443;

/// Only fixed categories escape; provider bodies, credentials, request paths,
/// TLS errors and account data are never interpolated into errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHttpError {
    InvalidConfiguration,
    DeadlineExceeded,
    ConnectionFailed,
    TlsRejected,
    HttpFailed,
    BodyLimitExceeded,
    InvalidResponse,
    WorkspaceMismatch,
    Unauthorized,
    Forbidden,
    NotFound,
    RedirectRejected,
    RateLimited,
    ProviderUnavailable,
    UnexpectedStatus,
}

impl fmt::Display for ProviderHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid provider read configuration",
            Self::DeadlineExceeded => "provider read invocation deadline exceeded",
            Self::ConnectionFailed => "provider connection failed",
            Self::TlsRejected => "provider TLS authentication failed",
            Self::HttpFailed => "provider HTTP exchange failed",
            Self::BodyLimitExceeded => "provider response body limit exceeded",
            Self::InvalidResponse => "invalid provider response",
            Self::WorkspaceMismatch => "provider workspace does not match the bound workspace",
            Self::Unauthorized => "provider authentication rejected",
            Self::Forbidden => "provider access forbidden",
            Self::NotFound => "provider read target not found",
            Self::RedirectRejected => "provider redirect rejected",
            Self::RateLimited => "provider rate limit response",
            Self::ProviderUnavailable => "provider unavailable",
            Self::UnexpectedStatus => "unexpected provider status",
        })
    }
}
impl std::error::Error for ProviderHttpError {}

/// Owned credential with no Debug, Serialize, or plaintext accessor.
///
/// The input buffer is wiped on consumption, including validation failure.
/// Maintained HTTP/TLS implementations make their own buffers; this does not
/// claim erasure of all copies of the credential from process memory.
///
/// ```compile_fail
/// use zrpc_lifecycle::provider_http::ApiKey;
/// let key = ApiKey::new(b"synthetic".to_vec()).unwrap();
/// println!("{key:?}");
/// ```
pub struct ApiKey(header::HeaderValue);

impl ApiKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProviderHttpError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.iter().any(u8::is_ascii_control) {
            return Err(ProviderHttpError::InvalidConfiguration);
        }
        let mut value = header::HeaderValue::from_bytes(&bytes)
            .map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        value.set_sensitive(true);
        Ok(Self(value))
    }
}

/// Unauthenticated read configuration. Only `authenticate` can produce the
/// scoped capability. Construction opens no socket and reads no environment.
pub struct ProviderClient {
    api_key: ApiKey,
    workspace_id: String,
    workspace_header: header::HeaderValue,
    tls: Arc<ClientConfig>,
    deadline: Instant,
    body_limit: NonZeroUsize,
    #[cfg(test)]
    test_address: Option<std::net::SocketAddr>,
}

/// Created only after `/auth/me` returns the exact configured workspace ID.
/// There is no mutation, generic HTTP, URL, or RPC method on this capability.
/// Authentication scope is kept distinct from optional per-item workspace data.
///
/// ```compile_fail
/// use zrpc_lifecycle::provider_http::ScopedReads;
/// fn duplicate(reads: &ScopedReads) -> ScopedReads { reads.clone() }
/// ```
///
/// ```compile_fail
/// use zrpc_lifecycle::provider_http::ScopedReads;
/// let reads: ScopedReads = serde_json::from_str("{}").unwrap();
/// ```
pub struct ScopedReads(ProviderClient);

/// A detail 404 reports only absence from this authenticated API response. It
/// proves neither complete inventory nor disappearance of attached storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CvmDetail {
    Present(provider_wire::Cvm),
    NotFound,
}

impl ProviderClient {
    /// Required positive invocation budget and body limit have no defaults.
    /// The same absolute deadline covers construction, authentication, every
    /// read, body collection and parsing; subsequent calls never renew it.
    /// Trust roots are explicit operator-trusted DER certificates. No system
    /// root discovery, certificate bypass or custom verifier is available.
    pub fn new(
        api_key: ApiKey,
        workspace_id: String,
        trust_roots: Vec<CertificateDer<'static>>,
        invocation_budget: Duration,
        body_limit: NonZeroUsize,
    ) -> Result<Self, ProviderHttpError> {
        let deadline = Instant::now()
            .checked_add(invocation_budget)
            .filter(|_| !invocation_budget.is_zero())
            .ok_or(ProviderHttpError::InvalidConfiguration)?;
        if workspace_id.trim().is_empty() || trust_roots.is_empty() {
            return Err(ProviderHttpError::InvalidConfiguration);
        }
        let workspace_header = header::HeaderValue::from_str(&workspace_id)
            .map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        let mut roots = RootCertStore::empty();
        for root in trust_roots {
            roots
                .add(root)
                .map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        }
        // Explicit Ring provider plus the maintained default WebPKI verifier:
        // normal chain, validity, name, signature and handshake verification.
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| ProviderHttpError::InvalidConfiguration)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        tls.enable_secret_extraction = false;
        tls.key_log = Arc::new(rustls::NoKeyLog);
        let client = Self {
            api_key,
            workspace_id,
            workspace_header,
            tls: Arc::new(tls),
            deadline,
            body_limit,
            #[cfg(test)]
            test_address: None,
        };
        client.finish(Ok(()))?;
        Ok(client)
    }

    pub async fn authenticate(self) -> Result<ScopedReads, ProviderHttpError> {
        let body = self.read(ReadRequest::Authenticate).await?;
        let identity = self.finish(
            provider_wire::parse_current_workspace(&body, self.body_limit.get())
                .map_err(|_| ProviderHttpError::InvalidResponse),
        )?;
        if identity.workspace_id != self.workspace_id {
            return self.finish(Err(ProviderHttpError::WorkspaceMismatch));
        }
        self.finish(Ok(()))?;
        Ok(ScopedReads(self))
    }

    fn finish<T>(&self, result: Result<T, ProviderHttpError>) -> Result<T, ProviderHttpError> {
        if Instant::now() >= self.deadline {
            Err(ProviderHttpError::DeadlineExceeded)
        } else {
            result
        }
    }

    async fn read(&self, request: ReadRequest<'_>) -> Result<Vec<u8>, ProviderHttpError> {
        self.finish(Ok(()))?;
        debug_assert_eq!(request.method(), "GET");
        let path = request
            .path_and_query()
            .map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        self.finish(Ok(()))?;
        let result = tokio::time::timeout_at(self.deadline, self.exchange(path))
            .await
            .map_err(|_| ProviderHttpError::DeadlineExceeded)?;
        self.finish(result)
    }

    async fn exchange(&self, path: String) -> Result<Vec<u8>, ProviderHttpError> {
        #[cfg(test)]
        let socket = match self.test_address {
            Some(address) => TcpStream::connect(address).await,
            None => TcpStream::connect((HOST, PORT)).await,
        };
        #[cfg(not(test))]
        let socket = TcpStream::connect((HOST, PORT)).await;
        let socket = socket.map_err(|_| ProviderHttpError::ConnectionFailed)?;
        let server_name =
            ServerName::try_from(HOST).map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        let stream = TlsConnector::from(self.tls.clone())
            .connect(server_name, socket)
            .await
            .map_err(|_| ProviderHttpError::TlsRejected)?;
        if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || stream.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice())
            || !matches!(
                stream.get_ref().1.handshake_kind(),
                Some(
                    rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest
                )
            )
        {
            return Err(ProviderHttpError::TlsRejected);
        }
        // No credential application bytes exist on the socket until ordinary
        // certificate/name verification and the TLS handshake have completed.
        self.finish(Ok(()))?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ProviderHttpError::HttpFailed)?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = Request::builder()
            .method(hyper::Method::GET)
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CONNECTION, "close")
            .header("X-API-Key", self.api_key.0.clone())
            .header("X-Phala-Version", provider_wire::PHALA_API_VERSION)
            .header("X-Phala-Workspace", self.workspace_header.clone())
            .body(Empty::<Bytes>::new())
            .map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        self.finish(Ok(()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| ProviderHttpError::HttpFailed)?;
        if response.status() != StatusCode::OK {
            // Drop all error bodies without decoding/logging them. In particular,
            // never follow Location, Retry-After, authentication or provider URLs.
            return Err(status_error(response.status()));
        }
        for encoding in response.headers().get_all(header::CONTENT_ENCODING) {
            if encoding.as_bytes() != b"identity" {
                return Err(ProviderHttpError::InvalidResponse);
            }
        }
        if let Some(length) = response.headers().get(header::CONTENT_LENGTH) {
            let length = length
                .to_str()
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(ProviderHttpError::InvalidResponse)?;
            if u128::from(length) > self.body_limit.get() as u128 {
                return Err(ProviderHttpError::BodyLimitExceeded);
            }
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| ProviderHttpError::HttpFailed)?;
            if let Some(data) = frame.data_ref() {
                let new_len = bytes
                    .len()
                    .checked_add(data.len())
                    .filter(|len| *len <= self.body_limit.get())
                    .ok_or(ProviderHttpError::BodyLimitExceeded)?;
                bytes
                    .try_reserve_exact(new_len - bytes.len())
                    .map_err(|_| ProviderHttpError::BodyLimitExceeded)?;
                bytes.extend_from_slice(data);
            } else if frame.trailers_ref().is_some() {
                // No documented response needs trailers; do not accept an
                // alternative location for identity/framing metadata.
                return Err(ProviderHttpError::InvalidResponse);
            }
        }
        Ok(bytes)
    }
}

impl ScopedReads {
    pub fn workspace_id(&self) -> &str {
        &self.0.workspace_id
    }

    pub async fn inventory_page(
        &mut self,
        page: u64,
        page_size: u64,
    ) -> Result<provider_wire::InventoryPage, ProviderHttpError> {
        let body = self
            .0
            .read(ReadRequest::Inventory { page, page_size })
            .await?;
        let result = provider_wire::parse_inventory_page(&body, self.0.body_limit.get())
            .map_err(|_| ProviderHttpError::InvalidResponse)
            .and_then(|result| {
                if result.page != page || result.page_size != page_size {
                    return Err(ProviderHttpError::InvalidResponse);
                }
                for item in &result.items {
                    self.check_workspace(item)?;
                }
                Ok(result)
            });
        self.0.finish(result)
    }

    pub async fn cvm_detail(&mut self, cvm_id: &str) -> Result<CvmDetail, ProviderHttpError> {
        let body = match self.0.read(ReadRequest::Detail { cvm_id }).await {
            Ok(body) => body,
            Err(ProviderHttpError::NotFound) => return self.0.finish(Ok(CvmDetail::NotFound)),
            Err(error) => return Err(error),
        };
        let result = provider_wire::parse_cvm_detail(&body, self.0.body_limit.get())
            .map_err(|_| ProviderHttpError::InvalidResponse)
            .and_then(|cvm| {
                self.check_workspace(&cvm)?;
                if cvm.id != cvm_id {
                    return Err(ProviderHttpError::InvalidResponse);
                }
                Ok(CvmDetail::Present(cvm))
            });
        self.0.finish(result)
    }

    /// Explicit original-start/cutoff window. This does not join either CVM
    /// identifier with usage.instance_id or convert rows to accepted charges.
    pub async fn usage_page(
        &mut self,
        app_id: &str,
        start_unix_seconds: u64,
        end_unix_seconds: u64,
        limit: u64,
        offset: u64,
    ) -> Result<provider_wire::UsagePage, ProviderHttpError> {
        let body = self
            .0
            .read(ReadRequest::Usage {
                app_id,
                start_unix_seconds,
                end_unix_seconds,
                limit,
                offset,
            })
            .await?;
        self.0.finish(
            provider_wire::parse_usage_page(&body, self.0.body_limit.get())
                .map_err(|_| ProviderHttpError::InvalidResponse),
        )
    }

    fn check_workspace(&self, cvm: &provider_wire::Cvm) -> Result<(), ProviderHttpError> {
        if cvm
            .workspace_id
            .as_ref()
            .is_some_and(|id| id != &self.0.workspace_id)
        {
            Err(ProviderHttpError::WorkspaceMismatch)
        } else {
            Ok(())
        }
    }
}

fn status_error(status: StatusCode) -> ProviderHttpError {
    match status {
        StatusCode::UNAUTHORIZED => ProviderHttpError::Unauthorized,
        StatusCode::FORBIDDEN => ProviderHttpError::Forbidden,
        StatusCode::NOT_FOUND => ProviderHttpError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => ProviderHttpError::RateLimited,
        status if status.is_redirection() => ProviderHttpError::RedirectRejected,
        status if status.is_server_error() => ProviderHttpError::ProviderUnavailable,
        _ => ProviderHttpError::UnexpectedStatus,
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests;
