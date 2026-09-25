//! Public-attestation-only TLS listener. No private RPC route or query authority.
use crate::attestation::{AttestationService, BootstrapLimits};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{
    ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::{CertifiedKey, SingleCertAndKey},
};
use std::{fmt, future::Future, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;
use zrpc_protocol::{ErrorCode, MAX_CONNECTION_LIFETIME_SECONDS, SafeError};

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "The public attestation listener is unavailable.",
    )
}

fn ephemeral_config() -> Result<Arc<ServerConfig>, SafeError> {
    let key =
        Zeroizing::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| unavailable())?);
    // Diagnostic name only: the native bootstrap does not trust certificate
    // names or PKI. Keep rcgen's documented 1975..4096 validity defaults; these
    // dates do not approve identity, freshness, deployment or a resource lease.
    let params = CertificateParams::new(vec!["localhost".into()]).map_err(|_| unavailable())?;
    let cert = params.self_signed(&*key).map_err(|_| unavailable())?;
    // Borrow the generated DER into the maintained Ring parser, without cloning
    // the serialized private key. Zeroizing wipes rcgen's serialized buffer on
    // every return path; no complete erasure claim is made for Ring internals.
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialized_der()));
    let signing_key =
        rustls::crypto::ring::sign::any_ecdsa_type(&der).map_err(|_| unavailable())?;
    let certified_key = CertifiedKey::new(vec![cert.der().clone()], signing_key);
    certified_key.keys_match().map_err(|_| unavailable())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| unavailable())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    // The pinned builder installs NeverProducesTickets. Fail closed if that
    // assumption changes in a future maintained dependency update.
    if config.ticketer.enabled() {
        return Err(unavailable());
    }
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.enable_secret_extraction = false;
    // Never consult SSLKEYLOGFILE or inherit a key logger from a caller.
    config.key_log = Arc::new(rustls::NoKeyLog);
    Ok(Arc::new(config))
}

/// Owns a freshly generated, process-local TLS identity and a public-only route.
/// It accepts no key/certificate input and exposes no key, TLS configuration,
/// stream or private-query API. Binding is an explicit local operator action;
/// callers remain responsible for choosing the permitted network interface.
///
/// ```compile_fail
/// fn cannot_export(listener: zrpc_server::bootstrap::BoundPublicListener) {
///     let key = listener.export_private_key();
/// }
/// ```
pub struct BoundPublicListener {
    socket: TcpListener,
    acceptor: TlsAcceptor,
    service: AttestationService,
}

impl BoundPublicListener {
    pub async fn bind(
        address: SocketAddr,
        dstack_socket: &Path,
        limits: BootstrapLimits,
    ) -> Result<Self, SafeError> {
        let service = AttestationService::new(dstack_socket, limits)?;
        let acceptor = TlsAcceptor::from(ephemeral_config()?);
        let socket = TcpListener::bind(address)
            .await
            .map_err(|_| unavailable())?;
        Ok(Self {
            socket,
            acceptor,
            service,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, SafeError> {
        self.socket.local_addr().map_err(|_| unavailable())
    }

    /// Run until explicit shutdown. Each accepted socket gets the design's
    /// original 300-second lifetime including TLS, HTTP and quote work. Excess
    /// sockets are closed before spawning a task or starting TLS. No peer address
    /// is retained or logged. Cancelling this future aborts its owned tasks.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), SafeError> {
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                // Prioritize shutdown and completed entries over new accepts;
                // completed tasks cannot accumulate behind a busy listen socket.
                biased;
                _ = &mut shutdown => {
                    tasks.shutdown().await;
                    return Ok(());
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
                accepted = self.socket.accept() => {
                    let (socket, _) = accepted.map_err(|_| unavailable())?;
                    let deadline = tokio::time::Instant::now()
                        + Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS);
                    let admission = match self.service.admit_connection() {
                        Ok(admission) => admission,
                        Err(_) => { drop(socket); continue; }
                    };
                    let acceptor = self.acceptor.clone();
                    let service = self.service.clone();
                    tasks.spawn(async move {
                        let stream = match tokio::time::timeout_at(deadline, acceptor.accept(socket)).await {
                            Ok(Ok(stream)) => stream,
                            _ => return,
                        };
                        // The service retains this same permit and deadline; it
                        // does not acquire twice or grant a new HTTP lifetime.
                        let _ = service.serve_admitted_connection(stream, admission, deadline).await;
                    });
                }
            }
        }
    }
}

impl fmt::Debug for BoundPublicListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundPublicListener([public attestation only; private mode unavailable])")
    }
}

#[cfg(test)]
mod tests;
