//! TLS handshake possession is not attested server identity or query authority.

use crate::{RequirePassword, UnverifiedChannel};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, HandshakeKind, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_socks::tcp::Socks5Stream;
use zrpc_protocol::{ErrorCode, MAX_CONNECTION_LIFETIME_SECONDS, SafeError};

mod attestation;
pub use attestation::{
    EndpointInspection, EndpointInspectionIssue, UnverifiedGcpEvidence, UnverifiedPublicEvidence,
    VerifiedRpcSession,
};

type BootstrapStream = TlsStream<Socks5Stream<RequirePassword<TcpStream>>>;

// Design §7 limits each connection to five minutes before a new handshake and
// challenge. This is an upper lifetime bound, not evidence of quote freshness.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS);
const ALPN: &[u8] = b"http/1.1";

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "Public TLS bootstrap failed; private queries remain unavailable.",
    )
}

/// Parse the peer certificate and verify its actual CertificateVerify signature,
/// while intentionally making no PKI or attestation identity assertion. This
/// verifier is private to a channel that cannot carry caller application bytes.
#[derive(Debug)]
struct BootstrapVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for BootstrapVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        rustls::server::ParsedCertificate::try_from(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General(
            "TLS 1.2 is not supported by the bootstrap policy".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn bootstrap_config() -> Result<Arc<ClientConfig>, SafeError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| unavailable())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BootstrapVerifier { provider }))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    config.enable_secret_extraction = false;
    // Never consult SSLKEYLOGFILE, even when inherited by the native process.
    config.key_log = Arc::new(rustls::NoKeyLog);
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

impl UnverifiedChannel {
    /// Perform TLS 1.3 on the already connected SOCKS socket. The hostname is
    /// carried from SOCKS CONNECT; there is no resolver, redirect, or reconnect.
    /// This verifies TLS key possession only. No certificate identity is trusted.
    pub async fn start_tls(self) -> Result<PublicBootstrapTls, SafeError> {
        let socket = self.socket.ok_or_else(unavailable)?;
        let authority = self.authority.ok_or_else(unavailable)?;
        let name = ServerName::try_from(self.server_name.ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        let stream = TlsConnector::from(bootstrap_config()?)
            .connect(name, socket)
            .await
            .map_err(|_| unavailable())?;
        let (_, connection) = stream.get_ref();
        if connection.is_handshaking()
            || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || !matches!(
                connection.handshake_kind(),
                Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
            )
            || connection.alpn_protocol() != Some(ALPN)
        {
            return Err(unavailable());
        }
        Ok(PublicBootstrapTls {
            stream,
            established: Instant::now(),
            authority,
        })
    }
}

/// An encrypted session whose peer owns its TLS key, with identity and
/// attestation still unchecked. No application or private-query write API exists.
///
/// ```compile_fail
/// use tokio::io::AsyncWriteExt;
/// async fn cannot_write(mut tls: zrpc_transport::PublicBootstrapTls) {
///     tls.write_all(b"private query").await.unwrap();
/// }
/// ```
/// ```compile_fail
/// fn cannot_extract(tls: zrpc_transport::PublicBootstrapTls) {
///     let stream = tls.into_inner();
/// }
/// ```
/// ```compile_fail
/// fn cannot_authorize(tls: zrpc_transport::PublicBootstrapTls) {
///     let _: zrpc_verifier::VerifiedChannel = tls.into();
/// }
/// ```
pub struct PublicBootstrapTls {
    // Retained to keep challenge ownership tied to this single TLS connection.
    stream: BootstrapStream,
    established: Instant,
    authority: String,
}

impl PublicBootstrapTls {
    fn ensure_live(&self) -> Result<(), SafeError> {
        if Instant::now()
            .checked_duration_since(self.established)
            .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            return Err(SafeError::new(
                ErrorCode::StaleNonce,
                "TLS bootstrap lifetime expired; establish a new connection.",
            ));
        }
        Ok(())
    }

    /// Generate the design's 32-byte challenge with the operating system RNG.
    /// Consuming the TLS value permits only one challenge for this connection.
    /// Nothing is sent to the peer, and no quote freshness has been checked.
    pub fn prepare_challenge(self) -> Result<PendingChallenge, SafeError> {
        self.ensure_live()?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| unavailable())?;
        Ok(PendingChallenge { tls: self, nonce })
    }

    pub fn private_rpc_allowed(&self) -> bool {
        false
    }
}

impl fmt::Debug for PublicBootstrapTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicBootstrapTls")
            .field(
                "tls13_handshake_complete",
                &!self.stream.get_ref().1.is_handshaking(),
            )
            .field("server_identity_verified", &false)
            .field("attestation_verified", &false)
            .field("private_rpc_allowed", &false)
            .finish()
    }
}

/// One fresh random challenge held with its original, unauthenticated TLS
/// session. Possessing this value is not evidence that a quote contains it.
///
/// ```compile_fail
/// fn cannot_authorize(challenge: zrpc_transport::PendingChallenge) {
///     let _: zrpc_verifier::VerifiedChannel = challenge.into();
/// }
/// ```
/// ```compile_fail
/// use tokio::io::AsyncWriteExt;
/// async fn cannot_write(mut challenge: zrpc_transport::PendingChallenge) {
///     challenge.write_all(b"private query").await.unwrap();
/// }
/// ```
pub struct PendingChallenge {
    tls: PublicBootstrapTls,
    nonce: [u8; 32],
}

impl PendingChallenge {
    /// Public challenge bytes only, while this connection is within its lifetime.
    pub fn nonce(&self) -> Result<&[u8; 32], SafeError> {
        self.tls.ensure_live()?;
        Ok(&self.nonce)
    }

    pub fn private_rpc_allowed(&self) -> bool {
        false
    }
}

impl fmt::Debug for PendingChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingChallenge")
            .field("server_identity_verified", &false)
            .field("quote_freshness_verified", &false)
            .field("live_key_binding_verified", &false)
            .field("private_rpc_allowed", &false)
            .finish()
    }
}

#[cfg(test)]
mod tests;
