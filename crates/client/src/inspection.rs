//! Shared native Tor/bootstrap core for diagnostics and reviewed private sessions.
use serde::Serialize;
use serde_json::Value;
use std::{
    net::SocketAddrV4,
    path::PathBuf,
    time::{Duration, Instant},
};
use zrpc_protocol::{
    Backend, ErrorCode, MAX_CONNECTION_LIFETIME_SECONDS, SafeError, TestnetTransparentAddress,
};
#[cfg(unix)]
use zrpc_transport::ManagedTor;
use zrpc_transport::{
    EndpointInspection, IsolationLabel, PublicTestnetPreview, RemoteEndpoint, TorConfig,
    UnverifiedGcpEvidence, UnverifiedPublicEvidence, VerifiedRpcSession,
};
use zrpc_verifier::{
    ReleasePolicy,
    gcp::GcpWorkloadPolicy,
    workload::{WorkloadInspection, WorkloadPolicy},
};

/// Explicit endpoint and numeric loopback SOCKS address. No discovery, defaults,
/// direct mode, proxy environment or caller-supplied stream-isolation secret.
#[derive(Debug)]
pub struct PublicInspectionConfig {
    platform: Backend,
    tor: TorConfig,
    endpoint: RemoteEndpoint,
}

impl PublicInspectionConfig {
    pub fn new(hostname: &str, port: u16, socks: &str) -> Result<Self, SafeError> {
        Self::for_platform(Backend::PhalaDstack, hostname, port, socks)
    }

    pub fn for_platform(
        platform: Backend,
        hostname: &str,
        port: u16,
        socks: &str,
    ) -> Result<Self, SafeError> {
        let address: SocketAddrV4 = socks.parse().map_err(|_| {
            SafeError::new(
                ErrorCode::TorUnavailable,
                "A numeric IPv4 loopback SOCKS address and nonzero port are required.",
            )
        })?;
        Ok(Self {
            platform,
            tor: TorConfig::new(address)?,
            endpoint: RemoteEndpoint::new(hostname, port)?,
        })
    }

    pub fn platform(&self) -> Backend {
        self.platform
    }
}

/// Genuine private sessions use a child process launched from the selected
/// local Tor installation. An arbitrary TCP SOCKS listener cannot construct
/// this configuration or be promoted by the transport authorization API.
pub struct PrivateEndpointConfig {
    platform: Backend,
    endpoint: RemoteEndpoint,
    tor_executable: PathBuf,
    #[cfg(unix)]
    tor: tokio::sync::OnceCell<ManagedTor>,
}

/// A separate TEE preview configuration; it cannot select a private release.
pub struct PreviewEndpointConfig {
    endpoint: RemoteEndpoint,
    tor_executable: PathBuf,
    #[cfg(unix)]
    tor: tokio::sync::OnceCell<ManagedTor>,
}

impl PreviewEndpointConfig {
    pub fn for_phala(
        hostname: &str,
        port: u16,
        tor_executable: impl Into<PathBuf>,
    ) -> Result<Self, SafeError> {
        let tor_executable = tor_executable.into();
        if !tor_executable.is_absolute() {
            return Err(SafeError::new(
                ErrorCode::TorUnavailable,
                "An absolute path to the local Tor executable is required.",
            ));
        }
        Ok(Self {
            endpoint: RemoteEndpoint::new(hostname, port)?,
            tor_executable,
            #[cfg(unix)]
            tor: tokio::sync::OnceCell::new(),
        })
    }

    pub fn platform(&self) -> Backend {
        Backend::PhalaDstack
    }
}

#[derive(Debug, Serialize)]
pub struct LiveTestnetPreview {
    pub inspection: EndpointInspection,
    pub public_preview_passed: bool,
    pub workload_identity_verified: bool,
    pub public_query_sent: Option<bool>,
    pub preview: Option<PublicTestnetPreview>,
    pub query_error: Option<SafeError>,
}

/// The same native public preview operation is called by the CLI and local
/// dashboard. It inspects the live quote on the retained TLS session before
/// sending only typed public testnet reads. No workload identity or reviewed
/// release is populated.
pub async fn preview_testnet(
    config: &PreviewEndpointConfig,
    collateral: &[u8],
    address: &TestnetTransparentAddress,
) -> Result<LiveTestnetPreview, SafeError> {
    #[cfg(not(unix))]
    return Err(SafeError::new(
        ErrorCode::TorUnavailable,
        "Managed local Tor requires a Unix-domain socket on this client platform.",
    ));
    #[cfg(unix)]
    {
        let tor = config
            .tor
            .get_or_try_init(|| async { ManagedTor::launch(&config.tor_executable) })
            .await?;
        let evidence = request_evidence_with(
            Backend::PhalaDstack,
            &config.endpoint,
            EvidenceTransport::Managed(tor),
        )
        .await?;
        let (inspection, session) = match evidence {
            NativeEvidence::Phala(evidence) => evidence.inspect_for_public_preview(collateral)?,
            _ => return Err(wrong_platform()),
        };
        let public_preview_passed = inspection.public_preview_passed();
        let Some(session) = session else {
            return Ok(LiveTestnetPreview {
                inspection,
                public_preview_passed,
                workload_identity_verified: false,
                public_query_sent: Some(false),
                preview: None,
                query_error: None,
            });
        };
        match session.public_testnet_preview(address).await {
            Ok(preview) => Ok(LiveTestnetPreview {
                inspection,
                public_preview_passed,
                workload_identity_verified: false,
                public_query_sent: Some(true),
                preview: Some(preview),
                query_error: None,
            }),
            Err(error) => Ok(LiveTestnetPreview {
                inspection,
                public_preview_passed,
                workload_identity_verified: false,
                public_query_sent: None,
                preview: None,
                query_error: Some(error),
            }),
        }
    }
}

/// Diagnose the current peer launch over the same managed-Tor, retained TLS
/// attestation exchange as the public preview. The connection is consumed;
/// this function has no RPC sender or reviewed-release acceptance path.
pub async fn inspect_preview_launch(
    config: &PreviewEndpointConfig,
    collateral: &[u8],
    raw_app_compose: &[u8],
    policy: &WorkloadPolicy,
) -> Result<(EndpointInspection, Option<WorkloadInspection>), SafeError> {
    #[cfg(not(unix))]
    return Err(SafeError::new(
        ErrorCode::TorUnavailable,
        "Managed local Tor requires a Unix-domain socket on this client platform.",
    ));
    #[cfg(unix)]
    {
        let tor = config
            .tor
            .get_or_try_init(|| async { ManagedTor::launch(&config.tor_executable) })
            .await?;
        let evidence = request_evidence_with(
            Backend::PhalaDstack,
            &config.endpoint,
            EvidenceTransport::Managed(tor),
        )
        .await?;
        match evidence {
            NativeEvidence::Phala(evidence) => {
                evidence.inspect_public_preview_launch(collateral, raw_app_compose, policy)
            }
            _ => Err(wrong_platform()),
        }
    }
}

impl PrivateEndpointConfig {
    pub fn for_platform(
        platform: Backend,
        hostname: &str,
        port: u16,
        tor_executable: impl Into<PathBuf>,
    ) -> Result<Self, SafeError> {
        let tor_executable = tor_executable.into();
        if !tor_executable.is_absolute() {
            return Err(SafeError::new(
                ErrorCode::TorUnavailable,
                "An absolute path to the local Tor executable is required.",
            ));
        }
        Ok(Self {
            platform,
            endpoint: RemoteEndpoint::new(hostname, port)?,
            tor_executable,
            #[cfg(unix)]
            tor: tokio::sync::OnceCell::new(),
        })
    }

    pub fn platform(&self) -> Backend {
        self.platform
    }
}

fn expired() -> SafeError {
    SafeError::new(
        ErrorCode::StaleNonce,
        "Public endpoint inspection exceeded the connection lifetime policy.",
    )
}

/// Sends a fresh public nonce only, then consumes the connection while locally
/// inspecting received evidence with supplied collateral and policy. No customer
/// RPC body is accepted, serialized or transmitted. A match is not release approval.
pub async fn inspect_endpoint(
    config: &PublicInspectionConfig,
    collateral_json: &[u8],
    raw_app_compose: &[u8],
    policy: &WorkloadPolicy,
) -> Result<EndpointInspection, SafeError> {
    if config.platform != Backend::PhalaDstack {
        return Err(wrong_platform());
    }
    let evidence = request_evidence(config).await?;
    match evidence {
        NativeEvidence::Phala(evidence) => {
            Ok(evidence.inspect(collateral_json, raw_app_compose, policy))
        }
        NativeEvidence::Gcp(_) => Err(wrong_platform()),
    }
}

pub async fn inspect_gcp_endpoint(
    config: &PublicInspectionConfig,
    collateral: &[u8],
    policy: &GcpWorkloadPolicy,
) -> Result<EndpointInspection, SafeError> {
    if config.platform != Backend::GcpTdx {
        return Err(wrong_platform());
    }
    match request_evidence(config).await? {
        NativeEvidence::Gcp(evidence) => Ok(evidence.inspect(collateral, policy)),
        NativeEvidence::Phala(_) => Err(wrong_platform()),
    }
}

fn wrong_platform() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidPolicy,
        "The evidence policy does not match the explicitly selected platform.",
    )
}

enum NativeEvidence {
    Phala(UnverifiedPublicEvidence),
    Gcp(UnverifiedGcpEvidence),
}

/// This is the only native promotion to a private-capable connection. It
/// retains the original Tor/TLS socket and cannot accept a diagnostic policy.
pub async fn connect_verified(
    config: &PrivateEndpointConfig,
    collateral_json: &[u8],
    raw_app_compose: &[u8],
    selection: &ReleasePolicy,
) -> Result<VerifiedRpcSession, SafeError> {
    // Reject unapproved local policy before dialing or receiving evidence.
    if config.platform == Backend::GcpTdx && !raw_app_compose.is_empty() {
        return Err(wrong_platform());
    }
    if !zrpc_verifier::ApprovedRelease::selected(selection)?
        .iter()
        .any(|release| release.backend() == config.platform)
    {
        return Err(SafeError::new(
            ErrorCode::UnknownRelease,
            "This client has no selected reviewed release.",
        ));
    }
    // Selection must succeed before a local Tor process is started. A cached
    // child is reused by dashboard requests; a dead child is never restarted.
    #[cfg(not(unix))]
    return Err(SafeError::new(
        ErrorCode::TorUnavailable,
        "Managed local Tor requires a Unix-domain socket on this client platform.",
    ));
    #[cfg(unix)]
    {
        let tor = config
            .tor
            .get_or_try_init(|| async { ManagedTor::launch(&config.tor_executable) })
            .await?;
        match request_evidence_with(
            config.platform,
            &config.endpoint,
            EvidenceTransport::Managed(tor),
        )
        .await?
        {
            NativeEvidence::Phala(evidence) => {
                evidence.authorize(collateral_json, raw_app_compose, selection)
            }
            NativeEvidence::Gcp(evidence) => evidence.authorize(collateral_json, selection),
        }
    }
}

/// Build/read query bytes only after approval, then parse the typed allowlist
/// and transmit through the retained original TLS sender.
pub async fn query_endpoint(
    config: &PrivateEndpointConfig,
    collateral_json: &[u8],
    raw_app_compose: &[u8],
    selection: &ReleasePolicy,
    body: impl FnOnce() -> Result<Vec<u8>, SafeError>,
) -> Result<Value, SafeError> {
    let session = connect_verified(config, collateral_json, raw_app_compose, selection).await?;
    session.query_from_body(body).await
}

async fn request_evidence(config: &PublicInspectionConfig) -> Result<NativeEvidence, SafeError> {
    request_evidence_with(
        config.platform,
        &config.endpoint,
        EvidenceTransport::Diagnostic(&config.tor),
    )
    .await
}

enum EvidenceTransport<'a> {
    Diagnostic(&'a TorConfig),
    #[cfg(unix)]
    Managed(&'a ManagedTor),
}

async fn request_evidence_with(
    platform: Backend,
    endpoint: &RemoteEndpoint,
    transport: EvidenceTransport<'_>,
) -> Result<NativeEvidence, SafeError> {
    // Fresh OS randomness per native session; its encoded isolation label is
    // never returned or logged. RFC1929's one-byte length accommodates 64 hex bytes.
    let mut isolation = [0u8; 32];
    getrandom::fill(&mut isolation).map_err(|_| {
        SafeError::new(
            ErrorCode::TorUnavailable,
            "Session randomness is unavailable.",
        )
    })?;
    let isolation = IsolationLabel::new(hex::encode(isolation))?;
    // Conservatively include dialing/handshake in the design §7 five-minute
    // connection budget rather than granting extra time before TLS completes.
    let lifetime = Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS);
    let started = Instant::now();
    let operation = async {
        let channel = match transport {
            EvidenceTransport::Diagnostic(tor) => {
                tor.connect_bootstrap(endpoint, isolation).await?
            }
            #[cfg(unix)]
            EvidenceTransport::Managed(tor) => tor.connect_bootstrap(endpoint, isolation).await?,
        };
        let pending = channel.start_tls().await?.prepare_challenge()?;
        match platform {
            Backend::PhalaDstack => pending
                .request_attestation()
                .await
                .map(NativeEvidence::Phala),
            Backend::GcpTdx => pending
                .request_gcp_attestation()
                .await
                .map(NativeEvidence::Gcp),
        }
    };
    let result = tokio::time::timeout(lifetime, operation)
        .await
        .map_err(|_| expired())?;
    // Synchronous quote verification cannot be preempted by an async timer.
    // Recheck elapsed time before returning its result.
    if started.elapsed() >= lifetime {
        return Err(expired());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_is_explicit_local_socks_and_endpoint_only() {
        assert!(PublicInspectionConfig::new("fixture.invalid", 443, "127.0.0.1:9050").is_ok());
        assert!(
            PublicInspectionConfig::for_platform(
                Backend::GcpTdx,
                "192.0.2.1",
                443,
                "127.0.0.1:9050"
            )
            .is_ok()
        );
        for (host, port, socks) in [
            ("https://fixture.invalid", 443, "127.0.0.1:9050"),
            ("fixture.invalid", 0, "127.0.0.1:9050"),
            ("fixture.invalid", 443, "localhost:9050"),
            ("fixture.invalid", 443, "192.0.2.1:9050"),
            ("fixture.invalid", 443, "127.0.0.1:0"),
        ] {
            assert!(PublicInspectionConfig::new(host, port, socks).is_err());
        }
    }

    #[tokio::test]
    async fn empty_reviewed_catalog_never_reads_query_or_opens_tor() {
        let config = PrivateEndpointConfig::for_platform(
            Backend::PhalaDstack,
            "fixture.invalid",
            443,
            "/missing/local/tor",
        )
        .unwrap();
        let result = query_endpoint(&config, b"{}", b"{}", &ReleasePolicy::default(), || {
            panic!("private body read before approval")
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::UnknownRelease);
        let config = PrivateEndpointConfig::for_platform(
            Backend::GcpTdx,
            "192.0.2.1",
            443,
            "/missing/local/tor",
        )
        .unwrap();
        let result = query_endpoint(&config, b"{}", b"", &ReleasePolicy::default(), || {
            panic!("GCP private body read before approval")
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::UnknownRelease);
    }

    #[tokio::test]
    async fn preview_requires_managed_local_tor_before_public_rpc() {
        assert!(PreviewEndpointConfig::for_phala("fixture.invalid", 443, "relative/tor").is_err());
        let config =
            PreviewEndpointConfig::for_phala("fixture.invalid", 443, "/missing/local/tor").unwrap();
        let address =
            TestnetTransparentAddress::parse(zrpc_protocol::PREVIEW_TESTNET_ADDRESS).unwrap();
        let error = preview_testnet(&config, b"{}", &address).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::TorUnavailable);
    }
}
