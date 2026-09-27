//! Shared native Tor/bootstrap core for diagnostics and reviewed private sessions.
use serde_json::Value;
use std::{
    net::SocketAddrV4,
    time::{Duration, Instant},
};
use zrpc_protocol::{Backend, ErrorCode, MAX_CONNECTION_LIFETIME_SECONDS, SafeError};
use zrpc_transport::{
    EndpointInspection, IsolationLabel, RemoteEndpoint, TorConfig, UnverifiedGcpEvidence,
    UnverifiedPublicEvidence, VerifiedRpcSession,
};
use zrpc_verifier::{ReleasePolicy, gcp::GcpWorkloadPolicy, workload::WorkloadPolicy};

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
    config: &PublicInspectionConfig,
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
    match request_evidence(config).await? {
        NativeEvidence::Phala(evidence) => {
            evidence.authorize(collateral_json, raw_app_compose, selection)
        }
        NativeEvidence::Gcp(evidence) => evidence.authorize(collateral_json, selection),
    }
}

/// Build/read query bytes only after approval, then parse the typed allowlist
/// and transmit through the retained original TLS sender.
pub async fn query_endpoint(
    config: &PublicInspectionConfig,
    collateral_json: &[u8],
    raw_app_compose: &[u8],
    selection: &ReleasePolicy,
    body: impl FnOnce() -> Result<Vec<u8>, SafeError>,
) -> Result<Value, SafeError> {
    let session = connect_verified(config, collateral_json, raw_app_compose, selection).await?;
    session.query_from_body(body).await
}

async fn request_evidence(config: &PublicInspectionConfig) -> Result<NativeEvidence, SafeError> {
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
        let channel = config
            .tor
            .connect_bootstrap(&config.endpoint, isolation)
            .await?;
        let pending = channel.start_tls().await?.prepare_challenge()?;
        match config.platform {
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
        let config = PublicInspectionConfig::new("fixture.invalid", 443, "127.0.0.1:9").unwrap();
        let result = query_endpoint(&config, b"{}", b"{}", &ReleasePolicy::default(), || {
            panic!("private body read before approval")
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::UnknownRelease);
        let config =
            PublicInspectionConfig::for_platform(Backend::GcpTdx, "192.0.2.1", 443, "127.0.0.1:9")
                .unwrap();
        let result = query_endpoint(&config, b"{}", b"", &ReleasePolicy::default(), || {
            panic!("GCP private body read before approval")
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::UnknownRelease);
    }
}
