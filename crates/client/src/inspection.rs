//! Shared native public diagnostic. No private query input or authorization API.
use std::{
    net::SocketAddrV4,
    time::{Duration, Instant},
};
use zrpc_protocol::{ErrorCode, MAX_CONNECTION_LIFETIME_SECONDS, SafeError};
use zrpc_transport::{EndpointInspection, IsolationLabel, RemoteEndpoint, TorConfig};
use zrpc_verifier::workload::WorkloadPolicy;

/// Explicit endpoint and numeric loopback SOCKS address. No discovery, defaults,
/// direct mode, proxy environment or caller-supplied stream-isolation secret.
#[derive(Debug)]
pub struct PublicInspectionConfig {
    tor: TorConfig,
    endpoint: RemoteEndpoint,
}

impl PublicInspectionConfig {
    pub fn new(hostname: &str, port: u16, socks: &str) -> Result<Self, SafeError> {
        let address: SocketAddrV4 = socks.parse().map_err(|_| {
            SafeError::new(
                ErrorCode::TorUnavailable,
                "A numeric IPv4 loopback SOCKS address and nonzero port are required.",
            )
        })?;
        Ok(Self {
            tor: TorConfig::new(address)?,
            endpoint: RemoteEndpoint::new(hostname, port)?,
        })
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
        let evidence = pending.request_attestation().await?;
        Ok(evidence.inspect(collateral_json, raw_app_compose, policy))
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
    fn configuration_is_explicit_local_socks_and_dns_endpoint_only() {
        assert!(PublicInspectionConfig::new("fixture.invalid", 443, "127.0.0.1:9050").is_ok());
        for (host, port, socks) in [
            ("https://fixture.invalid", 443, "127.0.0.1:9050"),
            ("127.0.0.1", 443, "127.0.0.1:9050"),
            ("fixture.invalid", 0, "127.0.0.1:9050"),
            ("fixture.invalid", 443, "localhost:9050"),
            ("fixture.invalid", 443, "192.0.2.1:9050"),
            ("fixture.invalid", 443, "127.0.0.1:0"),
        ] {
            assert!(PublicInspectionConfig::new(host, port, socks).is_err());
        }
    }
}
