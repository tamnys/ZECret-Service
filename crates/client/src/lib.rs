//! Shared CLI/dashboard client. Simulation and genuine approval have no conversion.
#![forbid(unsafe_code)]

use serde::Serialize;
use serde_json::Value;
use std::str::FromStr;
use zrpc_protocol::{ChainReadiness, ErrorCode, SafeError, parse_request};
use zrpc_server::{FixtureServer, NodeState};
use zrpc_transport::{RpcChannel, UnverifiedChannel};
use zrpc_verifier::{ReleasePolicy, UntrustedEvidence, VerifiedChannel, Verifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    NotChecked,
    NotConnected,
    SimulatedMatch,
    SimulatedRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    pub transport: CheckStatus,
    pub hardware: CheckStatus,
    pub application: CheckStatus,
    pub security_policy: CheckStatus,
    pub key_binding: CheckStatus,
    pub freshness: CheckStatus,
}

impl VerificationReport {
    fn not_checked() -> Self {
        Self {
            transport: CheckStatus::NotConnected,
            hardware: CheckStatus::NotChecked,
            application: CheckStatus::NotChecked,
            security_policy: CheckStatus::NotChecked,
            key_binding: CheckStatus::NotChecked,
            freshness: CheckStatus::NotChecked,
        }
    }

    fn synthetic() -> Self {
        Self {
            transport: CheckStatus::SimulatedMatch,
            hardware: CheckStatus::SimulatedMatch,
            application: CheckStatus::SimulatedMatch,
            security_policy: CheckStatus::SimulatedMatch,
            key_binding: CheckStatus::SimulatedMatch,
            freshness: CheckStatus::SimulatedMatch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClientReport {
    pub mode: &'static str,
    pub simulation: bool,
    pub private_accepted: bool,
    /// Actual network query transmission, always false in M0.
    pub query_sent: bool,
    /// Local in-memory fixture invocation, separately labeled from query_sent.
    pub fixture_dispatched: bool,
    pub serialized_rpc_bodies: u64,
    pub outbound_rpc_requests: u64,
    pub verification: VerificationReport,
    pub chain_readiness: ChainReadiness,
    pub release_identity: Option<&'static str>,
    pub policy_version: u32,
    pub client_observed_round_trip_micros: Option<u64>,
    pub server_reported_processing_micros: Option<u64>,
    pub retention_policy: &'static str,
    pub result: Option<Value>,
    pub error: Option<SafeError>,
}

impl ClientReport {
    fn blocked(error: SafeError) -> Self {
        Self {
            mode: "private_blocked",
            simulation: false,
            private_accepted: false,
            query_sent: false,
            fixture_dispatched: false,
            serialized_rpc_bodies: 0,
            outbound_rpc_requests: 0,
            verification: VerificationReport::not_checked(),
            chain_readiness: ChainReadiness::NotChecked,
            release_identity: None,
            policy_version: 1,
            client_observed_round_trip_micros: None,
            server_reported_processing_micros: None,
            retention_policy: "No private session exists. Retention behavior of a cloud release has not been verified.",
            result: None,
            error: Some(error),
        }
    }

    fn simulation() -> Self {
        Self {
            mode: "simulation_fixture_only",
            simulation: true,
            private_accepted: false,
            query_sent: false,
            fixture_dispatched: false,
            serialized_rpc_bodies: 0,
            outbound_rpc_requests: 0,
            verification: VerificationReport::synthetic(),
            chain_readiness: ChainReadiness::NotChecked,
            release_identity: Some("synthetic-m0-fixture-not-a-release"),
            policy_version: 1,
            client_observed_round_trip_micros: None,
            server_reported_processing_micros: None,
            retention_policy: "Synthetic local fixture only; no cloud retention claim or proof of deletion.",
            result: None,
            error: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    #[default]
    Fixture,
    UnknownRelease,
    WrongKey,
    InvalidNonce,
    StaleNonce,
    AlteredEventLog,
    ExpiredCollateral,
    UnacceptableTcb,
    DebugImage,
    TorUnavailable,
    NodeUnavailable,
}

impl Scenario {
    pub const ALL: &'static [Self] = &[
        Self::Fixture,
        Self::UnknownRelease,
        Self::WrongKey,
        Self::InvalidNonce,
        Self::StaleNonce,
        Self::AlteredEventLog,
        Self::ExpiredCollateral,
        Self::UnacceptableTcb,
        Self::DebugImage,
        Self::TorUnavailable,
        Self::NodeUnavailable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::UnknownRelease => "unknown-release",
            Self::WrongKey => "wrong-key",
            Self::InvalidNonce => "invalid-nonce",
            Self::StaleNonce => "stale-nonce",
            Self::AlteredEventLog => "altered-event-log",
            Self::ExpiredCollateral => "expired-collateral",
            Self::UnacceptableTcb => "unacceptable-tcb",
            Self::DebugImage => "debug-image",
            Self::TorUnavailable => "tor-unavailable",
            Self::NodeUnavailable => "node-unavailable",
        }
    }
}

impl FromStr for Scenario {
    type Err = SafeError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|scenario| scenario.as_str() == value)
            .ok_or(SafeError::new(
                ErrorCode::InvalidParameters,
                "Unknown simulation scenario.",
            ))
    }
}

/// A simulation cannot become a genuine private client or channel.
///
/// ```compile_fail
/// let approved: zrpc_verifier::VerifiedChannel = zrpc_client::SimulationClient.into();
/// ```
pub struct SimulationClient;

impl SimulationClient {
    pub fn query(bytes: &[u8], scenario: Scenario) -> ClientReport {
        let mut report = ClientReport::simulation();
        let rejection = match scenario {
            Scenario::Fixture | Scenario::NodeUnavailable => None,
            Scenario::UnknownRelease => {
                report.verification.application = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::UnknownRelease,
                    "SIMULATED rejection: unknown approved release.",
                ))
            }
            Scenario::WrongKey => {
                report.verification.key_binding = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::WrongKey,
                    "SIMULATED rejection: connection key mismatch.",
                ))
            }
            Scenario::InvalidNonce => {
                report.verification.freshness = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::InvalidNonce,
                    "SIMULATED rejection: nonce mismatch.",
                ))
            }
            Scenario::StaleNonce => {
                report.verification.freshness = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::StaleNonce,
                    "SIMULATED rejection: stale challenge.",
                ))
            }
            Scenario::AlteredEventLog => {
                report.verification.application = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::AlteredEventLog,
                    "SIMULATED rejection: event-log mismatch.",
                ))
            }
            Scenario::ExpiredCollateral => {
                report.verification.hardware = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::ExpiredCollateral,
                    "SIMULATED rejection: expired collateral.",
                ))
            }
            Scenario::UnacceptableTcb => {
                report.verification.security_policy = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::UnacceptableTcb,
                    "SIMULATED rejection: unacceptable TCB status.",
                ))
            }
            Scenario::DebugImage => {
                report.verification.security_policy = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::DebugImage,
                    "SIMULATED rejection: debug image.",
                ))
            }
            Scenario::TorUnavailable => {
                report.verification = VerificationReport::not_checked();
                report.verification.transport = CheckStatus::SimulatedRejected;
                Some(SafeError::new(
                    ErrorCode::TorUnavailable,
                    "SIMULATED rejection: Tor unavailable; no fallback.",
                ))
            }
        };
        if let Some(error) = rejection {
            report.error = Some(error);
            return report;
        }
        let request = match parse_request(bytes) {
            Ok(request) => request,
            Err(error) => {
                report.error = Some(error);
                return report;
            }
        };
        let state = if scenario == Scenario::NodeUnavailable {
            NodeState::Unavailable
        } else {
            NodeState::FixtureAvailable
        };
        report.fixture_dispatched = true;
        match FixtureServer::dispatch(&request, state) {
            Ok(value) => {
                report.chain_readiness = ChainReadiness::Synthetic;
                report.result = Some(value);
            }
            Err(error) => {
                report.chain_readiness = ChainReadiness::Unavailable;
                report.error = Some(error);
            }
        }
        report
    }
}

/// State machine owns its state; only genuine verifier output can advance it.
pub struct PrivateSession<State> {
    state: State,
}

impl Default for PrivateSession<UnverifiedChannel> {
    fn default() -> Self {
        Self {
            state: UnverifiedChannel::new(),
        }
    }
}

impl PrivateSession<UnverifiedChannel> {
    pub fn verify(
        self,
        policy: &ReleasePolicy,
        evidence: UntrustedEvidence,
    ) -> Result<PrivateSession<VerifiedChannel>, SafeError> {
        Verifier::verify(policy, evidence).map(|state| PrivateSession { state })
    }
}

impl PrivateSession<VerifiedChannel> {
    /// This method is not available on PrivateSession<UnverifiedChannel>.
    pub fn query(self, bytes: &[u8]) -> Result<(), SafeError> {
        let request = parse_request(bytes)?;
        RpcChannel::from_verified(self.state).query(&request)
    }
}

/// Default private entrypoint. It never falls back to fixtures or direct networking.
///
/// ```compile_fail
/// use zrpc_client::PrivateSession;
/// use zrpc_transport::UnverifiedChannel;
/// PrivateSession::<UnverifiedChannel>::default().query(b"private query");
/// ```
#[derive(Default)]
pub struct PrivateClient {
    policy: ReleasePolicy,
}

impl PrivateClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_policy(policy: ReleasePolicy) -> Result<Self, SafeError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn verify(&self) -> ClientReport {
        self.query_deferred(Vec::new)
    }

    pub fn query(&self, bytes: &[u8]) -> ClientReport {
        self.query_deferred(|| bytes.to_vec())
    }

    /// The body builder is not invoked until a genuine verified session exists.
    /// Passing serialization here keeps even serialization behind the gate.
    pub fn query_deferred(&self, body: impl FnOnce() -> Vec<u8>) -> ClientReport {
        let bootstrap = PrivateSession::<UnverifiedChannel>::default();
        match bootstrap.verify(
            &self.policy,
            UntrustedEvidence::HardwareEvidenceNotIntegrated,
        ) {
            Err(error) => ClientReport::blocked(error),
            Ok(session) => {
                // Unreachable in M0: VerifiedChannel is an uninhabited sealed type.
                let error = session.query(&body()).err().unwrap_or(SafeError::new(
                    ErrorCode::PrivateModeUnavailable,
                    "M0 does not support private RPC completion.",
                ));
                ClientReport::blocked(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const QUERY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;

    #[test]
    fn all_simulated_attestation_and_tor_failures_prevent_fixture_dispatch() {
        for scenario in Scenario::ALL
            .iter()
            .copied()
            .filter(|scenario| !matches!(scenario, Scenario::Fixture | Scenario::NodeUnavailable))
        {
            let report = SimulationClient::query(QUERY, scenario);
            assert!(report.simulation);
            assert!(!report.private_accepted);
            assert!(!report.query_sent);
            assert!(!report.fixture_dispatched);
            assert_eq!(report.serialized_rpc_bodies, 0);
            assert_eq!(report.outbound_rpc_requests, 0);
            assert!(report.error.is_some());
        }
    }

    #[test]
    fn positive_fixture_is_never_private_acceptance() {
        let report = SimulationClient::query(QUERY, Scenario::Fixture);
        assert!(report.simulation && report.fixture_dispatched);
        assert!(!report.private_accepted && !report.query_sent);
        assert_eq!(report.chain_readiness, ChainReadiness::Synthetic);
        assert_eq!(report.result.unwrap()["result"], 42);
    }

    #[test]
    fn private_failure_does_not_build_serialize_or_dispatch_body() {
        let built = Cell::new(false);
        let report = PrivateClient::new().query_deferred(|| {
            built.set(true);
            panic!("private query body must not be built before verification")
        });
        assert!(!built.get());
        assert!(!report.query_sent && !report.fixture_dispatched && !report.private_accepted);
        assert_eq!(report.serialized_rpc_bodies, 0);
        assert_eq!(report.outbound_rpc_requests, 0);
        assert!(!report.simulation);
    }

    #[test]
    fn provider_assertions_and_fixture_evidence_cannot_advance_state() {
        for evidence in [
            UntrustedEvidence::Synthetic,
            UntrustedEvidence::ProviderAssertion { verified: true },
        ] {
            assert!(
                PrivateSession::<UnverifiedChannel>::default()
                    .verify(&ReleasePolicy::default(), evidence)
                    .is_err()
            );
        }
    }

    #[test]
    fn marker_does_not_escape_private_failure_or_fixture_parser_error() {
        let bytes =
            br#"{"jsonrpc":"2.0","id":1,"method":"forbidden","seed":"SYNTHETIC_QUERY_MARKER"}"#;
        for report in [
            PrivateClient::new().query(bytes),
            SimulationClient::query(bytes, Scenario::Fixture),
        ] {
            assert!(
                !serde_json::to_string(&report)
                    .unwrap()
                    .contains("SYNTHETIC_QUERY_MARKER")
            );
            assert!(!format!("{report:?}").contains("SYNTHETIC_QUERY_MARKER"));
        }
    }

    #[test]
    fn unavailable_node_is_distinct_from_verification_rejection() {
        let report = SimulationClient::query(QUERY, Scenario::NodeUnavailable);
        assert!(report.fixture_dispatched);
        assert_eq!(report.chain_readiness, ChainReadiness::Unavailable);
        assert_eq!(report.error.unwrap().code, ErrorCode::NodeUnavailable);
        assert!(!report.query_sent);
    }

    #[test]
    fn scenario_names_roundtrip() {
        for scenario in Scenario::ALL {
            assert_eq!(scenario.as_str().parse::<Scenario>().unwrap(), *scenario);
        }
        assert!("live-verified".parse::<Scenario>().is_err());
    }
}
