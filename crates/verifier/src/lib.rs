//! Fail-closed M0 integration boundary. No synthetic fact can mint an approval.
#![forbid(unsafe_code)]

pub mod offline;

use serde::{Deserialize, Serialize};
use zrpc_protocol::{ErrorCode, Network, SafeError};

/// M0 has no approved release measurements. An empty policy is deliberately
/// non-operational; selecting genuine measurement fields awaits gates A–D.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    pub schema_version: u32,
    pub network: Network,
    pub private_mode_enabled: bool,
    pub approved_release_ids: Vec<String>,
}

impl Default for ReleasePolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            network: Network::Testnet,
            private_mode_enabled: false,
            approved_release_ids: Vec::new(),
        }
    }
}

impl ReleasePolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SafeError> {
        if bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            != Some(b'{')
        {
            return Err(invalid_policy());
        }
        let policy: Self = serde_json::from_slice(bytes).map_err(|_| invalid_policy())?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), SafeError> {
        if self.schema_version != 1
            || self.private_mode_enabled
            || !self.approved_release_ids.is_empty()
        {
            return Err(invalid_policy());
        }
        Ok(())
    }
}

fn invalid_policy() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidPolicy,
        "M0 requires the disabled testnet policy with no approved releases.",
    )
}

/// Explicit classification only, never a verification result. M0 does not parse
/// purported quotes or use a provider's verification assertion as authority.
#[derive(Debug, Clone, Copy)]
pub enum UntrustedEvidence {
    Synthetic,
    ProviderAssertion { verified: bool },
    HardwareEvidenceNotIntegrated,
}

/// There is intentionally no constructible approval in M0. This type will only
/// acquire a constructor when the maintained verifier and live TLS session are
/// integrated and all feasibility gates have evidence.
///
/// ```compile_fail
/// use zrpc_verifier::VerifiedChannel;
/// let forged = VerifiedChannel {};
/// ```
///
/// ```compile_fail
/// let forged: zrpc_verifier::VerifiedChannel = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct VerifiedChannel {
    _genuine_session: GenuineSessionNotImplemented,
}

#[derive(Debug)]
enum GenuineSessionNotImplemented {}

pub struct Verifier;

impl Verifier {
    pub fn verify(
        policy: &ReleasePolicy,
        evidence: UntrustedEvidence,
    ) -> Result<VerifiedChannel, SafeError> {
        policy.validate()?;
        match evidence {
            UntrustedEvidence::Synthetic => Err(SafeError::new(
                ErrorCode::SimulationRejected,
                "Synthetic evidence cannot authorize private mode.",
            )),
            UntrustedEvidence::ProviderAssertion { .. }
            | UntrustedEvidence::HardwareEvidenceNotIntegrated => Err(SafeError::new(
                ErrorCode::PrivateModeUnavailable,
                "Genuine local hardware, workload, freshness, and live TLS-key verification are not integrated in M0.",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_assertion_and_synthetic_evidence_never_approve() {
        let policy = ReleasePolicy::default();
        for evidence in [
            UntrustedEvidence::Synthetic,
            UntrustedEvidence::ProviderAssertion { verified: true },
            UntrustedEvidence::ProviderAssertion { verified: false },
            UntrustedEvidence::HardwareEvidenceNotIntegrated,
        ] {
            assert!(Verifier::verify(&policy, evidence).is_err());
        }
    }

    #[test]
    fn policy_cannot_enable_private_mode_or_trust_server_releases() {
        let mut policy = ReleasePolicy::default();
        policy.private_mode_enabled = true;
        assert!(
            Verifier::verify(
                &policy,
                UntrustedEvidence::ProviderAssertion { verified: true }
            )
            .is_err()
        );
        policy.private_mode_enabled = false;
        policy
            .approved_release_ids
            .push("server-claims-approved".into());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn strict_policy_rejects_mainnet_unknown_and_duplicate_fields() {
        for raw in [
            r#"[1,"testnet",false,[]]"#,
            r#"{"schema_version":1,"network":"mainnet","private_mode_enabled":false,"approved_release_ids":[]}"#,
            r#"{"schema_version":1,"network":"testnet","private_mode_enabled":false,"approved_release_ids":[],"verified":true}"#,
            r#"{"schema_version":1,"network":"testnet","private_mode_enabled":false,"private_mode_enabled":true,"approved_release_ids":[]}"#,
        ] {
            assert!(ReleasePolicy::from_json(raw.as_bytes()).is_err());
        }
        let bytes = serde_json::to_vec(&ReleasePolicy::default()).unwrap();
        assert_eq!(
            ReleasePolicy::from_json(&bytes).unwrap(),
            ReleasePolicy::default()
        );
    }
}
