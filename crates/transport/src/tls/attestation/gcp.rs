//! GCP evidence can authorize only the connection that produced its exporter.
use super::{
    EndpointInspection, EndpointInspectionIssue, PrivateDeadline, UnverifiedGcpEvidence,
    VerifiedRpcSession,
};
use crate::tls::MAX_CONNECTION_LIFETIME;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zrpc_protocol::{Backend, ErrorCode, GcpAttestationResponse, SafeError};
use zrpc_verifier::{
    ApprovedRelease, ReleasePolicy,
    gcp::{GcpWorkloadPolicy, inspect_gcp_workload_and_report_data},
    offline::InspectionStatus,
};

impl UnverifiedGcpEvidence {
    pub fn raw_unverified(&self) -> &GcpAttestationResponse {
        &self.evidence
    }
    pub fn private_rpc_allowed(&self) -> bool {
        false
    }

    /// Diagnostic policies can describe expected measurements but cannot grant
    /// release approval. Consuming this value also closes the original socket.
    pub fn inspect(self, collateral: &[u8], policy: &GcpWorkloadPolicy) -> EndpointInspection {
        self.inspect_against(collateral, policy)
    }

    pub fn authorize(
        self,
        collateral: &[u8],
        selection: &ReleasePolicy,
    ) -> Result<VerifiedRpcSession, SafeError> {
        let releases = ApprovedRelease::selected(selection)?;
        if !releases
            .iter()
            .any(|release| release.backend() == Backend::GcpTdx)
        {
            return Err(SafeError::new(
                ErrorCode::UnknownRelease,
                "This client has no selected reviewed GCP release.",
            ));
        }
        let collateral_deadline = releases.iter().find_map(|release| {
            release.gcp_workload().and_then(|policy| {
                let report = self.inspect_against_with_release(collateral, policy, Some(release));
                (report.diagnostic_passed()
                    && report
                        .gcp_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.private_acceptance_ready()))
                .then_some(report.private_collateral_deadline)
                .flatten()
            })
        });
        let Some(collateral_deadline) = collateral_deadline else {
            return Err(SafeError::new(
                ErrorCode::PrivateModeUnavailable,
                "Hardware, workload, provenance, freshness or live TLS key did not match a reviewed release.",
            ));
        };
        VerifiedRpcSession::from_authenticated_inspection(
            self.connection.session,
            self.connection.deadline,
            self.connection.authority,
            collateral_deadline,
        )
    }

    fn inspect_against(&self, collateral: &[u8], policy: &GcpWorkloadPolicy) -> EndpointInspection {
        self.inspect_against_with_release(collateral, policy, None)
    }

    fn inspect_against_with_release(
        &self,
        collateral: &[u8],
        policy: &GcpWorkloadPolicy,
        release: Option<&ApprovedRelease>,
    ) -> EndpointInspection {
        let mut report = EndpointInspection::new();
        report.platform = Backend::GcpTdx;
        self.check_session(&mut report);
        if report.issue.is_some() {
            return report;
        }
        let before = SystemTime::now();
        let Ok(before_unix) = before.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        report.local_clock = InspectionStatus::Verified;
        if self.evidence.nonce != self.connection.nonce {
            report.issue = Some(EndpointInspectionIssue::ChallengeMismatch);
            return report;
        }
        let (Ok(quote), Ok(ccel)) = (
            hex::decode(&self.evidence.quote),
            hex::decode(&self.evidence.ccel),
        ) else {
            report.issue = Some(EndpointInspectionIssue::MalformedQuoteEncoding);
            return report;
        };
        report.gcp_evidence = Some(match release {
            Some(release) => {
                let Some(inspection) = release.inspect_gcp_evidence(
                    &quote,
                    collateral,
                    &ccel,
                    &self.connection.expected_report_data,
                ) else {
                    return report;
                };
                inspection
            }
            None => inspect_gcp_workload_and_report_data(
                &quote,
                collateral,
                &ccel,
                policy,
                &self.connection.expected_report_data,
            ),
        });
        self.check_session(&mut report);
        let after_instant = Instant::now();
        let after = SystemTime::now();
        let Ok(after_unix) = after.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        let inspection = &report.gcp_evidence.as_ref().unwrap().workload.quote;
        match inspection.checked_at_unix_seconds {
            None => {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            }
            Some(checked)
                if after < before
                    || checked < before_unix.as_secs()
                    || checked > after_unix.as_secs() =>
            {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockChangedDuringInspection);
            }
            _ => {
                if let Some(expiration) = inspection.collateral_earliest_expiration_unix_seconds {
                    match PrivateDeadline::from_inspection_snapshot(
                        expiration,
                        after,
                        after_instant,
                    ) {
                        Some(deadline) => report.private_collateral_deadline = Some(deadline),
                        None => {
                            report.issue.get_or_insert(
                                EndpointInspectionIssue::CollateralExpiredDuringInspection,
                            );
                        }
                    }
                }
            }
        }
        report
    }

    fn check_session(&self, report: &mut EndpointInspection) {
        let now = Instant::now();
        if now >= self.connection.deadline
            || now
                .checked_duration_since(self.connection.established)
                .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            report.local_session_lifetime = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionExpired);
        } else {
            report.local_session_lifetime = InspectionStatus::Verified;
        }
        if self.connection.session.sender.is_closed()
            || self.connection.session.driver.is_finished()
        {
            report.session_observed_open = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionClosed);
        } else {
            report.session_observed_open = InspectionStatus::Verified;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{
        ALPN,
        tests::{
            assert_no_application_bytes,
            attestation_tests::{read_public_request, response, synthetic_body},
            connect_pair, server_config,
        },
    };
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    async fn fixture(
        body: impl FnOnce([u8; 32]) -> Vec<u8> + Send + 'static,
    ) -> (
        Result<UnverifiedGcpEvidence, SafeError>,
        tokio::task::JoinHandle<()>,
    ) {
        let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
        let pending = client.unwrap().prepare_challenge().unwrap();
        let mut server = server.unwrap();
        let task = tokio::spawn(async move {
            let nonce = read_public_request(&mut server).await.nonce;
            server
                .write_all(&response("200 OK", "", &body(nonce)))
                .await
                .unwrap();
            server.flush().await.unwrap();
            assert_no_application_bytes(server).await;
        });
        (pending.request_gcp_attestation().await, task)
    }

    fn body(nonce: [u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&GcpAttestationResponse {
            schema_version: 1,
            platform: Backend::GcpTdx,
            nonce,
            quote: "00".into(),
            ccel: "00".into(),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn gcp_rejects_phala_and_replayed_nonce_without_private_bytes() {
        let (result, peer) = fixture(synthetic_body).await;
        assert!(result.is_err());
        peer.await.unwrap();
        let (result, peer) = fixture(|mut nonce| {
            nonce[0] ^= 1;
            body(nonce)
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidNonce);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn gcp_fixture_cannot_authorize_retained_sender() {
        let (result, peer) = fixture(body).await;
        let evidence = result.unwrap();
        assert!(!evidence.private_rpc_allowed());
        assert_eq!(
            evidence
                .authorize(b"{}", &ReleasePolicy::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::UnknownRelease
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn gcp_synthetic_session_expiry_prevents_body_read_and_transmission() {
        let (result, peer) = fixture(body).await;
        let evidence = result.unwrap();
        // Unit-only construction bypasses the empty release catalog to test
        // the retained sender. No synthetic quote becomes accepted evidence.
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + Duration::from_millis(200),
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let mut body_read = false;
        let error = session
            .query_from_body(|| {
                body_read = true;
                Ok(b"SYNTHETIC_PRIVATE_CANARY".to_vec())
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ExpiredCollateral);
        assert!(!body_read);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn gcp_diagnostic_checks_connection_lifetime_before_evidence() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        evidence.connection.established = Instant::now() - MAX_CONNECTION_LIFETIME;
        evidence.connection.deadline = evidence.connection.established + MAX_CONNECTION_LIFETIME;
        let policy = GcpWorkloadPolicy::from_json(include_bytes!(
            "../../../../../tests/fixtures/gcp/policy.synthetic.json"
        ))
        .unwrap();
        let report = evidence.inspect(b"{}", &policy);
        assert_eq!(
            report.issue,
            Some(EndpointInspectionIssue::ConnectionExpired)
        );
        assert!(report.gcp_evidence.is_none());
        assert!(!report.diagnostic_passed() && !report.private_accepted && !report.query_sent);
        peer.await.unwrap();
    }
}
