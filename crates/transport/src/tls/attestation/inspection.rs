//! Diagnostic authentication consumes the session but never grants query authority.

use super::{PrivateDeadline, UnverifiedPublicEvidence, VerifiedRpcSession};
use crate::tls::MAX_CONNECTION_LIFETIME;
use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zrpc_protocol::Backend;
use zrpc_verifier::{
    ApprovedRelease, ReleasePolicy,
    gcp::BoundGcpWorkloadInspection,
    offline::InspectionStatus,
    workload::{BoundWorkloadInspection, WorkloadPolicy, inspect_workload_and_report_data},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointInspectionIssue {
    ConnectionExpired,
    ConnectionClosed,
    ClockUnavailable,
    ClockChangedDuringInspection,
    CollateralExpiredDuringInspection,
    MalformedQuoteEncoding,
    ChallengeMismatch,
}

/// The checks describe this inspection only, not an approved release or a
/// continuing connection capability. Raw evidence and identifiers are omitted.
#[derive(Debug, Serialize)]
pub struct EndpointInspection {
    pub operation: &'static str,
    pub platform: Backend,
    pub evidence: Option<BoundWorkloadInspection>,
    pub gcp_evidence: Option<BoundGcpWorkloadInspection>,
    pub local_session_lifetime: InspectionStatus,
    pub session_observed_open: InspectionStatus,
    pub local_clock: InspectionStatus,
    pub release_policy_provenance: InspectionStatus,
    pub approved_workload_ownership: InspectionStatus,
    pub freshness: InspectionStatus,
    pub live_key_binding: InspectionStatus,
    pub private_accepted: bool,
    pub query_sent: bool,
    pub network_used: bool,
    pub issue: Option<EndpointInspectionIssue>,
    // Only the authorization path consumes this in-memory timestamp. It is
    // derived from the authenticated QVL claim and never serialized as policy.
    #[serde(skip)]
    pub(super) private_collateral_deadline: Option<PrivateDeadline>,
}

impl EndpointInspection {
    pub(super) fn new() -> Self {
        Self {
            operation: "endpoint_evidence_inspection",
            platform: Backend::PhalaDstack,
            evidence: None,
            gcp_evidence: None,
            local_session_lifetime: InspectionStatus::NotChecked,
            session_observed_open: InspectionStatus::NotChecked,
            local_clock: InspectionStatus::NotChecked,
            release_policy_provenance: InspectionStatus::NotChecked,
            approved_workload_ownership: InspectionStatus::NotChecked,
            freshness: InspectionStatus::NotChecked,
            live_key_binding: InspectionStatus::NotChecked,
            private_accepted: false,
            query_sent: false,
            // Construction follows the consumed nonce-only public exchange.
            network_used: true,
            issue: None,
            private_collateral_deadline: None,
        }
    }

    /// Suitable for a diagnostic command's exit code only. Explicit local
    /// expectations are not approved release policy, and private mode remains
    /// unavailable even if every diagnostic comparison passes.
    pub fn diagnostic_passed(&self) -> bool {
        self.issue.is_none()
            && self.local_session_lifetime == InspectionStatus::Verified
            && self.session_observed_open == InspectionStatus::Verified
            && self.local_clock == InspectionStatus::Verified
            && (match self.platform {
                Backend::GcpTdx => self
                    .gcp_evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.diagnostic_passed()),
                Backend::PhalaDstack => self.evidence.as_ref().is_some_and(|evidence| {
                    let quote = &evidence.workload.quote;
                    quote.issue.is_none()
                        && evidence.workload.workload_issue.is_none()
                        && evidence.workload.runtime_event_integrity == InspectionStatus::Verified
                        && evidence.workload.os_measurement_policy == InspectionStatus::Verified
                        && evidence.workload.app_configuration_policy == InspectionStatus::Verified
                        && quote.hardware_authenticity == InspectionStatus::Verified
                        && quote.security_policy == InspectionStatus::Verified
                        && quote.workload_policy == InspectionStatus::Verified
                        && evidence.authenticated_report_data_match == InspectionStatus::Verified
                }),
            })
    }
}

impl UnverifiedPublicEvidence {
    /// Authenticate supplied collateral and the peer's quote/event log, compare
    /// an explicit local workload policy, and compare authenticated REPORTDATA
    /// with this original TLS session's private exporter. Provider report_data,
    /// vm_config, verification flags and timestamps are never authority inputs.
    ///
    /// This consumes and closes the session. CPU verification uses the current
    /// system clock; no historical clock, expected exporter or nonce can be
    /// supplied by callers. No private-query or VerifiedChannel result exists.
    pub fn inspect(
        self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        policy: &WorkloadPolicy,
    ) -> EndpointInspection {
        self.inspect_against(collateral_json, raw_app_compose, policy)
    }

    /// Only client-packaged reviewed releases can authorize the retained TLS
    /// sender. Every selected release is compared against authenticated quote
    /// claims and the exact session exporter; none are learned from the peer.
    pub fn authorize(
        self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        selection: &ReleasePolicy,
    ) -> Result<VerifiedRpcSession, zrpc_protocol::SafeError> {
        let releases = ApprovedRelease::selected(selection)?;
        if releases.is_empty() {
            return Err(zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::UnknownRelease,
                "This client has no selected reviewed release.",
            ));
        }
        let collateral_deadline = releases.iter().find_map(|release| {
            let Some(policy) = release.workload() else {
                return None;
            };
            if !release.matches_launch_config(raw_app_compose) {
                return None;
            }
            let report = self.inspect_against(collateral_json, raw_app_compose, policy);
            report
                .diagnostic_passed()
                .then_some(report.private_collateral_deadline)
                .flatten()
        });
        let Some(collateral_deadline) = collateral_deadline else {
            return Err(zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::PrivateModeUnavailable,
                "Hardware, workload, freshness or live TLS key did not match a reviewed release.",
            ));
        };
        // Ownership moves, so this is the same sender that received the quote.
        VerifiedRpcSession::from_authenticated_inspection(
            self._session,
            self.deadline,
            self.authority,
            collateral_deadline,
        )
    }

    fn inspect_against(
        &self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        policy: &WorkloadPolicy,
    ) -> EndpointInspection {
        let mut report = EndpointInspection::new();
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
        if self.evidence.nonce != self.nonce {
            report.issue = Some(EndpointInspectionIssue::ChallengeMismatch);
            return report;
        }
        let quote = match hex::decode(&self.evidence.quote) {
            Ok(quote) => quote,
            Err(_) => {
                report.issue = Some(EndpointInspectionIssue::MalformedQuoteEncoding);
                return report;
            }
        };
        report.evidence = Some(inspect_workload_and_report_data(
            &quote,
            collateral_json,
            self.evidence.event_log.as_bytes(),
            raw_app_compose,
            policy,
            &self.expected_report_data,
        ));
        // Recheck after synchronous cryptographic/event-log work: its cost must
        // not extend the original lifetime or leave a closed session accepted.
        self.check_session(&mut report);
        let after_instant = Instant::now();
        let after = SystemTime::now();
        let Ok(after_unix) = after.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        let inspection = &report.evidence.as_ref().unwrap().workload.quote;
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
                // The original authenticated validity instant is reported by
                // QVL. Evidence that expires during CPU work cannot pass now.
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
        if now >= self.deadline
            || now
                .checked_duration_since(self.established)
                .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            report.local_session_lifetime = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionExpired);
        } else {
            report.local_session_lifetime = InspectionStatus::Verified;
        }
        if self._session.sender.is_closed() || self._session.driver.is_finished() {
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
mod tests;
