//! GCP TDX offline workload appraisal, separate from release approval.
//!
//! CCEL descriptions and event types are not authenticated by RTMR replay.
//! This profile therefore matches the full ordered event reference, including
//! each description's digest, and requires the UKI event's PE/COFF digest from
//! an independently reconstructed artifact. No quote-to-policy generator or
//! "learn" mode exists. Firmware endorsements and artifact reconstruction are
//! reviewed offline before packaging a release; supplied policy is diagnostic.
mod ccel;

use crate::{
    offline::{self, InspectionStatus, OfflineInspection},
    workload::{ReportDataIssue, decode_hash, encode_hash},
};
use dcap_qvl::quote::TDReport10;
use ez_hash::{Hasher, Sha256, Sha384};
use serde::{Deserialize, Serialize};
use zrpc_protocol::MAX_ATTESTATION_RESPONSE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpArtifactPolicy {
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub firmware_endorsement_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub uki_sha256: [u8; 32],
    /// Authenticode/PE-COFF measurement, not SHA384 of the entire PE file.
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub uki_pe_coff_sha384: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rootfs_verity_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub kernel_command_line_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub boot_policy_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub wrapper_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub zebra_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub quote_broker_sha256: [u8; 32],
    /// Reviewed inputs and derivation linking the boot digests to these files.
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub measurement_recipe_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpEventPolicy {
    /// Intel CC MR index: 1..=4 corresponds to RTMR0..=RTMR3.
    pub mr_index: u32,
    pub event_type: u32,
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub digest_sha384: [u8; 48],
    /// Exact descriptor reference. This is not a claim the descriptor is itself
    /// measured: image-load descriptors describe bytes measured elsewhere.
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub event_data_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpWorkloadPolicy {
    pub schema_version: u32,
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub mrtd: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr0: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr1: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr2: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr3: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub spec_id_sha256: [u8; 32],
    pub artifacts: GcpArtifactPolicy,
    /// Index into expected_events, excluding the Spec ID header.
    pub uki_event_index: usize,
    pub expected_events: Vec<GcpEventPolicy>,
}

impl GcpWorkloadPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, GcpWorkloadIssue> {
        if bytes.len() > MAX_ATTESTATION_RESPONSE_BYTES {
            return Err(GcpWorkloadIssue::InvalidPolicy);
        }
        let shape: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| GcpWorkloadIssue::InvalidPolicy)?;
        if !shape.is_object()
            || !shape.get("artifacts").is_some_and(|a| a.is_object())
            || !shape
                .get("expected_events")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().all(|v| v.is_object()))
        {
            return Err(GcpWorkloadIssue::InvalidPolicy);
        }
        let policy: Self =
            serde_json::from_slice(bytes).map_err(|_| GcpWorkloadIssue::InvalidPolicy)?;
        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<(), GcpWorkloadIssue> {
        let uki = self
            .expected_events
            .get(self.uki_event_index)
            .ok_or(GcpWorkloadIssue::InvalidPolicy)?;
        // Google's TDX profile measures TDVF/Secure Boot configuration in
        // RTMR0 and the kernel/command line in RTMR2. An empty register or a
        // log containing only unextended EV_NO_ACTION records there cannot
        // bind either part of this appliance's boot policy.
        let has_extended_event = |index| {
            self.expected_events
                .iter()
                .any(|event| event.mr_index == index && event.event_type != ccel::EV_NO_ACTION)
        };
        if self.schema_version != 1
            || self
                .expected_events
                .iter()
                .any(|e| !(1..=4).contains(&e.mr_index))
            || !has_extended_event(1)
            || !has_extended_event(3)
            || uki.mr_index != 2
            || uki.event_type != ccel::EV_EFI_BOOT_SERVICES_APPLICATION
            || uki.digest_sha384 != self.artifacts.uki_pe_coff_sha384
        {
            return Err(GcpWorkloadIssue::InvalidPolicy);
        }
        // The image contains every executable/configuration input. These
        // commitments cannot be omitted or substituted with "not applicable".
        let a = &self.artifacts;
        if [
            a.firmware_endorsement_sha256,
            a.uki_sha256,
            a.rootfs_verity_sha256,
            a.kernel_command_line_sha256,
            a.boot_policy_sha256,
            a.wrapper_sha256,
            a.zebra_sha256,
            a.quote_broker_sha256,
            a.measurement_recipe_sha256,
        ]
        .contains(&[0; 32])
            || a.uki_pe_coff_sha384 == [0; 48]
            || self.mrtd == [0; 48]
            || self.rtmr0 == [0; 48]
            || self.rtmr1 == [0; 48]
            || self.rtmr2 == [0; 48]
        {
            return Err(GcpWorkloadIssue::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpWorkloadIssue {
    InvalidPolicy,
    MalformedCcel,
    UnsupportedCcel,
    UnsupportedTee,
    RuntimeMeasurementMismatch,
    FirmwareMeasurementMismatch,
    BootMeasurementMismatch,
    EventSequenceMismatch,
    EventDescriptorMismatch,
    EventContentDigestMismatch,
}

#[derive(Debug, Serialize)]
pub struct GcpWorkloadInspection {
    #[serde(flatten)]
    pub quote: OfflineInspection,
    pub policy_source: &'static str,
    pub ccel_integrity: InspectionStatus,
    pub firmware_policy: InspectionStatus,
    pub boot_artifact_policy: InspectionStatus,
    pub workload_issue: Option<GcpWorkloadIssue>,
}

#[derive(Debug, Serialize)]
pub struct BoundGcpWorkloadInspection {
    #[serde(flatten)]
    pub workload: GcpWorkloadInspection,
    pub authenticated_report_data_match: InspectionStatus,
    pub binding_issue: Option<ReportDataIssue>,
}

impl BoundGcpWorkloadInspection {
    /// Diagnostic agreement only. Session authorization additionally requires
    /// a client-packaged ApprovedRelease and retained exporter-owning transport.
    pub fn diagnostic_passed(&self) -> bool {
        let q = &self.workload.quote;
        [
            q.hardware_authenticity,
            q.security_policy,
            q.workload_policy,
            self.workload.ccel_integrity,
            self.workload.firmware_policy,
            self.workload.boot_artifact_policy,
            self.authenticated_report_data_match,
        ]
        .iter()
        .all(|s| *s == InspectionStatus::Verified)
            && self.workload.workload_issue.is_none()
            && self.binding_issue.is_none()
    }
}

pub fn inspect_gcp_workload(
    quote: &[u8],
    collateral_json: &[u8],
    ccel: &[u8],
    policy: &GcpWorkloadPolicy,
) -> GcpWorkloadInspection {
    inspect_using(ccel, policy, None, |inspect| {
        offline::inspect_quote_with_claims(quote, collateral_json, inspect)
    })
    .workload
}

pub fn inspect_gcp_workload_and_report_data(
    quote: &[u8],
    collateral_json: &[u8],
    ccel: &[u8],
    policy: &GcpWorkloadPolicy,
    expected: &[u8; 64],
) -> BoundGcpWorkloadInspection {
    inspect_using(ccel, policy, Some(expected), |inspect| {
        offline::inspect_quote_with_claims(quote, collateral_json, inspect)
    })
}

fn inspect_using(
    ccel: &[u8],
    policy: &GcpWorkloadPolicy,
    expected: Option<&[u8; 64]>,
    inspect_quote: impl FnOnce(&mut dyn FnMut(&dcap_qvl::QuoteClaims)) -> OfflineInspection,
) -> BoundGcpWorkloadInspection {
    let mut checks = Checks::default();
    let mut report_data = InspectionStatus::NotChecked;
    let mut issue = None;
    let mut quote = inspect_quote(&mut |claims| {
        // No unauthenticated quote field reaches replay or policy comparison.
        if let Some(td) = claims.report.as_td10() {
            if let Some(expected) = expected {
                report_data = if td.report_data == *expected {
                    InspectionStatus::Verified
                } else {
                    InspectionStatus::Rejected
                };
            }
            issue = check(td, ccel, policy, &mut checks).err();
        } else {
            issue = Some(GcpWorkloadIssue::UnsupportedTee);
        }
    });
    quote.operation = "offline_gcp_workload_inspection";
    if issue.is_some() {
        quote.workload_policy = InspectionStatus::Rejected;
    } else if checks.artifacts == InspectionStatus::Verified {
        quote.workload_policy = InspectionStatus::Verified;
    }
    BoundGcpWorkloadInspection {
        workload: GcpWorkloadInspection {
            quote,
            policy_source: "explicit_local_input_not_release_approval",
            ccel_integrity: checks.replay,
            firmware_policy: checks.firmware,
            boot_artifact_policy: checks.artifacts,
            workload_issue: issue,
        },
        authenticated_report_data_match: report_data,
        binding_issue: (report_data == InspectionStatus::Rejected)
            .then_some(ReportDataIssue::AuthenticatedReportDataMismatch),
    }
}

struct Checks {
    replay: InspectionStatus,
    firmware: InspectionStatus,
    artifacts: InspectionStatus,
}
impl Default for Checks {
    fn default() -> Self {
        Self {
            replay: InspectionStatus::NotChecked,
            firmware: InspectionStatus::NotChecked,
            artifacts: InspectionStatus::NotChecked,
        }
    }
}

fn check(
    td: &TDReport10,
    bytes: &[u8],
    policy: &GcpWorkloadPolicy,
    checks: &mut Checks,
) -> Result<(), GcpWorkloadIssue> {
    policy.validate()?;
    checks.replay = InspectionStatus::Rejected;
    let log = ccel::parse(bytes)?;
    let registers = [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3];
    if ccel::replay(&log.events) != registers {
        return Err(GcpWorkloadIssue::RuntimeMeasurementMismatch);
    }
    checks.replay = InspectionStatus::Verified;
    checks.firmware = InspectionStatus::Rejected;
    if td.mr_td != policy.mrtd {
        return Err(GcpWorkloadIssue::FirmwareMeasurementMismatch);
    }
    checks.firmware = InspectionStatus::Verified;
    checks.artifacts = InspectionStatus::Rejected;
    if registers != [policy.rtmr0, policy.rtmr1, policy.rtmr2, policy.rtmr3] {
        return Err(GcpWorkloadIssue::BootMeasurementMismatch);
    }
    if log.events.len() != policy.expected_events.len()
        || Sha256::hash(log.spec_id) != policy.spec_id_sha256
    {
        return Err(GcpWorkloadIssue::EventSequenceMismatch);
    }
    for (event, expected) in log.events.iter().zip(&policy.expected_events) {
        if event.mr_index != expected.mr_index
            || event.event_type != expected.event_type
            || event.digest != expected.digest_sha384
        {
            return Err(GcpWorkloadIssue::EventSequenceMismatch);
        }
        if Sha256::hash(event.data) != expected.event_data_sha256 {
            return Err(GcpWorkloadIssue::EventDescriptorMismatch);
        }
        // These event formats hash the complete data. PE/COFF and IPL events
        // instead hash external artifacts and must match reconstructed references.
        if matches!(
            event.event_type,
            4 | 5 | 0x8000_0001 | 0x8000_0007 | 0x8000_00e0
        ) && Sha384::hash(event.data) != event.digest
        {
            return Err(GcpWorkloadIssue::EventContentDigestMismatch);
        }
    }
    checks.artifacts = InspectionStatus::Verified;
    Ok(())
}

#[cfg(test)]
mod tests;
