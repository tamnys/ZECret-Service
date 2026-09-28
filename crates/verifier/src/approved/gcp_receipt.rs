//! Exact, client-packaged GCP candidate receipt binding.
//!
//! A receipt can show that two embedded documents name the same inputs. It
//! cannot prove that a separate tool examined those inputs or that a VM booted
//! them. No value in this module is a runtime provenance or private-mode grant.

use super::GcpReleaseManifest;
use crate::{
    gcp::{GcpProviderIdentity, GcpWorkloadPolicy},
    invalid_policy,
    workload::decode_hash,
};
use ez_hash::{Hasher, Sha256};
use serde::Deserialize;
use serde_json::Value;
use zrpc_protocol::SafeError;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptStatus {
    ReferenceBindingOnlyUnapproved,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GcpCandidateReceipt {
    schema_version: u32,
    status: ReceiptStatus,
    release_id: String,
    source_commit: String,
    /// The signed endorsement must later be independently checked against the
    /// exact firmware bytes; this field alone does not perform that check.
    #[serde(deserialize_with = "decode_hash")]
    firmware_sha384: [u8; 48],
    /// Identities of separate offline validation outputs. Their content and
    /// derivation are a future release gate, not established by this parser.
    #[serde(deserialize_with = "decode_hash")]
    firmware_validation_report_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash")]
    artifact_validation_report_sha256: [u8; 32],
    #[serde(deserialize_with = "decode_hash")]
    provider_validation_report_sha256: [u8; 32],
    workload: GcpWorkloadPolicy,
    provider: GcpProviderIdentity,
}

/// Retained only by an embedded GCP release. Its private fields and absence of
/// authorization methods prevent a candidate receipt becoming a trust flag.
pub(super) struct BoundGcpCandidateReceipt {
    _sha256: [u8; 32],
}

/// Serde can deserialize a struct from a positional array. Require objects at
/// each authority-bearing level before parsing the exact bytes again, so the
/// typed parser can also reject duplicate keys and unknown fields.
pub(super) fn has_gcp_document_shape(bytes: &[u8]) -> bool {
    let Ok(Value::Object(root)) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let Some(Value::Object(workload)) = root.get("workload") else {
        return false;
    };
    root.get("provider").is_some_and(Value::is_object)
        && workload.get("artifacts").is_some_and(Value::is_object)
        && workload
            .get("expected_events")
            .and_then(Value::as_array)
            .is_some_and(|events| events.iter().all(Value::is_object))
}

pub(super) fn bind(
    manifest: &GcpReleaseManifest,
    bytes: &[u8],
    embedded_sha256: [u8; 32],
) -> Result<BoundGcpCandidateReceipt, SafeError> {
    if embedded_sha256 == [0; 32]
        || embedded_sha256 != manifest.candidate_receipt_sha256
        || Sha256::hash(bytes) != embedded_sha256
        || !has_gcp_document_shape(bytes)
    {
        return Err(invalid_policy());
    }
    let receipt: GcpCandidateReceipt =
        serde_json::from_slice(bytes).map_err(|_| invalid_policy())?;
    if receipt.schema_version != 1
        || !matches!(
            receipt.status,
            ReceiptStatus::ReferenceBindingOnlyUnapproved
        )
        || receipt.release_id != manifest.release_id
        || receipt.source_commit != manifest.source_commit
        || receipt.firmware_sha384 == [0; 48]
        || receipt.firmware_validation_report_sha256 == [0; 32]
        || receipt.artifact_validation_report_sha256 == [0; 32]
        || receipt.provider_validation_report_sha256 == [0; 32]
        || receipt.workload != manifest.workload
        || receipt.provider != manifest.provider
    {
        return Err(invalid_policy());
    }
    Ok(BoundGcpCandidateReceipt {
        _sha256: embedded_sha256,
    })
}
