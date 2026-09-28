//! Reviewed client-packaged releases, separate from diagnostic workload inputs.
//!
//! An embedded entry requires review of the exact manifest bytes and digest as
//! part of a new native-client release. No runtime file, fixture, provider flag,
//! or first-seen quote can append to this table. It is deliberately empty until
//! provider-specific image, administration, disk and hardware gates are complete
//! (including KMS policy for the Phala backend).
use crate::{
    ReleasePolicy,
    gcp::{self, BoundGcpWorkloadInspection, GcpProviderIdentity, GcpWorkloadPolicy},
    invalid_policy,
    workload::{StorageFs, WorkloadPolicy, decode_hash},
};
use ez_hash::{Hasher, Sha256};
use serde::{
    Deserialize,
    de::{self, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};
use zrpc_protocol::{Backend, ErrorCode, SafeError};

mod gcp_receipt;

struct EmbeddedGcpReceipt {
    sha256: [u8; 32],
    json: &'static [u8],
}

struct EmbeddedRelease {
    backend: Backend,
    id: &'static str,
    manifest_sha256: [u8; 32],
    manifest_json: &'static [u8],
    gcp_candidate_receipt: Option<EmbeddedGcpReceipt>,
}

const EMBEDDED_RELEASES: &[EmbeddedRelease] = &[];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GcpReleaseManifest {
    schema_version: u32,
    platform: Backend,
    release_id: String,
    source_commit: String,
    /// An exact client-embedded candidate receipt, never an operator file or
    /// assertion that its referenced offline checks have been performed.
    #[serde(deserialize_with = "decode_hash")]
    candidate_receipt_sha256: [u8; 32],
    workload: GcpWorkloadPolicy,
    /// Expected provider facts and hashes of the exact evidence reviewed when
    /// packaging this release. The hashes do not authenticate local JSON.
    provider: GcpProviderIdentity,
}

impl GcpReleaseManifest {
    fn validate(&self, embedded_id: &str) -> Result<(), SafeError> {
        if self.schema_version != 4
            || self.platform != Backend::GcpTdx
            || self.release_id != embedded_id
            || self.source_commit.len() != 40
            || !self.source_commit.bytes().all(|b| b.is_ascii_hexdigit())
            || self.candidate_receipt_sha256 == [0; 32]
            || self.workload.validate().is_err()
            || !self.provider.validate()
        {
            return Err(invalid_policy());
        }
        Ok(())
    }
}

pub(crate) fn is_embedded(id: &str) -> bool {
    EMBEDDED_RELEASES.iter().any(|release| release.id == id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: u32,
    release_id: String,
    source_commit: String,
    rootfs_verity_sha256: String,
    launch_config_sha256: String,
    sys_config_sha256: String,
    container_digests: Vec<String>,
    kms_policy_sha256: String,
    workload: WorkloadPolicy,
}

#[derive(Deserialize)]
struct LaunchImages {
    docker_compose_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeImages {
    name: Option<String>,
    services: UniqueServices,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceImage {
    image: String,
    user: String,
    read_only: bool,
    cap_drop: Vec<String>,
    security_opt: Vec<String>,
    logging: ServiceLogging,
    restart: Option<String>,
    environment: Option<BTreeMap<String, String>>,
    network_mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceLogging {
    driver: String,
}

struct UniqueServices(BTreeMap<String, ServiceImage>);

impl<'de> Deserialize<'de> for UniqueServices {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ServicesVisitor;

        impl<'de> Visitor<'de> for ServicesVisitor {
            type Value = UniqueServices;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a nonempty Compose service map with unique names")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut services = BTreeMap::new();
                while let Some((name, service)) = map.next_entry::<String, ServiceImage>()? {
                    if name.is_empty() || services.insert(name, service).is_some() {
                        return Err(de::Error::custom("duplicate or empty Compose service"));
                    }
                }
                if services.is_empty() {
                    return Err(de::Error::custom("Compose services are empty"));
                }
                Ok(UniqueServices(services))
            }
        }

        deserializer.deserialize_map(ServicesVisitor)
    }
}

fn lower_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nonroot_numeric_user(user: &str) -> bool {
    fn positive_decimal(value: &str) -> bool {
        value
            .as_bytes()
            .first()
            .is_some_and(|first| (b'1'..=b'9').contains(first))
            && value.bytes().all(|byte| byte.is_ascii_digit())
    }
    match user.split_once(':') {
        Some((uid, gid)) => positive_decimal(uid) && positive_decimal(gid),
        None => positive_decimal(user),
    }
}

fn launch_container_digests(raw_app_compose: &[u8]) -> Option<Vec<String>> {
    // The pinned dstack copy step caps the guest-owned launch document here.
    if raw_app_compose.len() > 256 * 1024 {
        return None;
    }
    let launch: LaunchImages = serde_json::from_slice(raw_app_compose).ok()?;
    let compose: ComposeImages = serde_json::from_str(&launch.docker_compose_file).ok()?;
    if compose
        .name
        .as_ref()
        .is_some_and(|name| name.is_empty() || name.contains('$'))
    {
        return None;
    }
    let mut digests = Vec::with_capacity(compose.services.0.len());
    for (name, service) in &compose.services.0 {
        if name.contains('$')
            || !nonroot_numeric_user(&service.user)
            || !service.read_only
            || service.cap_drop != ["ALL"]
            || service.security_opt != ["no-new-privileges:true"]
            || service.logging.driver != "none"
            || service
                .restart
                .as_deref()
                .is_some_and(|restart| restart != "no")
            || service.environment.as_ref().is_some_and(|environment| {
                environment
                    .iter()
                    .any(|(key, value)| key.contains('$') || value.contains('$'))
            })
            || service.network_mode.as_ref().is_some_and(|mode| {
                mode.strip_prefix("service:")
                    .is_none_or(|other| other == name || !compose.services.0.contains_key(other))
            })
        {
            return None;
        }
        let (reference, digest) = service.image.split_once("@sha256:")?;
        if reference.is_empty()
            || !reference.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
            })
            || !lower_hex32(digest)
        {
            return None;
        }
        digests.push(format!("sha256:{digest}"));
    }
    digests.sort_unstable();
    Some(digests)
}

impl ReleaseManifest {
    fn validate(&self, embedded_id: &str) -> Result<(), SafeError> {
        let mut launch_config_hash = [0u8; 32];
        if self.schema_version != 1
            || self.release_id != embedded_id
            || self.source_commit.len() != 40
            || !self.source_commit.bytes().all(|b| b.is_ascii_hexdigit())
            || !hex32(&self.rootfs_verity_sha256)
            || hex::decode_to_slice(&self.launch_config_sha256, &mut launch_config_hash).is_err()
            || launch_config_hash != self.workload.compose_hash
            || !hex32(&self.sys_config_sha256)
            || !hex32(&self.kms_policy_sha256)
            || self.container_digests.is_empty()
            || !self
                .container_digests
                .iter()
                .all(|digest| digest.strip_prefix("sha256:").is_some_and(lower_hex32))
            || self.workload.storage_fs != StorageFs::Ext4
            || self.workload.key_provider.name != "kms"
            || self.workload.validate().is_err()
        {
            return Err(invalid_policy());
        }
        Ok(())
    }
}

/// Opaque reviewed release authority. Diagnostic `WorkloadPolicy` values cannot
/// be converted into this type. The manifest digest is verified against bytes
/// embedded in the native binary before its workload policy can be used.
pub struct ApprovedRelease {
    id: String,
    manifest_sha256: [u8; 32],
    workload: ApprovedWorkload,
}

enum ApprovedWorkload {
    Phala {
        policy: WorkloadPolicy,
        container_digests: Vec<String>,
    },
    Gcp {
        policy: GcpWorkloadPolicy,
        provider: GcpProviderIdentity,
        // The receipt proves consistency of packaged references only. The
        // runtime GCP provenance statuses remain NotChecked.
        _candidate_receipt: gcp_receipt::BoundGcpCandidateReceipt,
    },
}

impl ApprovedRelease {
    pub fn selected(policy: &ReleasePolicy) -> Result<Vec<Self>, SafeError> {
        policy.validate()?;
        policy
            .approved_release_ids
            .iter()
            .map(|id| Self::one(id))
            .collect()
    }

    fn one(id: &str) -> Result<Self, SafeError> {
        let embedded = EMBEDDED_RELEASES
            .iter()
            .find(|release| release.id == id)
            .ok_or_else(unknown_release)?;
        Self::from_embedded(embedded)
    }

    fn from_embedded(embedded: &EmbeddedRelease) -> Result<Self, SafeError> {
        if Sha256::hash(embedded.manifest_json) != embedded.manifest_sha256 {
            return Err(invalid_policy());
        }
        let workload = match embedded.backend {
            Backend::PhalaDstack => {
                if embedded.gcp_candidate_receipt.is_some() {
                    return Err(invalid_policy());
                }
                let manifest: ReleaseManifest =
                    serde_json::from_slice(embedded.manifest_json).map_err(|_| invalid_policy())?;
                manifest.validate(embedded.id)?;
                ApprovedWorkload::Phala {
                    policy: manifest.workload,
                    container_digests: manifest.container_digests,
                }
            }
            Backend::GcpTdx => {
                let candidate = embedded
                    .gcp_candidate_receipt
                    .as_ref()
                    .ok_or_else(invalid_policy)?;
                if !gcp_receipt::has_gcp_document_shape(embedded.manifest_json) {
                    return Err(invalid_policy());
                }
                let manifest: GcpReleaseManifest =
                    serde_json::from_slice(embedded.manifest_json).map_err(|_| invalid_policy())?;
                manifest.validate(embedded.id)?;
                let bound = gcp_receipt::bind(&manifest, candidate.json, candidate.sha256)?;
                ApprovedWorkload::Gcp {
                    policy: manifest.workload,
                    provider: manifest.provider,
                    _candidate_receipt: bound,
                }
            }
        };
        Ok(Self {
            id: embedded.id.to_owned(),
            manifest_sha256: embedded.manifest_sha256,
            workload,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    pub fn backend(&self) -> Backend {
        match &self.workload {
            ApprovedWorkload::Phala { .. } => Backend::PhalaDstack,
            ApprovedWorkload::Gcp { .. } => Backend::GcpTdx,
        }
    }

    pub fn workload(&self) -> Option<&WorkloadPolicy> {
        match &self.workload {
            ApprovedWorkload::Phala { policy, .. } => Some(policy),
            _ => None,
        }
    }

    pub fn gcp_workload(&self) -> Option<&GcpWorkloadPolicy> {
        match &self.workload {
            ApprovedWorkload::Gcp { policy, .. } => Some(policy),
            _ => None,
        }
    }

    /// Compare provider identity only against expectations packaged into this
    /// reviewed release. Callers cannot promote diagnostic policies to it.
    pub fn inspect_gcp_evidence(
        &self,
        quote: &[u8],
        collateral_json: &[u8],
        ccel: &[u8],
        expected_report_data: &[u8; 64],
    ) -> Option<BoundGcpWorkloadInspection> {
        let ApprovedWorkload::Gcp {
            policy, provider, ..
        } = &self.workload
        else {
            return None;
        };
        Some(gcp::inspect_approved_gcp_workload_and_report_data(
            quote,
            collateral_json,
            ccel,
            policy,
            provider,
            expected_report_data,
        ))
    }

    /// The manifest's image list must describe the exact launch bytes whose
    /// digest is authenticated by the workload event log. The list is a
    /// multiset: two services using one digest require two manifest entries.
    pub fn matches_launch_config(&self, raw_app_compose: &[u8]) -> bool {
        let ApprovedWorkload::Phala {
            policy,
            container_digests,
        } = &self.workload
        else {
            return false;
        };
        if Sha256::hash(raw_app_compose) != policy.compose_hash {
            return false;
        }
        let Some(actual) = launch_container_digests(raw_app_compose) else {
            return false;
        };
        let mut expected = container_digests.clone();
        expected.sort_unstable();
        actual == expected
    }
}

fn hex32(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unknown_release() -> SafeError {
    SafeError::new(
        ErrorCode::UnknownRelease,
        "No reviewed release is selected by this client.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::KeyProviderPolicy;
    use serde_json::{Value, json};

    fn synthetic_gcp_documents() -> (Value, Value) {
        let workload: Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/gcp/policy.synthetic.json"
        ))
        .unwrap();
        let provider = json!({
            "ppid": hex::encode([1; 16]),
            "host_registry_sha256": hex::encode([2; 32]),
            "project_number": 123456789012u64,
            "zone": "us-central1-a",
            "instance_id": 112233445566778899u64,
            "instance_inventory_sha256": hex::encode([3; 32]),
        });
        let receipt = json!({
            "schema_version": 1,
            "status": "reference_binding_only_unapproved",
            "release_id": "SYNTHETIC_NOT_APPROVED",
            "source_commit": "1".repeat(40),
            "firmware_sha384": hex::encode([4; 48]),
            "firmware_validation_report_sha256": hex::encode([5; 32]),
            "artifact_validation_report_sha256": hex::encode([6; 32]),
            "provider_validation_report_sha256": hex::encode([7; 32]),
            "workload": workload.clone(),
            "provider": provider.clone(),
        });
        let manifest = json!({
            "schema_version": 4,
            "platform": "gcp-tdx",
            "release_id": "SYNTHETIC_NOT_APPROVED",
            "source_commit": "1".repeat(40),
            "candidate_receipt_sha256": hex::encode([8; 32]),
            "workload": workload,
            "provider": provider,
        });
        (manifest, receipt)
    }

    fn synthetic_embedded(mut manifest: Value, receipt: Value) -> EmbeddedRelease {
        let receipt = serde_json::to_vec(&receipt).unwrap();
        let receipt_sha256 = Sha256::hash(&receipt);
        manifest["candidate_receipt_sha256"] = json!(hex::encode(receipt_sha256));
        embedded_from_bytes(serde_json::to_vec(&manifest).unwrap(), receipt)
    }

    fn embedded_from_bytes(manifest: Vec<u8>, receipt: Vec<u8>) -> EmbeddedRelease {
        let manifest_sha256 = Sha256::hash(&manifest);
        let receipt_sha256 = Sha256::hash(&receipt);
        EmbeddedRelease {
            backend: Backend::GcpTdx,
            id: "SYNTHETIC_NOT_APPROVED",
            manifest_sha256,
            manifest_json: Box::leak(manifest.into_boxed_slice()),
            gcp_candidate_receipt: Some(EmbeddedGcpReceipt {
                sha256: receipt_sha256,
                json: Box::leak(receipt.into_boxed_slice()),
            }),
        }
    }

    #[test]
    fn no_local_selection_or_server_claim_can_create_approval() {
        let mut policy = ReleasePolicy::default();
        assert!(ApprovedRelease::selected(&policy).unwrap().is_empty());
        policy.private_mode_enabled = true;
        policy.approved_release_ids.push("SYNTHETIC".into());
        assert!(ApprovedRelease::selected(&policy).is_err());
        assert!(EMBEDDED_RELEASES.is_empty());
    }

    #[test]
    fn gcp_manifest_and_policy_do_not_require_or_accept_fake_phala_fields() {
        let workload = GcpWorkloadPolicy::from_json(include_bytes!(
            "../../../tests/fixtures/gcp/policy.synthetic.json"
        ))
        .unwrap();
        let provider = GcpProviderIdentity {
            ppid: [1; 16],
            host_registry_sha256: [2; 32],
            project_number: 123456789012,
            zone: "us-central1-a".into(),
            instance_id: 112233445566778899,
            instance_inventory_sha256: [3; 32],
        };
        let mut manifest = GcpReleaseManifest {
            schema_version: 4,
            platform: Backend::GcpTdx,
            release_id: "SYNTHETIC_NOT_APPROVED".into(),
            source_commit: "1".repeat(40),
            candidate_receipt_sha256: [8; 32],
            workload: workload.clone(),
            provider: provider.clone(),
        };
        assert!(manifest.validate("SYNTHETIC_NOT_APPROVED").is_ok());
        manifest.platform = Backend::PhalaDstack;
        assert!(manifest.validate("SYNTHETIC_NOT_APPROVED").is_err());
        manifest.platform = Backend::GcpTdx;
        manifest.provider.zone = "us-central1-a/other".into();
        assert!(manifest.validate("SYNTHETIC_NOT_APPROVED").is_err());
        manifest.provider = provider.clone();
        manifest.provider.host_registry_sha256 = [0; 32];
        assert!(manifest.validate("SYNTHETIC_NOT_APPROVED").is_err());
        let (manifest_bytes, receipt_bytes) = synthetic_gcp_documents();
        let embedded = synthetic_embedded(manifest_bytes.clone(), receipt_bytes);
        let release = ApprovedRelease::from_embedded(&embedded).unwrap();
        assert_eq!(release.backend(), Backend::GcpTdx);
        assert!(release.workload().is_none());
        assert!(release.gcp_workload().is_some());
        assert!(!release.matches_launch_config(b"{}"));
        assert!(!is_embedded(release.id()));
        let mut value = serde_json::json!({
            "schema_version": 4, "platform": "gcp-tdx", "release_id": "synthetic",
            "source_commit": "1".repeat(40), "workload": release.gcp_workload(),
            "candidate_receipt_sha256": hex::encode([8; 32]),
            "provider": {
                "ppid": hex::encode([1; 16]),
                "host_registry_sha256": hex::encode([2; 32]),
                "project_number": 123456789012u64,
                "zone": "us-central1-a",
                "instance_id": 112233445566778899u64,
                "instance_inventory_sha256": hex::encode([3; 32]),
            },
        });
        let mut no_provider = value.clone();
        no_provider.as_object_mut().unwrap().remove("provider");
        assert!(serde_json::from_value::<GcpReleaseManifest>(no_provider).is_err());
        assert!(serde_json::from_value::<GcpReleaseManifest>(value.clone()).is_ok());
        value["kms_policy_sha256"] = serde_json::json!("0".repeat(64));
        assert!(serde_json::from_value::<GcpReleaseManifest>(value).is_err());
    }

    #[test]
    fn candidate_receipt_binds_only_embedded_exact_bytes_without_authorizing_queries() {
        let (manifest, receipt) = synthetic_gcp_documents();
        let embedded = synthetic_embedded(manifest, receipt);
        let release = ApprovedRelease::from_embedded(&embedded).unwrap();
        let inspection = release
            .inspect_gcp_evidence(b"not a quote", b"{}", b"not a CCEL", &[0; 64])
            .unwrap();
        assert_eq!(
            inspection.workload.firmware_endorsement_provenance,
            crate::offline::InspectionStatus::NotChecked
        );
        assert_eq!(
            inspection.workload.artifact_provenance,
            crate::offline::InspectionStatus::NotChecked
        );
        assert!(!inspection.private_acceptance_ready());
        assert!(EMBEDDED_RELEASES.is_empty());

        let mut external = ReleasePolicy::default();
        external.private_mode_enabled = true;
        external
            .approved_release_ids
            .push("SYNTHETIC_NOT_APPROVED".into());
        assert!(ApprovedRelease::selected(&external).is_err());
    }

    #[test]
    fn candidate_receipt_rejects_missing_or_changed_digest_and_old_manifest_schema() {
        let (manifest, receipt) = synthetic_gcp_documents();
        let mut embedded = synthetic_embedded(manifest.clone(), receipt.clone());
        embedded.gcp_candidate_receipt = None;
        assert!(ApprovedRelease::from_embedded(&embedded).is_err());

        let mut embedded = synthetic_embedded(manifest.clone(), receipt.clone());
        embedded.gcp_candidate_receipt.as_mut().unwrap().sha256[0] ^= 1;
        assert!(ApprovedRelease::from_embedded(&embedded).is_err());

        let mut embedded = synthetic_embedded(manifest.clone(), receipt.clone());
        embedded.manifest_sha256[0] ^= 1;
        assert!(ApprovedRelease::from_embedded(&embedded).is_err());

        let mut wrong_manifest_pin = manifest.clone();
        wrong_manifest_pin["candidate_receipt_sha256"] = json!(hex::encode([9; 32]));
        let embedded = embedded_from_bytes(
            serde_json::to_vec(&wrong_manifest_pin).unwrap(),
            serde_json::to_vec(&receipt).unwrap(),
        );
        assert!(ApprovedRelease::from_embedded(&embedded).is_err());

        let mut old_manifest = manifest;
        old_manifest["schema_version"] = json!(3);
        assert!(
            ApprovedRelease::from_embedded(&synthetic_embedded(old_manifest, receipt)).is_err()
        );
    }

    #[test]
    fn candidate_receipt_rejects_substituted_references_and_provider_identity() {
        let (manifest, receipt) = synthetic_gcp_documents();
        for pointer in [
            "/workload/artifacts/firmware_endorsement_sha256",
            "/workload/artifacts/uki_sha256",
            "/workload/artifacts/uki_pe_coff_sha384",
            "/workload/artifacts/rootfs_verity_sha256",
            "/workload/artifacts/kernel_command_line_sha256",
            "/workload/artifacts/boot_policy_sha256",
            "/workload/artifacts/wrapper_sha256",
            "/workload/artifacts/zebra_sha256",
            "/workload/artifacts/quote_broker_sha256",
            "/workload/artifacts/measurement_recipe_sha256",
            "/workload/mrtd",
            "/workload/rtmr0",
            "/workload/rtmr1",
            "/workload/rtmr2",
            "/workload/rtmr3",
            "/workload/spec_id_sha256",
            "/workload/uki_event_index",
            "/workload/expected_events/0/event_data_sha256",
            "/provider/ppid",
            "/provider/host_registry_sha256",
            "/provider/project_number",
            "/provider/zone",
            "/provider/instance_id",
            "/provider/instance_inventory_sha256",
            "/release_id",
            "/source_commit",
        ] {
            let mut changed = receipt.clone();
            let field = changed.pointer_mut(pointer).unwrap();
            *field = if field.is_u64() {
                json!(field.as_u64().unwrap() + 1)
            } else if field.is_string() {
                let original = field.as_str().unwrap();
                if original.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    let mut changed = original.as_bytes().to_vec();
                    changed[0] = if changed[0] == b'a' { b'b' } else { b'a' };
                    json!(String::from_utf8(changed).unwrap())
                } else {
                    json!(format!("{original}x"))
                }
            } else {
                panic!("unexpected receipt field at {pointer}");
            };
            assert!(
                ApprovedRelease::from_embedded(&synthetic_embedded(manifest.clone(), changed))
                    .is_err(),
                "receipt substitution at {pointer}"
            );
        }
        for pointer in [
            "/firmware_sha384",
            "/firmware_validation_report_sha256",
            "/artifact_validation_report_sha256",
            "/provider_validation_report_sha256",
        ] {
            let mut changed = receipt.clone();
            let field = changed.pointer_mut(pointer).unwrap();
            *field = json!("00".repeat(field.as_str().unwrap().len() / 2));
            assert!(
                ApprovedRelease::from_embedded(&synthetic_embedded(manifest.clone(), changed))
                    .is_err(),
                "empty report or firmware identity at {pointer}"
            );
        }
    }

    #[test]
    fn candidate_receipt_rejects_unknown_fields_duplicate_keys_and_positional_objects() {
        let (manifest, receipt) = synthetic_gcp_documents();
        for (target, field) in [
            (true, "verified"),
            (true, "private_mode_approved"),
            (false, "verified"),
            (false, "private_mode_approved"),
        ] {
            let mut changed_manifest = manifest.clone();
            let mut changed_receipt = receipt.clone();
            if target {
                changed_manifest[field] = json!(true);
            } else {
                changed_receipt[field] = json!(true);
            }
            assert!(
                ApprovedRelease::from_embedded(&synthetic_embedded(
                    changed_manifest,
                    changed_receipt
                ))
                .is_err()
            );
        }
        let mut changed = receipt.clone();
        changed["status"] = json!("verified");
        assert!(
            ApprovedRelease::from_embedded(&synthetic_embedded(manifest.clone(), changed)).is_err()
        );

        let mut changed = receipt.clone();
        changed["provider"] = json!([1, 2, 3]);
        assert!(
            ApprovedRelease::from_embedded(&synthetic_embedded(manifest.clone(), changed)).is_err()
        );
        let mut changed = manifest.clone();
        changed["workload"]["artifacts"] = json!([1, 2, 3]);
        assert!(
            ApprovedRelease::from_embedded(&synthetic_embedded(changed, receipt.clone())).is_err()
        );

        let raw_receipt = serde_json::to_string(&receipt)
            .unwrap()
            .replacen('{', "{\"schema_version\":1,", 1)
            .into_bytes();
        let mut manifest_for_receipt = manifest.clone();
        manifest_for_receipt["candidate_receipt_sha256"] =
            json!(hex::encode(Sha256::hash(&raw_receipt)));
        assert!(
            ApprovedRelease::from_embedded(&embedded_from_bytes(
                serde_json::to_vec(&manifest_for_receipt).unwrap(),
                raw_receipt,
            ))
            .is_err()
        );

        let embedded = synthetic_embedded(manifest, receipt);
        let raw_manifest = std::str::from_utf8(embedded.manifest_json)
            .unwrap()
            .replacen('{', "{\"schema_version\":4,", 1)
            .into_bytes();
        assert!(
            ApprovedRelease::from_embedded(&embedded_from_bytes(
                raw_manifest,
                embedded.gcp_candidate_receipt.unwrap().json.to_vec(),
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_launch_digest_must_be_the_authenticated_compose_digest() {
        let workload = WorkloadPolicy {
            schema_version: 1,
            mrtd: [0; 48],
            rtmr0: [0; 48],
            rtmr1: [0; 48],
            rtmr2: [0; 48],
            os_image_hash: [0; 32],
            compose_hash: [7; 32],
            mr_kms: [0; 32],
            app_id: [0; 20],
            instance_id: [0; 20],
            storage_fs: StorageFs::Ext4,
            key_provider: KeyProviderPolicy {
                name: "kms".into(),
                id: "synthetic-kms".into(),
            },
        };
        let mut manifest = ReleaseManifest {
            schema_version: 1,
            release_id: "SYNTHETIC".into(),
            source_commit: "0".repeat(40),
            rootfs_verity_sha256: "0".repeat(64),
            launch_config_sha256: hex::encode([7; 32]),
            sys_config_sha256: "1".repeat(64),
            container_digests: vec![format!("sha256:{}", "0".repeat(64))],
            kms_policy_sha256: "0".repeat(64),
            workload,
        };
        assert!(manifest.validate("SYNTHETIC").is_ok());
        manifest.launch_config_sha256 = hex::encode([8; 32]);
        assert!(manifest.validate("SYNTHETIC").is_err());
        manifest.launch_config_sha256 = hex::encode([7; 32]);
        manifest.workload.compose_hash = [8; 32];
        assert!(manifest.validate("SYNTHETIC").is_err());
        manifest.workload.compose_hash = [7; 32];
        manifest.sys_config_sha256.clear();
        assert!(manifest.validate("SYNTHETIC").is_err());
        assert!(EMBEDDED_RELEASES.is_empty());
    }

    fn synthetic_release(raw: &[u8], container_digests: Vec<String>) -> ApprovedRelease {
        ApprovedRelease {
            id: "SYNTHETIC".into(),
            manifest_sha256: [0; 32],
            workload: ApprovedWorkload::Phala {
                policy: WorkloadPolicy {
                    schema_version: 1,
                    mrtd: [0; 48],
                    rtmr0: [0; 48],
                    rtmr1: [0; 48],
                    rtmr2: [0; 48],
                    os_image_hash: [0; 32],
                    compose_hash: Sha256::hash(raw),
                    mr_kms: [0; 32],
                    app_id: [0; 20],
                    instance_id: [0; 20],
                    storage_fs: StorageFs::Ext4,
                    key_provider: KeyProviderPolicy {
                        name: "kms".into(),
                        id: "synthetic-kms".into(),
                    },
                },
                container_digests,
            },
        }
    }

    #[test]
    fn embedded_image_list_must_equal_images_in_exact_launch_bytes() {
        let first = format!("sha256:{}", "a".repeat(64));
        let second = format!("sha256:{}", "b".repeat(64));
        let inner = serde_json::json!({"services": {
            "zebra": {
                "image": format!("example.invalid/zebra@{first}"),
                "user": "10001:10001", "read_only": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "logging": {"driver": "none"}
            },
            "wrapper": {
                "image": format!("example.invalid/wrapper@{second}"),
                "user": "10002:10002", "read_only": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "logging": {"driver": "none"},
                "network_mode": "service:zebra"
            },
        }});
        let raw = serde_json::to_vec(&serde_json::json!({
            "runner": "docker-compose",
            "docker_compose_file": inner.to_string(),
        }))
        .unwrap();
        let release = synthetic_release(&raw, vec![second.clone(), first.clone()]);
        assert!(release.matches_launch_config(&raw));
        assert!(!release.matches_launch_config(&[raw.as_slice(), b" "].concat()));
        assert!(
            !synthetic_release(&raw, vec![first.clone(), first.clone()])
                .matches_launch_config(&raw)
        );
        assert!(!synthetic_release(&raw, vec![first.clone()]).matches_launch_config(&raw));

        for changed in [
            serde_json::json!({
                "services": inner["services"],
                "include": ["unreviewed.json"],
            }),
            serde_json::json!({
                "services": {
                    "zebra": {
                        "image": format!("example.invalid/zebra@{first}"),
                        "user": "10001:10001", "read_only": true,
                        "cap_drop": ["ALL"],
                        "security_opt": ["no-new-privileges:true"],
                        "logging": {"driver": "none"},
                        "volumes": ["/run/docker.sock:/run/docker.sock"]
                    }
                }
            }),
        ] {
            let changed = serde_json::to_vec(&serde_json::json!({
                "docker_compose_file": changed.to_string(),
            }))
            .unwrap();
            assert!(
                !synthetic_release(&changed, vec![first.clone(), second.clone()])
                    .matches_launch_config(&changed)
            );
        }

        let service = inner["services"]["zebra"].to_string();
        let duplicate_service = format!(r#"{{"services":{{"one":{service},"one":{service}}}}}"#);
        let duplicate_launch = serde_json::to_vec(&serde_json::json!({
            "docker_compose_file": duplicate_service,
        }))
        .unwrap();
        assert!(
            !synthetic_release(&duplicate_launch, vec![first])
                .matches_launch_config(&duplicate_launch)
        );
        assert!(EMBEDDED_RELEASES.is_empty());
    }
}
