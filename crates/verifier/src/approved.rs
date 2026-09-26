//! Reviewed client-packaged releases, separate from diagnostic workload inputs.
//!
//! An embedded entry requires review of the exact manifest bytes and digest as
//! part of a new native-client release. No runtime file, fixture, provider flag,
//! or first-seen quote can append to this table. It is deliberately empty until
//! production image, KMS, administration, disk and hardware gates are complete.
use crate::{
    ReleasePolicy, invalid_policy,
    workload::{StorageFs, WorkloadPolicy},
};
use ez_hash::{Hasher, Sha256};
use serde::Deserialize;
use zrpc_protocol::{ErrorCode, SafeError};

struct EmbeddedRelease {
    id: &'static str,
    manifest_sha256: [u8; 32],
    manifest_json: &'static [u8],
}

const EMBEDDED_RELEASES: &[EmbeddedRelease] = &[];

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
                .all(|digest| digest.strip_prefix("sha256:").is_some_and(hex32))
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
    workload: WorkloadPolicy,
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
        if Sha256::hash(embedded.manifest_json) != embedded.manifest_sha256 {
            return Err(invalid_policy());
        }
        let manifest: ReleaseManifest =
            serde_json::from_slice(embedded.manifest_json).map_err(|_| invalid_policy())?;
        manifest.validate(id)?;
        Ok(Self {
            id: manifest.release_id,
            manifest_sha256: embedded.manifest_sha256,
            workload: manifest.workload,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    pub fn workload(&self) -> &WorkloadPolicy {
        &self.workload
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
}
