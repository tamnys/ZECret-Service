//! Phala-managed guest approval is separate from provider-independent approval.
//! The client packages exact reviewed manifest bytes; a local selection can
//! only narrow this catalog. The catalog stays empty until live review.

use crate::{PhalaTrustedPolicy, invalid_policy, workload::WorkloadPolicy};
use ez_hash::{Hasher, Sha256};
use serde::{
    Deserialize,
    de::{self, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};
use zrpc_protocol::{ErrorCode, SafeError};

struct EmbeddedRelease {
    id: &'static str,
    manifest_sha256: [u8; 32],
    manifest_json: &'static [u8],
}

// A reviewed, live Phala artifact must be packaged by a later client release.
const EMBEDDED_RELEASES: &[EmbeddedRelease] = &[];

pub(crate) fn is_embedded(id: &str) -> bool {
    EMBEDDED_RELEASES.iter().any(|release| release.id == id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    release_id: String,
    trust_model: String,
    stock_os_sha256: String,
    measurement_reference_sha256: String,
    launch_config_sha256: String,
    pre_launch_script_sha256: String,
    container_digests: Vec<String>,
    kms_identity: String,
    workload: WorkloadPolicy,
}

#[derive(Deserialize)]
struct Launch {
    docker_compose_file: String,
    #[serde(default)]
    pre_launch_script: String,
}

#[derive(Deserialize)]
struct Compose {
    services: UniqueServices,
}

#[derive(Deserialize)]
struct Service {
    image: String,
}

struct UniqueServices(BTreeMap<String, Service>);

impl<'de> Deserialize<'de> for UniqueServices {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ServicesVisitor;
        impl<'de> Visitor<'de> for ServicesVisitor {
            type Value = UniqueServices;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("unique, nonempty Compose services")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut services = BTreeMap::new();
                while let Some((name, service)) = map.next_entry::<String, Service>()? {
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

fn hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn digest_reference(value: &str) -> Option<String> {
    let (reference, digest) = value.split_once("@sha256:")?;
    if reference.is_empty()
        || !reference.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        || !hex32(digest)
    {
        return None;
    }
    Some(format!("sha256:{digest}"))
}

fn launch_parts(raw: &[u8]) -> Option<([u8; 32], Vec<String>)> {
    if raw.len() > 256 * 1024 {
        return None;
    }
    let launch: Launch = serde_json::from_slice(raw).ok()?;
    let compose: Compose = serde_json::from_str(&launch.docker_compose_file).ok()?;
    let mut digests = compose
        .services
        .0
        .values()
        .map(|service| digest_reference(&service.image))
        .collect::<Option<Vec<_>>>()?;
    digests.sort_unstable();
    Some((Sha256::hash(launch.pre_launch_script.as_bytes()), digests))
}

/// Approval of a specific Phala-managed stock guest, KMS identity and launch.
/// This type does not claim isolation from Phala administrators or writable
/// runtime state. It cannot be created from server evidence or a local file.
pub struct PhalaTrustedRelease {
    id: String,
    manifest_sha256: [u8; 32],
    launch_sha256: [u8; 32],
    pre_launch_script_sha256: [u8; 32],
    container_digests: Vec<String>,
    workload: WorkloadPolicy,
}

impl PhalaTrustedRelease {
    pub fn selected(policy: &PhalaTrustedPolicy) -> Result<Vec<Self>, SafeError> {
        policy.validate()?;
        policy
            .reviewed_release_ids
            .iter()
            .map(|id| Self::one(id))
            .collect()
    }

    fn one(id: &str) -> Result<Self, SafeError> {
        let embedded = EMBEDDED_RELEASES
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| {
                SafeError::new(
                    ErrorCode::UnknownRelease,
                    "No packaged Phala-trusting release is selected.",
                )
            })?;
        Self::from_embedded(embedded)
    }

    fn from_embedded(embedded: &EmbeddedRelease) -> Result<Self, SafeError> {
        if Sha256::hash(embedded.manifest_json) != embedded.manifest_sha256 {
            return Err(invalid_policy());
        }
        let manifest: Manifest =
            serde_json::from_slice(embedded.manifest_json).map_err(|_| invalid_policy())?;
        // The reference is the canonical serialized policy packaged in this
        // client, never a digest asserted by the peer or learned from a quote.
        let measurement_reference =
            serde_json::to_vec(&manifest.workload).map_err(|_| invalid_policy())?;
        if manifest.schema_version != 1
            || manifest.release_id != embedded.id
            || manifest.trust_model != "phala-managed-guest-kms-runtime"
            || !hex32(&manifest.stock_os_sha256)
            || !hex32(&manifest.measurement_reference_sha256)
            || manifest.measurement_reference_sha256
                != hex::encode(Sha256::hash(&measurement_reference))
            || !hex32(&manifest.launch_config_sha256)
            || !hex32(&manifest.pre_launch_script_sha256)
            || manifest.kms_identity.is_empty()
            || manifest.workload.validate().is_err()
            || hex::encode(manifest.workload.os_image_hash) != manifest.stock_os_sha256
            || hex::encode(manifest.workload.compose_hash) != manifest.launch_config_sha256
            || manifest.workload.key_provider.id != manifest.kms_identity
            || manifest.container_digests.is_empty()
            || !manifest
                .container_digests
                .iter()
                .all(|digest| digest.strip_prefix("sha256:").is_some_and(hex32))
        {
            return Err(invalid_policy());
        }
        let mut script_hash = [0u8; 32];
        hex::decode_to_slice(&manifest.pre_launch_script_sha256, &mut script_hash)
            .map_err(|_| invalid_policy())?;
        let mut expected = manifest.container_digests;
        expected.sort_unstable();
        Ok(Self {
            id: embedded.id.to_owned(),
            manifest_sha256: embedded.manifest_sha256,
            launch_sha256: manifest.workload.compose_hash,
            pre_launch_script_sha256: script_hash,
            container_digests: expected,
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

    pub fn matches_launch_config(&self, raw: &[u8]) -> bool {
        if Sha256::hash(raw) != self.launch_sha256 {
            return false;
        }
        launch_parts(raw).is_some_and(|(script, images)| {
            script == self.pre_launch_script_sha256 && images == self.container_digests
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_selection_cannot_add_releases() {
        let mut policy = PhalaTrustedPolicy::default();
        assert!(PhalaTrustedRelease::selected(&policy).unwrap().is_empty());
        policy.phala_trusted_enabled = true;
        policy.reviewed_release_ids.push("SYNTHETIC".into());
        assert!(PhalaTrustedRelease::selected(&policy).is_err());
        assert!(EMBEDDED_RELEASES.is_empty());
    }

    #[test]
    fn launch_parser_rejects_mutable_images_and_duplicate_services() {
        let image = format!("repo@sha256:{}", "a".repeat(64));
        let compose = format!(
            "{{\"services\":{{\"node\":{{\"image\":\"{image}\"}},\"node\":{{\"image\":\"{image}\"}}}}}}"
        );
        let launch = serde_json::json!({"docker_compose_file":compose});
        assert!(launch_parts(&serde_json::to_vec(&launch).unwrap()).is_none());
        let mutable = serde_json::json!({"docker_compose_file":"{\"services\":{\"node\":{\"image\":\"repo:latest\"}}}"});
        assert!(launch_parts(&serde_json::to_vec(&mutable).unwrap()).is_none());
    }
}
