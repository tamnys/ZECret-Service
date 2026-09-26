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
    workload: WorkloadPolicy,
    container_digests: Vec<String>,
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
            container_digests: manifest.container_digests,
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

    /// The manifest's image list must describe the exact launch bytes whose
    /// digest is authenticated by the workload event log. The list is a
    /// multiset: two services using one digest require two manifest entries.
    pub fn matches_launch_config(&self, raw_app_compose: &[u8]) -> bool {
        if Sha256::hash(raw_app_compose) != self.workload.compose_hash {
            return false;
        }
        let Some(actual) = launch_container_digests(raw_app_compose) else {
            return false;
        };
        let mut expected = self.container_digests.clone();
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

    fn synthetic_release(raw: &[u8], container_digests: Vec<String>) -> ApprovedRelease {
        ApprovedRelease {
            id: "SYNTHETIC".into(),
            manifest_sha256: [0; 32],
            workload: WorkloadPolicy {
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
