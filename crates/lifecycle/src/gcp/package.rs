//! Typed, hash-bound local deployment package. No provider or credential reads.
use super::{Error, Result, digest, read_regular, valid_digest};
use crate::MAX_LIFETIME_SECONDS;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
};

const IMPORT_GIB: u64 = 1024 * 1024 * 1024;
// Google manual boot-disk import caps this raw-disk workflow at 2048 GB (2 TB).
// https://docs.cloud.google.com/compute/docs/import/import-existing-image
const MAX_IMPORT_GIB: u64 = 2048;
// The custom Debian image package uses only Google's listed non-Local-SSD C3
// standard VM types for TDX. TDX on c3-standard-*-lssd has a separate image
// support list containing only COS families, so it cannot admit this image.
// Re-review both lists before adding a type:
// https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations
// https://docs.cloud.google.com/compute/docs/general-purpose-machines#c3_machine_types
const CUSTOM_IMAGE_C3_TDX_MACHINE_TYPES: [&str; 6] = [
    "c3-standard-4",
    "c3-standard-8",
    "c3-standard-22",
    "c3-standard-44",
    "c3-standard-88",
    "c3-standard-176",
];
// Google's C3 TDX zone list is distinct from the C3 Local SSD and C4 lists.
// Review the current provider list before admitting an additional zone:
// https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations
const CUSTOM_IMAGE_C3_TDX_ZONES: [&str; 24] = [
    "asia-northeast1-b",
    "asia-south1-b",
    "asia-southeast1-a",
    "asia-southeast1-b",
    "asia-southeast1-c",
    "europe-west3-a",
    "europe-west3-b",
    "europe-west4-a",
    "europe-west4-b",
    "europe-west4-c",
    "europe-west9-a",
    "europe-west9-b",
    "us-central1-a",
    "us-central1-b",
    "us-central1-c",
    "us-east1-b",
    "us-east1-c",
    "us-east4-a",
    "us-east4-b",
    "us-east4-c",
    "us-east5-b",
    "us-east5-c",
    "us-west1-a",
    "us-west1-b",
];
// Embed the checked source so a path next to the operator binary cannot
// replace the import validator. Python's maintained gzip/tarfile decoders are
// required on the operator's reviewed Linux host; absence fails closed.
const IMPORT_CHECKER: &str = include_str!("../../../../tools/gcp-guest/gcp_import_archive.py");

/// Candidate producer record. Its executable hashes and status fields cannot
/// grant toolchain or private-mode approval; the live deployment blocker stays.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportReceipt {
    archive_sha256: String,
    raw_disk_sha256: String,
    raw_disk_bytes: u64,
    oldgnu_single_member_checked: bool,
    private_mode_approved: bool,
    gnu_tar_version: String,
    gnu_tar_sha256: String,
    gnu_gzip_version: String,
    gnu_gzip_sha256: String,
    python_executable_sha256: String,
    python_version: String,
    toolchain_reviewed: bool,
    workspace_volume_override_used: bool,
}

fn verify_import_receipt(spec: &DeploymentSpec) -> Result<()> {
    let bytes = read_regular(&spec.import_receipt.path)?;
    if digest(&bytes) != spec.import_receipt.sha256 {
        return Err(Error("import receipt SHA-256 mismatch"));
    }
    let receipt: ImportReceipt =
        serde_json::from_slice(&bytes).map_err(|_| Error("invalid typed import receipt"))?;
    if receipt.archive_sha256 != spec.raw_image_tar_gz.sha256
        || receipt.raw_disk_sha256 != spec.raw_disk_sha256
        || receipt.raw_disk_bytes != spec.raw_disk_bytes
        || !receipt.oldgnu_single_member_checked
        || receipt.private_mode_approved
        || receipt.toolchain_reviewed
        || !receipt.gnu_tar_version.starts_with("tar (GNU tar) ")
        || !receipt.gnu_gzip_version.starts_with("gzip ")
        || receipt.python_version.is_empty()
        || !valid_digest(&receipt.gnu_tar_sha256)
        || !valid_digest(&receipt.gnu_gzip_sha256)
        || !valid_digest(&receipt.python_executable_sha256)
    {
        return Err(Error(
            "import receipt differs from candidate media or status",
        ));
    }
    // These producer hashes and versions describe archive creation. They do
    // not identify or approve the separate operator-host verifier toolchain.
    let _ = receipt.workspace_volume_override_used;
    Ok(())
}

fn verify_import_archive(
    archive: &Artifact,
    raw_sha256: &str,
    raw_bytes: u64,
    python: &Artifact,
) -> Result<()> {
    // Keep the operator executable separate from the producer receipt. A
    // caller-supplied executable path must never select arbitrary code here.
    let system_python = fs::canonicalize("/usr/bin/python3")
        .map_err(|_| Error("operator Python executable unavailable"))?;
    if python.path != system_python {
        return Err(Error("import verifier must use canonical system Python"));
    }
    python.verify()?;
    static CHECKED: OnceLock<Mutex<BTreeMap<(String, String), (String, u64)>>> = OnceLock::new();
    let checked = CHECKED.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = checked
        .lock()
        .map_err(|_| Error("import archive cache poisoned"))?;
    let key = (archive.sha256.clone(), python.sha256.clone());
    if cache.get(&key) == Some(&(raw_sha256.to_owned(), raw_bytes)) {
        return Ok(());
    }
    let status = Command::new(&python.path)
        .arg("-I")
        .arg("-c")
        .arg(IMPORT_CHECKER)
        .arg("verify")
        .arg(&archive.path)
        .arg(&archive.sha256)
        .arg(raw_sha256)
        .arg(raw_bytes.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error("offline import archive validator unavailable"))?;
    if !status.success() {
        return Err(Error(
            "raw image archive is not the reviewed oldgnu disk.raw",
        ));
    }
    // The artifact hash is checked before and after the decoder. A changed
    // upload is also rejected by the provider's streaming media hash check.
    archive.verify()?;
    if super::provider::file_sha256(&python.path)? != python.sha256 {
        return Err(Error("operator Python changed during archive verification"));
    }
    cache.insert(key, (raw_sha256.to_owned(), raw_bytes));
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
}
impl Artifact {
    pub fn verify(&self) -> Result<()> {
        if !valid_digest(&self.sha256) || !self.path.is_absolute() {
            return Err(Error("artifact requires an absolute path and SHA-256"));
        }
        // The controller checks this again immediately before using artifacts.
        if super::provider::file_sha256(&self.path)? != self.sha256 {
            return Err(Error("artifact SHA-256 mismatch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
    pub source: String,
    pub quoted_at: u64,
    pub expires_at: u64,
    /// Informational quote, never an implicit budget or permission to spend.
    pub projected_total_microusd: u64,
    pub components_microusd: BTreeMap<String, u64>,
    pub evidence: Artifact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpec {
    pub schema_version: u32,
    pub experiment: String,
    pub project: String,
    pub region: String,
    pub zone: String,
    pub machine_type: String,
    pub boot_disk_gib: u64,
    pub public_data_disk_gib: u64,
    pub subnet_cidr: String,
    pub wrapper_port: u16,
    /// Pre-existing private staging bucket, never deleted by this tool.
    pub staging_bucket: String,
    pub start_unix_seconds: u64,
    pub deadline_unix_seconds: u64,
    pub raw_image_tar_gz: Artifact,
    /// SHA-256 of logical disk.raw bytes after GNU sparse expansion.
    pub raw_disk_sha256: String,
    pub raw_disk_bytes: u64,
    /// Hash-bound candidate record emitted by the offline archive packer.
    pub import_receipt: Artifact,
    /// Exact operator-host interpreter for the embedded offline validator.
    /// This identity is separate from the producer's Python in the receipt.
    pub import_verifier_python: Artifact,
    pub release_manifest: Artifact,
    pub boot_policy: Artifact,
    pub memory_measurement: Artifact,
    pub reproducibility_report: Artifact,
    pub secure_boot_pk_der: Artifact,
    pub secure_boot_kek_der: Artifact,
    pub secure_boot_db_der: Artifact,
    /// Reviewed EFI revocation database; never inherit Google's mutable default.
    pub secure_boot_dbx_bin: Artifact,
    pub pricing: Pricing,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    StagingObject,
    Network,
    Subnetwork,
    Firewall,
    Image,
    BootDisk,
    PublicDataDisk,
    Instance,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourcePlan {
    pub kind: ResourceKind,
    /// Fully qualified API path; no caller-selected host or arbitrary URL.
    pub path: String,
    pub create_body: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub schema_version: u32,
    pub spec: DeploymentSpec,
    pub resources: Vec<ResourcePlan>,
}

pub(crate) fn name(value: &str) -> bool {
    // Compute Engine resource naming contract (RFC1035, 1..=63 bytes).
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}
impl DeploymentSpec {
    pub fn validate(&self, at: u64) -> Result<()> {
        if self.schema_version != 4
            || !name(&self.experiment)
            || self.experiment.len() + "-public-data".len() > 63
            || !name(&self.project)
            || !name(&self.region)
            || !name(&self.zone)
            || !self.zone.starts_with(&format!("{}-", self.region))
            || !CUSTOM_IMAGE_C3_TDX_ZONES.contains(&self.zone.as_str())
            || !name(&self.machine_type)
            || !CUSTOM_IMAGE_C3_TDX_MACHINE_TYPES.contains(&self.machine_type.as_str())
            || self.boot_disk_gib == 0
            || self.boot_disk_gib > MAX_IMPORT_GIB
            || self.public_data_disk_gib == 0
            || self.wrapper_port == 0
        {
            return Err(Error("invalid GCP C3 TDX resource configuration"));
        }
        if !valid_digest(&self.raw_disk_sha256)
            || self.raw_disk_bytes == 0
            || self.raw_disk_bytes % IMPORT_GIB != 0
            || self.raw_disk_bytes / IMPORT_GIB > self.boot_disk_gib
            || self.raw_disk_bytes / IMPORT_GIB > MAX_IMPORT_GIB
        {
            return Err(Error(
                "reviewed disk.raw identity or boot disk size invalid",
            ));
        }
        // Strict subset avoids object/glob syntax and path/query injection.
        if !name(&self.staging_bucket) {
            return Err(Error("staging bucket must be a simple DNS label"));
        }
        let (ip, prefix) = self
            .subnet_cidr
            .split_once('/')
            .ok_or(Error("IPv4 subnet CIDR required"))?;
        let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| Error("IPv4 subnet CIDR required"))?;
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| Error("IPv4 subnet CIDR required"))?;
        if !ip.is_private()
            || prefix > 29
            || prefix < 8
            || u32::from(ip) & (u32::MAX >> prefix) != 0
        {
            return Err(Error(
                "subnet must be a canonical private IPv4 range supported by Google",
            ));
        }
        let duration = self
            .deadline_unix_seconds
            .checked_sub(self.start_unix_seconds)
            .filter(|d| *d > 0 && *d <= MAX_LIFETIME_SECONDS)
            .ok_or(Error(
                "evaluation must retain positive lifetime at most 168 hours",
            ))?;
        let _ = duration;
        if at >= self.deadline_unix_seconds
            || self.pricing.quoted_at > at
            || self.pricing.expires_at <= at
            || self.pricing.expires_at <= self.start_unix_seconds
            || !self.pricing.source.starts_with("https://")
        {
            return Err(Error("expired deadline or pricing quote"));
        }
        for key in [
            "compute",
            "boot_disk",
            "public_data_disk",
            "image",
            "staging",
            "external_ip",
            "network",
            "taxes",
        ] {
            if !self.pricing.components_microusd.contains_key(key) {
                return Err(Error("quote omits a charge category"));
            }
        }
        let total = self
            .pricing
            .components_microusd
            .values()
            .try_fold(0u64, |a, b| a.checked_add(*b))
            .ok_or(Error("quote arithmetic overflow"))?;
        if total != self.pricing.projected_total_microusd {
            return Err(Error("quote total differs from its components"));
        }
        for artifact in self.artifacts() {
            artifact.verify()?;
        }
        verify_import_receipt(self)?;
        verify_import_archive(
            &self.raw_image_tar_gz,
            &self.raw_disk_sha256,
            self.raw_disk_bytes,
            &self.import_verifier_python,
        )?;
        Ok(())
    }
    pub fn artifacts(&self) -> [&Artifact; 12] {
        [
            &self.raw_image_tar_gz,
            &self.import_receipt,
            &self.import_verifier_python,
            &self.release_manifest,
            &self.boot_policy,
            &self.memory_measurement,
            &self.reproducibility_report,
            &self.secure_boot_pk_der,
            &self.secure_boot_kek_der,
            &self.secure_boot_db_der,
            &self.secure_boot_dbx_bin,
            &self.pricing.evidence,
        ]
    }
    pub fn object_name(&self) -> String {
        format!(
            "{}-{}.tar.gz",
            self.experiment, self.raw_image_tar_gz.sha256
        )
    }
}

impl Package {
    pub fn prepare(spec: DeploymentSpec, at: u64) -> Result<Self> {
        spec.validate(at)?;
        let p = format!("projects/{}", spec.project);
        let z = format!("{p}/zones/{}", spec.zone);
        let r = format!("{p}/regions/{}", spec.region);
        let n = &spec.experiment;
        let ownership = format!(
            "zrpc-gcp-experiment:{n}; artifact:{}",
            spec.raw_image_tar_gz.sha256
        );
        let image = format!("{p}/global/images/{n}-image");
        let network = format!("{p}/global/networks/{n}-network");
        let subnet = format!("{r}/subnetworks/{n}-subnet");
        let boot = format!("{z}/disks/{n}-boot");
        let data = format!("{z}/disks/{n}-public-data");
        let secure_boot_file = |a: &Artifact, file_type| -> Result<Value> {
            let bytes = read_regular(&a.path)?;
            if bytes.is_empty() {
                return Err(Error("Secure Boot policy input must not be empty"));
            }
            if digest(&bytes) != a.sha256 {
                return Err(Error("Secure Boot policy input changed during preparation"));
            }
            Ok(json!({"fileType":file_type, "content":STANDARD.encode(bytes)}))
        };
        let cert = |a: &Artifact| secure_boot_file(a, "X509");
        let resources = vec![
            ResourcePlan {
                kind: ResourceKind::StagingObject,
                path: format!("b/{}/o/{}", spec.staging_bucket, spec.object_name()),
                create_body: json!({"zrpc-experiment":n,"zrpc-sha256":spec.raw_image_tar_gz.sha256}),
            },
            ResourcePlan {
                kind: ResourceKind::Network,
                path: network.clone(),
                create_body: json!({"name":format!("{n}-network"),"description":ownership,"autoCreateSubnetworks":false}),
            },
            ResourcePlan {
                kind: ResourceKind::Subnetwork,
                path: subnet.clone(),
                create_body: json!({"name":format!("{n}-subnet"),"description":ownership,"network":network,"ipCidrRange":spec.subnet_cidr,"privateIpGoogleAccess":false}),
            },
            ResourcePlan {
                kind: ResourceKind::Firewall,
                path: format!("{p}/global/firewalls/{n}-rpc"),
                create_body: json!({"name":format!("{n}-rpc"),"description":ownership,"network":network,"direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"targetTags":[n],"allowed":[{"IPProtocol":"tcp","ports":[spec.wrapper_port.to_string()]}],"logConfig":{"enable":false}}),
            },
            ResourcePlan {
                kind: ResourceKind::Image,
                path: image.clone(),
                create_body: json!({"name":format!("{n}-image"),"description":ownership,"architecture":"X86_64","rawDisk":{"source":format!("https://storage.googleapis.com/{}/{}",spec.staging_bucket,spec.object_name()),"containerType":"TAR"},"guestOsFeatures":[{"type":"UEFI_COMPATIBLE"},{"type":"GVNIC"},{"type":"TDX_CAPABLE"}],"shieldedInstanceInitialState":{"pk":cert(&spec.secure_boot_pk_der)?,"keks":[cert(&spec.secure_boot_kek_der)?],"dbs":[cert(&spec.secure_boot_db_der)?],"dbxs":[secure_boot_file(&spec.secure_boot_dbx_bin, "BIN")?]}}),
            },
            ResourcePlan {
                kind: ResourceKind::BootDisk,
                path: boot.clone(),
                create_body: json!({"name":format!("{n}-boot"),"description":ownership,"type":format!("{z}/diskTypes/pd-balanced"),"sizeGb":spec.boot_disk_gib.to_string(),"sourceImage":image}),
            },
            ResourcePlan {
                kind: ResourceKind::PublicDataDisk,
                path: data.clone(),
                create_body: json!({"name":format!("{n}-public-data"),"description":ownership,"type":format!("{z}/diskTypes/pd-balanced"),"sizeGb":spec.public_data_disk_gib.to_string()}),
            },
            ResourcePlan {
                kind: ResourceKind::Instance,
                path: format!("{z}/instances/{n}"),
                create_body: json!({"name":n,"description":ownership,"machineType":format!("{z}/machineTypes/{}",spec.machine_type),"tags":{"items":[n]},"confidentialInstanceConfig":{"enableConfidentialCompute":true,"confidentialInstanceType":"TDX"},"shieldedInstanceConfig":{"enableSecureBoot":true,"enableVtpm":true,"enableIntegrityMonitoring":false},"scheduling":{"onHostMaintenance":"TERMINATE","automaticRestart":false},"deletionProtection":false,"serviceAccounts":[],"disks":[{"boot":true,"autoDelete":false,"source":boot,"interface":"NVME","mode":"READ_WRITE","deviceName":"zrpc-boot"},{"boot":false,"autoDelete":false,"source":data,"interface":"NVME","mode":"READ_WRITE","deviceName":"zrpc-public-data"}],"networkInterfaces":[{"subnetwork":subnet,"nicType":"GVNIC","accessConfigs":[{"type":"ONE_TO_ONE_NAT","name":"External NAT"}]}],"metadata":{"items":[{"key":"block-project-ssh-keys","value":"true"},{"key":"enable-oslogin","value":"FALSE"},{"key":"serial-port-enable","value":"FALSE"},{"key":"serial-port-logging-enable","value":"FALSE"},{"key":"enable-osconfig","value":"FALSE"}]}}),
            },
        ];
        Ok(Self {
            schema_version: 4,
            spec,
            resources,
        })
    }
    pub fn validate(&self, at: u64) -> Result<()> {
        let expected = Self::prepare(self.spec.clone(), at)?;
        if self.schema_version != 4 || self.resources != expected.resources {
            return Err(Error(
                "package resources differ from typed deployment policy",
            ));
        }
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|_| Error("package serialization failed"))
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(digest(&self.bytes()?))
    }
    pub fn write_new(&self, path: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error("package output exists or cannot be created"))?;
        file.write_all(&self.bytes()?)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error("package persistence failed"))?;
        fs::File::open(path.parent().ok_or(Error("package parent missing"))?)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error("package directory sync failed"))
    }
}
