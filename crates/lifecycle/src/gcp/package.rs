//! Typed, hash-bound local deployment package. No provider or credential reads.
use super::{Error, Result, digest, read_regular, valid_digest};
use crate::MAX_LIFETIME_SECONDS;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ImportReports {
    sizing: Artifact,
    gpt: Artifact,
    esp: Artifact,
    verity: Artifact,
    roothash: Artifact,
    rootfs: Artifact,
    #[serde(rename = "uki-digest")]
    uki_digest: Artifact,
}
impl ImportReports {
    fn entries(&self) -> [(&'static str, &Artifact, &'static str); 7] {
        [
            (
                "sizing",
                &self.sizing,
                "diagnostic-import-sized-gpt-unapproved",
            ),
            ("gpt", &self.gpt, "diagnostic-gpt-only-unapproved"),
            ("esp", &self.esp, "diagnostic-esp-uki-sections-unapproved"),
            (
                "verity",
                &self.verity,
                "diagnostic-raw-root-verity-unapproved",
            ),
            (
                "roothash",
                &self.roothash,
                "diagnostic-uki-roothash-gpt-match-unapproved",
            ),
            (
                "rootfs",
                &self.rootfs,
                "diagnostic-raw-root-overlay-bytes-matched-unapproved",
            ),
            (
                "uki-digest",
                &self.uki_digest,
                "diagnostic-uki-pe-coff-sha384-unapproved",
            ),
        ]
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageDiagnostics {
    esp_diagnostic: Artifact,
    uki_digest_diagnostic: Artifact,
    verity_diagnostic: Artifact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorHandoff {
    schema_version: u8,
    status: String,
    source_commit: String,
    stage_manifest_sha256: String,
    input_lock_sha256: String,
    native_rust_manifest_sha256: String,
    mkosi_disk_sha256: String,
    mkosi_disk_bytes: u64,
    raw_disk_sha256: String,
    raw_disk_bytes: u64,
    sfdisk_sha256: String,
    sfdisk_package_archive_sha256: String,
    sfdisk_archive_membership_rechecked: bool,
    sfdisk_dynamic_runtime_authenticated: bool,
    disk_raw: PathBuf,
    reinspection_receipt: Artifact,
    review_reports: ImportReports,
    package_diagnostics: PackageDiagnostics,
    import_archive_created: bool,
    import_package_ready: bool,
    boot_verified: bool,
    private_mode_approved: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReinspectionReceipt {
    schema_version: u8,
    status: String,
    source_commit: String,
    stage_manifest_sha256: String,
    input_lock_sha256: String,
    native_rust_manifest_sha256: String,
    mkosi_disk_sha256: String,
    mkosi_disk_bytes: u64,
    raw_disk_sha256: String,
    raw_disk_bytes: u64,
    sfdisk_sha256: String,
    sfdisk_package_archive_sha256: String,
    sfdisk_archive_membership_rechecked: bool,
    sfdisk_dynamic_runtime_authenticated: bool,
    disk_raw: PathBuf,
    reports: ImportReports,
    package_diagnostics: PackageDiagnostics,
    import_archive_created: bool,
    import_package_ready: bool,
    boot_verified: bool,
    private_mode_approved: bool,
}

/// Offline ESP inspection and PE hashing are consistency inputs only. Neither
/// report proves a signed boot or authorizes a client release.
#[derive(Debug, Deserialize)]
struct EspDiagnostic {
    status: String,
    raw_disk_sha256: String,
    raw_disk_bytes: u64,
    uki_sha256: String,
    uki_bytes: u64,
    uki_cmdline_for_review: String,
    complete_builder_toolchain: bool,
    signed_uki_checked: bool,
    cmdline_approved: bool,
    dm_verity_checked: bool,
    image_built: bool,
    private_mode_approved: bool,
}

/// Userspace root/verity inspection of this same raw disk. Its affirmative
/// verification field records a local tool result, not a boot or release fact.
#[derive(Debug, Deserialize)]
struct VerityDiagnostic {
    status: String,
    raw_disk_sha256: String,
    raw_disk_bytes: u64,
    uki_sha256: String,
    uki_cmdline_for_review: String,
    verity_userspace_verified: bool,
    complete_builder_toolchain: bool,
    signed_uki_checked: bool,
    cmdline_approved: bool,
    dm_verity_boot_checked: bool,
    image_built: bool,
    private_mode_approved: bool,
}

#[derive(Debug, Deserialize)]
struct UkiDigestDiagnostic {
    schema_version: u8,
    status: String,
    uki_sha256: String,
    uki_bytes: u64,
    uki_pe_coff_sha256: String,
    signed_uki_checked: bool,
    boot_measurement_checked: bool,
    release_approved: bool,
    private_mode_approved: bool,
}

fn read_hashed_diagnostic(artifact: &Artifact) -> Result<Vec<u8>> {
    let bytes = read_regular(&artifact.path)?;
    if digest(&bytes) != artifact.sha256 {
        return Err(Error("diagnostic report SHA-256 mismatch"));
    }
    Ok(bytes)
}

fn same_file_identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.mode(),
        a.nlink(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.mode(),
        b.nlink(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}

fn verify_source_disk(path: &Path, expected_sha256: &str, expected_bytes: u64) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error("final import disk unavailable"))?;
    let before = file
        .metadata()
        .map_err(|_| Error("final import disk metadata unavailable"))?;
    if !before.is_file() || before.nlink() != 1 || before.len() != expected_bytes {
        return Err(Error("final import disk size or file type differs"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| Error("final import disk read failed"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| Error("final import disk metadata unavailable"))?;
    if !same_file_identity(&before, &after) || hex::encode(hasher.finalize()) != expected_sha256 {
        return Err(Error("final import disk differs from operator handoff"));
    }
    Ok(())
}

fn verify_operator_handoff(spec: &DeploymentSpec, verify_disk: bool) -> Result<()> {
    let handoff: OperatorHandoff =
        serde_json::from_slice(&read_hashed_diagnostic(&spec.operator_handoff)?)
            .map_err(|_| Error("invalid typed operator handoff"))?;
    let directory = spec
        .operator_handoff
        .path
        .parent()
        .ok_or(Error("operator handoff parent missing"))?;
    if handoff.schema_version != 1
        || handoff.status != "diagnostic-operator-import-handoff-unapproved"
        || handoff.source_commit.len() != 40
        || !handoff.source_commit.bytes().all(|b| b.is_ascii_hexdigit())
        || [
            &handoff.stage_manifest_sha256,
            &handoff.input_lock_sha256,
            &handoff.native_rust_manifest_sha256,
            &handoff.mkosi_disk_sha256,
            &handoff.sfdisk_sha256,
            &handoff.sfdisk_package_archive_sha256,
        ]
        .iter()
        .any(|digest| !valid_digest(digest))
        || handoff.mkosi_disk_bytes == 0
        || handoff.raw_disk_sha256 != spec.raw_disk_sha256
        || handoff.raw_disk_bytes != spec.raw_disk_bytes
        || handoff.disk_raw != directory.join("disk.raw")
        || handoff.reinspection_receipt.path != directory.join("reinspection.json")
        || !handoff.sfdisk_archive_membership_rechecked
        || handoff.sfdisk_dynamic_runtime_authenticated
        || handoff.import_archive_created
        || handoff.import_package_ready
        || handoff.boot_verified
        || handoff.private_mode_approved
        || handoff.package_diagnostics.esp_diagnostic != spec.esp_diagnostic
        || handoff.package_diagnostics.uki_digest_diagnostic != spec.uki_digest_diagnostic
        || handoff.package_diagnostics.verity_diagnostic != spec.verity_diagnostic
        || handoff.package_diagnostics.esp_diagnostic != handoff.review_reports.esp
        || handoff.package_diagnostics.uki_digest_diagnostic != handoff.review_reports.uki_digest
        || handoff.package_diagnostics.verity_diagnostic != handoff.review_reports.verity
    {
        return Err(Error("operator handoff differs from candidate package"));
    }
    let receipt: ReinspectionReceipt =
        serde_json::from_slice(&read_hashed_diagnostic(&handoff.reinspection_receipt)?)
            .map_err(|_| Error("invalid typed import reinspection receipt"))?;
    if receipt.schema_version != 1
        || receipt.status != "diagnostic-import-disk-reinspected-unapproved"
        || receipt.source_commit != handoff.source_commit
        || receipt.stage_manifest_sha256 != handoff.stage_manifest_sha256
        || receipt.input_lock_sha256 != handoff.input_lock_sha256
        || receipt.native_rust_manifest_sha256 != handoff.native_rust_manifest_sha256
        || receipt.mkosi_disk_sha256 != handoff.mkosi_disk_sha256
        || receipt.mkosi_disk_bytes != handoff.mkosi_disk_bytes
        || receipt.raw_disk_sha256 != handoff.raw_disk_sha256
        || receipt.raw_disk_bytes != handoff.raw_disk_bytes
        || receipt.sfdisk_sha256 != handoff.sfdisk_sha256
        || receipt.sfdisk_package_archive_sha256 != handoff.sfdisk_package_archive_sha256
        || !receipt.sfdisk_archive_membership_rechecked
        || receipt.sfdisk_dynamic_runtime_authenticated
        || receipt.import_archive_created
        || receipt.import_package_ready
        || receipt.boot_verified
        || receipt.private_mode_approved
        || !receipt.disk_raw.is_absolute()
        || receipt.package_diagnostics.esp_diagnostic != receipt.reports.esp
        || receipt.package_diagnostics.uki_digest_diagnostic != receipt.reports.uki_digest
        || receipt.package_diagnostics.verity_diagnostic != receipt.reports.verity
    {
        return Err(Error(
            "import reinspection receipt differs from operator handoff",
        ));
    }
    let guest_directory = receipt
        .disk_raw
        .parent()
        .ok_or(Error("import reinspection disk parent missing"))?;
    for ((name, host, status), (guest_name, guest, _)) in handoff
        .review_reports
        .entries()
        .into_iter()
        .zip(receipt.reports.entries())
    {
        if name != guest_name
            || host.path != directory.join(format!("{name}.json"))
            || guest.path != guest_directory.join(format!("{name}.json"))
            || host.sha256 != guest.sha256
        {
            return Err(Error(
                "import report identity differs from operator handoff",
            ));
        }
        let report: Value = serde_json::from_slice(&read_hashed_diagnostic(host)?)
            .map_err(|_| Error("invalid import review report"))?;
        if report.get("status").and_then(Value::as_str) != Some(status)
            || report.get("private_mode_approved").and_then(Value::as_bool) != Some(false)
            || (name != "uki-digest"
                && (report.get("raw_disk_sha256").and_then(Value::as_str)
                    != Some(spec.raw_disk_sha256.as_str())
                    || report.get("raw_disk_bytes").and_then(Value::as_u64)
                        != Some(spec.raw_disk_bytes)))
        {
            return Err(Error("import review report differs from final disk"));
        }
        if name == "sizing"
            && (report.get("mkosi_disk_sha256").and_then(Value::as_str)
                != Some(handoff.mkosi_disk_sha256.as_str())
                || report.get("mkosi_disk_bytes").and_then(Value::as_u64)
                    != Some(handoff.mkosi_disk_bytes)
                || report.get("sfdisk_sha256").and_then(Value::as_str)
                    != Some(handoff.sfdisk_sha256.as_str()))
        {
            return Err(Error("import sizing report differs from operator handoff"));
        }
    }
    if verify_disk {
        verify_source_disk(
            &handoff.disk_raw,
            &spec.raw_disk_sha256,
            spec.raw_disk_bytes,
        )?;
    }
    Ok(())
}

fn reviewed_roothash(cmdline: &str) -> Option<&str> {
    // Keep the package consumer bound to the compiled source profile as well
    // as the two diagnostic records for the same extracted UKI.
    let source = include_str!("../../../../deploy/gcp/guest/mkosi.conf");
    let mut lines = source
        .lines()
        .filter_map(|line| line.strip_prefix("KernelCommandLine="));
    let fixed = lines.next()?;
    if fixed.is_empty() || lines.next().is_some() {
        return None;
    }
    let (prefix, rest) = cmdline.split_once(' ')?;
    let hash = prefix.strip_prefix("roothash=")?;
    (hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && rest == fixed)
        .then_some(hash)
}

// UEFI 2.10 §32: EFI_SIGNATURE_LIST with EFI_CERT_SHA256_GUID, no signature
// header, and one EFI_SIGNATURE_DATA (16-byte owner GUID + 32-byte image hash).
// GUID fields are little-endian on the EFI wire. This is a structural policy
// check, not a claim that Google C3 TDX firmware accepts a hash-only db.
// https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html
const EFI_CERT_SHA256_GUID_WIRE: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];
const SINGLE_SHA256_ESL_BYTES: usize = 16 + 4 + 4 + 4 + 16 + 32;

fn verify_exact_uki_db(spec: &DeploymentSpec) -> Result<()> {
    let esp: EspDiagnostic = serde_json::from_slice(&read_hashed_diagnostic(&spec.esp_diagnostic)?)
        .map_err(|_| Error("invalid typed ESP diagnostic"))?;
    let uki: UkiDigestDiagnostic =
        serde_json::from_slice(&read_hashed_diagnostic(&spec.uki_digest_diagnostic)?)
            .map_err(|_| Error("invalid typed UKI digest diagnostic"))?;
    let verity: VerityDiagnostic =
        serde_json::from_slice(&read_hashed_diagnostic(&spec.verity_diagnostic)?)
            .map_err(|_| Error("invalid typed root/verity diagnostic"))?;
    if esp.status != "diagnostic-esp-uki-sections-unapproved"
        || esp.raw_disk_sha256 != spec.raw_disk_sha256
        || esp.raw_disk_bytes != spec.raw_disk_bytes
        || !valid_digest(&esp.uki_sha256)
        || esp.uki_bytes == 0
        || reviewed_roothash(&esp.uki_cmdline_for_review).is_none()
        || esp.complete_builder_toolchain
        || esp.signed_uki_checked
        || esp.cmdline_approved
        || esp.dm_verity_checked
        || esp.image_built
        || esp.private_mode_approved
        || uki.schema_version != 1
        || uki.status != "diagnostic-uki-pe-coff-sha384-unapproved"
        || uki.uki_sha256 != esp.uki_sha256
        || uki.uki_bytes != esp.uki_bytes
        || !valid_digest(&uki.uki_pe_coff_sha256)
        || uki.signed_uki_checked
        || uki.boot_measurement_checked
        || uki.release_approved
        || uki.private_mode_approved
        || verity.status != "diagnostic-raw-root-verity-unapproved"
        || verity.raw_disk_sha256 != spec.raw_disk_sha256
        || verity.raw_disk_bytes != spec.raw_disk_bytes
        || verity.uki_sha256 != esp.uki_sha256
        || verity.uki_cmdline_for_review != esp.uki_cmdline_for_review
        || !verity.verity_userspace_verified
        || verity.complete_builder_toolchain
        || verity.signed_uki_checked
        || verity.cmdline_approved
        || verity.dm_verity_boot_checked
        || verity.image_built
        || verity.private_mode_approved
    {
        return Err(Error("boot diagnostics do not bind the reviewed raw disk"));
    }
    let db = read_regular(&spec.secure_boot_db_esl.path)?;
    if digest(&db) != spec.secure_boot_db_esl.sha256 {
        return Err(Error("Secure Boot db changed during preparation"));
    }
    if db.len() != SINGLE_SHA256_ESL_BYTES
        || db[..16] != EFI_CERT_SHA256_GUID_WIRE
        || db[16..20] != (SINGLE_SHA256_ESL_BYTES as u32).to_le_bytes()
        || db[20..24] != 0u32.to_le_bytes()
        || db[24..28] != 48u32.to_le_bytes()
    {
        return Err(Error(
            "Secure Boot db must contain one exact UKI SHA-256 hash",
        ));
    }
    let mut reported_hash = [0u8; 32];
    hex::decode_to_slice(&uki.uki_pe_coff_sha256, &mut reported_hash)
        .map_err(|_| Error("invalid UKI PE/COFF SHA-256 digest"))?;
    if db[44..] != reported_hash {
        return Err(Error("Secure Boot db hash differs from UKI PE/COFF digest"));
    }
    Ok(())
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
    /// Pre-archive handoff from the final disk reinspection. Preparation hashes
    /// its disk directly; later validation checks the frozen archive instead.
    pub operator_handoff: Artifact,
    /// Exact operator-host interpreter for the embedded offline validator.
    /// This identity is separate from the producer's Python in the receipt.
    pub import_verifier_python: Artifact,
    pub release_manifest: Artifact,
    pub boot_policy: Artifact,
    pub memory_measurement: Artifact,
    pub reproducibility_report: Artifact,
    /// Diagnostic inspection of the exact raw disk's ESP and extracted UKI.
    pub esp_diagnostic: Artifact,
    /// Diagnostic Authenticode digest of that same extracted UKI.
    pub uki_digest_diagnostic: Artifact,
    /// Userspace root/verity check against that disk's extracted UKI roothash.
    pub verity_diagnostic: Artifact,
    pub secure_boot_pk_der: Artifact,
    pub secure_boot_kek_der: Artifact,
    /// One EFI_CERT_SHA256_GUID EFI_SIGNATURE_LIST, not a signer certificate.
    pub secure_boot_db_esl: Artifact,
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
        self.validate_inner(at, true)
    }
    fn validate_inner(&self, at: u64, verify_disk: bool) -> Result<()> {
        if self.schema_version != 7
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
        verify_operator_handoff(self, verify_disk)?;
        verify_import_receipt(self)?;
        verify_import_archive(
            &self.raw_image_tar_gz,
            &self.raw_disk_sha256,
            self.raw_disk_bytes,
            &self.import_verifier_python,
        )?;
        verify_exact_uki_db(self)?;
        Ok(())
    }
    pub fn artifacts(&self) -> [&Artifact; 16] {
        [
            &self.raw_image_tar_gz,
            &self.import_receipt,
            &self.operator_handoff,
            &self.import_verifier_python,
            &self.release_manifest,
            &self.boot_policy,
            &self.memory_measurement,
            &self.reproducibility_report,
            &self.esp_diagnostic,
            &self.uki_digest_diagnostic,
            &self.verity_diagnostic,
            &self.secure_boot_pk_der,
            &self.secure_boot_kek_der,
            &self.secure_boot_db_esl,
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
        Self::from_spec(spec, at, true)
    }
    fn from_spec(spec: DeploymentSpec, at: u64, verify_disk: bool) -> Result<Self> {
        spec.validate_inner(at, verify_disk)?;
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
                // Google accepts BIN database inputs; only hardware readback
                // can confirm C3 TDX's effective variables and boot behavior.
                // https://docs.cloud.google.com/compute/shielded-vm/docs/creating-shielded-images
                create_body: json!({"name":format!("{n}-image"),"description":ownership,"architecture":"X86_64","rawDisk":{"source":format!("https://storage.googleapis.com/{}/{}",spec.staging_bucket,spec.object_name()),"containerType":"TAR"},"guestOsFeatures":[{"type":"UEFI_COMPATIBLE"},{"type":"GVNIC"},{"type":"TDX_CAPABLE"}],"shieldedInstanceInitialState":{"pk":cert(&spec.secure_boot_pk_der)?,"keks":[cert(&spec.secure_boot_kek_der)?],"dbs":[secure_boot_file(&spec.secure_boot_db_esl, "BIN")?],"dbxs":[secure_boot_file(&spec.secure_boot_dbx_bin, "BIN")?]}}),
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
            schema_version: 7,
            spec,
            resources,
        })
    }
    pub fn validate(&self, at: u64) -> Result<()> {
        let expected = Self::from_spec(self.spec.clone(), at, false)?;
        if self.schema_version != 7 || self.resources != expected.resources {
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
