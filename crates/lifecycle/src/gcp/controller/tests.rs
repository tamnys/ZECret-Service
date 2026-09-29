//! Synthetic provider and filesystem tests. No Google or hardware calls.
use super::*;
use crate::gcp::{
    digest,
    package::{Artifact, DeploymentSpec, Pricing},
    store::Journal,
    watchdog::{Controls, WatchdogBinding},
};
use serde_json::json;
use std::{cell::Cell, collections::BTreeMap, fs, path::PathBuf, sync::OnceLock};

fn diagnostic_artifact(root: &std::path::Path, name: &str, value: &Value) -> Artifact {
    let bytes = serde_json::to_vec(value).unwrap();
    let path = root.join(name);
    fs::write(&path, &bytes).unwrap();
    Artifact {
        path,
        sha256: digest(&bytes),
    }
}

fn exact_sha256_esl(image_hash: &str) -> Vec<u8> {
    // EFI_CERT_SHA256_GUID in EFI mixed-endian wire order; one signature.
    let mut db = vec![
        0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43,
        0x28,
    ];
    db.extend_from_slice(&76u32.to_le_bytes());
    db.extend_from_slice(&0u32.to_le_bytes());
    db.extend_from_slice(&48u32.to_le_bytes());
    db.extend_from_slice(&[0xa5; 16]); // Synthetic SignatureOwner GUID.
    db.extend_from_slice(&hex::decode(image_hash).unwrap());
    db
}

fn synthetic_import_archive() -> &'static (Vec<u8>, String, Vec<u8>) {
    static IMAGE: OnceLock<(Vec<u8>, String, Vec<u8>)> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let base = PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        );
        let root = base.join(format!("gcp-import-fixture-{}", uuid().unwrap()));
        fs::create_dir(&root).unwrap();
        let raw = root.join("disk.raw");
        fs::File::create(&raw)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        let archive = root.join("synthetic.tar.gz");
        let receipt: Value =
            serde_json::to_value(crate::gcp::package::pack_import_archive(&raw, &archive).unwrap())
                .unwrap();
        assert_eq!(receipt["private_mode_approved"], false);
        assert_eq!(receipt["toolchain_reviewed"], false);
        assert_eq!(receipt["producer"], "zrpc-gcp-lifecycle-rust");
        let bytes = fs::read(archive).unwrap();
        let raw_sha256 = receipt["raw_disk_sha256"].as_str().unwrap().to_owned();
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        fs::remove_dir_all(root).unwrap();
        (bytes, raw_sha256, receipt_bytes)
    })
}

#[test]
fn older_journal_without_upload_proof_defaults_to_unverified() {
    let mut old = serde_json::to_value(crate::gcp::store::ResourceState::default()).unwrap();
    old.as_object_mut()
        .unwrap()
        .remove("upload_media_stream_verified");
    let decoded: crate::gcp::store::ResourceState = serde_json::from_value(old).unwrap();
    assert!(!decoded.upload_media_stream_verified);
}

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    package: Package,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        )
        .join(format!("zrpc-gcp-synthetic-{}", uuid().unwrap()));
        fs::create_dir(&root).unwrap();
        let artifact_path = root.join("synthetic-artifact");
        fs::write(&artifact_path, b"SYNTHETIC - NOT A BOOTABLE IMAGE").unwrap();
        let a = Artifact {
            path: artifact_path,
            sha256: digest(b"SYNTHETIC - NOT A BOOTABLE IMAGE"),
        };
        let (image_bytes, raw_disk_sha256, receipt_bytes) = synthetic_import_archive();
        let producer_receipt: Value = serde_json::from_slice(&receipt_bytes).unwrap();
        let producer_sha256 = producer_receipt["producer_executable_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let producer_binary = Artifact {
            path: std::env::current_exe().unwrap(),
            sha256: producer_sha256.clone(),
        };
        let native_rust_manifest = diagnostic_artifact(
            &root,
            "native-rust-manifest.json",
            &json!({
                "schema_version":1,
                "artifact_kind":"unsigned_native_scaffold",
                "source_commit":"a".repeat(40),
                "reproducible":true,
                "approved_release":false,
                "private_accepted":false,
                "deployment_enabled":false,
                "published":false,
                "signed":false,
                "selected_binaries":[{"package":"zrpc-lifecycle","name":"zrpc-gcp-lifecycle"}],
                "artifact_sha256":{"zrpc-gcp-lifecycle":producer_sha256}
            }),
        );
        let disk_raw = root.join("disk.raw");
        fs::File::create(&disk_raw)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        let uki_sha256 = digest(b"SYNTHETIC UKI BYTES");
        let uki_pe_coff_sha256 = digest(b"SYNTHETIC PE/COFF IMAGE DIGEST");
        let fixed_cmdline = include_str!("../../../../../deploy/gcp/guest/mkosi.conf")
            .lines()
            .find_map(|line| line.strip_prefix("KernelCommandLine="))
            .unwrap();
        let uki_cmdline = format!("roothash={} {fixed_cmdline}", "a".repeat(64));
        let esp_diagnostic = diagnostic_artifact(
            &root,
            "esp.json",
            &json!({
                "status":"diagnostic-esp-uki-sections-unapproved",
                "raw_disk_sha256":raw_disk_sha256,
                "raw_disk_bytes":1024 * 1024 * 1024,
                "uki_sha256":uki_sha256,
                "uki_bytes":19,
                "uki_cmdline_for_review":uki_cmdline,
                "complete_builder_toolchain":false,
                "signed_uki_checked":false,
                "cmdline_approved":false,
                "dm_verity_checked":false,
                "image_built":false,
                "private_mode_approved":false
            }),
        );
        let verity_diagnostic = diagnostic_artifact(
            &root,
            "verity.json",
            &json!({
                "status":"diagnostic-raw-root-verity-unapproved",
                "raw_disk_sha256":raw_disk_sha256,
                "raw_disk_bytes":1024 * 1024 * 1024,
                "uki_sha256":uki_sha256,
                "uki_cmdline_for_review":uki_cmdline,
                "verity_userspace_verified":true,
                "complete_builder_toolchain":false,
                "signed_uki_checked":false,
                "cmdline_approved":false,
                "dm_verity_boot_checked":false,
                "image_built":false,
                "private_mode_approved":false
            }),
        );
        let uki_digest_diagnostic = diagnostic_artifact(
            &root,
            "uki-digest.json",
            &json!({
                "schema_version":1,
                "status":"diagnostic-uki-pe-coff-sha384-unapproved",
                "uki_sha256":uki_sha256,
                "uki_bytes":19,
                "uki_pe_coff_sha256":uki_pe_coff_sha256,
                "signed_uki_checked":false,
                "boot_measurement_checked":false,
                "release_approved":false,
                "private_mode_approved":false
            }),
        );
        let mkosi_sha256 = "c".repeat(64);
        let sfdisk_sha256 = "3".repeat(64);
        let sfdisk_archive_sha256 = "4".repeat(64);
        let sizing = diagnostic_artifact(
            &root,
            "sizing.json",
            &json!({"status":"diagnostic-import-sized-gpt-unapproved",
                "mkosi_disk_sha256":mkosi_sha256,"mkosi_disk_bytes":1024 * 1024 * 1024,
                "raw_disk_sha256":raw_disk_sha256,"raw_disk_bytes":1024 * 1024 * 1024,
                "sfdisk_sha256":sfdisk_sha256,"private_mode_approved":false}),
        );
        let extra_report = |name: &str, status: &str| {
            diagnostic_artifact(
                &root,
                &format!("{name}.json"),
                &json!({"status":status,"raw_disk_sha256":raw_disk_sha256,
                    "raw_disk_bytes":1024 * 1024 * 1024,"private_mode_approved":false}),
            )
        };
        let gpt = extra_report("gpt", "diagnostic-gpt-only-unapproved");
        let roothash = extra_report("roothash", "diagnostic-uki-roothash-gpt-match-unapproved");
        let rootfs = extra_report(
            "rootfs",
            "diagnostic-raw-root-overlay-bytes-matched-unapproved",
        );
        let host_reports = json!({"sizing":sizing,"gpt":gpt,"esp":esp_diagnostic,
            "verity":verity_diagnostic,"roothash":roothash,"rootfs":rootfs,
            "uki-digest":uki_digest_diagnostic});
        let guest = |name: &str, artifact: &Artifact| Artifact {
            path: PathBuf::from(format!("/workspace/import-disk/{name}.json")),
            sha256: artifact.sha256.clone(),
        };
        let guest_reports = json!({
            "sizing":guest("sizing", &sizing), "gpt":guest("gpt", &gpt),
            "esp":guest("esp", &esp_diagnostic),
            "verity":guest("verity", &verity_diagnostic),
            "roothash":guest("roothash", &roothash),
            "rootfs":guest("rootfs", &rootfs),
            "uki-digest":guest("uki-digest", &uki_digest_diagnostic),
        });
        let reinspection = diagnostic_artifact(
            &root,
            "reinspection.json",
            &json!({
                "schema_version":1,"status":"diagnostic-import-disk-reinspected-unapproved",
                "source_commit":"a".repeat(40),"stage_manifest_sha256":"b".repeat(64),
                "input_lock_sha256":"d".repeat(64),
                "native_rust_manifest_sha256":native_rust_manifest.sha256,
                "mkosi_disk_sha256":mkosi_sha256,"mkosi_disk_bytes":1024 * 1024 * 1024,
                "raw_disk_sha256":raw_disk_sha256,"raw_disk_bytes":1024 * 1024 * 1024,
                "sfdisk_sha256":sfdisk_sha256,
                "sfdisk_package_archive_sha256":sfdisk_archive_sha256,
                "sfdisk_archive_membership_rechecked":true,
                "sfdisk_dynamic_runtime_authenticated":false,
                "disk_raw":"/workspace/import-disk/disk.raw",
                "reports":guest_reports,
                "package_diagnostics":{"esp_diagnostic":guest("esp", &esp_diagnostic),
                    "uki_digest_diagnostic":guest("uki-digest", &uki_digest_diagnostic),
                    "verity_diagnostic":guest("verity", &verity_diagnostic)},
                "import_archive_created":false,"import_package_ready":false,
                "boot_verified":false,"private_mode_approved":false,
            }),
        );
        let operator_handoff = diagnostic_artifact(
            &root,
            "operator-handoff.json",
            &json!({
                "schema_version":1,"status":"diagnostic-operator-import-handoff-unapproved",
                "source_commit":"a".repeat(40),"stage_manifest_sha256":"b".repeat(64),
                "input_lock_sha256":"d".repeat(64),
                "native_rust_manifest_sha256":native_rust_manifest.sha256,
                "mkosi_disk_sha256":mkosi_sha256,"mkosi_disk_bytes":1024 * 1024 * 1024,
                "raw_disk_sha256":raw_disk_sha256,"raw_disk_bytes":1024 * 1024 * 1024,
                "sfdisk_sha256":sfdisk_sha256,
                "sfdisk_package_archive_sha256":sfdisk_archive_sha256,
                "sfdisk_archive_membership_rechecked":true,
                "sfdisk_dynamic_runtime_authenticated":false,
                "disk_raw":disk_raw,"reinspection_receipt":reinspection,
                "review_reports":host_reports,
                "package_diagnostics":{"esp_diagnostic":esp_diagnostic,
                    "uki_digest_diagnostic":uki_digest_diagnostic,
                    "verity_diagnostic":verity_diagnostic},
                "import_archive_created":false,"import_package_ready":false,
                "boot_verified":false,"private_mode_approved":false,
            }),
        );
        let db_bytes = exact_sha256_esl(&uki_pe_coff_sha256);
        let db_path = root.join("secure-boot-db.esl");
        fs::write(&db_path, &db_bytes).unwrap();
        let secure_boot_db_esl = Artifact {
            path: db_path,
            sha256: digest(&db_bytes),
        };
        let archive_path = root.join("synthetic.tar.gz");
        fs::write(&archive_path, image_bytes).unwrap();
        let raw_image_tar_gz = Artifact {
            path: archive_path,
            sha256: digest(image_bytes),
        };
        let import_receipt_path = root.join("import-receipt.json");
        fs::write(&import_receipt_path, receipt_bytes).unwrap();
        let import_receipt = Artifact {
            path: import_receipt_path,
            sha256: digest(receipt_bytes),
        };
        let components = [
            "compute",
            "boot_disk",
            "public_data_disk",
            "image",
            "staging",
            "external_ip",
            "network",
            "taxes",
        ]
        .map(|k| (k.to_owned(), 1))
        .into();
        let spec = DeploymentSpec {
            schema_version: 9,
            experiment: "synthetic-evaluation".into(),
            project: "synthetic-project".into(),
            region: "us-central1".into(),
            zone: "us-central1-a".into(),
            machine_type: "c3-standard-4".into(),
            boot_disk_gib: 10,
            public_data_disk_gib: 10,
            subnet_cidr: "10.42.0.0/24".into(),
            wrapper_port: 8443,
            staging_bucket: "synthetic-staging-bucket".into(),
            start_unix_seconds: 1000,
            deadline_unix_seconds: 1000 + crate::MAX_LIFETIME_SECONDS,
            raw_image_tar_gz,
            raw_disk_sha256: raw_disk_sha256.clone(),
            raw_disk_bytes: 1024 * 1024 * 1024,
            import_receipt,
            native_rust_manifest,
            producer_binary,
            operator_handoff,
            release_manifest: a.clone(),
            boot_policy: a.clone(),
            memory_measurement: a.clone(),
            reproducibility_report: a.clone(),
            esp_diagnostic,
            uki_digest_diagnostic,
            verity_diagnostic,
            secure_boot_pk_der: a.clone(),
            secure_boot_kek_der: a.clone(),
            secure_boot_db_esl,
            secure_boot_dbx_bin: a.clone(),
            pricing: Pricing {
                source: "https://example.invalid/synthetic-quote".into(),
                quoted_at: 900,
                expires_at: 2000,
                projected_total_microusd: 8,
                components_microusd: components,
                evidence: a,
            },
        };
        let package = Package::prepare(spec, 1000).unwrap();
        let state = root.join("journal");
        Store::initialize(&state, &package).unwrap();
        let artifact = package.spec.release_manifest.clone();
        let runtime = crate::gcp::provider::Runtime {
            gcloud: artifact.clone(),
            gcloud_distribution_receipt: artifact.clone(),
            gcloud_config_directory: root.join("credentials"),
            trust_roots_der: vec![artifact.clone()],
            invocation_budget_ms: 11_000,
            response_limit_bytes: 4096,
        };
        let controls_path = root.join("controls.json");
        let runtime_path = root.join("runtime.json");
        let runtime_bytes = serde_json::to_vec(&runtime).unwrap();
        fs::write(&runtime_path, &runtime_bytes).unwrap();
        let controls = Controls {
            package_sha256: package.sha256().unwrap(),
            executable: artifact.clone(),
            runtime_file: Artifact {
                path: runtime_path,
                sha256: digest(&runtime_bytes),
            },
            state_directory: state.clone(),
            controller_machine_id: "a".repeat(32),
            controller_uid: unsafe { libc::geteuid() }.max(1),
            poll_interval_seconds: 20,
            deletion_duration_seconds: 100,
            systemd_delay_seconds: 3,
            deletion_rehearsal: artifact.clone(),
            independent_backstop: artifact,
        };
        let controls_bytes = serde_json::to_vec(&controls).unwrap();
        fs::write(&controls_path, &controls_bytes).unwrap();
        Store::open(&state)
            .unwrap()
            .admit_watchdog(
                WatchdogBinding::from_admitted(
                    &controls,
                    &controls_path,
                    &controls_bytes,
                    &package,
                )
                .unwrap(),
            )
            .unwrap();
        Self {
            root,
            state,
            package,
        }
    }
    fn mock(&self) -> Mock {
        Mock {
            state: self.state.clone(),
            objects: BTreeMap::new(),
            staging_noncurrent: false,
            staging_soft_deleted: false,
            staging_residual_failure: false,
            operations: BTreeMap::new(),
            preflight_calls: 0,
            calls: Vec::new(),
            deletes: Vec::new(),
            compute_delete_response: None,
            fail_after_create: false,
            outage: false,
        }
    }
    fn spec_with_receipt_edit(&self, edit: impl FnOnce(&mut Value)) -> DeploymentSpec {
        let mut spec = self.package.spec.clone();
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&spec.import_receipt.path).unwrap()).unwrap();
        edit(&mut receipt);
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let path = self
            .root
            .join(format!("edited-receipt-{}.json", uuid().unwrap()));
        fs::write(&path, &bytes).unwrap();
        spec.import_receipt = Artifact {
            path,
            sha256: digest(&bytes),
        };
        spec
    }
    fn spec_with_handoff_edit(&self, edit: impl FnOnce(&mut Value)) -> DeploymentSpec {
        let mut spec = self.package.spec.clone();
        let mut handoff: Value =
            serde_json::from_slice(&fs::read(&spec.operator_handoff.path).unwrap()).unwrap();
        edit(&mut handoff);
        spec.operator_handoff = diagnostic_artifact(
            &self.root,
            &format!("edited-handoff-{}.json", uuid().unwrap()),
            &handoff,
        );
        spec
    }
    fn spec_with_diagnostic_edit(
        &self,
        esp: bool,
        edit: impl FnOnce(&mut Value),
    ) -> DeploymentSpec {
        let mut spec = self.package.spec.clone();
        let artifact = if esp {
            &mut spec.esp_diagnostic
        } else {
            &mut spec.uki_digest_diagnostic
        };
        let mut report: Value = serde_json::from_slice(&fs::read(&artifact.path).unwrap()).unwrap();
        edit(&mut report);
        *artifact = diagnostic_artifact(
            &self.root,
            &format!("edited-diagnostic-{}.json", uuid().unwrap()),
            &report,
        );
        spec
    }
    fn spec_with_verity_edit(&self, edit: impl FnOnce(&mut Value)) -> DeploymentSpec {
        let mut spec = self.package.spec.clone();
        let mut report: Value =
            serde_json::from_slice(&fs::read(&spec.verity_diagnostic.path).unwrap()).unwrap();
        edit(&mut report);
        spec.verity_diagnostic = diagnostic_artifact(
            &self.root,
            &format!("edited-verity-{}.json", uuid().unwrap()),
            &report,
        );
        spec
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn image_package_pins_the_complete_secure_boot_policy() {
    let f = Fixture::new();
    let image = f
        .package
        .resources
        .iter()
        .find(|r| r.kind == ResourceKind::Image)
        .unwrap();
    let state = &image.create_body["shieldedInstanceInitialState"];
    assert_eq!(state["pk"]["fileType"], "X509");
    assert_eq!(state["keks"][0]["fileType"], "X509");
    assert_eq!(state["dbs"][0]["fileType"], "BIN");
    assert_eq!(state["dbxs"][0]["fileType"], "BIN");
    assert_eq!(
        state["dbs"][0]["content"],
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            fs::read(&f.package.spec.secure_boot_db_esl.path).unwrap()
        )
    );
    assert_eq!(
        state["dbxs"][0]["content"],
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"SYNTHETIC - NOT A BOOTABLE IMAGE"
        )
    );

    let mut missing_dbx = serde_json::to_value(&f.package.spec).unwrap();
    missing_dbx
        .as_object_mut()
        .unwrap()
        .remove("secure_boot_dbx_bin");
    assert!(serde_json::from_value::<DeploymentSpec>(missing_dbx).is_err());

    let mut inherited_default = f.package.clone();
    inherited_default
        .resources
        .iter_mut()
        .find(|r| r.kind == ResourceKind::Image)
        .unwrap()
        .create_body["shieldedInstanceInitialState"]
        .as_object_mut()
        .unwrap()
        .remove("dbxs");
    assert!(inherited_default.validate(1000).is_err());
}

#[test]
fn image_package_rejects_extra_secure_boot_authorities_and_wrong_hash() {
    let f = Fixture::new();
    let original = fs::read(&f.package.spec.secure_boot_db_esl.path).unwrap();
    let cases = [
        {
            let mut db = original.clone();
            db.extend_from_slice(&original); // A second hash list.
            db
        },
        {
            let mut db = original.clone();
            db.extend_from_slice(&db[28..].to_vec()); // A second hash entry.
            db[16..20].copy_from_slice(&124u32.to_le_bytes());
            db
        },
        {
            let mut db = original.clone();
            db[0] ^= 1; // Wrong signature-list type (including X509).
            db
        },
        {
            let mut db = original.clone();
            db[20..24].copy_from_slice(&1u32.to_le_bytes()); // Header present.
            db
        },
        {
            let mut db = original.clone();
            db[44] ^= 1; // One entry, wrong UKI image digest.
            db
        },
    ];
    for db in cases {
        let mut spec = f.package.spec.clone();
        let path = f.root.join(format!("wrong-db-{}.esl", uuid().unwrap()));
        fs::write(&path, &db).unwrap();
        spec.secure_boot_db_esl = Artifact {
            path,
            sha256: digest(&db),
        };
        assert!(Package::prepare(spec, 1000).is_err());
    }

    let mut extra_api_authority = f.package.clone();
    extra_api_authority
        .resources
        .iter_mut()
        .find(|r| r.kind == ResourceKind::Image)
        .unwrap()
        .create_body["shieldedInstanceInitialState"]["dbs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"fileType":"X509","content":"synthetic-signer"}));
    assert!(extra_api_authority.validate(1000).is_err());
}

#[test]
fn image_package_rejects_diagnostic_substitution_or_unlinked_disk() {
    let f = Fixture::new();
    for spec in [
        f.spec_with_diagnostic_edit(true, |v| v["raw_disk_sha256"] = json!("0".repeat(64))),
        f.spec_with_diagnostic_edit(true, |v| v["uki_sha256"] = json!("1".repeat(64))),
        f.spec_with_diagnostic_edit(false, |v| v["uki_sha256"] = json!("1".repeat(64))),
        f.spec_with_diagnostic_edit(false, |v| v["uki_pe_coff_sha256"] = json!("1".repeat(64))),
        f.spec_with_diagnostic_edit(false, |v| v["release_approved"] = json!(true)),
        f.spec_with_diagnostic_edit(true, |v| {
            v["uki_cmdline_for_review"] = json!("roothash=00 extra=1")
        }),
    ] {
        assert!(Package::prepare(spec, 1000).is_err());
    }
}

#[test]
fn image_package_requires_the_same_diagnostic_root_verity_pair() {
    let f = Fixture::new();
    for spec in [
        f.spec_with_verity_edit(|v| v["status"] = json!("private-approved")),
        f.spec_with_verity_edit(|v| v["raw_disk_sha256"] = json!("0".repeat(64))),
        f.spec_with_verity_edit(|v| v["raw_disk_bytes"] = json!(42)),
        f.spec_with_verity_edit(|v| v["uki_sha256"] = json!("1".repeat(64))),
        f.spec_with_verity_edit(|v| {
            let old = v["uki_cmdline_for_review"].as_str().unwrap();
            v["uki_cmdline_for_review"] = json!(old.replacen('a', "b", 1));
        }),
        f.spec_with_verity_edit(|v| v["verity_userspace_verified"] = json!(false)),
        f.spec_with_verity_edit(|v| v["complete_builder_toolchain"] = json!(true)),
        f.spec_with_verity_edit(|v| v["signed_uki_checked"] = json!(true)),
        f.spec_with_verity_edit(|v| v["cmdline_approved"] = json!(true)),
        f.spec_with_verity_edit(|v| v["dm_verity_boot_checked"] = json!(true)),
        f.spec_with_verity_edit(|v| v["image_built"] = json!(true)),
        f.spec_with_verity_edit(|v| v["private_mode_approved"] = json!(true)),
    ] {
        assert!(Package::prepare(spec, 1000).is_err());
    }
    let mut missing = serde_json::to_value(&f.package.spec).unwrap();
    missing.as_object_mut().unwrap().remove("verity_diagnostic");
    assert!(serde_json::from_value::<DeploymentSpec>(missing).is_err());
    let mut old_schema = f.package.spec.clone();
    old_schema.schema_version = 5;
    assert!(Package::prepare(old_schema, 1000).is_err());
}

#[test]
fn image_package_requires_the_reviewed_raw_disk_inside_the_import_archive() {
    let f = Fixture::new();
    let mut wrong_raw = f.package.spec.clone();
    wrong_raw.raw_disk_sha256 = "0".repeat(64);
    assert!(Package::prepare(wrong_raw, 1000).is_err());

    let mut undersized_boot = f.package.spec.clone();
    undersized_boot.raw_disk_bytes = 11 * 1024 * 1024 * 1024;
    assert!(Package::prepare(undersized_boot, 1000).is_err());

    let mut oversized_boot = f.package.spec.clone();
    oversized_boot.boot_disk_gib = 2049;
    assert!(Package::prepare(oversized_boot, 1000).is_err());

    let mut wrong_archive = f.package.spec.clone();
    wrong_archive.raw_image_tar_gz = wrong_archive.release_manifest.clone();
    assert!(Package::prepare(wrong_archive, 1000).is_err());

    let mut old_schema = f.package.spec.clone();
    old_schema.schema_version = 3;
    assert!(Package::prepare(old_schema, 1000).is_err());
}

#[test]
fn custom_image_package_rejects_incompatible_c3_tdx_machine_types() {
    let f = Fixture::new();
    for machine_type in [
        "c3-standard-4",
        "c3-standard-8",
        "c3-standard-22",
        "c3-standard-44",
        "c3-standard-88",
        "c3-standard-176",
    ] {
        let mut spec = f.package.spec.clone();
        spec.machine_type = machine_type.into();
        let package = Package::prepare(spec, 1000).unwrap();
        let instance = package
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::Instance)
            .unwrap();
        assert_eq!(
            instance.create_body["machineType"],
            format!("projects/synthetic-project/zones/us-central1-a/machineTypes/{machine_type}")
        );
    }
    for machine_type in [
        "c3-standard-4-lssd",
        "c3-standard-44-lssd",
        "c3-standard-12",
        "c3-standard-192-metal",
        "c3-highcpu-4",
        "c3-highmem-4",
        "c3d-standard-4",
        "c4-standard-4",
    ] {
        let mut spec = f.package.spec.clone();
        spec.machine_type = machine_type.into();
        assert!(
            Package::prepare(spec, 1000).is_err(),
            "must reject {machine_type} for this custom Debian TDX image"
        );
    }
}

#[test]
fn custom_image_package_rejects_zones_without_c3_tdx_support() {
    let f = Fixture::new();
    let mut supported = f.package.spec.clone();
    supported.region = "us-east5".into();
    supported.zone = "us-east5-c".into();
    assert!(Package::prepare(supported, 1000).is_ok());

    for zone in ["us-central1-d", "us-central1-f"] {
        let mut unsupported = f.package.spec.clone();
        unsupported.zone = zone.into();
        assert!(
            Package::prepare(unsupported, 1000).is_err(),
            "{zone} is not in Google's C3 TDX zone list"
        );
    }
}

#[test]
fn import_receipt_binds_candidate_media_with_native_validation_without_approval() {
    let f = Fixture::new();
    let original: Value =
        serde_json::from_slice(&fs::read(&f.package.spec.import_receipt.path).unwrap()).unwrap();
    assert_eq!(original["toolchain_reviewed"], false);
    assert_eq!(original["private_mode_approved"], false);
    assert!(
        crate::gcp::LIVE_DEPLOYMENT_BLOCKERS
            .iter()
            .any(|item| item.contains("import producer executable identity"))
    );

    let mut missing = serde_json::to_value(&f.package.spec).unwrap();
    missing.as_object_mut().unwrap().remove("import_receipt");
    assert!(serde_json::from_value::<DeploymentSpec>(missing).is_err());
    for field in ["native_rust_manifest", "producer_binary"] {
        let mut missing = serde_json::to_value(&f.package.spec).unwrap();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<DeploymentSpec>(missing).is_err(),
            "{field}"
        );
    }
    let mut unexpected_verifier = serde_json::to_value(&f.package.spec).unwrap();
    unexpected_verifier.as_object_mut().unwrap().insert(
        "import_verifier_python".into(),
        json!({"path":"/usr/bin/python3", "sha256":"0".repeat(64)}),
    );
    assert!(serde_json::from_value::<DeploymentSpec>(unexpected_verifier).is_err());

    for field in ["archive_sha256", "raw_disk_sha256"] {
        let changed = f.spec_with_receipt_edit(|receipt| receipt[field] = json!("0".repeat(64)));
        assert!(Package::prepare(changed, 1000).is_err(), "field {field}");
    }
    for field in ["producer_executable_sha256"] {
        let malformed = f.spec_with_receipt_edit(|receipt| receipt[field] = json!("not-a-sha256"));
        assert!(Package::prepare(malformed, 1000).is_err(), "field {field}");
    }
    let wrong_size = f.spec_with_receipt_edit(|receipt| receipt["raw_disk_bytes"] = json!(2));
    assert!(Package::prepare(wrong_size, 1000).is_err());
    for field in ["toolchain_reviewed", "private_mode_approved"] {
        let false_approval = f.spec_with_receipt_edit(|receipt| receipt[field] = json!(true));
        assert!(
            Package::prepare(false_approval, 1000).is_err(),
            "field {field}"
        );
    }
    let changed_claim =
        f.spec_with_receipt_edit(|receipt| receipt["oldgnu_single_member_checked"] = json!(false));
    assert!(Package::prepare(changed_claim, 1000).is_err());
    // A self-reported executable identity must match the hash-checked binary
    // and the native build manifest; none of these records proves execution.
    let different_producer = f.spec_with_receipt_edit(|receipt| {
        for field in ["producer_executable_sha256"] {
            receipt[field] = json!("0".repeat(64));
        }
    });
    assert!(Package::prepare(different_producer, 1000).is_err());
    let mut wrong_binary = f.package.spec.clone();
    wrong_binary.producer_binary.sha256 = "0".repeat(64);
    assert!(Package::prepare(wrong_binary, 1000).is_err());
    let mut wrong_manifest = f.package.spec.clone();
    wrong_manifest.native_rust_manifest.sha256 = "0".repeat(64);
    assert!(Package::prepare(wrong_manifest, 1000).is_err());
    let wrong_producer = f.spec_with_receipt_edit(|receipt| receipt["producer"] = json!("other"));
    assert!(Package::prepare(wrong_producer, 1000).is_err());
    let stale_hash = f.package.spec.clone();
    fs::write(&stale_hash.import_receipt.path, b"{}%").unwrap();
    assert!(Package::prepare(stale_hash, 1000).is_err());
}

#[test]
fn operator_handoff_binds_the_final_disk_and_review_reports_without_approval() {
    let f = Fixture::new();
    assert!(f.package.validate(1000).is_ok());
    let mut missing = serde_json::to_value(&f.package.spec).unwrap();
    missing.as_object_mut().unwrap().remove("operator_handoff");
    assert!(serde_json::from_value::<DeploymentSpec>(missing).is_err());
    for edit in [
        ("status", json!("approved")),
        ("raw_disk_sha256", json!("0".repeat(64))),
        ("disk_raw", json!(f.root.join("other.raw"))),
        ("import_package_ready", json!(true)),
        ("private_mode_approved", json!(true)),
        ("sfdisk_archive_membership_rechecked", json!(false)),
    ] {
        let spec = f.spec_with_handoff_edit(|handoff| handoff[edit.0] = edit.1);
        assert!(
            Package::prepare(spec, 1000).is_err(),
            "handoff field {}",
            edit.0
        );
    }
    let redirected = f.spec_with_handoff_edit(|handoff| {
        handoff["package_diagnostics"]["esp_diagnostic"]["sha256"] = json!("0".repeat(64));
    });
    assert!(Package::prepare(redirected, 1000).is_err());

    let raw = f.root.join("disk.raw");
    use std::io::Write;
    fs::OpenOptions::new()
        .write(true)
        .open(&raw)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    assert!(Package::prepare(f.package.spec.clone(), 1000).is_err());
    // Frozen package validation still checks the archive's expanded bytes.
    assert!(f.package.validate(1000).is_ok());
    fs::remove_file(raw).unwrap();
    assert!(f.package.validate(1000).is_ok());
}

#[test]
fn operator_handoff_rejects_rehashed_reinspection_and_report_tampering() {
    let f = Fixture::new();
    let spec = f.package.spec.clone();
    let reinspection_path = f.root.join("reinspection.json");
    let mut reinspection: Value =
        serde_json::from_slice(&fs::read(&reinspection_path).unwrap()).unwrap();
    reinspection["raw_disk_sha256"] = json!("0".repeat(64));
    let bytes = serde_json::to_vec(&reinspection).unwrap();
    fs::write(&reinspection_path, &bytes).unwrap();
    let wrong_receipt = f.spec_with_handoff_edit(|handoff| {
        handoff["reinspection_receipt"]["sha256"] = json!(digest(&bytes));
    });
    assert!(Package::prepare(wrong_receipt, 1000).is_err());

    reinspection["raw_disk_sha256"] = json!(spec.raw_disk_sha256);
    let gpt_path = f.root.join("gpt.json");
    let mut gpt: Value = serde_json::from_slice(&fs::read(&gpt_path).unwrap()).unwrap();
    gpt["status"] = json!("private-approved");
    let gpt_bytes = serde_json::to_vec(&gpt).unwrap();
    fs::write(&gpt_path, &gpt_bytes).unwrap();
    let gpt_sha256 = digest(&gpt_bytes);
    reinspection["reports"]["gpt"]["sha256"] = json!(gpt_sha256);
    let receipt_bytes = serde_json::to_vec(&reinspection).unwrap();
    fs::write(&reinspection_path, &receipt_bytes).unwrap();
    let wrong_report = f.spec_with_handoff_edit(|handoff| {
        handoff["reinspection_receipt"]["sha256"] = json!(digest(&receipt_bytes));
        handoff["review_reports"]["gpt"]["sha256"] = json!(gpt_sha256);
    });
    assert!(Package::prepare(wrong_report, 1000).is_err());
}

struct Mock {
    state: PathBuf,
    objects: BTreeMap<String, Value>,
    staging_noncurrent: bool,
    staging_soft_deleted: bool,
    staging_residual_failure: bool,
    operations: BTreeMap<String, Operation>,
    preflight_calls: usize,
    calls: Vec<String>,
    deletes: Vec<String>,
    compute_delete_response: Option<Mutation>,
    fail_after_create: bool,
    outage: bool,
}
impl Mock {
    fn assert_committed(&self, request: &str) {
        let mut files = fs::read_dir(&self.state)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_str().unwrap().len() == 25)
            .collect::<Vec<_>>();
        files.sort();
        let j: Journal = serde_json::from_slice(&fs::read(files.last().unwrap()).unwrap()).unwrap();
        assert!(
            j.watchdog.is_some(),
            "provider mutation preceded durable watchdog admission"
        );
        assert!(
            j.resources.iter().any(|r| [&r.create, &r.delete]
                .iter()
                .any(|i| i.as_ref().is_some_and(|i| i.request_id == request))),
            "mutation observed before durable intent"
        );
        assert!(!self.state.join("pending.json").exists());
    }
    fn op(&self, r: &ResourcePlan, request: &str, id: &str, deleting: bool) -> Operation {
        Operation {
            name: format!("operation-{request}"),
            status: "DONE".into(),
            operation_type: if deleting { "delete" } else { "insert" }.into(),
            target_link: format!("https://www.googleapis.com/compute/v1/{}", r.path),
            target_id: Some(id.into()),
            client_operation_id: Some(request.into()),
            error: None,
        }
    }
}
impl Provider for Mock {
    async fn preflight(&mut self, _: &Package) -> Result<()> {
        self.preflight_calls += 1;
        if self.outage {
            Err(Error("synthetic outage"))
        } else {
            Ok(())
        }
    }
    async fn get(&mut self, r: &ResourcePlan) -> Result<Option<Value>> {
        if self.outage {
            return Err(Error("synthetic outage"));
        }
        Ok(self.objects.get(&r.path).cloned())
    }
    async fn staging_generation_residual(
        &mut self,
        r: &ResourcePlan,
        identity: &str,
    ) -> Result<bool> {
        if r.kind != ResourceKind::StagingObject || !identity.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error("invalid synthetic staging generation"));
        }
        if self.outage || self.staging_residual_failure {
            return Err(Error("synthetic staging generation read failed"));
        }
        Ok(self.staging_noncurrent || self.staging_soft_deleted)
    }
    async fn create(
        &mut self,
        _: &Package,
        r: &ResourcePlan,
        request: &str,
        _: u64,
    ) -> Result<Mutation> {
        self.assert_committed(request);
        self.calls.push(request.into());
        let id = (self.objects.len() + 1).to_string();
        let object = if r.kind == ResourceKind::StagingObject {
            json!({"name":r.path.split("/o/").nth(1).unwrap(),"generation":id,"metadata":r.create_body})
        } else {
            json!({"id":id,"name":r.create_body["name"],"description":r.create_body["description"]})
        };
        self.objects.insert(r.path.clone(), object.clone());
        let response = if r.kind == ResourceKind::StagingObject {
            Mutation::Object(object)
        } else {
            let op = self.op(r, request, &id, false);
            self.operations.insert(request.into(), op.clone());
            Mutation::Operation(op)
        };
        if self.fail_after_create {
            self.fail_after_create = false;
            return Err(Error(
                "synthetic connection lost after provider accepted creation",
            ));
        }
        Ok(response)
    }
    async fn delete(&mut self, r: &ResourcePlan, id: &str, request: &str) -> Result<Mutation> {
        self.assert_committed(request);
        self.deletes.push(r.path.clone());
        if r.kind != ResourceKind::StagingObject {
            if let Some(response) = self.compute_delete_response.take() {
                self.objects.remove(&r.path);
                return Ok(response);
            }
        }
        self.objects.remove(&r.path);
        if r.kind == ResourceKind::StagingObject {
            return Ok(Mutation::Object(Value::Null));
        }
        let op = self.op(r, request, id, true);
        self.operations.insert(request.into(), op.clone());
        Ok(Mutation::Operation(op))
    }
    async fn operation(&mut self, _: &ResourcePlan, name: &str) -> Result<Operation> {
        self.operations
            .values()
            .find(|o| o.name == name)
            .cloned()
            .ok_or(Error("unknown synthetic operation"))
    }
    async fn recover_operation(
        &mut self,
        _: &ResourcePlan,
        request: &str,
    ) -> Result<Option<Operation>> {
        Ok(self.operations.get(request).cloned())
    }
}
// Legacy synthetic cases use their fixture clock. Production deploy_once
// always obtains a fresh wall-clock value itself.
async fn deploy_once(store: &mut Store, provider: &mut Mock, at: u64) -> Result<Progress> {
    deploy_once_with_clock(store, provider, || Ok(at)).await
}

async fn deploy_all(store: &mut Store, provider: &mut Mock, package: &Package) {
    for _ in &package.resources {
        assert_eq!(
            deploy_once(store, provider, 1000).await.unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        deploy_once(store, provider, 1000).await.unwrap(),
        Progress::DeployedForSyntheticEvaluation
    );
}

#[tokio::test]
async fn create_intents_are_durable_and_cleanup_tracks_every_owned_resource() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    deploy_all(&mut store, &mut provider, &f.package).await;
    assert!(store.journal().resources[0].upload_media_stream_verified);
    let mut reset = store.journal().clone();
    reset.resources[0].upload_media_stream_verified = false;
    assert!(store.commit(reset).is_err());
    assert_eq!(provider.calls.len(), f.package.resources.len());
    for _ in &f.package.resources {
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1001)
            .await
            .unwrap(),
        Progress::PlannedResourcesAbsentBillingUnreconciled
    );
    assert_eq!(
        provider.deletes,
        f.package
            .resources
            .iter()
            .rev()
            .map(|r| r.path.clone())
            .collect::<Vec<_>>()
    );
    assert!(store.journal().resources.iter().all(|r| r.observed_absent));
    assert!(store.journal().billing_evidence_sha256.is_none());
}

#[tokio::test]
async fn completion_status_does_not_claim_project_wide_inventory() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    let unplanned_name = format!("{}-untracked", f.package.spec.experiment);
    let unplanned = format!(
        "projects/{}/global/images/{unplanned_name}",
        f.package.spec.project
    );
    provider.objects.insert(
        unplanned.clone(),
        json!({"id":"987654321","name":unplanned_name}),
    );
    deploy_all(&mut store, &mut provider, &f.package).await;
    for _ in &f.package.resources {
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap(),
            Progress::Pending
        );
    }
    let progress = teardown_once(&mut store, &mut provider, 1001)
        .await
        .unwrap();
    assert_eq!(
        progress,
        Progress::PlannedResourcesAbsentBillingUnreconciled
    );
    assert_eq!(
        serde_json::to_value(progress).unwrap(),
        json!("planned_resources_absent_billing_unreconciled")
    );
    assert!(provider.objects.contains_key(&unplanned));
    assert!(!provider.deletes.contains(&unplanned));
    assert!(store.journal().billing_evidence_sha256.is_none());
}

#[tokio::test]
async fn out_of_band_disappearance_does_not_complete_cleanup_or_admit_billing_evidence() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    deploy_all(&mut store, &mut provider, &f.package).await;

    provider.objects.clear();
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1001)
            .await
            .unwrap_err()
            .0,
        "resource absent without recorded deletion; cleanup uncertain"
    );
    assert!(store.journal().teardown_started);
    assert!(provider.deletes.is_empty());
    assert!(store.journal().resources.iter().all(|r| r.delete.is_none()));

    observe(&mut store, &mut provider, 1002).await.unwrap();
    assert!(store.journal().resources.iter().all(|r| r.observed_absent));
    assert!(
        store
            .record_billing_evidence(&f.package.spec.release_manifest)
            .is_err()
    );
    assert!(store.journal().billing_evidence_sha256.is_none());
}

#[tokio::test]
async fn failed_done_deletion_does_not_complete_cleanup_or_admit_billing_evidence() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    deploy_all(&mut store, &mut provider, &f.package).await;
    for _ in &f.package.resources {
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap(),
        Progress::PlannedResourcesAbsentBillingUnreconciled
    );

    let index = f.package.resources.len() - 1;
    let resource = &f.package.resources[index];
    let state = &store.journal().resources[index];
    let mut operation = provider.op(
        resource,
        &state.delete.as_ref().unwrap().request_id,
        state.identity.as_ref().unwrap(),
        true,
    );
    operation.error = Some(json!({"errors": [{"code": "synthetic"}]}));
    accept_operation(&mut store, index, resource, operation, true).unwrap();
    assert!(
        store.journal().resources[index]
            .delete
            .as_ref()
            .unwrap()
            .failed
    );
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1003)
            .await
            .unwrap_err()
            .0,
        "deletion operation failed; original intent retained"
    );
    assert!(
        store
            .record_billing_evidence(&f.package.spec.release_manifest)
            .is_err()
    );
    assert!(store.journal().billing_evidence_sha256.is_none());
}
#[tokio::test]
async fn billing_reference_is_post_cleanup_append_only_and_never_changes_status() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    let bytes = b"synthetic billing evidence, not reconciliation";
    let evidence_path = f.root.join("billing-evidence");
    fs::write(&evidence_path, bytes).unwrap();
    let hash = digest(bytes);
    let evidence = Artifact {
        path: evidence_path.clone(),
        sha256: hash.clone(),
    };

    let initial_generation = store.journal().generation;
    assert!(store.record_billing_evidence(&evidence).is_err());
    assert_eq!(store.journal().generation, initial_generation);

    let mut early = store.journal().clone();
    early.billing_evidence_sha256 = Some(hash.clone());
    assert!(store.commit(early).is_err());

    deploy_all(&mut store, &mut provider, &f.package).await;
    let mut before_cleanup = store.journal().clone();
    before_cleanup.teardown_started = true;
    before_cleanup.billing_evidence_sha256 = Some(hash.clone());
    assert!(store.commit(before_cleanup).is_err());

    for _ in &f.package.resources {
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap(),
        Progress::PlannedResourcesAbsentBillingUnreconciled
    );
    let mut malformed = store.journal().clone();
    malformed.billing_evidence_sha256 = Some("not-a-sha256".into());
    assert!(store.commit(malformed).is_err());

    let mut wrong_digest = evidence.clone();
    wrong_digest.sha256 = digest(b"other bytes");
    assert!(store.record_billing_evidence(&wrong_digest).is_err());
    assert!(store.journal().billing_evidence_sha256.is_none());
    store.record_billing_evidence(&evidence).unwrap();
    let recorded_generation = store.journal().generation;
    store.record_billing_evidence(&evidence).unwrap();
    assert_eq!(store.journal().generation, recorded_generation);
    let mut replaced = store.journal().clone();
    replaced.billing_evidence_sha256 = Some(digest(b"replacement"));
    assert!(store.commit(replaced).is_err());
    let mut removed = store.journal().clone();
    removed.billing_evidence_sha256 = None;
    assert!(store.commit(removed).is_err());
    fs::write(evidence_path, b"changed billing evidence").unwrap();
    assert!(store.record_billing_evidence(&evidence).is_err());
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap(),
        Progress::PlannedResourcesAbsentBillingUnreconciled
    );
    drop(store);
    assert_eq!(
        Store::open(&f.state)
            .unwrap()
            .journal()
            .billing_evidence_sha256,
        Some(hash)
    );
}
#[tokio::test]
async fn interrupted_staging_upload_cannot_advance_from_metadata_only() {
    let f = Fixture::new();
    let mut provider = f.mock();
    provider.fail_after_create = true;
    let id;
    {
        let mut store = Store::open(&f.state).unwrap();
        assert!(deploy_once(&mut store, &mut provider, 1000).await.is_err());
        id = store.journal().resources[0]
            .create
            .as_ref()
            .unwrap()
            .request_id
            .clone();
    }
    let mut store = Store::open(&f.state).unwrap();
    assert_eq!(
        store.journal().resources[0]
            .create
            .as_ref()
            .unwrap()
            .request_id,
        id
    );
    assert!(deploy_once(&mut store, &mut provider, 1001).await.is_err());
    assert!(!store.journal().resources[0].upload_media_stream_verified);
    assert!(store.journal().resources[0].create.as_ref().unwrap().done);
    assert_eq!(store.journal().resources[0].identity.as_deref(), Some("1"));
    assert_eq!(
        provider
            .calls
            .iter()
            .filter(|request| **request == id)
            .count(),
        1
    );
    assert_eq!(provider.objects.len(), 1);
    let image = f
        .package
        .resources
        .iter()
        .find(|r| r.kind == ResourceKind::Image)
        .unwrap();
    assert!(!provider.objects.contains_key(&image.path));
    // The exact observed generation remains deletable even though its bytes
    // cannot be authenticated from metadata after the interrupted response.
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap(),
        Progress::Pending
    );
    assert_eq!(provider.deletes, vec![f.package.resources[0].path.clone()]);
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1003)
            .await
            .unwrap(),
        Progress::PlannedResourcesAbsentBillingUnreconciled
    );
    assert!(store.journal().resources[0].observed_absent);
    assert!(store.journal().resources[0].delete.as_ref().unwrap().done);
    assert!(!store.journal().resources[0].upload_media_stream_verified);
    assert_eq!(store.journal().original_start, 1000);
}
#[tokio::test]
async fn compute_operation_recovery_preserves_request_identity() {
    let f = Fixture::new();
    let mut provider = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_once(&mut store, &mut provider, 1000).await.unwrap();
    provider.fail_after_create = true;
    assert!(deploy_once(&mut store, &mut provider, 1000).await.is_err());
    let id = store.journal().resources[1]
        .create
        .as_ref()
        .unwrap()
        .request_id
        .clone();
    drop(store);
    let mut store = Store::open(&f.state).unwrap();
    deploy_once(&mut store, &mut provider, 1001).await.unwrap();
    assert!(store.journal().resources[1].create.as_ref().unwrap().done);
    assert_eq!(provider.calls.iter().filter(|r| **r == id).count(), 1);
}
#[tokio::test]
async fn recovered_compute_creation_without_target_id_cannot_adopt_a_name_match() {
    let f = Fixture::new();
    let mut provider = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_once(&mut store, &mut provider, 1000).await.unwrap();
    provider.fail_after_create = true;
    assert!(deploy_once(&mut store, &mut provider, 1000).await.is_err());
    let resource = &f.package.resources[1];
    let request = store.journal().resources[1]
        .create
        .as_ref()
        .unwrap()
        .request_id
        .clone();
    let created_id = provider.objects[&resource.path]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    provider.operations.get_mut(&request).unwrap().target_id = None;
    assert!(deploy_once(&mut store, &mut provider, 1001).await.is_err());
    assert!(store.journal().resources[1].identity.is_none());
    assert!(
        store.journal().resources[1]
            .create
            .as_ref()
            .unwrap()
            .operation
            .is_none()
    );
    assert_eq!(provider.calls.iter().filter(|r| **r == request).count(), 1);

    provider.operations.get_mut(&request).unwrap().target_id = Some(created_id.clone());
    assert_eq!(
        deploy_once(&mut store, &mut provider, 1001).await.unwrap(),
        Progress::Pending
    );
    assert_eq!(
        store.journal().resources[1].identity.as_deref(),
        Some(created_id.as_str())
    );
}

#[tokio::test]
async fn unresolved_compute_creation_cannot_delete_a_name_match() {
    let f = Fixture::new();
    let mut provider = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_once(&mut store, &mut provider, 1000).await.unwrap();
    provider.fail_after_create = true;
    assert!(deploy_once(&mut store, &mut provider, 1000).await.is_err());
    let resource = &f.package.resources[1];
    let request = store.journal().resources[1]
        .create
        .as_ref()
        .unwrap()
        .request_id
        .clone();
    provider.operations.remove(&request);
    assert!(
        teardown_once(&mut store, &mut provider, 1001)
            .await
            .is_err()
    );
    assert!(store.journal().teardown_started);
    assert!(store.journal().resources[1].identity.is_some());
    assert!(!store.journal().resources[1].create.as_ref().unwrap().done);
    assert!(provider.objects.contains_key(&resource.path));
    assert!(provider.deletes.is_empty());
}

#[tokio::test]
async fn completed_compute_deletion_requires_the_journaled_target_id() {
    let f = Fixture::new();
    let mut provider = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_all(&mut store, &mut provider, &f.package).await;
    let index = f.package.resources.len() - 1;
    let resource = &f.package.resources[index];
    let id = store.journal().resources[index].identity.clone().unwrap();
    let mut next = store.journal().clone();
    next.teardown_started = true;
    next.resources[index].delete = Some(intent(1001).unwrap());
    store.commit(next).unwrap();
    let request = store.journal().resources[index]
        .delete
        .as_ref()
        .unwrap()
        .request_id
        .clone();
    let generation = store.journal().generation;
    for (target_id, error) in [
        (None, None),
        (None, Some(json!({"errors": [{"code": "synthetic"}]}))),
        (Some("999".into()), None),
    ] {
        let mut operation = provider.op(resource, &request, &id, true);
        operation.target_id = target_id;
        operation.error = error;
        assert!(accept_operation(&mut store, index, resource, operation, true).is_err());
        assert_eq!(store.journal().generation, generation);
        assert_eq!(
            store.journal().resources[index].identity.as_deref(),
            Some(id.as_str())
        );
        assert!(
            !store.journal().resources[index]
                .delete
                .as_ref()
                .unwrap()
                .done
        );
    }
    let mut wrong_action = provider.op(resource, &request, &id, true);
    wrong_action.operation_type = "insert".into();
    assert!(accept_operation(&mut store, index, resource, wrong_action, true).is_err());
    assert_eq!(store.journal().generation, generation);

    let mut running = provider.op(resource, &request, &id, true);
    running.status = "RUNNING".into();
    accept_operation(&mut store, index, resource, running, true).unwrap();
    assert!(
        !store.journal().resources[index]
            .delete
            .as_ref()
            .unwrap()
            .done
    );
    accept_operation(
        &mut store,
        index,
        resource,
        provider.op(resource, &request, &id, true),
        true,
    )
    .unwrap();
    assert!(
        store.journal().resources[index]
            .delete
            .as_ref()
            .unwrap()
            .done
    );
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap_err()
            .0,
        "resource remains after completed deletion; cleanup uncertain"
    );
}

#[tokio::test]
async fn compute_delete_404_or_object_cannot_complete_cleanup() {
    for response in [Mutation::Absent, Mutation::Object(json!({"id": "8"}))] {
        let f = Fixture::new();
        let mut store = Store::open(&f.state).unwrap();
        let mut provider = f.mock();
        deploy_all(&mut store, &mut provider, &f.package).await;
        provider.compute_delete_response = Some(response);

        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap_err()
                .0,
            "Compute deletion lacks a matching operation; outcome remains uncertain"
        );
        let instance = store.journal().resources.last().unwrap();
        let delete = instance.delete.as_ref().unwrap();
        assert!(store.journal().teardown_started);
        assert!(delete.operation.is_none());
        assert!(!delete.done);
        assert!(!delete.failed);
        assert_eq!(provider.deletes.len(), 1);

        // The mock removes the VM before returning its ambiguous response.
        // A later missing GET still cannot replace a completed delete operation.
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1002)
                .await
                .unwrap_err()
                .0,
            "deletion outcome uncertain; absence alone cannot finish cleanup"
        );
        assert!(
            store
                .record_billing_evidence(&f.package.spec.release_manifest)
                .is_err()
        );
    }
}
#[tokio::test]
async fn rejects_early_late_and_tampered_deploy_without_provider_mutations() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    assert!(deploy_once(&mut store, &mut p, 999).await.is_err());
    assert!(deploy_once(&mut store, &mut p, 2000).await.is_err());
    fs::write(
        &f.package.spec.raw_image_tar_gz.path,
        b"changed executable image",
    )
    .unwrap();
    assert!(deploy_once(&mut store, &mut p, 1000).await.is_err());
    assert!(p.calls.is_empty());
}

#[tokio::test]
async fn creation_window_rejects_delayed_admission_before_provider_calls() {
    let f = Fixture::new();
    let store = Store::open(&f.state).unwrap();
    assert!(ensure_creation_window(&store, 1000).is_ok());
    let trigger = store
        .journal()
        .watchdog
        .as_ref()
        .unwrap()
        .deletion_start_unix_seconds;
    let deadline = store.journal().original_deadline;
    let original_generation = store.journal().generation;
    drop(store);

    for late_at in [trigger, deadline] {
        let mut store = Store::open(&f.state).unwrap();
        let mut provider = f.mock();
        let error = deploy_once_with_clock(&mut store, &mut provider, || Ok(late_at))
            .await
            .unwrap_err();
        assert!(error.0.contains("original deletion trigger"));
        assert_eq!(provider.preflight_calls, 0);
        assert!(provider.calls.is_empty());
        assert!(provider.objects.is_empty());
        assert_eq!(store.journal().generation, original_generation);
    }
}

#[tokio::test]
async fn creation_window_rejects_expiration_after_durable_intent() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    let trigger = store
        .journal()
        .watchdog
        .as_ref()
        .unwrap()
        .deletion_start_unix_seconds;
    let reads = Cell::new(0);
    let error = deploy_once_with_clock(&mut store, &mut provider, || {
        let next = reads.get() + 1;
        reads.set(next);
        Ok(if next == 6 { trigger } else { 1000 })
    })
    .await
    .unwrap_err();
    assert!(error.0.contains("original deletion trigger"));
    assert_eq!(reads.get(), 6);
    assert_eq!(provider.preflight_calls, 1);
    assert!(provider.calls.is_empty());
    assert!(provider.objects.is_empty());
    assert!(store.journal().resources[0].create.is_some());
}

#[tokio::test]
async fn cleanup_survives_expired_quote_missing_image_and_outage() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_all(&mut store, &mut p, &f.package).await;
    fs::remove_file(&f.package.spec.raw_image_tar_gz.path).unwrap();
    p.outage = true;
    assert!(teardown_once(&mut store, &mut p, 900000).await.is_err());
    assert!(store.journal().teardown_started);
    assert!(p.deletes.is_empty());
    p.outage = false;
    assert_eq!(
        teardown_once(&mut store, &mut p, 900001).await.unwrap(),
        Progress::Pending
    );
    assert_eq!(
        store.journal().original_deadline,
        f.package.spec.deadline_unix_seconds
    );
}
#[tokio::test]
async fn replacement_and_untracked_resources_are_never_deleted() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_all(&mut store, &mut p, &f.package).await;
    let instance = f.package.resources.last().unwrap();
    p.objects.get_mut(&instance.path).unwrap()["id"] = json!("999");
    assert!(teardown_once(&mut store, &mut p, 1001).await.is_err());
    assert!(p.deletes.is_empty());
}

#[tokio::test]
async fn absent_live_staging_object_with_retained_generation_blocks_cleanup() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_all(&mut store, &mut p, &f.package).await;
    let staging = &f.package.resources[0];
    let identity = store.journal().resources[0].identity.as_deref().unwrap();
    let paths = crate::gcp::provider::staging_generation_paths(staging, identity).unwrap();
    assert_eq!(
        paths,
        [
            format!("/storage/v1/{}?generation={identity}", staging.path),
            format!(
                "/storage/v1/{}?generation={identity}&softDeleted=true",
                staging.path
            ),
        ]
    );
    assert!(crate::gcp::provider::staging_generation_paths(staging, "not-a-generation").is_err());
    assert!(
        crate::gcp::provider::staging_generation_paths(
            f.package.resources.last().unwrap(),
            identity
        )
        .is_err()
    );

    // Simulate a bucket policy change after deploy: ordinary GET now misses
    // the object, but its recorded generation remains billable.
    p.objects.remove(&staging.path);
    p.staging_noncurrent = true;
    let generation = store.journal().generation;
    assert!(
        observe_resource(&mut store, &mut p, &f.package, 0, 1001)
            .await
            .is_err()
    );
    assert_eq!(store.journal().generation, generation);
    assert!(!store.journal().resources[0].observed_absent);
    assert!(p.deletes.is_empty());

    p.staging_noncurrent = false;
    p.staging_soft_deleted = true;
    assert!(
        observe_resource(&mut store, &mut p, &f.package, 0, 1002)
            .await
            .is_err()
    );
    assert_eq!(store.journal().generation, generation);
    assert!(!store.journal().resources[0].observed_absent);

    p.staging_soft_deleted = false;
    p.staging_residual_failure = true;
    assert!(
        observe_resource(&mut store, &mut p, &f.package, 0, 1003)
            .await
            .is_err()
    );
    assert_eq!(store.journal().generation, generation);
    assert!(!store.journal().resources[0].observed_absent);

    p.staging_residual_failure = false;
    assert!(
        observe_resource(&mut store, &mut p, &f.package, 0, 1004)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.journal().resources[0].observed_absent);
}
#[test]
fn locked_store_and_original_binding_cannot_reset() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    assert!(Store::open(&f.state).is_err());
    assert!(Store::initialize(&f.state, &f.package).is_err());
    let mut next = store.journal().clone();
    next.original_deadline += 1;
    assert!(store.commit(next).is_err());
    let mut next = store.journal().clone();
    next.resources[0].create = Some(intent(1000).unwrap());
    store.commit(next).unwrap();
    let mut next = store.journal().clone();
    next.resources[0].create = None;
    assert!(store.commit(next).is_err());
}
#[test]
fn package_rejects_payload_mutation_and_does_not_apply_phala_cost_limit() {
    let f = Fixture::new();
    let mut package = f.package.clone();
    package.resources.last_mut().unwrap().create_body["serviceAccounts"] =
        json!([{"email":"default"}]);
    assert!(package.validate(1000).is_err());
    let mut spec = f.package.spec.clone();
    spec.pricing
        .components_microusd
        .insert("compute".into(), 500_000_000);
    spec.pricing.projected_total_microusd = 500_000_007;
    assert!(Package::prepare(spec, 1000).is_ok());
}
#[test]
fn journal_recovers_published_pending_commit_and_rejects_truncation() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut next = store.journal().clone();
    next.teardown_started = true;
    store.commit(next).unwrap();
    let current = f
        .state
        .join(format!("{:020}.json", store.journal().generation));
    drop(store);
    fs::hard_link(current, f.state.join("pending.json")).unwrap();
    assert!(Store::open(&f.state).is_err());
    Store::recover(&f.state).unwrap();
    assert!(Store::open(&f.state).unwrap().journal().teardown_started);
    fs::write(f.state.join("pending.json"), b"{truncated").unwrap();
    assert!(Store::recover(&f.state).is_err());
}
#[test]
fn operation_scope_uses_documented_global_regional_and_zonal_collections() {
    let f = Fixture::new();
    for (index, scope) in [
        (1, "global"),
        (2, "regions/us-central1"),
        (5, "zones/us-central1-a"),
    ] {
        assert_eq!(
            crate::gcp::provider::operation_path(&f.package.resources[index], "operation-example")
                .unwrap(),
            format!("/compute/v1/projects/synthetic-project/{scope}/operations/operation-example")
        );
    }
}

#[test]
fn placeholder_review_attachments_cannot_enable_live_creation() {
    let f = Fixture::new();
    assert!(f.package.validate(1000).is_ok());
    assert_eq!(
        fs::read(&f.package.spec.release_manifest.path).unwrap(),
        b"SYNTHETIC - NOT A BOOTABLE IMAGE"
    );
    let error = crate::gcp::ensure_live_creation_ready().unwrap_err();
    assert!(error.0.contains("post-build image inspection"));
    assert!(
        crate::gcp::LIVE_DEPLOYMENT_BLOCKERS
            .iter()
            .any(|blocker| blocker.contains("incarnation"))
    );
}

#[tokio::test]
async fn deployment_never_contacts_provider_without_frozen_watchdog() {
    let f = Fixture::new();
    let unbound = f.root.join("unbound-journal");
    Store::initialize(&unbound, &f.package).unwrap();
    let mut store = Store::open(&unbound).unwrap();
    let mut provider = f.mock();
    provider.outage = true;
    let error = deploy_once(&mut store, &mut provider, 1000)
        .await
        .unwrap_err();
    assert!(error.0.contains("durably admitted watchdog"));
    assert_eq!(store.journal().generation, 0);
    assert!(provider.calls.is_empty());
}

#[test]
fn frozen_watchdog_survives_restart_and_controls_mutation_accelerates_cleanup() {
    let f = Fixture::new();
    let store = Store::open(&f.state).unwrap();
    let original = store.journal().watchdog.clone().unwrap();
    let before = original.deletion_start_unix_seconds - 1;
    assert!(
        !original
            .due(&original.controls_path, before, false)
            .unwrap()
    );
    let mut controls: Controls =
        serde_json::from_slice(&fs::read(&original.controls_path).unwrap()).unwrap();
    controls.poll_interval_seconds = 1;
    controls.deletion_duration_seconds = 1;
    controls.systemd_delay_seconds = 1;
    assert!(controls.deletion_start(&f.package).unwrap() > original.deletion_start_unix_seconds);
    fs::write(
        &original.controls_path,
        serde_json::to_vec(&controls).unwrap(),
    )
    .unwrap();
    drop(store);

    let mut restarted = Store::open(&f.state).unwrap();
    assert_eq!(restarted.journal().watchdog.as_ref(), Some(&original));
    assert!(
        original
            .due(&original.controls_path, before, false)
            .unwrap()
    );
    assert!(
        original
            .due(
                &original.controls_path,
                original.deletion_start_unix_seconds,
                false
            )
            .unwrap()
    );
    fs::remove_file(&original.controls_path).unwrap();
    assert!(
        original
            .due(&original.controls_path, before, false)
            .unwrap()
    );

    let generation = restarted.journal().generation;
    let mut changed = original.clone();
    changed.deletion_start_unix_seconds += 1;
    assert!(restarted.admit_watchdog(changed).is_err());
    let mut removed = restarted.journal().clone();
    removed.watchdog = None;
    assert!(restarted.commit(removed).is_err());
    assert_eq!(restarted.journal().generation, generation);
}

#[test]
fn watchdog_deadline_includes_inflight_controller_and_exports_no_installer() {
    use crate::gcp::{provider::Runtime, watchdog::Controls};
    let f = Fixture::new();
    let artifact = f.package.spec.release_manifest.clone();
    let runtime = Runtime {
        gcloud: artifact.clone(),
        gcloud_distribution_receipt: artifact.clone(),
        gcloud_config_directory: f.root.join("credentials"),
        trust_roots_der: vec![artifact.clone()],
        invocation_budget_ms: 11_000,
        response_limit_bytes: 4096,
    };
    let runtime_bytes = serde_json::to_vec(&runtime).unwrap();
    let runtime_path = f.root.join("runtime.json");
    fs::write(&runtime_path, &runtime_bytes).unwrap();
    let controls = Controls {
        package_sha256: f.package.sha256().unwrap(),
        executable: artifact.clone(),
        runtime_file: Artifact {
            path: runtime_path,
            sha256: digest(&runtime_bytes),
        },
        state_directory: f.state.clone(),
        controller_machine_id: "a".repeat(32),
        controller_uid: 1000,
        poll_interval_seconds: 20,
        deletion_duration_seconds: 100,
        systemd_delay_seconds: 3,
        deletion_rehearsal: artifact.clone(),
        independent_backstop: artifact,
    };
    assert_eq!(
        controls.deletion_start(&f.package).unwrap(),
        f.package.spec.deadline_unix_seconds - (11 + 20 + 100 + 3)
    );
    let units = controls
        .units(&f.package, &f.root.join("controls.json"))
        .unwrap();
    assert_eq!(units.len(), 3);
    assert!(units.values().any(|s| s.contains("Persistent=true")));
    assert!(units.values().any(|s| s.contains("watchdog-once --state")));
    assert!(
        units
            .values()
            .all(|s| !s.contains("systemctl enable") && !s.contains(" deploy "))
    );
}
