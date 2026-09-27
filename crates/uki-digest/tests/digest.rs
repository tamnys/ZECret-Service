use sha2::{Digest, Sha256, Sha384};
use std::process::Command;
use zrpc_uki_digest::inspect_uki;

// Google authenticode-rs authenticode-v0.6.0 at
// 5d8df58ecc53309ca628b7353db4402264f862a1, testdata/tiny64.signed.efi.
// The upstream MIT license is retained as fixtures/LICENSE-MIT.authenticode-rs.
// Git blob de0dd7da03d53680d978b4951f10e2951ef0f705;
// SHA-256 8c204bd92aa82af6b6decebfd7da8a55bc599dd7b39b2ca010a827ef170303f7.
// The SHA-384 below was independently recomputed with Google go-tpm-tools
// v0.4.9 (79b91b3d1c4f69e01cf890b5327a8ed06a05f131,
// launcher/image/measure/measure.sh, blob ce028d791a751db203382817a3c11d771a8a3eee)
// and Cohere cvm-measure 4f1303e281986dee98e7e098db594779f040a190
// (src/cvm_measure/tdx/pe.py, blob c0b8fa5fcfea59fb15fc068db5d3f184550065bd).
const UKI: &[u8] = include_bytes!("fixtures/tiny64.signed.efi");
const UKI_SHA256: &str = "8c204bd92aa82af6b6decebfd7da8a55bc599dd7b39b2ca010a827ef170303f7";
const UKI_PE_SHA256: &str = "a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae";
const UKI_PE_SHA384: &str = "ad37d821bff4ac08f6ee2be764cbb9bc49404d1d723bbb8b234926127478265b0fa496ac0817070cae54d272e9aa13d1";

#[test]
fn signed_efi_matches_independent_sha384_vector_without_approval() {
    let report = inspect_uki(UKI, UKI_SHA256, UKI.len() as u64).unwrap();
    assert_eq!(report.uki_pe_coff_sha256, UKI_PE_SHA256);
    assert_eq!(report.uki_pe_coff_sha384, UKI_PE_SHA384);
    assert_eq!(report.uki_sha256, UKI_SHA256);
    assert!(!report.signed_uki_checked);
    assert!(!report.boot_measurement_checked);
    assert!(!report.release_approved);
    assert!(!report.private_mode_approved);
    assert_ne!(hex::encode(Sha256::digest(UKI)), UKI_PE_SHA256);
    assert_ne!(hex::encode(Sha384::digest(UKI)), UKI_PE_SHA384);
}

#[test]
fn changed_code_and_wrong_artifact_identity_fail() {
    let mut changed = UKI.to_vec();
    // First section is .text at file offset 1024 in this pinned fixture.
    changed[1024 + 16] ^= 1;
    assert_eq!(
        inspect_uki(&changed, UKI_SHA256, changed.len() as u64).unwrap_err(),
        "UKI SHA-256 differs from expected artifact"
    );
    let changed_sha256 = hex::encode(Sha256::digest(&changed));
    assert_ne!(
        inspect_uki(&changed, &changed_sha256, changed.len() as u64)
            .unwrap()
            .uki_pe_coff_sha384,
        UKI_PE_SHA384
    );
    assert!(inspect_uki(UKI, UKI_SHA256, UKI.len() as u64 + 1).is_err());
}

#[test]
fn malformed_and_unaligned_inputs_fail() {
    let bad = [0u8; 8];
    let bad_sha256 = hex::encode(Sha256::digest(bad));
    assert!(inspect_uki(&bad, &bad_sha256, bad.len() as u64).is_err());
    let mut unaligned = UKI.to_vec();
    unaligned.push(0);
    let unaligned_sha256 = hex::encode(Sha256::digest(&unaligned));
    assert_eq!(
        inspect_uki(&unaligned, &unaligned_sha256, unaligned.len() as u64).unwrap_err(),
        "UKI length is not 8-byte aligned for EFI measurement"
    );

    let mut wrong_machine = UKI.to_vec();
    // COFF Machine is at PE signature + 4; switch x86_64 to AArch64.
    wrong_machine[0x7d] = 0xaa;
    let wrong_machine_sha256 = hex::encode(Sha256::digest(&wrong_machine));
    assert_eq!(
        inspect_uki(
            &wrong_machine,
            &wrong_machine_sha256,
            wrong_machine.len() as u64
        )
        .unwrap_err(),
        "UKI PE machine is not x86_64"
    );
}

#[test]
fn cli_rejection_is_blocked_without_approval() {
    let output = Command::new(env!("CARGO_BIN_EXE_zrpc-uki-digest"))
        .args([
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signed.efi"
            ),
            "0",
            "3584",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "blocked");
    for field in [
        "signed_uki_checked",
        "boot_measurement_checked",
        "release_approved",
        "private_mode_approved",
    ] {
        assert_eq!(report[field], false);
    }
}

#[test]
fn cli_rejects_symlink_to_matching_fixture() {
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tiny64.signed.efi"
    );
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let link = std::env::temp_dir().join(format!(
        "zrpc-uki-digest-{}-{unique}.efi",
        std::process::id()
    ));
    symlink(fixture, &link).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zrpc-uki-digest"))
        .args([link.to_str().unwrap(), UKI_SHA256, "3584"])
        .output()
        .unwrap();
    std::fs::remove_file(&link).unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["release_approved"], false);
    assert_eq!(report["private_mode_approved"], false);
}
