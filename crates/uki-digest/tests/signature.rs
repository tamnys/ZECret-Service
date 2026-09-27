#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;
use zrpc_uki_digest::{
    ExpectedSignatureInput, SBVERIFY_RUNTIME, SBVERIFY_SHA256, SBVERIFY_SIZE, inspect_signed_uki,
};

// Public X.509 certificate extracted from the existing Google authenticode-rs
// tiny64.signed.efi fixture. See digest.rs and LICENSE-MIT.authenticode-rs for
// the upstream source and fixture license. No private signing key is included.
const UKI: &[u8] = include_bytes!("fixtures/tiny64.signed.efi");
const CERT: &[u8] = include_bytes!("fixtures/tiny64.signer.crt.pem");
const UKI_SHA256: &str = "8c204bd92aa82af6b6decebfd7da8a55bc599dd7b39b2ca010a827ef170303f7";
const CERT_SHA256: &str = "98a0046555919ed83a36aeaf252e4b94a92b64fa281317495ee69c88ab33ebeb";

fn expected(sha256: &str, bytes: usize) -> ExpectedSignatureInput<'_> {
    ExpectedSignatureInput {
        sha256,
        bytes: bytes as u64,
    }
}

fn reviewed_verifier_from_environment() -> Option<Vec<u8>> {
    let path = std::env::var_os("ZRPC_TEST_SBVERIFY")?;
    let verifier = fs::read(path).expect("ZRPC_TEST_SBVERIFY points to a readable file");
    assert_eq!(verifier.len(), SBVERIFY_SIZE);
    assert_eq!(hex::encode(Sha256::digest(&verifier)), SBVERIFY_SHA256);
    Some(verifier)
}

fn reviewed_runtime_from_environment() -> Option<(Vec<Vec<u8>>, Vec<String>)> {
    let directory = std::path::PathBuf::from(std::env::var_os("ZRPC_TEST_SBVERIFY_RUNTIME_DIR")?);
    let mut objects = Vec::new();
    let mut paths = Vec::new();
    for (name, size, digest) in SBVERIFY_RUNTIME {
        let path = directory.join(name);
        let object = fs::read(&path).expect("reviewed runtime object exists");
        assert_eq!(object.len(), size);
        assert_eq!(hex::encode(Sha256::digest(&object)), digest);
        objects.push(object);
        paths.push(path.to_str().expect("test path is UTF-8").to_owned());
    }
    Some((objects, paths))
}

#[test]
fn signer_and_verifier_identity_fail_closed() {
    let false_verifier = vec![0; SBVERIFY_SIZE];
    assert_eq!(
        inspect_signed_uki(
            UKI,
            expected(UKI_SHA256, UKI.len()),
            CERT,
            expected(CERT_SHA256, CERT.len()),
            &false_verifier,
            [&[]; 5],
        )
        .unwrap_err(),
        "sbverify executable differs from reviewed Debian package"
    );
    assert_eq!(
        inspect_signed_uki(
            UKI,
            expected(UKI_SHA256, UKI.len()),
            CERT,
            expected(UKI_SHA256, CERT.len()),
            &false_verifier,
            [&[]; 5],
        )
        .unwrap_err(),
        "signer certificate SHA-256 differs from expected artifact"
    );
}

#[test]
fn cli_refuses_ambient_runtime_command_shape() {
    let output = Command::new(env!("CARGO_BIN_EXE_zrpc-uki-digest"))
        .args([
            "verify-signature",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signed.efi"
            ),
            UKI_SHA256,
            "3584",
            "/nonexistent/sbverify",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signer.crt.pem"
            ),
            CERT_SHA256,
            "1107",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["signed_uki_checked"], false);
    assert_eq!(report["verifier_initial_elf_objects_pinned"], false);
    assert_eq!(report["private_mode_approved"], false);
}

#[test]
#[ignore = "requires ZRPC_TEST_SBVERIFY and ZRPC_TEST_SBVERIFY_RUNTIME_DIR set to pinned Debian objects"]
fn reviewed_sbverify_accepts_fixture_and_rejects_changed_signature() {
    let verifier_path = std::env::var_os("ZRPC_TEST_SBVERIFY")
        .expect("set ZRPC_TEST_SBVERIFY to the pinned Debian executable");
    let verifier = reviewed_verifier_from_environment().expect("test verifier path is set");
    let (runtime, runtime_paths) =
        reviewed_runtime_from_environment().expect("test runtime directory is set");
    let runtime_slices = || std::array::from_fn(|index| runtime[index].as_slice());
    let report = inspect_signed_uki(
        UKI,
        expected(UKI_SHA256, UKI.len()),
        CERT,
        expected(CERT_SHA256, CERT.len()),
        &verifier,
        runtime_slices(),
    )
    .unwrap();
    assert!(report.signed_uki_checked);
    assert!(report.verifier_initial_elf_objects_pinned);
    assert!(!report.signer_identity_reviewed);
    assert!(!report.verifier_runtime_closure_checked);
    assert!(!report.boot_measurement_checked);
    assert!(!report.release_approved);
    assert!(!report.private_mode_approved);

    let cli = Command::new(env!("CARGO_BIN_EXE_zrpc-uki-digest"))
        .args([
            "verify-signature",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signed.efi"
            ),
            UKI_SHA256,
            "3584",
            verifier_path.to_str().expect("test path is UTF-8"),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signer.crt.pem"
            ),
            CERT_SHA256,
            "1107",
        ])
        .args(&runtime_paths)
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stdout)
    );
    let cli_report: serde_json::Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(cli_report["signed_uki_checked"], true);
    assert_eq!(cli_report["verifier_initial_elf_objects_pinned"], true);
    assert_eq!(cli_report["signer_identity_reviewed"], false);
    assert_eq!(cli_report["verifier_runtime_closure_checked"], false);
    assert_eq!(cli_report["release_approved"], false);
    assert_eq!(cli_report["private_mode_approved"], false);

    let mut changed_signature = UKI.to_vec();
    // This byte is inside the fixture's PKCS7 signature table. It is excluded
    // from the PE Authenticode image digest, so only signature verification
    // rejects it when the full-file identity is updated to the changed bytes.
    changed_signature[3150] ^= 1;
    let changed_hash = hex::encode(Sha256::digest(&changed_signature));
    assert_eq!(
        inspect_signed_uki(
            &changed_signature,
            expected(&changed_hash, changed_signature.len()),
            CERT,
            expected(CERT_SHA256, CERT.len()),
            &verifier,
            runtime_slices(),
        )
        .unwrap_err(),
        "UKI Authenticode signature rejected by reviewed sbverify binary"
    );

    for index in 0..runtime.len() {
        let mut changed = runtime.clone();
        changed[index][0] ^= 1;
        assert_eq!(
            inspect_signed_uki(
                UKI,
                expected(UKI_SHA256, UKI.len()),
                CERT,
                expected(CERT_SHA256, CERT.len()),
                &verifier,
                std::array::from_fn(|index| changed[index].as_slice()),
            )
            .unwrap_err(),
            "sbverify runtime object differs from reviewed Debian package"
        );
    }
}

#[test]
fn cli_rejects_redirected_verifier_before_signature_claim() {
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let link =
        std::env::temp_dir().join(format!("zrpc-uki-sbverify-{}-{unique}", std::process::id()));
    symlink("/bin/true", &link).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zrpc-uki-digest"))
        .args([
            "verify-signature",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signed.efi"
            ),
            UKI_SHA256,
            "3584",
            link.to_str().unwrap(),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/tiny64.signer.crt.pem"
            ),
            CERT_SHA256,
            "1107",
            "/nonexistent/ld-linux-x86-64.so.2",
            "/nonexistent/libc.so.6",
            "/nonexistent/libz.so.1",
            "/nonexistent/libzstd.so.1",
            "/nonexistent/libcrypto.so.3",
        ])
        .output()
        .unwrap();
    fs::remove_file(link).unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["signed_uki_checked"], false);
    assert_eq!(report["verifier_initial_elf_objects_pinned"], false);
    assert_eq!(report["private_mode_approved"], false);
}
