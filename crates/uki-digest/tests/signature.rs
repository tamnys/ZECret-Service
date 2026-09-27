#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;
use zrpc_uki_digest::{SBVERIFY_SHA256, SBVERIFY_SIZE, inspect_signed_uki};

// Public X.509 certificate extracted from the existing Google authenticode-rs
// tiny64.signed.efi fixture. See digest.rs and LICENSE-MIT.authenticode-rs for
// the upstream source and fixture license. No private signing key is included.
const UKI: &[u8] = include_bytes!("fixtures/tiny64.signed.efi");
const CERT: &[u8] = include_bytes!("fixtures/tiny64.signer.crt.pem");
const UKI_SHA256: &str = "8c204bd92aa82af6b6decebfd7da8a55bc599dd7b39b2ca010a827ef170303f7";
const CERT_SHA256: &str = "98a0046555919ed83a36aeaf252e4b94a92b64fa281317495ee69c88ab33ebeb";

fn reviewed_verifier_from_environment() -> Option<Vec<u8>> {
    let path = std::env::var_os("ZRPC_TEST_SBVERIFY")?;
    let verifier = fs::read(path).expect("ZRPC_TEST_SBVERIFY points to a readable file");
    assert_eq!(verifier.len(), SBVERIFY_SIZE);
    assert_eq!(hex::encode(Sha256::digest(&verifier)), SBVERIFY_SHA256);
    Some(verifier)
}

#[test]
fn signer_and_verifier_identity_fail_closed() {
    let false_verifier = vec![0; SBVERIFY_SIZE];
    assert_eq!(
        inspect_signed_uki(
            UKI,
            UKI_SHA256,
            UKI.len() as u64,
            CERT,
            CERT_SHA256,
            CERT.len() as u64,
            &false_verifier,
        )
        .unwrap_err(),
        "sbverify executable differs from reviewed Debian package"
    );
    assert_eq!(
        inspect_signed_uki(
            UKI,
            UKI_SHA256,
            UKI.len() as u64,
            CERT,
            UKI_SHA256,
            CERT.len() as u64,
            &false_verifier,
        )
        .unwrap_err(),
        "signer certificate SHA-256 differs from expected artifact"
    );
}

#[test]
#[ignore = "requires ZRPC_TEST_SBVERIFY set to the pinned Debian executable"]
fn reviewed_sbverify_accepts_fixture_and_rejects_changed_signature() {
    let verifier_path = std::env::var_os("ZRPC_TEST_SBVERIFY")
        .expect("set ZRPC_TEST_SBVERIFY to the pinned Debian executable");
    let verifier = reviewed_verifier_from_environment().expect("test verifier path is set");
    let report = inspect_signed_uki(
        UKI,
        UKI_SHA256,
        UKI.len() as u64,
        CERT,
        CERT_SHA256,
        CERT.len() as u64,
        &verifier,
    )
    .unwrap();
    assert!(report.signed_uki_checked);
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
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stdout)
    );
    let cli_report: serde_json::Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(cli_report["signed_uki_checked"], true);
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
            &changed_hash,
            changed_signature.len() as u64,
            CERT,
            CERT_SHA256,
            CERT.len() as u64,
            &verifier,
        )
        .unwrap_err(),
        "UKI Authenticode signature rejected by reviewed sbverify binary"
    );
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
        ])
        .output()
        .unwrap();
    fs::remove_file(link).unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["signed_uki_checked"], false);
    assert_eq!(report["private_mode_approved"], false);
}
