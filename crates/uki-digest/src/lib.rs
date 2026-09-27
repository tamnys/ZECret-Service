//! Offline UKI diagnostics. Neither digest nor signature inspection approves a release.

#[cfg(target_os = "linux")]
mod signature;
#[cfg(target_os = "linux")]
pub use signature::{
    ExpectedSignatureInput, SBVERIFY_RUNTIME, SBVERIFY_SHA256, SBVERIFY_SIZE, SignatureDiagnostic,
    inspect_signed_uki,
};

use authenticode::authenticode_digest;
use object::read::pe::PeFile64;
use object::{Architecture, Object};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub schema_version: u8,
    pub status: &'static str,
    pub uki_sha256: String,
    pub uki_bytes: u64,
    pub uki_pe_coff_sha256: String,
    pub uki_pe_coff_sha384: String,
    pub digest_implementation: &'static str,
    pub signed_uki_checked: bool,
    pub boot_measurement_checked: bool,
    pub release_approved: bool,
    pub private_mode_approved: bool,
}

pub fn inspect_uki(
    data: &[u8],
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<Diagnostic, &'static str> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("expected SHA-256 must be 64 lowercase hexadecimal characters");
    }
    if expected_bytes == 0 || u64::try_from(data.len()) != Ok(expected_bytes) {
        return Err("UKI byte length differs from expected artifact");
    }
    let uki_sha256 = hex::encode(Sha256::digest(data));
    if uki_sha256 != expected_sha256 {
        return Err("UKI SHA-256 differs from expected artifact");
    }
    // Google's pinned UKI measurement implementation pads unsigned PE data to
    // 8 bytes. This library hashes the supplied bytes directly; refuse a file
    // whose result could disagree with the measured, padded image.
    if data.len() % 8 != 0 {
        return Err("UKI length is not 8-byte aligned for EFI measurement");
    }
    let pe = PeFile64::parse(data).map_err(|_| "UKI is not a valid PE32+ image")?;
    if pe.architecture() != Architecture::X86_64 {
        return Err("UKI PE machine is not x86_64");
    }
    let mut digest_sha256 = Sha256::new();
    authenticode_digest(&pe, &mut digest_sha256)
        .map_err(|_| "UKI PE/COFF Authenticode hash regions are invalid")?;
    let mut digest_sha384 = Sha384::new();
    authenticode_digest(&pe, &mut digest_sha384)
        .map_err(|_| "UKI PE/COFF Authenticode hash regions are invalid")?;
    Ok(Diagnostic {
        schema_version: 1,
        status: "diagnostic-uki-pe-coff-sha384-unapproved",
        uki_sha256,
        uki_bytes: expected_bytes,
        uki_pe_coff_sha256: hex::encode(digest_sha256.finalize()),
        uki_pe_coff_sha384: hex::encode(digest_sha384.finalize()),
        digest_implementation: "authenticode=0.6.0;object=0.39.0;sha2=0.10.9",
        signed_uki_checked: false,
        boot_measurement_checked: false,
        release_approved: false,
        private_mode_approved: false,
    })
}
