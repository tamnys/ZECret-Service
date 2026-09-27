//! A separate, offline signature diagnostic for one exact UKI and supplied certificate.
//! This does not establish that the certificate is an approved signer or that the
//! target firmware booted this image under the intended Secure Boot variables.

use crate::inspect_uki;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

// /usr/bin/sbverify extracted without maintainer scripts from Debian trixie
// sbsigntool 0.9.4-3.2+deb13u1 amd64. The .deb SHA-256 below is the entry in
// deploy/gcp/builder-direct-packages.lock.json, bound to the reviewed signed
// Debian 20260918 snapshot. Dynamic libraries are not pinned by this check.
pub const SBVERIFY_SHA256: &str =
    "e4cfb5bf60a8dd2034d728af0f7bf3dd1398f6420473c7bc19a0623fcd003881";
pub const SBVERIFY_SIZE: usize = 64872;
const SBVERIFY_PACKAGE_SHA256: &str =
    "b5390c50b1970a98bd5dab6a4a8bba124e41708792da9ea62bb75c0522dd714f";

#[derive(Debug, Serialize)]
pub struct SignatureDiagnostic {
    pub schema_version: u8,
    pub status: &'static str,
    pub uki_sha256: String,
    pub uki_bytes: u64,
    pub uki_pe_coff_sha256: String,
    pub uki_pe_coff_sha384: String,
    pub signer_certificate_sha256: String,
    pub sbverify_executable_sha256: &'static str,
    pub sbverify_debian_package_sha256: &'static str,
    pub signed_uki_checked: bool,
    pub signer_identity_reviewed: bool,
    pub verifier_runtime_closure_checked: bool,
    pub boot_measurement_checked: bool,
    pub release_approved: bool,
    pub private_mode_approved: bool,
}

fn sealed_input(data: &[u8], executable: bool) -> Result<File, &'static str> {
    let name = CString::new("zrpc-uki-signature-input").expect("fixed string has no NUL");
    // Deliberately omit MFD_CLOEXEC: the verifier opens these immutable files
    // through /proc/self/fd after exec. Only the checksum-matched verifier runs.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err("could not create immutable signature input");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(data)
        .map_err(|_| "could not copy signature input into memory")?;
    let permissions = if executable { 0o500 } else { 0o400 };
    if unsafe { libc::fchmod(file.as_raw_fd(), permissions) } != 0 {
        return Err("could not restrict signature input permissions");
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err("could not seal signature input");
    }
    Ok(file)
}

fn descriptor_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

/// Verify an exact UKI against an exact supplied X.509 certificate with the
/// checksum-pinned Debian `sbverify` binary. The signer certificate is caller-
/// supplied and is *not* an approved release identity. This remains diagnostic
/// until its runtime library closure and the effective firmware policy are
/// independently reviewed.
pub fn inspect_signed_uki(
    uki: &[u8],
    expected_uki_sha256: &str,
    expected_uki_bytes: u64,
    certificate: &[u8],
    expected_certificate_sha256: &str,
    expected_certificate_bytes: u64,
    verifier: &[u8],
) -> Result<SignatureDiagnostic, &'static str> {
    let digest = inspect_uki(uki, expected_uki_sha256, expected_uki_bytes)?;
    if expected_certificate_sha256.len() != 64
        || !expected_certificate_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("expected certificate SHA-256 must be 64 lowercase hexadecimal characters");
    }
    if expected_certificate_bytes == 0
        || u64::try_from(certificate.len()) != Ok(expected_certificate_bytes)
    {
        return Err("signer certificate byte length differs from expected artifact");
    }
    if hex::encode(Sha256::digest(certificate)) != expected_certificate_sha256 {
        return Err("signer certificate SHA-256 differs from expected artifact");
    }
    if verifier.len() != SBVERIFY_SIZE || hex::encode(Sha256::digest(verifier)) != SBVERIFY_SHA256 {
        return Err("sbverify executable differs from reviewed Debian package");
    }

    // Execute the exact inspected bytes; no mutable path is reopened between
    // the UKI/certificate/verifier checks and the verifier's reads.
    let verifier_file = sealed_input(verifier, true)?;
    let certificate_file = sealed_input(certificate, false)?;
    let uki_file = sealed_input(uki, false)?;
    let result = Command::new(descriptor_path(&verifier_file))
        .arg("--cert")
        .arg(descriptor_path(&certificate_file))
        .arg(descriptor_path(&uki_file))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "could not execute reviewed sbverify binary")?;
    if !result.success() {
        return Err("UKI Authenticode signature rejected by reviewed sbverify binary");
    }

    Ok(SignatureDiagnostic {
        schema_version: 1,
        status: "diagnostic-supplied-signer-signature-verified-unapproved",
        uki_sha256: digest.uki_sha256,
        uki_bytes: digest.uki_bytes,
        uki_pe_coff_sha256: digest.uki_pe_coff_sha256,
        uki_pe_coff_sha384: digest.uki_pe_coff_sha384,
        signer_certificate_sha256: expected_certificate_sha256.to_owned(),
        sbverify_executable_sha256: SBVERIFY_SHA256,
        sbverify_debian_package_sha256: SBVERIFY_PACKAGE_SHA256,
        signed_uki_checked: true,
        signer_identity_reviewed: false,
        verifier_runtime_closure_checked: false,
        boot_measurement_checked: false,
        release_approved: false,
        private_mode_approved: false,
    })
}
