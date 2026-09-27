//! A separate, offline signature diagnostic for one exact UKI and supplied certificate.
//! This does not establish that the certificate is an approved signer or that the
//! target firmware booted this image under the intended Secure Boot variables.

use crate::inspect_uki;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Command, Output, Stdio};

// /usr/bin/sbverify extracted without maintainer scripts from Debian trixie
// sbsigntool 0.9.4-3.2+deb13u1 amd64. The .deb SHA-256 below is the entry in
// deploy/gcp/builder-direct-packages.lock.json, bound to the reviewed signed
// Debian 20260918 snapshot. The interpreter and libraries below are extracted
// from that same signed snapshot's libc6, libssl3t64, zlib1g, and libzstd1
// packages. The loader's initial object report is checked against sealed fds;
// later dynamic loads are not authenticated by that report.
pub const SBVERIFY_SHA256: &str =
    "e4cfb5bf60a8dd2034d728af0f7bf3dd1398f6420473c7bc19a0623fcd003881";
pub const SBVERIFY_SIZE: usize = 64872;
const SBVERIFY_PACKAGE_SHA256: &str =
    "b5390c50b1970a98bd5dab6a4a8bba124e41708792da9ea62bb75c0522dd714f";

pub const SBVERIFY_RUNTIME: [(&str, usize, &str); 5] = [
    (
        "ld-linux-x86-64.so.2",
        225_672,
        "c8438e4fde1934e61c88311633f00949ff645d5c04cdb8671fa3d78164d2f307",
    ),
    (
        "libc.so.6",
        1_995_216,
        "9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92",
    ),
    (
        "libz.so.1",
        125_376,
        "85590dd58edf5445e18bc7193e5ebc01ac5841f1ae187e97705a662e90c6421e",
    ),
    (
        "libzstd.so.1",
        825_336,
        "27f07c9a49c2c956bcfb64cd4712976586a66facbf15fc7f09bc37413b5f2b21",
    ),
    (
        "libcrypto.so.3",
        6_517_312,
        "8bb5f3fdffe280d4453eb79a4663c2c47af70b7c247fe2e94e2da703cee1fd3d",
    ),
];

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
    pub verifier_initial_elf_objects_pinned: bool,
    pub signer_identity_reviewed: bool,
    pub verifier_runtime_closure_checked: bool,
    pub boot_measurement_checked: bool,
    pub release_approved: bool,
    pub private_mode_approved: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ExpectedSignatureInput<'a> {
    pub sha256: &'a str,
    pub bytes: u64,
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

fn check_loader_report(
    output: &Output,
    loader: &str,
    preloads: &[String],
) -> Result<(), &'static str> {
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("reviewed sbverify loader inspection failed");
    }
    let report = std::str::from_utf8(&output.stdout)
        .map_err(|_| "reviewed sbverify loader report is not UTF-8")?;
    let mut expected = HashSet::from([loader]);
    expected.extend(preloads.iter().map(String::as_str));
    for line in report.lines() {
        let (object, address) = line
            .trim()
            .rsplit_once(" (0x")
            .ok_or("reviewed sbverify loader reported an unexpected object")?;
        let address = address
            .strip_suffix(')')
            .ok_or("reviewed sbverify loader reported an unexpected object")?;
        if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("reviewed sbverify loader reported an unexpected object");
        }
        let object = if let Some((interpreter, path)) = object.split_once(" => ") {
            if interpreter != "/lib64/ld-linux-x86-64.so.2" || path != loader {
                return Err("reviewed sbverify loader reported an unexpected object");
            }
            path
        } else {
            object
        };
        if !expected.remove(object) {
            return Err("reviewed sbverify loader reported an unexpected object");
        }
    }
    if !expected.is_empty() {
        return Err("reviewed sbverify loader omitted a pinned object");
    }
    Ok(())
}

/// Verify an exact UKI against an exact supplied X.509 certificate with the
/// checksum-pinned Debian `sbverify` binary. The signer certificate is caller-
/// supplied and is *not* an approved release identity. This remains diagnostic
/// until post-start loads and the effective firmware policy are independently
/// reviewed. The caller must provide the five exact ELF objects in the order
/// of `SBVERIFY_RUNTIME`, derived from authenticated Debian package archives.
pub fn inspect_signed_uki(
    uki: &[u8],
    expected_uki: ExpectedSignatureInput<'_>,
    certificate: &[u8],
    expected_certificate: ExpectedSignatureInput<'_>,
    verifier: &[u8],
    runtime: [&[u8]; 5],
) -> Result<SignatureDiagnostic, &'static str> {
    let digest = inspect_uki(uki, expected_uki.sha256, expected_uki.bytes)?;
    if expected_certificate.sha256.len() != 64
        || !expected_certificate
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("expected certificate SHA-256 must be 64 lowercase hexadecimal characters");
    }
    if expected_certificate.bytes == 0
        || u64::try_from(certificate.len()) != Ok(expected_certificate.bytes)
    {
        return Err("signer certificate byte length differs from expected artifact");
    }
    if hex::encode(Sha256::digest(certificate)) != expected_certificate.sha256 {
        return Err("signer certificate SHA-256 differs from expected artifact");
    }
    if verifier.len() != SBVERIFY_SIZE || hex::encode(Sha256::digest(verifier)) != SBVERIFY_SHA256 {
        return Err("sbverify executable differs from reviewed Debian package");
    }

    for (object, (_, size, sha256)) in runtime.iter().zip(SBVERIFY_RUNTIME.iter()) {
        if object.len() != *size || hex::encode(Sha256::digest(object)) != *sha256 {
            return Err("sbverify runtime object differs from reviewed Debian package");
        }
    }

    // Execute only the inspected program and startup ELF bytes. Every file is
    // sealed before the loader inspects or uses it, so the observed objects
    // cannot be changed between the two child processes.
    let verifier_file = sealed_input(verifier, true)?;
    let certificate_file = sealed_input(certificate, false)?;
    let uki_file = sealed_input(uki, false)?;
    let mut runtime_files = Vec::with_capacity(runtime.len());
    for (index, object) in runtime.iter().enumerate() {
        runtime_files.push(sealed_input(object, index == 0)?);
    }
    let loader = descriptor_path(&runtime_files[0]);
    let preloads = runtime_files[1..]
        .iter()
        .map(descriptor_path)
        .collect::<Vec<_>>();
    let preload_arg = preloads.join(":");
    let verifier_path = descriptor_path(&verifier_file);
    let loader_args = [
        "--inhibit-cache",
        "--preload",
        preload_arg.as_str(),
        "--library-path",
        "/nonexistent",
    ];
    let inspected = Command::new(&loader)
        .args(loader_args)
        .arg("--list")
        .arg(&verifier_path)
        .env_clear()
        .output()
        .map_err(|_| "could not inspect reviewed sbverify loader objects")?;
    check_loader_report(&inspected, &loader, &preloads)?;

    let result = Command::new(&loader)
        .args(loader_args)
        .arg(&verifier_path)
        .arg("--cert")
        .arg(descriptor_path(&certificate_file))
        .arg(descriptor_path(&uki_file))
        .env_clear()
        .env("OPENSSL_CONF", "/dev/null")
        .env("OPENSSL_MODULES", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "could not execute reviewed sbverify binary")?;
    if !result.success() {
        return Err("UKI Authenticode signature rejected by reviewed sbverify binary");
    }

    Ok(SignatureDiagnostic {
        schema_version: 2,
        status: "diagnostic-supplied-signer-signature-verified-unapproved",
        uki_sha256: digest.uki_sha256,
        uki_bytes: digest.uki_bytes,
        uki_pe_coff_sha256: digest.uki_pe_coff_sha256,
        uki_pe_coff_sha384: digest.uki_pe_coff_sha384,
        signer_certificate_sha256: expected_certificate.sha256.to_owned(),
        sbverify_executable_sha256: SBVERIFY_SHA256,
        sbverify_debian_package_sha256: SBVERIFY_PACKAGE_SHA256,
        signed_uki_checked: true,
        verifier_initial_elf_objects_pinned: true,
        signer_identity_reviewed: false,
        verifier_runtime_closure_checked: false,
        boot_measurement_checked: false,
        release_approved: false,
        private_mode_approved: false,
    })
}
