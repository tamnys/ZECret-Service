use serde_json::json;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zrpc_uki_digest::inspect_uki;
#[cfg(target_os = "linux")]
use zrpc_uki_digest::{SBVERIFY_SIZE, inspect_signed_uki};

#[cfg(not(unix))]
compile_error!("zrpc-uki-digest requires Unix no-follow file opening");

fn parse_bytes(value: &str) -> Result<u64, &'static str> {
    value
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes > 0)
        .ok_or("expected byte length must be a positive integer")
}

fn read_exact_file(path: &Path, expected_bytes: u64) -> Result<Vec<u8>, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "artifact file unavailable or redirected")?;
    let metadata = file.metadata().map_err(|_| "artifact file unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() != expected_bytes {
        return Err("artifact file is not regular or byte length differs");
    }
    let mut data = Vec::new();
    file.take(
        expected_bytes
            .checked_add(1)
            .ok_or("expected byte length overflows")?,
    )
    .read_to_end(&mut data)
    .map_err(|_| "artifact file could not be read")?;
    if u64::try_from(data.len()) != Ok(expected_bytes) {
        return Err("artifact file changed during read");
    }
    Ok(data)
}

fn run_digest(args: &[String]) -> Result<serde_json::Value, &'static str> {
    let expected_bytes = parse_bytes(&args[3])?;
    let data = read_exact_file(Path::new(&args[1]), expected_bytes)?;
    let report = inspect_uki(&data, &args[2], expected_bytes)?;
    Ok(serde_json::to_value(report).expect("fixed report is serializable"))
}

#[cfg(target_os = "linux")]
fn run_signature(args: &[String]) -> Result<serde_json::Value, &'static str> {
    let uki_bytes = parse_bytes(&args[4])?;
    let certificate_bytes = parse_bytes(&args[8])?;
    let uki = read_exact_file(Path::new(&args[2]), uki_bytes)?;
    let verifier = read_exact_file(Path::new(&args[5]), SBVERIFY_SIZE as u64)?;
    let certificate = read_exact_file(Path::new(&args[6]), certificate_bytes)?;
    let report = inspect_signed_uki(
        &uki,
        &args[3],
        uki_bytes,
        &certificate,
        &args[7],
        certificate_bytes,
        &verifier,
    )?;
    Ok(serde_json::to_value(report).expect("fixed report is serializable"))
}

#[cfg(not(target_os = "linux"))]
fn run_signature(_args: &[String]) -> Result<serde_json::Value, &'static str> {
    Err("signature verification requires Linux")
}

fn run(args: &[String]) -> Result<serde_json::Value, &'static str> {
    match args {
        [_, _, _, _] => run_digest(args),
        [_, command, _, _, _, _, _, _, _] if command == "verify-signature" => run_signature(args),
        _ => Err(
            "usage: zrpc-uki-digest UKI expected_sha256 expected_bytes | verify-signature UKI expected_sha256 expected_bytes sbverify signer_cert expected_cert_sha256 expected_cert_bytes",
        ),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(report) => println!("{report}"),
        Err(reason) => {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": reason,
                    "signed_uki_checked": false,
                    "signer_identity_reviewed": false,
                    "verifier_runtime_closure_checked": false,
                    "boot_measurement_checked": false,
                    "release_approved": false,
                    "private_mode_approved": false
                })
            );
            std::process::exit(1);
        }
    }
}
