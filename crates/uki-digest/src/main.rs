use serde_json::json;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zrpc_uki_digest::inspect_uki;

#[cfg(not(unix))]
compile_error!("zrpc-uki-digest requires Unix no-follow file opening");

fn run(args: &[String]) -> Result<zrpc_uki_digest::Diagnostic, &'static str> {
    if args.len() != 4 {
        return Err("usage: zrpc-uki-digest UKI expected_sha256 expected_bytes");
    }
    let expected_bytes = args[3]
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes > 0)
        .ok_or("expected byte length must be a positive integer")?;
    let path = Path::new(&args[1]);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "UKI file unavailable or redirected")?;
    let metadata = file.metadata().map_err(|_| "UKI file unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() != expected_bytes {
        return Err("UKI file is not regular or byte length differs");
    }
    let mut data = Vec::new();
    file.take(
        expected_bytes
            .checked_add(1)
            .ok_or("expected byte length overflows")?,
    )
    .read_to_end(&mut data)
    .map_err(|_| "UKI file could not be read")?;
    inspect_uki(&data, &args[2], expected_bytes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(report) => println!(
            "{}",
            serde_json::to_string(&report).expect("fixed report is serializable")
        ),
        Err(reason) => {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": reason,
                    "signed_uki_checked": false,
                    "boot_measurement_checked": false,
                    "release_approved": false,
                    "private_mode_approved": false
                })
            );
            std::process::exit(1);
        }
    }
}
