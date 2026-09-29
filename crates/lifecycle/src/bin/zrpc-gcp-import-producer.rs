//! Offline import-archive producer. This executable has no cloud command path.
use std::{ffi::OsStr, path::PathBuf};
use zrpc_lifecycle::gcp::{Error, Result, package};

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0].as_os_str() == OsStr::new("--help") {
        println!(
            "zrpc-gcp-import-producer pack-import --raw ABSOLUTE_DISK.raw --archive ABSOLUTE_NEW.tar.gz\n\nCreates one offline Google raw-image archive on /workspace. Its receipt grants no deployment or private-mode approval."
        );
        return Ok(());
    }
    if args.len() != 5
        || args[0].as_os_str() != OsStr::new("pack-import")
        || args[1].as_os_str() != OsStr::new("--raw")
        || args[3].as_os_str() != OsStr::new("--archive")
    {
        return Err(Error("invalid import-producer arguments; see --help"));
    }
    let raw = PathBuf::from(&args[2]);
    let archive = PathBuf::from(&args[4]);
    let receipt = package::pack_import_archive(&raw, &archive)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).map_err(|_| Error("output encoding failed"))?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
