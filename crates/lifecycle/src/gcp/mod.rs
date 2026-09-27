//! Google Cloud operator control plane. Separate from private-query transport.
//!
//! Preparation performs local work only. Neither a package nor an operator
//! receipt grants private-mode approval. Live execution is an explicit command
//! and checks external controls before requesting an OAuth access token.
pub mod controller;
pub mod package;
pub mod provider;
pub mod store;
pub mod watchdog;

/// Provider API contract still required before this adapter may incur costs.
/// A name-based GET followed by DELETE is not an incarnation precondition.
pub const LIVE_DEPLOYMENT_BLOCKERS: &[&str] = &[
    "Compute deletion has no reviewed incarnation-safe precondition; same-name replacement race unresolved",
    "operator Python/GNU tar import toolchain identity and its receipt have not been independently reviewed/pinned",
];

pub fn ensure_live_creation_ready() -> Result<()> {
    if let Some(blocker) = LIVE_DEPLOYMENT_BLOCKERS.first() {
        return Err(Error(blocker));
    }
    Ok(())
}

use ez_hash::{Hasher, Sha256};
use std::{fmt, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::hash(bytes))
}
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error("cannot read regular operator file"))?;
    if !file
        .metadata()
        .map_err(|_| Error("operator file metadata unavailable"))?
        .is_file()
    {
        return Err(Error("operator input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| Error("operator file read failed"))?;
    Ok(bytes)
}
pub fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error("system clock precedes epoch"))
}
pub(crate) fn uuid() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error("OS randomness unavailable"))?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
