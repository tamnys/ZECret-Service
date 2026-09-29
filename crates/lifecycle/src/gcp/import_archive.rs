//! Offline validation of the one Google manual-import archive.
//!
//! The producer receipt does not authorize its own output. This independent
//! reader checks the compressed bytes and the expanded disk before the
//! operator package can be prepared; it never extracts archive paths.

use super::{Artifact, Error, Result};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{self, BufRead, BufReader, Read},
    os::unix::fs::OpenOptionsExt,
    sync::{Mutex, OnceLock},
};

const BLOCK: u64 = 512;
const GNU_MAGIC: &[u8; 8] = b"ustar  \0";
const DISK_NAME: &[u8] = b"disk.raw";

struct Counted<R> {
    inner: R,
    bytes: u64,
}

impl<R> Counted<R> {
    fn new(inner: R) -> Self {
        Self { inner, bytes: 0 }
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(size as u64)
            .ok_or_else(|| io::Error::other("TAR byte count overflow"))?;
        Ok(size)
    }
}

fn inspect<R: BufRead>(compressed: R, raw_sha256: &str, raw_bytes: u64) -> Result<()> {
    // The bufread decoder stops at one gzip member and leaves any following
    // compressed bytes in its buffered source for a separate EOF check.
    let decoder = GzDecoder::new(compressed);
    let mut archive = tar::Archive::new(Counted::new(decoder));
    {
        let mut entries = archive
            .entries()
            .map_err(|_| Error("invalid import TAR header"))?;
        let mut entry = entries
            .next()
            .ok_or(Error("import TAR has no disk.raw"))?
            .map_err(|_| Error("invalid import TAR entry"))?;
        let header = entry.header();
        let bytes = header.as_bytes();
        if entry.raw_header_position() != 0
            || &bytes[257..265] != GNU_MAGIC
            || header.as_gnu().is_none()
            || &bytes[..DISK_NAME.len()] != DISK_NAME
            || bytes[DISK_NAME.len()..100].iter().any(|byte| *byte != 0)
            || bytes[157..257].iter().any(|byte| *byte != 0)
            || !matches!(header.entry_type().as_byte(), 0 | b'0' | b'S')
            || entry.size() != raw_bytes
        {
            return Err(Error("import TAR is not one oldgnu disk.raw"));
        }
        let mut digest = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let size = entry
                .read(&mut buffer)
                .map_err(|_| Error("import disk.raw cannot be expanded"))?;
            if size == 0 {
                break;
            }
            total = total
                .checked_add(size as u64)
                .filter(|size| *size <= raw_bytes)
                .ok_or(Error("import disk.raw exceeds reviewed size"))?;
            digest.update(&buffer[..size]);
        }
        if total != raw_bytes || hex::encode(digest.finalize()) != raw_sha256 {
            return Err(Error("import disk.raw differs from reviewed raw disk"));
        }
        drop(entry);
        if entries.next().is_some() {
            return Err(Error("import TAR has another or malformed entry"));
        }
    }

    // tar-rs stops after the first zero header. Drain the remaining TAR bytes
    // to force gzip CRC validation, require a second end block, and reject
    // hidden members or nonzero content after the end marker.
    let mut counted = archive.into_inner();
    if counted.bytes % BLOCK != 0 {
        return Err(Error("import TAR end marker is unaligned"));
    }
    let mut remaining = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let size = counted
            .read(&mut buffer)
            .map_err(|_| Error("import gzip trailer is invalid"))?;
        if size == 0 {
            break;
        }
        if buffer[..size].iter().any(|byte| *byte != 0) {
            return Err(Error("import TAR contains bytes after its end marker"));
        }
        remaining = remaining
            .checked_add(size as u64)
            .ok_or(Error("import TAR trailer length overflow"))?;
    }
    if remaining < BLOCK || remaining % BLOCK != 0 {
        return Err(Error("import TAR lacks two complete end blocks"));
    }
    let mut source = counted.inner.into_inner();
    if source
        .read(&mut buffer[..1])
        .map_err(|_| Error("import gzip trailing input cannot be read"))?
        != 0
    {
        return Err(Error(
            "import archive has multiple gzip members or trailing bytes",
        ));
    }
    Ok(())
}

pub(super) fn verify_import_archive(
    archive: &Artifact,
    raw_sha256: &str,
    raw_bytes: u64,
) -> Result<()> {
    archive.verify()?;
    // Cache only an already-inspected immutable byte identity. The compressed
    // archive is rehashed before every lookup, so a changed path cannot reuse
    // a prior expansion result. The provider hashes upload bytes again.
    static CHECKED: OnceLock<Mutex<BTreeSet<(String, String, u64)>>> = OnceLock::new();
    let checked = CHECKED.get_or_init(|| Mutex::new(BTreeSet::new()));
    let key = (archive.sha256.clone(), raw_sha256.to_owned(), raw_bytes);
    if checked
        .lock()
        .map_err(|_| Error("import archive cache poisoned"))?
        .contains(&key)
    {
        return Ok(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&archive.path)
        .map_err(|_| Error("import archive cannot be opened"))?;
    if !file
        .metadata()
        .map_err(|_| Error("import archive metadata unavailable"))?
        .is_file()
    {
        return Err(Error("import archive must be a regular file"));
    }
    inspect(BufReader::new(file), raw_sha256, raw_bytes)?;
    // The provider also hashes upload bytes while streaming. Keep this check
    // against replacement during local inspection.
    archive.verify()?;
    checked
        .lock()
        .map_err(|_| Error("import archive cache poisoned"))?
        .insert(key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::{Cursor, Seek, SeekFrom, Write};

    fn tar_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = tar::Builder::new(Vec::new());
        for (name, body) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            writer
                .append_data(&mut header, name, Cursor::new(body))
                .unwrap();
        }
        writer.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut writer = GzEncoder::new(Vec::new(), Compression::default());
        writer.write_all(data).unwrap();
        writer.finish().unwrap()
    }

    fn check(archive: &[u8], disk: &[u8]) -> Result<()> {
        inspect(
            Cursor::new(archive),
            &hex::encode(Sha256::digest(disk)),
            disk.len() as u64,
        )
    }

    #[test]
    fn one_oldgnu_disk_is_accepted() {
        let disk = b"synthetic import bytes";
        assert!(check(&gzip(&tar_bytes(&[("disk.raw", disk)])), disk).is_ok());
    }

    #[test]
    fn oldgnu_sparse_disk_expands_to_the_reviewed_bytes() {
        let path = std::path::PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        )
        .join(format!("import-sparse-{}.raw", crate::gcp::uuid().unwrap()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"synthetic").unwrap();
        file.set_len(1024 * 1024).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut writer = tar::Builder::new(Vec::new());
        writer.append_file("disk.raw", &mut file).unwrap();
        let tar = writer.into_inner().unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(tar[156], b'S', "test volume must expose sparse files");
        let mut disk = vec![0u8; 1024 * 1024];
        disk[..9].copy_from_slice(b"synthetic");
        assert!(check(&gzip(&tar), &disk).is_ok());
    }

    #[test]
    fn hidden_members_and_nonzero_trailers_are_rejected() {
        let disk = b"synthetic import bytes";
        assert!(
            check(
                &gzip(&tar_bytes(&[("disk.raw", disk), ("other", b"x")])),
                disk
            )
            .is_err()
        );

        let mut tar = tar_bytes(&[("disk.raw", disk)]);
        // First end block begins at 1024, the second at 1536.
        tar[1536] = 1;
        assert!(check(&gzip(&tar), disk).is_err());
        tar[1536] = 0;
        tar.truncate(1536);
        assert!(check(&gzip(&tar), disk).is_err());
    }

    #[test]
    fn wrong_disk_and_extra_gzip_input_are_rejected() {
        let disk = b"synthetic import bytes";
        let tar = tar_bytes(&[("disk.raw", disk)]);
        let mut compressed = gzip(&tar);
        assert!(check(&compressed, b"another disk").is_err());
        compressed.extend_from_slice(&gzip(&tar));
        assert!(check(&compressed, disk).is_err());
        compressed.truncate(compressed.len() - gzip(&tar).len());
        compressed.extend_from_slice(b"trailing");
        assert!(check(&compressed, disk).is_err());
    }

    #[test]
    fn other_tar_names_and_formats_are_rejected() {
        let disk = b"synthetic import bytes";
        assert!(check(&gzip(&tar_bytes(&[("other", disk)])), disk).is_err());
        let mut writer = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(disk.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        writer
            .append_data(&mut header, "disk.raw", Cursor::new(disk))
            .unwrap();
        assert!(check(&gzip(&writer.into_inner().unwrap()), disk).is_err());
    }

    #[test]
    fn cached_expansion_requires_the_same_compressed_bytes() {
        let disk = b"synthetic import bytes";
        let bytes = gzip(&tar_bytes(&[("disk.raw", disk)]));
        let path = std::path::PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        )
        .join(format!(
            "import-cache-{}.tar.gz",
            crate::gcp::uuid().unwrap()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let artifact = Artifact {
            path: path.clone(),
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        let disk_hash = hex::encode(Sha256::digest(disk));
        assert!(verify_import_archive(&artifact, &disk_hash, disk.len() as u64).is_ok());
        assert!(verify_import_archive(&artifact, &disk_hash, disk.len() as u64).is_ok());
        std::fs::write(&path, [bytes.as_slice(), b"trailing"].concat()).unwrap();
        assert!(verify_import_archive(&artifact, &disk_hash, disk.len() as u64).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
