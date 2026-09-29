//! Offline validation of the one Google manual-import archive.
//!
//! The producer receipt does not authorize its own output. This independent
//! reader checks the compressed bytes and the expanded disk before the
//! operator package can be prepared; it never extracts archive paths.

use super::{Artifact, Error, Result};
use flate2::bufread::GzDecoder;
use flate2::{Compression, GzBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Mutex, OnceLock},
};

const BLOCK: u64 = 512;
const GNU_MAGIC: &[u8; 8] = b"ustar  \0";
const DISK_NAME: &[u8] = b"disk.raw";
const IMPORT_GIB: u64 = 1024 * 1024 * 1024;
const MAX_IMPORT_GIB: u64 = 2048;

/// A producer record is diagnostic. The operator still needs an independent
/// review of the packaged executable and its complete execution environment.
#[derive(Debug, Serialize)]
pub(super) struct NativeImportReceipt {
    schema_version: u8,
    producer: &'static str,
    producer_executable_sha256: String,
    archive_sha256: String,
    raw_disk_sha256: String,
    raw_disk_bytes: u64,
    oldgnu_single_member_checked: bool,
    private_mode_approved: bool,
    toolchain_reviewed: bool,
}

fn file_digest(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error("import file seek failed"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let size = file
            .read(&mut buffer)
            .map_err(|_| Error("import file read failed"))?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error("import file seek failed"))?;
    Ok(hex::encode(digest.finalize()))
}

fn same_identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.mode(),
        a.nlink(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.mode(),
        b.nlink(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}

#[cfg(target_os = "linux")]
fn running_executable_digest() -> Result<String> {
    // current_exe() resolves to a pathname. Another process can rename and
    // replace that pathname after exec, making a receipt describe different
    // bytes from the code that produced the archive. Procfs opens the mapped
    // executable inode even if its original name has since been replaced.
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/proc/self/exe")
        .map_err(|_| Error("running producer executable cannot be opened"))?;
    if !executable
        .metadata()
        .map_err(|_| Error("producer metadata unavailable"))?
        .is_file()
    {
        return Err(Error("running producer executable is not regular"));
    }
    file_digest(&mut executable)
}

#[cfg(not(target_os = "linux"))]
fn running_executable_digest() -> Result<String> {
    Err(Error("native import producer requires Linux procfs"))
}

/// Create a single-member oldgnu sparse archive on the managed workspace
/// volume. This makes no network or provider calls and grants no approval.
pub(super) fn pack_import_archive(
    raw_path: &Path,
    archive_path: &Path,
) -> Result<NativeImportReceipt> {
    if !raw_path.is_absolute()
        || !archive_path.is_absolute()
        || raw_path.file_name().is_none_or(|name| name != "disk.raw")
        || !archive_path.to_string_lossy().ends_with(".tar.gz")
        || archive_path.exists()
        || archive_path.is_symlink()
    {
        return Err(Error(
            "import paths must be absolute disk.raw and new .tar.gz",
        ));
    }
    let raw_canonical = fs::canonicalize(raw_path).map_err(|_| Error("import disk unavailable"))?;
    let parent = fs::canonicalize(
        archive_path
            .parent()
            .ok_or(Error("archive parent missing"))?,
    )
    .map_err(|_| Error("archive parent unavailable"))?;
    if !raw_canonical.starts_with("/workspace") || !parent.starts_with("/workspace") {
        return Err(Error("import input and output must be on /workspace"));
    }
    let mut raw = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(raw_path)
        .map_err(|_| Error("import disk cannot be opened"))?;
    let before = raw
        .metadata()
        .map_err(|_| Error("import disk metadata unavailable"))?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() % IMPORT_GIB != 0
        || before.len() / IMPORT_GIB > MAX_IMPORT_GIB
    {
        return Err(Error(
            "import disk must be a regular whole-GiB disk within Google size limits",
        ));
    }
    let raw_sha256 = file_digest(&mut raw)?;
    let producer_executable_sha256 = running_executable_digest()?;
    let temporary = parent.join(format!(".disk-import-{}.tar.gz", crate::gcp::uuid()?));
    let result = (|| {
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Error("import archive temporary file cannot be created"))?;
        let gzip = GzBuilder::new()
            .mtime(0)
            .write(output, Compression::default());
        let mut tar = tar::Builder::new(gzip);
        tar.mode(tar::HeaderMode::Deterministic);
        tar.append_file("disk.raw", &mut raw)
            .map_err(|_| Error("import TAR creation failed"))?;
        let gzip = tar
            .into_inner()
            .map_err(|_| Error("import TAR finish failed"))?;
        let mut output = gzip
            .finish()
            .map_err(|_| Error("import gzip finish failed"))?;
        output
            .sync_all()
            .map_err(|_| Error("import archive sync failed"))?;
        let archive_sha256 = file_digest(&mut output)?;
        if !same_identity(
            &before,
            &raw.metadata()
                .map_err(|_| Error("import disk metadata unavailable"))?,
        ) || file_digest(&mut raw)? != raw_sha256
        {
            return Err(Error("import disk changed during archive creation"));
        }
        let archive = Artifact {
            path: temporary.clone(),
            sha256: archive_sha256.clone(),
        };
        verify_import_archive(&archive, &raw_sha256, before.len())?;
        fs::hard_link(&temporary, archive_path)
            .map_err(|_| Error("new import archive cannot be published"))?;
        File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error("import archive directory sync failed"))?;
        Ok(NativeImportReceipt {
            schema_version: 2,
            producer: "zrpc-gcp-import-producer-rust",
            producer_executable_sha256,
            archive_sha256,
            raw_disk_sha256: raw_sha256,
            raw_disk_bytes: before.len(),
            oldgnu_single_member_checked: true,
            private_mode_approved: false,
            toolchain_reviewed: false,
        })
    })();
    let _ = fs::remove_file(&temporary);
    result
}

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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires native Linux procfs; QEMU user mode cannot open /proc/self/exe"]
    fn producer_receipt_hashes_running_inode_after_path_replacement() {
        use std::{
            io::Read,
            os::unix::net::{UnixListener, UnixStream},
            process::Command,
        };

        const SOCKET_ENV: &str = "ZRPC_RUNNING_IMAGE_TEST_SOCKET";
        if let Some(socket) = std::env::var_os(SOCKET_ENV) {
            let mut channel = UnixStream::connect(socket).unwrap();
            channel.write_all(b"ready").unwrap();
            let mut go = [0u8; 1];
            channel.read_exact(&mut go).unwrap();
            assert_eq!(go, *b"G");
            channel
                .write_all(running_executable_digest().unwrap().as_bytes())
                .unwrap();
            return;
        }

        let root = std::path::PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        )
        .join(format!("e-{}", crate::gcp::uuid().unwrap()));
        fs::create_dir(&root).unwrap();
        let running = root.join("running");
        fs::copy(std::env::current_exe().unwrap(), &running).unwrap();
        let mut original = File::open(&running).unwrap();
        let expected = file_digest(&mut original).unwrap();
        let listener = UnixListener::bind(root.join("s")).unwrap();
        let mut child = Command::new(&running)
            .arg("--exact")
            .arg("gcp::package::import_archive::tests::producer_receipt_hashes_running_inode_after_path_replacement")
            .arg("--ignored")
            .arg("--nocapture")
            .env(SOCKET_ENV, root.join("s"))
            .spawn()
            .unwrap();
        listener.set_nonblocking(true).unwrap();
        let (mut channel, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        child.try_wait().unwrap().is_none(),
                        "native replacement child exited before connecting"
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("native replacement socket failed: {error}"),
            }
        };
        let mut ready = [0u8; 5];
        channel.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready");

        fs::rename(&running, root.join("old")).unwrap();
        fs::write(&running, b"replacement pathname contents").unwrap();
        channel.write_all(b"G").unwrap();
        let mut observed = [0u8; 64];
        channel.read_exact(&mut observed).unwrap();
        assert_eq!(std::str::from_utf8(&observed).unwrap(), expected);
        assert!(child.wait().unwrap().success());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn producer_rejects_non_import_disks_and_existing_outputs() {
        let root = std::path::PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        )
        .join(format!(
            "import-producer-negative-{}",
            crate::gcp::uuid().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let raw = root.join("disk.raw");
        let archive = root.join("disk.tar.gz");
        fs::write(&raw, b"not a whole GiB").unwrap();
        assert!(pack_import_archive(&raw, &archive).is_err());
        assert!(!archive.exists());
        fs::write(&archive, b"preserve existing output").unwrap();
        assert!(pack_import_archive(&raw, &archive).is_err());
        assert_eq!(fs::read(&archive).unwrap(), b"preserve existing output");
        fs::remove_dir_all(root).unwrap();
    }

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
