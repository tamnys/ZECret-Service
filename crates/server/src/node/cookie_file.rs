//! Linux-only, fd-relative loading of Zebra's generated RPC cookie.
//! This is a storage-boundary check, not proof of the node's identity.

use super::{CookieAuth, unavailable};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::fs::{Mode, OFlags, fstatfs, openat};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
use zeroize::Zeroizing;
use zrpc_protocol::SafeError;

// Zebra v6.4.2 writes `__cookie__:` plus STANDARD.encode([u8; 32]) with mode
// 0600. Change these only after reviewing the exact pinned replacement source.
const PREFIX: &[u8] = b"__cookie__:";
const SECRET_BYTES: usize = 32;
const ENCODED_BYTES: usize = SECRET_BYTES.div_ceil(3) * 4;
const COOKIE_BYTES: usize = PREFIX.len() + ENCODED_BYTES;

#[cfg(target_os = "linux")]
fn child(parent: &File, component: &std::ffi::OsStr, directory: bool) -> Result<File, SafeError> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    // The maintained safe binding opens relative to an already-open parent;
    // NOFOLLOW rejects a swapped symlink at every component.
    let fd = openat(parent, component, flags, Mode::empty()).map_err(|_| unavailable())?;
    Ok(File::from(fd))
}

#[cfg(target_os = "linux")]
fn open_checked(path: &Path) -> Result<File, SafeError> {
    if !path.is_absolute() {
        return Err(unavailable());
    }
    let mut components = path.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(unavailable());
    }
    let mut parent = File::open("/").map_err(|_| unavailable())?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(unavailable());
        };
        let is_directory = components.peek().is_some();
        parent = child(&parent, name, is_directory)?;
    }
    Ok(parent)
}

#[cfg(target_os = "linux")]
fn on_tmpfs(file: &File) -> bool {
    // fstatfs observes the opened inode, not a pathname that could be swapped.
    fstatfs(file).is_ok_and(|stat| stat.f_type as u64 == libc::TMPFS_MAGIC as u64)
}

#[cfg(target_os = "linux")]
pub(super) fn read(path: &Path) -> Result<CookieAuth, SafeError> {
    let bytes = read_owned(path, rustix::process::geteuid().as_raw())?;
    CookieAuth::from_cookie(&*bytes)
}

#[cfg(target_os = "linux")]
fn read_owned(path: &Path, owner: u32) -> Result<Zeroizing<[u8; COOKIE_BYTES]>, SafeError> {
    let mut file = open_checked(path)?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != owner
        || metadata.len() != COOKIE_BYTES as u64
        || !on_tmpfs(&file)
    {
        return Err(unavailable());
    }
    let mut bytes = Zeroizing::new([0u8; COOKIE_BYTES]);
    file.read_exact(&mut *bytes).map_err(|_| unavailable())?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(|_| unavailable())? != 0 || !bytes.starts_with(PREFIX) {
        return Err(unavailable());
    }
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    if STANDARD
        .decode_slice(&bytes[PREFIX.len()..], &mut *secret)
        .ok()
        != Some(SECRET_BYTES)
    {
        return Err(unavailable());
    }
    let canonical = Zeroizing::new(STANDARD.encode(&*secret));
    if canonical.as_bytes() != &bytes[PREFIX.len()..] {
        return Err(unavailable());
    }
    Ok(bytes)
}

/// Immutable GCP startup handoff between the separate node and wrapper UIDs.
/// All opens are fd-relative/NOFOLLOW; contents and both mounts are checked.
/// A pre-existing destination is denied, prohibiting same-boot cookie refresh.
#[cfg(target_os = "linux")]
pub fn stage_gcp_cookie(
    node_uid: u32,
    wrapper_uid: u32,
    wrapper_gid: u32,
) -> Result<(), SafeError> {
    use std::io::Write;
    if rustix::process::geteuid().as_raw() != 0
        || node_uid == 0
        || wrapper_uid == 0
        || node_uid == wrapper_uid
    {
        return Err(unavailable());
    }
    let bytes = read_owned(Path::new("/run/zrpc-node/.cookie"), node_uid)?;
    let parent = open_checked(Path::new("/run/zrpc-wrapper"))?;
    let metadata = parent.metadata().map_err(|_| unavailable())?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o027 != 0
        || !on_tmpfs(&parent)
    {
        return Err(unavailable());
    }
    let fd = openat(
        &parent,
        ".cookie",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| unavailable())?;
    let mut file = File::from(fd);
    file.write_all(&*bytes).map_err(|_| unavailable())?;
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(wrapper_uid)),
        Some(rustix::process::Gid::from_raw(wrapper_gid)),
    )
    .map_err(|_| unavailable())?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn read(_path: &Path) -> Result<CookieAuth, SafeError> {
    Err(unavailable())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs::{self, DirBuilder, OpenOptions, Permissions},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = Path::new("/dev/shm").join(format!(
                "zrpc-cookie-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).unwrap();
            Self(path)
        }
        fn cookie(&self) -> std::path::PathBuf {
            self.0.join(".cookie")
        }
        fn write(&self, bytes: &[u8]) {
            use std::io::Write;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.cookie())
                .unwrap();
            file.write_all(bytes).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn valid() -> Vec<u8> {
        let mut out = PREFIX.to_vec();
        out.extend_from_slice(STANDARD.encode([7u8; SECRET_BYTES]).as_bytes());
        out
    }

    #[test]
    fn exact_tmpfs_cookie_is_accepted_and_redacted() {
        let fixture = Fixture::new();
        fixture.write(&valid());
        let auth = read(&fixture.cookie()).unwrap();
        assert!(
            read_owned(
                &fixture.cookie(),
                rustix::process::geteuid().as_raw().wrapping_add(1)
            )
            .is_err()
        );
        assert!(!format!("{auth:?}").contains("BwcH"));
    }

    #[test]
    fn persistent_symlink_world_readable_and_malformed_cookies_fail() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.codex-tmp");
        fs::create_dir_all(&base).unwrap();
        let persistent = base.join(format!("zrpc-persistent-cookie-{}", std::process::id()));
        fs::write(&persistent, valid()).unwrap();
        fs::set_permissions(&persistent, Permissions::from_mode(0o600)).unwrap();
        if !on_tmpfs(&File::open(&persistent).unwrap()) {
            assert!(read(&persistent).is_err());
        }
        fs::remove_file(&persistent).unwrap();

        let fixture = Fixture::new();
        fixture.write(&valid());
        fs::set_permissions(fixture.cookie(), Permissions::from_mode(0o644)).unwrap();
        assert!(read(&fixture.cookie()).is_err());
        fs::set_permissions(fixture.cookie(), Permissions::from_mode(0o600)).unwrap();
        let alias = fixture.0.join("alias");
        symlink(fixture.cookie(), &alias).unwrap();
        assert!(read(&alias).is_err());
        assert!(read(Path::new("relative/.cookie")).is_err());

        let malformed = Fixture::new();
        let mut bad = valid();
        bad[0] = b'X';
        malformed.write(&bad);
        assert!(read(&malformed.cookie()).is_err());
    }
}
