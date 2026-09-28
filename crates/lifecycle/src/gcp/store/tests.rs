//! Synthetic journal-directory failures; no provider or cloud operation.
use super::*;
use std::os::unix::{ffi::OsStringExt, fs::symlink};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let parent = PathBuf::from(
            std::env::var_os("CODEX_TMP_DIR").expect("managed workspace scratch required"),
        );
        let path = parent.join(format!(
            "zrpc-gcp-journal-inventory-{}",
            super::super::uuid().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn displaced_latest_snapshot_is_rejected_before_loading_a_legacy_prefix() {
    let root = Scratch::new();
    for name in [
        "package.json",
        "writer.lock",
        "00000000000000000000.json",
        "00000000000000000001.json",
    ] {
        fs::write(root.0.join(name), b"synthetic journal bytes").unwrap();
    }
    assert_eq!(snapshot_files(&root.0).unwrap().len(), 2);
    fs::rename(
        root.0.join("00000000000000000001.json"),
        root.0.join("displaced-head.json"),
    )
    .unwrap();
    assert_eq!(
        snapshot_files(&root.0).unwrap_err().0,
        "unexpected journal directory entry"
    );
}

#[test]
fn non_utf8_or_multibyte_snapshot_name_cannot_be_ignored_or_panic() {
    let root = Scratch::new();
    let name = std::ffi::OsString::from_vec(b"head-\xff.json".to_vec());
    fs::write(root.0.join(&name), b"synthetic journal bytes").unwrap();
    assert_eq!(
        snapshot_files(&root.0).unwrap_err().0,
        "journal entry name is not UTF-8"
    );
    fs::remove_file(root.0.join(name)).unwrap();
    // The first 20 bytes end inside a multibyte code point. A string slice
    // would panic instead of rejecting the unexpected entry.
    let name = format!("{}é.json", "0".repeat(19));
    fs::write(root.0.join(name), b"synthetic journal bytes").unwrap();
    assert_eq!(
        snapshot_files(&root.0).unwrap_err().0,
        "unexpected journal directory entry"
    );
}

#[test]
fn dangling_pending_marker_requires_recovery_instead_of_open() {
    let root = Scratch::new();
    symlink(root.0.join("missing-target"), root.0.join("pending.json")).unwrap();
    assert_eq!(
        ensure_no_pending(&root.0).unwrap_err().0,
        "journal has pending commit; explicit recover required"
    );
}
