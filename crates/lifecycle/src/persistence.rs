//! Unix local storage, not authenticated storage or live watchdog activation.
//! The operator must protect the original file, its initialization receipt, the
//! store and their ancestors from replacement/deletion by other writers. OS
//! locks coordinate cooperating writers; hostile same-UID/filesystem rollback
//! is outside this contract. No API replaces committed snapshots or resets a store.

use crate::{
    LifecycleError,
    controller::{ExperimentBinding, ExperimentLedger},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::{RawValue, to_raw_value};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions, TryLockError},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const LOCK: &str = "writer.lock";
const PENDING: &str = "pending.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Io,
    UnsafePath,
    ExistingOutput,
    Locked,
    InvalidState,
    PendingRecovery,
    ReloadRequired,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Io => "lifecycle store I/O failed; commit outcome may be uncertain",
            Self::UnsafePath => {
                "lifecycle store requires regular files and operator-controlled directories"
            }
            Self::ExistingOutput => {
                "lifecycle output already exists; replacement or reset is forbidden"
            }
            Self::Locked => "another lifecycle writer holds the store lock",
            Self::InvalidState => {
                "lifecycle state is missing, malformed, inconsistent, or bound elsewhere"
            }
            Self::PendingRecovery => "uncommitted draft requires explicit recovery before writing",
            Self::ReloadRequired => "reload lifecycle state after an uncertain write outcome",
        })
    }
}
impl std::error::Error for StoreError {}
impl From<LifecycleError> for StoreError {
    fn from(_: LifecycleError) -> Self {
        Self::InvalidState
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalRecord {
    binding: ExperimentBinding,
    store_directory: PathBuf,
    initial_ledger: Box<RawValue>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    generation: u64,
    ledger: Box<RawValue>,
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|_| StoreError::InvalidState)
}
fn parse_object<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
        return Err(StoreError::InvalidState);
    }
    serde_json::from_slice(bytes).map_err(|_| StoreError::InvalidState)
}
fn ledger_from_raw(
    value: &RawValue,
    binding: &ExperimentBinding,
) -> Result<ExperimentLedger, StoreError> {
    let bytes = value.get().as_bytes();
    if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
        return Err(StoreError::InvalidState);
    }
    // Do not pass through Value: that would erase duplicate nested fields
    // before the typed ledger's strict deserializer can reject them.
    Ok(ExperimentLedger::from_json(bytes, binding)?)
}
fn validate_absolute(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}
fn sibling(path: &Path, suffix: &str) -> Result<PathBuf, StoreError> {
    let mut name = path
        .file_name()
        .ok_or(StoreError::UnsafePath)?
        .to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}
fn directory(path: &Path) -> Result<File, StoreError> {
    validate_absolute(path)?;
    // Reject existing symlink ancestors too. O_NOFOLLOW on each actual open
    // protects its final component; ancestor stability remains owner trust.
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component);
        let metadata = fs::symlink_metadata(&ancestor).map_err(|_| StoreError::UnsafePath)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(StoreError::UnsafePath);
        }
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|_| StoreError::UnsafePath)
}
fn regular(path: &Path, write: bool) -> Result<File, StoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| StoreError::UnsafePath)?;
    if !file.metadata().map_err(|_| StoreError::Io)?.is_file() {
        return Err(StoreError::UnsafePath);
    }
    Ok(file)
}
fn create_file(path: &Path) -> Result<File, StoreError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::ExistingOutput
            } else {
                StoreError::Io
            }
        })
}
fn read_file(path: &Path) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    regular(path, false)?
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Io)?;
    Ok(bytes)
}
fn no_output(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(StoreError::ExistingOutput),
        Err(_) => Err(StoreError::Io),
    }
}
fn sync_directory(file: &File) -> Result<(), StoreError> {
    file.sync_all().map_err(|_| StoreError::Io)
}

/// Explicit local initialization of a new operator-owned original. The file is
/// outside the mutable store, contains its fixed location and initial history,
/// and is read-only after publication. Existing outputs are never overwritten.
/// A partial original publication is left for operator inspection, not repaired.
pub fn create_original_binding(
    path: &Path,
    store_directory: &Path,
    initial: &ExperimentLedger,
) -> Result<(), StoreError> {
    validate_absolute(path)?;
    validate_absolute(store_directory)?;
    if path.starts_with(store_directory) {
        return Err(StoreError::UnsafePath);
    }
    let parent = directory(path.parent().ok_or(StoreError::UnsafePath)?)?;
    directory(store_directory.parent().ok_or(StoreError::UnsafePath)?)?;
    no_output(path)?;
    no_output(store_directory)?;
    let record = OriginalRecord {
        binding: initial.binding().clone(),
        store_directory: store_directory.to_path_buf(),
        initial_ledger: to_raw_value(initial).map_err(|_| StoreError::InvalidState)?,
    };
    ledger_from_raw(&record.initial_ledger, &record.binding)?;
    let pending = sibling(path, ".pending")?;
    let mut file = create_file(&pending)?;
    file.write_all(&json_bytes(&record)?)
        .map_err(|_| StoreError::Io)?;
    let mut permissions = file.metadata().map_err(|_| StoreError::Io)?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .map_err(|_| StoreError::Io)?;
    file.sync_all().map_err(|_| StoreError::Io)?;
    fs::hard_link(&pending, path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            StoreError::ExistingOutput
        } else {
            StoreError::Io
        }
    })?;
    sync_directory(&parent)?;
    fs::remove_file(&pending).map_err(|_| StoreError::Io)?;
    sync_directory(&parent)
}

fn original(path: &Path) -> Result<(OriginalRecord, File), StoreError> {
    validate_absolute(path)?;
    directory(path.parent().ok_or(StoreError::UnsafePath)?)?;
    let file = regular(path, false)?;
    if file.metadata().map_err(|_| StoreError::Io)?.mode() & 0o222 != 0 {
        return Err(StoreError::UnsafePath);
    }
    let record: OriginalRecord = parse_object(&read_file(path)?)?;
    validate_absolute(&record.store_directory)?;
    if path.starts_with(&record.store_directory) {
        return Err(StoreError::UnsafePath);
    }
    ledger_from_raw(&record.initial_ledger, &record.binding)?;
    Ok((record, file))
}

fn snapshot_name(generation: u64) -> String {
    // 20 is the number of decimal digits needed to represent every u64 value.
    format!("ledger-{generation:020}.json")
}
fn snapshot_generation(name: &str) -> Option<u64> {
    let generation = name
        .strip_prefix("ledger-")?
        .strip_suffix(".json")?
        .parse()
        .ok()?;
    (snapshot_name(generation) == name).then_some(generation)
}

/// Owns a permanent lock inode until dropped. All writers/loaders use the same
/// exclusive OS lock; unsupported locking/filesystem operations fail closed.
pub struct LedgerStore {
    original_path: PathBuf,
    original: OriginalRecord,
    directory: File,
    _lock: File,
    ledger: ExperimentLedger,
    generation: u64,
    pending: bool,
    poisoned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitPoint {
    DraftCreated,
    DraftWritten,
    DraftSynced,
    SnapshotLinked,
    DirectorySynced,
    DraftRemoved,
}

impl LedgerStore {
    /// A create-new initialization receipt lives beside the trusted original.
    /// Once claimed, missing/deleted/partially initialized stores are never reset
    /// by this API. Such failures need operator investigation.
    pub fn initialize(original_path: &Path) -> Result<Self, StoreError> {
        let (record, _) = original(original_path)?;
        no_output(&record.store_directory)?;
        let receipt = sibling(original_path, ".initialized")?;
        fs::hard_link(original_path, &receipt).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::ExistingOutput
            } else {
                StoreError::Io
            }
        })?;
        sync_directory(&directory(
            original_path.parent().ok_or(StoreError::UnsafePath)?,
        )?)?;
        DirBuilder::new()
            .mode(0o700)
            .create(&record.store_directory)
            .map_err(|_| StoreError::Io)?;
        sync_directory(&directory(
            record
                .store_directory
                .parent()
                .ok_or(StoreError::UnsafePath)?,
        )?)?;
        let dir = directory(&record.store_directory)?;
        let lock = create_file(&record.store_directory.join(LOCK))?;
        lock.sync_all().map_err(|_| StoreError::Io)?;
        sync_directory(&dir)?;
        acquire_lock(&lock)?;
        let ledger = ledger_from_raw(&record.initial_ledger, &record.binding)?;
        let mut store = Self {
            original_path: original_path.to_path_buf(),
            original: record,
            directory: dir,
            _lock: lock,
            ledger,
            generation: 0,
            pending: false,
            poisoned: false,
        };
        store.write_snapshot(0, &store.ledger.clone(), &mut |_| Ok(()))?;
        Ok(store)
    }

    pub fn open(original_path: &Path) -> Result<Self, StoreError> {
        let (record, original_file) = original(original_path)?;
        let receipt = regular(&sibling(original_path, ".initialized")?, false)?;
        let a = original_file.metadata().map_err(|_| StoreError::Io)?;
        let b = receipt.metadata().map_err(|_| StoreError::Io)?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err(StoreError::InvalidState);
        }
        let dir = directory(&record.store_directory)?;
        if dir.metadata().map_err(|_| StoreError::Io)?.mode() & 0o022 != 0 {
            return Err(StoreError::UnsafePath);
        }
        let lock = regular(&record.store_directory.join(LOCK), true)?;
        acquire_lock(&lock)?;
        let (generation, ledger, pending) = load_history(&record)?;
        Ok(Self {
            original_path: original_path.to_path_buf(),
            original: record,
            directory: dir,
            _lock: lock,
            ledger,
            generation,
            pending,
            poisoned: false,
        })
    }

    pub fn ledger(&self) -> Result<&ExperimentLedger, StoreError> {
        if self.poisoned {
            return Err(StoreError::ReloadRequired);
        }
        Ok(&self.ledger)
    }
    pub fn has_uncommitted_draft(&self) -> bool {
        self.pending
    }

    fn verify_current(&self) -> Result<(), StoreError> {
        let (record, _) = original(&self.original_path)?;
        if json_bytes(&record)? != json_bytes(&self.original)? {
            return Err(StoreError::InvalidState);
        }
        let held = self.directory.metadata().map_err(|_| StoreError::Io)?;
        let current = directory(&self.original.store_directory)?
            .metadata()
            .map_err(|_| StoreError::Io)?;
        if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
            return Err(StoreError::InvalidState);
        }
        let (generation, ledger, pending) = load_history(&record)?;
        if generation != self.generation || json_bytes(&ledger)? != json_bytes(&self.ledger)? {
            return Err(StoreError::InvalidState);
        }
        if pending {
            return Err(StoreError::PendingRecovery);
        }
        Ok(())
    }

    pub fn commit(&mut self, next: &ExperimentLedger) -> Result<(), StoreError> {
        self.commit_with_hook(next, &mut |_| Ok(()))
    }

    fn commit_with_hook(
        &mut self,
        next: &ExperimentLedger,
        hook: &mut impl FnMut(CommitPoint) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::ReloadRequired);
        }
        if let Err(error) = self.verify_current() {
            if error != StoreError::PendingRecovery {
                self.poisoned = true;
            }
            return Err(error);
        }
        next.validate_successor(&self.ledger)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(StoreError::InvalidState)?;
        if let Err(error) = self.write_snapshot(generation, next, hook) {
            self.poisoned = true;
            return Err(error);
        }
        self.generation = generation;
        self.ledger = next.clone();
        self.pending = false;
        Ok(())
    }

    fn write_snapshot(
        &mut self,
        generation: u64,
        ledger: &ExperimentLedger,
        hook: &mut impl FnMut(CommitPoint) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let snapshot = Snapshot {
            generation,
            ledger: to_raw_value(ledger).map_err(|_| StoreError::InvalidState)?,
        };
        let pending = self.original.store_directory.join(PENDING);
        let mut file = create_file(&pending)?;
        hook(CommitPoint::DraftCreated)?;
        file.write_all(&json_bytes(&snapshot)?)
            .map_err(|_| StoreError::Io)?;
        hook(CommitPoint::DraftWritten)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        hook(CommitPoint::DraftSynced)?;
        fs::hard_link(
            &pending,
            self.original
                .store_directory
                .join(snapshot_name(generation)),
        )
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::ExistingOutput
            } else {
                StoreError::Io
            }
        })?;
        hook(CommitPoint::SnapshotLinked)?;
        sync_directory(&self.directory)?;
        hook(CommitPoint::DirectorySynced)?;
        fs::remove_file(&pending).map_err(|_| StoreError::Io)?;
        hook(CommitPoint::DraftRemoved)?;
        sync_directory(&self.directory)
    }

    /// Explicitly discard only the reserved uncommitted draft, under the writer
    /// lock, after validating every committed generation. Never promote a draft
    /// and never remove/repair a malformed committed snapshot.
    pub fn discard_uncommitted_draft(&mut self) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::ReloadRequired);
        }
        let (generation, ledger, pending) = load_history(&self.original)?;
        if generation != self.generation || json_bytes(&ledger)? != json_bytes(&self.ledger)? {
            return Err(StoreError::InvalidState);
        }
        if !pending {
            return Ok(());
        }
        regular(&self.original.store_directory.join(PENDING), false)?;
        fs::remove_file(self.original.store_directory.join(PENDING)).map_err(|_| StoreError::Io)?;
        if let Err(error) = sync_directory(&self.directory) {
            self.poisoned = true;
            return Err(error);
        }
        self.pending = false;
        Ok(())
    }
}

fn acquire_lock(lock: &File) -> Result<(), StoreError> {
    match lock.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(StoreError::Locked),
        Err(TryLockError::Error(_)) => Err(StoreError::Io),
    }
}

fn load_history(original: &OriginalRecord) -> Result<(u64, ExperimentLedger, bool), StoreError> {
    let mut snapshots = BTreeMap::new();
    let mut pending = false;
    for entry in fs::read_dir(&original.store_directory).map_err(|_| StoreError::Io)? {
        let entry = entry.map_err(|_| StoreError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| StoreError::InvalidState)?;
        // Open with O_NOFOLLOW before accepting any reserved regular file name.
        regular(&entry.path(), false)?;
        if name == LOCK {
            continue;
        }
        if name == PENDING {
            pending = true;
            continue;
        }
        let generation = snapshot_generation(&name).ok_or(StoreError::InvalidState)?;
        snapshots.insert(generation, entry.path());
    }
    let mut previous: Option<(u64, ExperimentLedger)> = None;
    for (generation, path) in snapshots {
        let snapshot: Snapshot = parse_object(&read_file(&path)?)?;
        if snapshot.generation != generation {
            return Err(StoreError::InvalidState);
        }
        let ledger = ledger_from_raw(&snapshot.ledger, &original.binding)?;
        if let Some((prior_generation, prior)) = &previous {
            if prior_generation.checked_add(1) != Some(generation) {
                return Err(StoreError::InvalidState);
            }
            ledger.validate_successor(prior)?;
        } else if generation != 0
            || json_bytes(&ledger)?
                != json_bytes(&ledger_from_raw(
                    &original.initial_ledger,
                    &original.binding,
                )?)?
        {
            return Err(StoreError::InvalidState);
        }
        previous = Some((generation, ledger));
    }
    let (generation, ledger) = previous.ok_or(StoreError::InvalidState)?;
    Ok((generation, ledger, pending))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MAX_LIFETIME_SECONDS,
        controller::{TrackedCvm, UsageRecord},
    };
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            // Keep generated test state on the workspace volume, not /tmp/home.
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.codex-tmp/lifecycle-persistence-tests");
            fs::create_dir_all(&base).unwrap();
            let base = fs::canonicalize(base).unwrap();
            let path = base.join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn original(&self) -> PathBuf {
            self.0.join("original.json")
        }
        fn store(&self) -> PathBuf {
            self.0.join("state")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn ledger() -> ExperimentLedger {
        let binding = ExperimentBinding::new(
            "experiment".into(),
            "workspace".into(),
            1000,
            1000 + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 1).unwrap();
        ledger.begin_attempt("first".into(), 1000).unwrap();
        ledger
            .track_cvm(
                "workspace",
                "first",
                TrackedCvm {
                    cvm_id: "one".into(),
                    app_id: "app".into(),
                    instance_id: "instance".into(),
                    created_at_unix_seconds: 1000,
                    compute_and_disk_microusd_per_hour: 243_120,
                },
            )
            .unwrap();
        ledger
    }
    fn add_usage(ledger: &mut ExperimentLedger) {
        ledger
            .record_usage(UsageRecord {
                billing_key: "bill".into(),
                app_id: "app".into(),
                instance_id: "instance".into(),
                usage_type: "storage".into(),
                cost_usd_decimal: "1.25".into(),
            })
            .unwrap();
    }
    fn setup(temp: &Temp) -> LedgerStore {
        create_original_binding(&temp.original(), &temp.store(), &ledger()).unwrap();
        LedgerStore::initialize(&temp.original()).unwrap()
    }

    #[test]
    fn resource_and_usage_roundtrip_and_reset_rejection() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        let mut next = store.ledger().unwrap().clone();
        add_usage(&mut next);
        store.commit(&next).unwrap();
        assert!(store.commit(&ledger()).is_err());
        drop(store);
        let restored = LedgerStore::open(&temp.original()).unwrap();
        assert_eq!(
            json_bytes(restored.ledger().unwrap()).unwrap(),
            json_bytes(&next).unwrap()
        );
        assert!(!restored.has_uncommitted_draft());
        assert!(LedgerStore::initialize(&temp.original()).is_err());
    }

    #[test]
    fn concurrent_writer_is_rejected_and_lock_releases_on_drop() {
        let temp = Temp::new();
        let store = setup(&temp);
        assert!(matches!(
            LedgerStore::open(&temp.original()),
            Err(StoreError::Locked)
        ));
        drop(store);
        assert!(LedgerStore::open(&temp.original()).is_ok());
    }

    #[test]
    fn existing_files_symlinks_and_initialization_receipt_prevent_overwrite() {
        let temp = Temp::new();
        let store = setup(&temp);
        assert_eq!(
            create_original_binding(&temp.original(), &temp.store(), &ledger()),
            Err(StoreError::ExistingOutput)
        );
        let alias = temp.0.join("alias.json");
        symlink(temp.original(), &alias).unwrap();
        assert!(LedgerStore::open(&alias).is_err());
        drop(store);
        let snapshot = temp.store().join(snapshot_name(0));
        let bytes = fs::read(&snapshot).unwrap();
        fs::remove_file(&snapshot).unwrap();
        symlink(temp.original(), &snapshot).unwrap();
        assert!(LedgerStore::open(&temp.original()).is_err());
        assert_eq!(
            fs::read(&snapshot).unwrap(),
            fs::read(temp.original()).unwrap()
        );
        fs::remove_file(&snapshot).unwrap();
        fs::write(&snapshot, bytes).unwrap();
        fs::remove_dir_all(temp.store()).unwrap();
        assert!(matches!(
            LedgerStore::initialize(&temp.original()),
            Err(StoreError::ExistingOutput)
        ));
        assert!(!temp.store().exists());
    }

    #[test]
    fn wrong_binding_and_any_truncated_newer_snapshot_fail_closed() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        let other = ExperimentLedger::new(
            ExperimentBinding::new(
                "other".into(),
                "workspace".into(),
                1000,
                1000 + MAX_LIFETIME_SECONDS,
            )
            .unwrap(),
            1,
        )
        .unwrap();
        assert!(store.commit(&other).is_err());
        drop(store);
        fs::write(temp.store().join(snapshot_name(1)), b"{\"generation\":1,").unwrap();
        assert!(LedgerStore::open(&temp.original()).is_err());
    }

    #[test]
    fn malformed_original_and_symlink_publication_fail_without_replacement() {
        let temp = Temp::new();
        let victim = temp.0.join("existing.json");
        fs::write(&victim, b"preserve this file").unwrap();
        symlink(&victim, temp.original()).unwrap();
        assert!(create_original_binding(&temp.original(), &temp.store(), &ledger()).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"preserve this file");
        fs::remove_file(temp.original()).unwrap();
        let mut file = create_file(&temp.original()).unwrap();
        file.write_all(b"{\"binding\":").unwrap();
        let mut permissions = file.metadata().unwrap().permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions).unwrap();
        assert!(LedgerStore::initialize(&temp.original()).is_err());
        assert!(LedgerStore::open(&temp.original()).is_err());
        assert!(!temp.store().exists());
    }

    #[test]
    fn duplicate_nested_ledger_fields_fail_even_when_the_last_value_matches() {
        let clean = String::from_utf8(json_bytes(&ledger()).unwrap()).unwrap();
        for (needle, duplicate) in [
            (
                "\"initial_cost_microusd\":1",
                "\"initial_cost_microusd\":999,\"initial_cost_microusd\":1",
            ),
            (
                "\"workspace_id\":\"workspace\"",
                "\"workspace_id\":\"other\",\"workspace_id\":\"workspace\"",
            ),
            (
                "\"cvm_id\":\"one\"",
                "\"cvm_id\":\"other\",\"cvm_id\":\"one\"",
            ),
        ] {
            assert!(clean.contains(needle));
            let altered = clean.replacen(needle, duplicate, 1);
            let record = OriginalRecord {
                binding: ledger().binding().clone(),
                store_directory: PathBuf::from("/unused-local-fixture"),
                initial_ledger: RawValue::from_string(altered.clone()).unwrap(),
            };
            let decoded: OriginalRecord = parse_object(&json_bytes(&record).unwrap()).unwrap();
            assert!(ledger_from_raw(&decoded.initial_ledger, &decoded.binding).is_err());

            let temp = Temp::new();
            drop(setup(&temp));
            let snapshot = Snapshot {
                generation: 0,
                ledger: RawValue::from_string(altered).unwrap(),
            };
            fs::write(
                temp.store().join(snapshot_name(0)),
                json_bytes(&snapshot).unwrap(),
            )
            .unwrap();
            assert!(LedgerStore::open(&temp.original()).is_err());
        }
    }

    #[test]
    fn positional_arrays_cannot_replace_original_or_snapshot_objects() {
        let fixture = ledger();
        let original = serde_json::json!([fixture.binding(), "/unused-local-fixture", &fixture]);
        let snapshot = serde_json::json!([0, &fixture]);
        assert!(parse_object::<OriginalRecord>(&json_bytes(&original).unwrap()).is_err());
        assert!(parse_object::<Snapshot>(&json_bytes(&snapshot).unwrap()).is_err());
    }

    #[test]
    fn existing_draft_or_snapshot_is_never_overwritten() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        let pending = temp.store().join(PENDING);
        fs::write(&pending, b"interrupted draft").unwrap();
        let mut next = store.ledger().unwrap().clone();
        add_usage(&mut next);
        assert_eq!(store.commit(&next), Err(StoreError::PendingRecovery));
        assert_eq!(fs::read(&pending).unwrap(), b"interrupted draft");
        store.discard_uncommitted_draft().unwrap();
        let target = temp.store().join(snapshot_name(1));
        fs::write(&target, b"foreign existing output").unwrap();
        assert!(store.commit(&next).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"foreign existing output");
    }

    #[test]
    fn failed_write_reports_uncertainty_and_requires_reload() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        let mut next = store.ledger().unwrap().clone();
        add_usage(&mut next);
        assert_eq!(
            store.commit_with_hook(&next, &mut |point| {
                if point == CommitPoint::SnapshotLinked {
                    Err(StoreError::Io)
                } else {
                    Ok(())
                }
            }),
            Err(StoreError::Io)
        );
        assert!(matches!(store.ledger(), Err(StoreError::ReloadRequired)));
        assert_eq!(store.commit(&next), Err(StoreError::ReloadRequired));
        drop(store);
        let mut restored = LedgerStore::open(&temp.original()).unwrap();
        assert_eq!(
            json_bytes(restored.ledger().unwrap()).unwrap(),
            json_bytes(&next).unwrap()
        );
        assert!(restored.has_uncommitted_draft());
        restored.discard_uncommitted_draft().unwrap();
    }

    #[test]
    fn crash_child() {
        let Ok(path) = std::env::var("ZRPC_PERSISTENCE_CRASH_ORIGINAL") else {
            return;
        };
        let stage = std::env::var("ZRPC_PERSISTENCE_CRASH_STAGE").unwrap();
        let mut store = LedgerStore::open(Path::new(&path)).unwrap();
        let mut next = store.ledger().unwrap().clone();
        add_usage(&mut next);
        store
            .commit_with_hook(&next, &mut |point| {
                if format!("{point:?}") == stage {
                    // Exit without Rust destructors: the OS releases the writer lock.
                    std::process::exit(0);
                }
                Ok(())
            })
            .unwrap();
        panic!("requested crash boundary was not reached");
    }

    #[test]
    fn abrupt_process_exit_at_each_write_boundary_preserves_old_or_new_state() {
        for point in [
            CommitPoint::DraftCreated,
            CommitPoint::DraftWritten,
            CommitPoint::DraftSynced,
            CommitPoint::SnapshotLinked,
            CommitPoint::DirectorySynced,
            CommitPoint::DraftRemoved,
        ] {
            let temp = Temp::new();
            drop(setup(&temp));
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "persistence::tests::crash_child"])
                .env("ZRPC_PERSISTENCE_CRASH_ORIGINAL", temp.original())
                .env("ZRPC_PERSISTENCE_CRASH_STAGE", format!("{point:?}"))
                .status()
                .unwrap();
            assert!(status.success());
            let mut store = LedgerStore::open(&temp.original()).unwrap();
            let mut expected = ledger();
            if matches!(
                point,
                CommitPoint::SnapshotLinked
                    | CommitPoint::DirectorySynced
                    | CommitPoint::DraftRemoved
            ) {
                add_usage(&mut expected);
            }
            assert_eq!(
                json_bytes(store.ledger().unwrap()).unwrap(),
                json_bytes(&expected).unwrap()
            );
            store.discard_uncommitted_draft().unwrap();
            assert!(!store.has_uncommitted_draft());
        }
    }
}
