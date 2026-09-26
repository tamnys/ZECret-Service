//! Unix local storage, not authenticated storage or live watchdog activation.
//! The operator must protect the original file, its initialization receipt, the
//! store and their ancestors from replacement/deletion by other writers. OS
//! locks coordinate cooperating writers; hostile same-UID/filesystem rollback
//! is outside this contract. No API replaces committed snapshots or resets a store.

use crate::{
    LifecycleError,
    controller::{DeletionIntentRecord, DeletionOutcome, ExperimentBinding, ExperimentLedger},
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
    if !initial.deletion_intents().is_empty() {
        return Err(StoreError::InvalidState);
    }
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
    if !ledger_from_raw(&record.initial_ledger, &record.binding)?
        .deletion_intents()
        .is_empty()
    {
        return Err(StoreError::InvalidState);
    }
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
    if !ledger_from_raw(&record.initial_ledger, &record.binding)?
        .deletion_intents()
        .is_empty()
    {
        return Err(StoreError::InvalidState);
    }
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

/// A concrete immutable snapshot reference observed under the local writer lock.
/// It is not a signature, live activation receipt, or provider deletion evidence.
#[derive(Debug, Clone, Serialize)]
pub struct CommittedLedgerReference {
    original_binding_path: PathBuf,
    snapshot_path: PathBuf,
    generation: u64,
}

/// Proof of a locally committed intent while its writer lock is retained.
/// This is not operator approval, authenticated provider identity or a network
/// capability. No live adapter accepts it yet. Dropping it preserves pending
/// history; retries require future reconciliation support.
///
/// ```compile_fail
/// fn cannot_clone(intent: zrpc_lifecycle::persistence::CommittedDeletionIntent<'_>) {
///     let replay = intent.clone();
/// }
/// ```
/// ```compile_fail
/// fn cannot_restore(bytes: &[u8]) {
///     let intent: zrpc_lifecycle::persistence::CommittedDeletionIntent<'_> =
///         serde_json::from_slice(bytes).unwrap();
/// }
/// ```
pub struct CommittedDeletionIntent<'a> {
    store: &'a mut LedgerStore,
    index: usize,
}
impl CommittedDeletionIntent<'_> {
    pub fn workspace_id(&self) -> &str {
        self.store.ledger.workspace_id()
    }
    pub fn record(&self) -> &DeletionIntentRecord {
        &self.store.ledger.deletion_intents()[self.index]
    }
    pub fn finish(self, outcome: DeletionOutcome, now: u64) -> Result<(), StoreError> {
        self.finish_with_hook(outcome, now, &mut |_| Ok(()))
    }
    fn finish_with_hook(
        self,
        outcome: DeletionOutcome,
        now: u64,
        hook: &mut impl FnMut(CommitPoint) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let mut next = self.store.ledger()?.clone();
        next.finish_deletion_intent(self.index, outcome, now)?;
        self.store.commit_with_hook(&next, hook)
    }
}

impl CommittedLedgerReference {
    pub fn generation(&self) -> u64 {
        self.generation
    }
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
    /// Record an explicit first cleanup intent for an already committed target.
    /// No provider request is made; generation/workspace arguments are local
    /// consistency checks, not provider authentication or spending permission.
    pub fn prepare_deletion(
        &mut self,
        expected_generation: u64,
        workspace: &str,
        cvm_id: &str,
        now: u64,
    ) -> Result<CommittedDeletionIntent<'_>, StoreError> {
        self.prepare_deletion_with_hook(
            expected_generation,
            workspace,
            cvm_id,
            now,
            &mut |_| Ok(()),
        )
    }

    fn prepare_deletion_with_hook(
        &mut self,
        expected_generation: u64,
        workspace: &str,
        cvm_id: &str,
        now: u64,
        hook: &mut impl FnMut(CommitPoint) -> Result<(), StoreError>,
    ) -> Result<CommittedDeletionIntent<'_>, StoreError> {
        self.ledger()?;
        self.verify_current()?;
        if self.generation != expected_generation {
            return Err(StoreError::InvalidState);
        }
        let mut next = self.ledger.clone();
        let index = next.append_deletion_intent(expected_generation, workspace, cvm_id, now)?;
        // All snapshot/file/directory synchronization finishes before the
        // borrowed token can be constructed or observed by a future adapter.
        self.commit_with_hook(&next, hook)?;
        Ok(CommittedDeletionIntent { store: self, index })
    }
    pub fn planning_reference(&self) -> Result<CommittedLedgerReference, StoreError> {
        self.ledger()?;
        self.verify_current()?;
        Ok(CommittedLedgerReference {
            original_binding_path: self.original_path.clone(),
            snapshot_path: self
                .original
                .store_directory
                .join(snapshot_name(self.generation)),
            generation: self.generation,
        })
    }

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
        // Ordinary callers may supply restored JSON. They cannot synthesize an
        // intent or fill/erase a pending outcome through generic persistence.
        if next.deletion_intents() != self.ledger()?.deletion_intents() {
            return Err(StoreError::InvalidState);
        }
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
        validate_journal_transition(&self.ledger, next, self.generation)?;
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

fn validate_journal_transition(
    previous: &ExperimentLedger,
    next: &ExperimentLedger,
    prior_generation: u64,
) -> Result<(), StoreError> {
    let before = previous.deletion_intents();
    let after = next.deletion_intents();
    // One purpose-specific write appends one intent or records one outcome.
    // This is the operation's atomicity contract, not a resource/request quota.
    if after.len() == before.len() {
        if before.iter().zip(after).filter(|(a, b)| a != b).count() > 1 {
            return Err(StoreError::InvalidState);
        }
    } else if after.len().checked_sub(before.len()) == Some(1) {
        if &after[..before.len()] != before {
            return Err(StoreError::InvalidState);
        }
        let intent = after.last().ok_or(StoreError::InvalidState)?;
        if intent.reviewed_generation != prior_generation || intent.outcome.is_some() {
            return Err(StoreError::InvalidState);
        }
        // The new target must predate the intent snapshot.
        let mut proof = previous.clone();
        proof.append_deletion_intent(
            prior_generation,
            previous.workspace_id(),
            &intent.target.cvm_id,
            intent.recorded_at_unix_seconds,
        )?;
        if proof.deletion_intents().last() != Some(intent) {
            return Err(StoreError::InvalidState);
        }
    } else {
        return Err(StoreError::InvalidState);
    }
    Ok(())
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
            validate_journal_transition(prior, &ledger, *prior_generation)?;
        } else if generation != 0
            || !ledger.deletion_intents().is_empty()
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
    fn deletion_intent_rejects_scope_generation_and_time_without_writing() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        for (generation, workspace, id, now) in [
            (1, "workspace", "one", 1000),
            (0, "other", "one", 1000),
            (0, "workspace", "untracked", 1000),
            (0, "workspace", "one", 999),
        ] {
            assert!(
                store
                    .prepare_deletion(generation, workspace, id, now)
                    .is_err()
            );
            assert_eq!(store.generation, 0);
            assert!(store.ledger().unwrap().deletion_intents().is_empty());
            assert!(!temp.store().join(snapshot_name(1)).exists());
        }
    }

    #[test]
    fn intent_is_durable_before_token_and_drop_retains_pending_without_retry() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        let intent = store.prepare_deletion(0, "workspace", "one", 1000).unwrap();
        assert_eq!(intent.workspace_id(), "workspace");
        assert_eq!(intent.record().committed_generation, 1);
        assert!(intent.record().outcome.is_none());
        let snapshot: Snapshot =
            parse_object(&fs::read(temp.store().join(snapshot_name(1))).unwrap()).unwrap();
        let durable = ledger_from_raw(&snapshot.ledger, intent.store.ledger.binding()).unwrap();
        assert_eq!(durable.deletion_intents(), &[intent.record().clone()]);
        assert!(matches!(
            LedgerStore::open(&temp.original()),
            Err(StoreError::Locked)
        ));
        drop(intent);
        drop(store);
        let mut store = LedgerStore::open(&temp.original()).unwrap();
        assert!(
            store.ledger().unwrap().deletion_intents()[0]
                .outcome
                .is_none()
        );
        assert!(store.prepare_deletion(1, "workspace", "one", 1001).is_err());
        // Pending work for one CVM does not hide another committed resource.
        let mut next = store.ledger().unwrap().clone();
        next.track_cvm(
            "workspace",
            "first",
            TrackedCvm {
                cvm_id: "two".into(),
                app_id: "app2".into(),
                instance_id: "instance2".into(),
                created_at_unix_seconds: 1000,
                compute_and_disk_microusd_per_hour: 243_120,
            },
        )
        .unwrap();
        store.commit(&next).unwrap();
        drop(store.prepare_deletion(2, "workspace", "two", 1001).unwrap());
        assert_eq!(store.ledger().unwrap().deletion_intents().len(), 2);
    }

    #[test]
    fn deletion_outcomes_never_prove_absence_or_renew_overdue_policy() {
        for outcome in [
            DeletionOutcome::Initiated204,
            DeletionOutcome::NotFound404,
            DeletionOutcome::TransportUncertain,
            DeletionOutcome::Rejected { status: 403 },
        ] {
            let temp = Temp::new();
            let mut store = setup(&temp);
            let original = store.ledger().unwrap().binding().clone();
            // Beyond the original deadline and above the overall expense cap:
            // cleanup intent must still be possible, without another attempt.
            let now = 1000 + MAX_LIFETIME_SECONDS * 2;
            store
                .prepare_deletion(0, "workspace", "one", now)
                .unwrap()
                .finish(outcome, now)
                .unwrap();
            assert_eq!(store.generation, 2);
            assert_eq!(store.ledger().unwrap().binding(), &original);
            assert!(
                store.ledger().unwrap().planning_cost_at(now).unwrap()
                    > crate::TOTAL_CEILING_MICROUSD
            );
            let record = &store.ledger().unwrap().deletion_intents()[0];
            assert_eq!(record.outcome.as_ref().unwrap().outcome, outcome);
            let view = serde_json::to_value(store.ledger().unwrap()).unwrap();
            assert_eq!(view["resources"]["one"]["deletion"], "tracking");
            assert!(store.prepare_deletion(2, "workspace", "one", now).is_err());
            drop(store);
            let restored = LedgerStore::open(&temp.original()).unwrap();
            assert_eq!(
                restored.ledger().unwrap().deletion_intents()[0]
                    .outcome
                    .as_ref()
                    .unwrap()
                    .outcome,
                outcome
            );
        }
    }

    #[test]
    fn generic_commit_cannot_forge_journal_or_outcomes_and_original_cannot_contain_intent() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        let mut forged = store.ledger().unwrap().clone();
        forged
            .append_deletion_intent(0, "workspace", "one", 1000)
            .unwrap();
        let forged =
            ExperimentLedger::from_json(&json_bytes(&forged).unwrap(), forged.binding()).unwrap();
        assert_eq!(store.commit(&forged), Err(StoreError::InvalidState));
        let elsewhere = Temp::new();
        assert_eq!(
            create_original_binding(&elsewhere.original(), &elsewhere.store(), &forged),
            Err(StoreError::InvalidState)
        );
        drop(store.prepare_deletion(0, "workspace", "one", 1000).unwrap());
        let mut forged = store.ledger().unwrap().clone();
        forged
            .finish_deletion_intent(0, DeletionOutcome::Initiated204, 1000)
            .unwrap();
        assert_eq!(store.commit(&forged), Err(StoreError::InvalidState));
        assert_eq!(store.generation, 1);
    }

    #[test]
    fn intent_and_outcome_write_failures_preserve_published_history() {
        for finishing in [false, true] {
            for boundary in [
                CommitPoint::DraftCreated,
                CommitPoint::DraftWritten,
                CommitPoint::DraftSynced,
                CommitPoint::SnapshotLinked,
                CommitPoint::DirectorySynced,
                CommitPoint::DraftRemoved,
            ] {
                let temp = Temp::new();
                let mut store = setup(&temp);
                let mut fail = |point| {
                    if point == boundary {
                        Err(StoreError::Io)
                    } else {
                        Ok(())
                    }
                };
                let result = if finishing {
                    store
                        .prepare_deletion(0, "workspace", "one", 1000)
                        .unwrap()
                        .finish_with_hook(DeletionOutcome::TransportUncertain, 1001, &mut fail)
                } else {
                    store
                        .prepare_deletion_with_hook(0, "workspace", "one", 1000, &mut fail)
                        .map(drop)
                };
                assert_eq!(result, Err(StoreError::Io));
                assert!(matches!(store.ledger(), Err(StoreError::ReloadRequired)));
                drop(store);
                let restored = LedgerStore::open(&temp.original()).unwrap();
                let published = matches!(
                    boundary,
                    CommitPoint::SnapshotLinked
                        | CommitPoint::DirectorySynced
                        | CommitPoint::DraftRemoved
                );
                let journal = restored.ledger().unwrap().deletion_intents();
                if finishing {
                    assert_eq!(journal.len(), 1);
                    assert_eq!(journal[0].outcome.is_some(), published);
                } else {
                    assert_eq!(journal.len(), usize::from(published));
                    assert!(journal.iter().all(|intent| intent.outcome.is_none()));
                }
            }
        }
    }

    #[test]
    fn replay_rejects_changed_intent_generation_target_or_prior_outcome() {
        let temp = Temp::new();
        let mut store = setup(&temp);
        store
            .prepare_deletion(0, "workspace", "one", 1000)
            .unwrap()
            .finish(DeletionOutcome::Initiated204, 1001)
            .unwrap();
        store.commit(&store.ledger().unwrap().clone()).unwrap();
        drop(store);
        let path = temp.store().join(snapshot_name(3));
        let original_bytes = fs::read(&path).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
        for field in [
            "removed",
            "generation",
            "target",
            "retroactive_outcome",
            "changed_outcome",
            "erased_outcome",
        ] {
            let mut changed = original.clone();
            let journal = &mut changed["ledger"]["deletion_intents"];
            match field {
                "removed" => *journal = serde_json::json!([]),
                "generation" => {
                    journal[0]["reviewed_generation"] = 1.into();
                    journal[0]["committed_generation"] = 2.into();
                }
                "target" => journal[0]["target"]["cvm_id"] = "other".into(),
                "changed_outcome" => journal[0]["outcome"]["outcome"] = "not_found404".into(),
                "erased_outcome" => journal[0]["outcome"] = serde_json::Value::Null,
                _ => journal[0]["outcome"]["recorded_at_unix_seconds"] = 999.into(),
            }
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(LedgerStore::open(&temp.original()).is_err(), "{field}");
        }
        fs::write(&path, original_bytes).unwrap();
        assert!(LedgerStore::open(&temp.original()).is_ok());
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
