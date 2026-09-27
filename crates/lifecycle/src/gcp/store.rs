//! Append-only, fsync-backed journal with an exclusive cooperating-writer lock.
//! Hostile rollback by the operator UID is outside the external-host trust model.
use super::{
    Error, Result, digest,
    package::{Artifact, Package},
    read_regular, valid_digest, valid_uuid,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub request_id: String,
    pub committed_at: u64,
    pub operation: Option<String>,
    pub done: bool,
    pub failed: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceState {
    pub create: Option<Intent>,
    pub delete: Option<Intent>,
    /// Compute incarnation id, or the exact storage-object generation.
    pub identity: Option<String>,
    /// Only a successful upload whose emitted media matched the package digest
    /// may set this. Object metadata observed after a lost response cannot.
    #[serde(default)]
    pub upload_media_stream_verified: bool,
    pub last_observed_at: Option<u64>,
    pub observed_absent: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub generation: u64,
    pub previous_sha256: Option<String>,
    pub package_sha256: String,
    pub original_start: u64,
    pub original_deadline: u64,
    pub resources: Vec<ResourceState>,
    /// Immutable audit reference only. A digest cannot establish that delayed
    /// charges, corrections, or invoices have finished arriving.
    pub billing_evidence_sha256: Option<String>,
    pub teardown_started: bool,
}

pub struct Store {
    directory: PathBuf,
    _lock: File,
    journal: Journal,
    current_sha256: String,
    poisoned: bool,
}
fn secure_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error("journal directory must be absolute"));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| Error("journal directory unavailable"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(Error(
            "journal directory requires current-UID ownership and mode 0700",
        ));
    }
    Ok(())
}
fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error("journal file exists or cannot be created"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error("uncertain journal write; preserve pending file"))
}
fn sync(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("uncertain journal directory sync"))
}
fn encode(j: &Journal) -> Result<Vec<u8>> {
    serde_json::to_vec(j).map_err(|_| Error("journal encode failed"))
}

impl Store {
    pub fn initialize(directory: &Path, package: &Package) -> Result<()> {
        DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|_| Error("journal exists; initialization never resets an experiment"))?;
        secure_directory(directory)?;
        let package_bytes = package.bytes()?;
        let journal = Journal {
            generation: 0,
            previous_sha256: None,
            package_sha256: digest(&package_bytes),
            original_start: package.spec.start_unix_seconds,
            original_deadline: package.spec.deadline_unix_seconds,
            resources: vec![ResourceState::default(); package.resources.len()],
            billing_evidence_sha256: None,
            teardown_started: false,
        };
        create(&directory.join("package.json"), &package_bytes)?;
        create(
            &directory.join("00000000000000000000.json"),
            &encode(&journal)?,
        )?;
        sync(directory)?;
        sync(directory.parent().ok_or(Error("journal parent missing"))?)
    }
    pub fn open(directory: &Path) -> Result<Self> {
        secure_directory(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("writer.lock"))
            .map_err(|_| Error("journal lock open failed"))?;
        if !lock
            .metadata()
            .map_err(|_| Error("journal lock metadata failed"))?
            .is_file()
        {
            return Err(Error("invalid journal lock"));
        }
        lock.try_lock()
            .map_err(|_| Error("another lifecycle invocation owns the journal"))?;
        if directory.join("pending.json").exists() {
            return Err(Error(
                "journal has pending commit; explicit recover required",
            ));
        }
        Self::load(directory, lock)
    }
    fn load(directory: &Path, lock: File) -> Result<Self> {
        let package_bytes = read_regular(&directory.join("package.json"))?;
        let package: Package = serde_json::from_slice(&package_bytes)
            .map_err(|_| Error("invalid original package"))?;
        let package_hash = digest(&package_bytes);
        let mut files = fs::read_dir(directory)
            .map_err(|_| Error("journal enumeration failed"))?
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .filter_map(|n| n.to_str().map(str::to_owned))
            .filter(|n| {
                n.len() == 25 && n.ends_with(".json") && n[..20].bytes().all(|b| b.is_ascii_digit())
            })
            .collect::<Vec<_>>();
        files.sort();
        let mut last: Option<Journal> = None;
        let mut hash = None;
        for (i, file) in files.iter().enumerate() {
            if *file != format!("{i:020}.json") {
                return Err(Error("journal history is not contiguous"));
            }
            let bytes = read_regular(&directory.join(file))?;
            let j: Journal =
                serde_json::from_slice(&bytes).map_err(|_| Error("corrupt journal snapshot"))?;
            if j.generation != i as u64
                || j.previous_sha256 != hash
                || j.package_sha256 != package_hash
                || j.original_start != package.spec.start_unix_seconds
                || j.original_deadline != package.spec.deadline_unix_seconds
                || j.resources.len() != package.resources.len()
            {
                return Err(Error("journal original binding or history changed"));
            }
            if let Some(previous) = &last {
                validate_transition(previous, &j)?;
            }
            hash = Some(digest(&bytes));
            last = Some(j);
        }
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
            journal: last.ok_or(Error("journal missing original snapshot"))?,
            current_sha256: hash.ok_or(Error("journal missing digest"))?,
            poisoned: false,
        })
    }
    pub fn package(&self) -> Result<Package> {
        let bytes = read_regular(&self.directory.join("package.json"))?;
        if digest(&bytes) != self.journal.package_sha256 {
            return Err(Error("original package changed"));
        }
        serde_json::from_slice(&bytes).map_err(|_| Error("invalid original package"))
    }
    pub fn journal(&self) -> &Journal {
        &self.journal
    }
    /// Preserve a reviewed billing artifact's identity after cleanup. This
    /// records evidence only; it cannot establish invoice finality.
    pub fn record_billing_evidence(&mut self, evidence: &Artifact) -> Result<()> {
        evidence.verify()?;
        if let Some(existing) = &self.journal.billing_evidence_sha256 {
            return if existing == &evidence.sha256 {
                Ok(())
            } else {
                Err(Error(
                    "billing evidence reference cannot be changed or removed",
                ))
            };
        }
        let mut next = self.journal.clone();
        next.billing_evidence_sha256 = Some(evidence.sha256.clone());
        self.commit(next)
    }
    pub fn commit(&mut self, mut next: Journal) -> Result<()> {
        if self.poisoned {
            return Err(Error("reload journal after uncertain persistence"));
        }
        next.generation = self
            .journal
            .generation
            .checked_add(1)
            .ok_or(Error("journal generation overflow"))?;
        next.previous_sha256 = Some(self.current_sha256.clone());
        validate_transition(&self.journal, &next)?;
        let bytes = encode(&next)?;
        self.poisoned = true;
        create(&self.directory.join("pending.json"), &bytes)?;
        // Atomic no-clobber publication. A crash leaves the original snapshots
        // plus pending.json for recovery; no provider action can precede this.
        fs::hard_link(
            self.directory.join("pending.json"),
            self.directory.join(format!("{:020}.json", next.generation)),
        )
        .map_err(|_| Error("uncertain journal publication"))?;
        sync(&self.directory)?;
        fs::remove_file(self.directory.join("pending.json"))
            .map_err(|_| Error("journal pending cleanup failed"))?;
        sync(&self.directory)?;
        self.current_sha256 = digest(&bytes);
        self.journal = next;
        self.poisoned = false;
        Ok(())
    }
    pub fn recover(directory: &Path) -> Result<()> {
        secure_directory(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join("writer.lock"))
            .map_err(|_| Error("recovery lock unavailable"))?;
        lock.try_lock()
            .map_err(|_| Error("another lifecycle invocation owns journal"))?;
        let store = Self::load(directory, lock)?;
        let bytes = read_regular(&directory.join("pending.json"))?;
        let next: Journal = serde_json::from_slice(&bytes).map_err(|_| {
            Error("partial pending commit requires manual inspection; original retained")
        })?;
        if next.generation == store.journal.generation && digest(&bytes) == store.current_sha256 {
            // Publication finished before the process died.
        } else {
            if next.generation != store.journal.generation + 1
                || next.previous_sha256 != Some(store.current_sha256.clone())
            {
                return Err(Error("pending snapshot is not next in history"));
            }
            validate_transition(&store.journal, &next)?;
            fs::hard_link(
                directory.join("pending.json"),
                directory.join(format!("{:020}.json", next.generation)),
            )
            .map_err(|_| Error("recovery publication failed"))?;
            sync(directory)?;
        }
        fs::remove_file(directory.join("pending.json"))
            .map_err(|_| Error("recovery pending cleanup failed"))?;
        sync(directory)
    }
}
fn validate_transition(previous: &Journal, next: &Journal) -> Result<()> {
    if previous.package_sha256 != next.package_sha256
        || previous.original_start != next.original_start
        || previous.original_deadline != next.original_deadline
        || previous.resources.len() != next.resources.len()
        || previous.teardown_started && !next.teardown_started
    {
        return Err(Error("journal original experiment cannot be reset"));
    }
    if previous.billing_evidence_sha256.is_some()
        && previous.billing_evidence_sha256 != next.billing_evidence_sha256
    {
        return Err(Error(
            "billing evidence reference cannot be changed or removed",
        ));
    }
    if let Some(hash) = &next.billing_evidence_sha256 {
        if !valid_digest(hash)
            || !next.teardown_started
            || next.resources.iter().any(|r| {
                r.create
                    .as_ref()
                    .is_some_and(|i| !i.done || !r.observed_absent)
                    || r.delete.as_ref().is_some_and(|i| !i.done)
            })
        {
            return Err(Error(
                "billing evidence requires a digest and observed completed teardown",
            ));
        }
    }
    for (a, b) in previous.resources.iter().zip(&next.resources) {
        if a.identity.is_some() && a.identity != b.identity {
            return Err(Error("resource incarnation cannot be replaced"));
        }
        if a.upload_media_stream_verified && !b.upload_media_stream_verified
            || b.upload_media_stream_verified
                && (b.identity.is_none() || !b.create.as_ref().is_some_and(|i| i.done))
        {
            return Err(Error(
                "verified upload media status is invalid or was reset",
            ));
        }
        for (old, new) in [(&a.create, &b.create), (&a.delete, &b.delete)] {
            if let Some(new) = new {
                if !valid_uuid(&new.request_id) {
                    return Err(Error("invalid Google requestId"));
                }
            }
            if let Some(old) = old {
                let new = new
                    .as_ref()
                    .ok_or(Error("committed intent cannot be removed"))?;
                if old.request_id != new.request_id
                    || old.committed_at != new.committed_at
                    || old.operation.is_some() && old.operation != new.operation
                    || old.done && !new.done
                    || old.failed && !new.failed
                {
                    return Err(Error("committed operation cannot be reset"));
                }
            }
        }
        if b.delete.is_some() && b.create.is_none() {
            return Err(Error(
                "cannot delete resource without committed creation intent",
            ));
        }
    }
    Ok(())
}
