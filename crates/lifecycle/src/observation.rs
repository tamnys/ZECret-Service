//! Ledger-bound, read-only provider observations. Results are in memory only;
//! no charge, deletion state, journal, snapshot or scheduler is modified.
//! Complete pagination is not an atomic snapshot, a billing reconciliation or
//! independent evidence that storage was deleted.

use crate::{
    controller::{ExperimentBinding, TrackedCvm},
    persistence::{CommittedLedgerReference, LedgerStore, StoreError},
    provider_http::{CvmDetail, ProviderClient, ProviderHttpError},
    provider_request::ReadRequest,
    provider_scan::{InventoryAccumulator, InventoryScan, UsageAccumulator, UsageScan},
    provider_wire::Cvm,
};
use std::{
    collections::BTreeMap,
    fmt,
    num::NonZeroUsize,
    time::{SystemTime, UNIX_EPOCH},
};

/// Page ranges come from the pinned provider API. Retention bounds must be
/// supplied by the caller, with no production defaults. The usage bound applies
/// separately to each distinct app already retained in the original ledger.
/// Together with the HTTP per-response byte bound and the finite tracked set,
/// these bounds constrain retained projections and duplicate-detection sets.
pub struct ObservationLimits {
    pub inventory_page_size: u64,
    pub usage_page_size: u64,
    pub max_inventory_records: NonZeroUsize,
    pub max_usage_records_per_app: NonZeroUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationError {
    Store(StoreError),
    Provider(ProviderHttpError),
    InvalidConfiguration,
    ClockRejected,
    IdentityConflict,
    LedgerRejected,
}
impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => e.fmt(f),
            Self::Provider(e) => e.fmt(f),
            Self::InvalidConfiguration => f.write_str("invalid provider observation configuration"),
            Self::ClockRejected => f.write_str("provider observation clock rejected"),
            Self::IdentityConflict => {
                f.write_str("provider resource identity conflicts with committed ledger")
            }
            Self::LedgerRejected => f.write_str("provider observation ledger rejected"),
        }
    }
}
impl std::error::Error for ObservationError {}
impl From<StoreError> for ObservationError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<ProviderHttpError> for ObservationError {
    fn from(value: ProviderHttpError) -> Self {
        Self::Provider(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMatch {
    /// Both app_id and the CVM object's known instance_id equal the retained target.
    /// This does not establish any usage.instance_id mapping.
    CvmFieldsMatch,
    Incomplete,
}

pub struct TrackedRead {
    target: TrackedCvm,
    inventory_identity: Option<IdentityMatch>,
    detail: CvmDetail,
    detail_identity: Option<IdentityMatch>,
}
impl TrackedRead {
    pub fn target(&self) -> &TrackedCvm {
        &self.target
    }
    pub fn inventory_identity(&self) -> Option<IdentityMatch> {
        self.inventory_identity
    }
    pub fn detail(&self) -> &CvmDetail {
        &self.detail
    }
    pub fn detail_identity(&self) -> Option<IdentityMatch> {
        self.detail_identity
    }
    /// Only the CVM's absence from these completed API reads, never its disk.
    pub fn cvm_absence_observed(&self) -> bool {
        self.inventory_identity.is_none() && matches!(self.detail, CvmDetail::NotFound)
    }
}

/// No public constructor or deserializer; only a completed scoped read produces
/// this result. Raw provider rows remain available, but all usage is unjoined.
/// The result is deliberately not a persisted or signed receipt.
pub struct ReadObservation {
    reference: CommittedLedgerReference,
    binding: ExperimentBinding,
    cutoff: u64,
    finished_at: u64,
    known_cost_floor: u64,
    inventory: InventoryScan,
    tracked: Vec<TrackedRead>,
    untracked_ids: Vec<String>,
    usage_by_app: BTreeMap<String, UsageScan>,
}
impl ReadObservation {
    pub fn reference(&self) -> &CommittedLedgerReference {
        &self.reference
    }
    pub fn original_binding(&self) -> &ExperimentBinding {
        &self.binding
    }
    pub fn usage_cutoff_unix_seconds(&self) -> u64 {
        self.cutoff
    }
    pub fn finished_at_unix_seconds(&self) -> u64 {
        self.finished_at
    }
    pub fn known_cost_floor_microusd(&self) -> u64 {
        self.known_cost_floor
    }
    pub fn inventory(&self) -> &InventoryScan {
        &self.inventory
    }
    pub fn tracked(&self) -> &[TrackedRead] {
        &self.tracked
    }
    pub fn untracked_inventory_ids(&self) -> &[String] {
        &self.untracked_ids
    }
    pub fn unjoined_usage_by_app(&self) -> &BTreeMap<String, UsageScan> {
        &self.usage_by_app
    }
    pub fn billing_reconciled(&self) -> bool {
        false
    }
    pub fn independent_disk_deletion_verified(&self) -> bool {
        false
    }
    pub fn cleanup_complete(&self) -> bool {
        false
    }
}

/// Holds a shared borrow of the writer-locked store throughout all awaits.
/// The caller cannot drop/unlock or commit it until this session is consumed.
/// No initialization, draft recovery, clock override or target argument exists.
pub struct ObservationSession<'a> {
    store: &'a LedgerStore,
    reference: CommittedLedgerReference,
    cutoff: u64,
}
impl<'a> ObservationSession<'a> {
    pub fn new(store: &'a LedgerStore) -> Result<Self, ObservationError> {
        Self::at(store, wall_time()?)
    }

    fn at(store: &'a LedgerStore, cutoff: u64) -> Result<Self, ObservationError> {
        let reference = store.planning_reference()?;
        // Includes original start and retained last-observed-time validation;
        // being over budget or after deadline must not block readback.
        store
            .ledger()?
            .planning_cost_at(cutoff)
            .map_err(|_| ObservationError::ClockRejected)?;
        Ok(Self {
            store,
            reference,
            cutoff,
        })
    }

    pub fn workspace_id(&self) -> Result<&str, ObservationError> {
        Ok(self.store.ledger()?.workspace_id())
    }

    pub async fn observe(
        self,
        client: ProviderClient,
        limits: ObservationLimits,
    ) -> Result<ReadObservation, ObservationError> {
        self.observe_with_clock(client, limits, wall_time).await
    }

    async fn observe_with_clock(
        self,
        client: ProviderClient,
        limits: ObservationLimits,
        mut clock: impl FnMut() -> Result<u64, ObservationError>,
    ) -> Result<ReadObservation, ObservationError> {
        let current = self.store.planning_reference()?;
        if current.generation() != self.reference.generation() {
            return Err(ObservationError::LedgerRejected);
        }
        let ledger = self.store.ledger()?;
        if client.workspace_id() != ledger.workspace_id() {
            return Err(ProviderHttpError::WorkspaceMismatch.into());
        }
        InventoryAccumulator::new(limits.inventory_page_size, limits.max_inventory_records)
            .map_err(|_| ObservationError::InvalidConfiguration)?;
        UsageAccumulator::new(limits.usage_page_size, limits.max_usage_records_per_app)
            .map_err(|_| ObservationError::InvalidConfiguration)?;
        let (start, _) = ledger.binding().original_window();
        let targets: BTreeMap<_, _> = ledger
            .tracked_cvms()
            .map(|c| (c.cvm_id.as_str(), c))
            .collect();
        let apps: std::collections::BTreeSet<_> =
            targets.values().map(|c| c.app_id.as_str()).collect();
        // Validate all ledger-derived routes before even authenticating.
        for target in targets.values() {
            ReadRequest::Detail {
                cvm_id: &target.cvm_id,
            }
            .path_and_query()
            .map_err(|_| ObservationError::InvalidConfiguration)?;
        }
        for app in &apps {
            ReadRequest::Usage {
                app_id: app,
                start_unix_seconds: start,
                end_unix_seconds: self.cutoff,
                limit: limits.usage_page_size,
                offset: 0,
            }
            .path_and_query()
            .map_err(|_| ObservationError::InvalidConfiguration)?;
        }
        let mut last_clock = self.cutoff;
        check_clock(&mut clock, &mut last_clock)?;
        let mut reads = client.authenticate().await?;
        check_clock(&mut clock, &mut last_clock)?;
        let inventory = reads
            .inventory_scan(limits.inventory_page_size, limits.max_inventory_records)
            .await?;
        check_clock(&mut clock, &mut last_clock)?;
        let inventory_by_id: BTreeMap<_, _> = inventory
            .items()
            .iter()
            .map(|c| (c.id.as_str(), c))
            .collect();
        let mut tracked = Vec::new();
        // Reject any explicit inventory conflict before requesting details.
        for target in targets.values() {
            if let Some(item) = inventory_by_id.get(target.cvm_id.as_str()) {
                compare_identity(item, target)?;
            }
        }
        for target in targets.values() {
            let inventory_identity = inventory_by_id
                .get(target.cvm_id.as_str())
                .map(|item| compare_identity(item, target))
                .transpose()?;
            let detail = reads.cvm_detail(&target.cvm_id).await?;
            check_clock(&mut clock, &mut last_clock)?;
            let detail_identity = match &detail {
                CvmDetail::Present(item) => Some(compare_identity(item, target)?),
                CvmDetail::NotFound => None,
            };
            tracked.push(TrackedRead {
                target: (*target).clone(),
                inventory_identity,
                detail,
                detail_identity,
            });
        }
        let untracked_ids = inventory
            .items()
            .iter()
            .filter(|item| !targets.contains_key(item.id.as_str()))
            .map(|item| item.id.clone())
            .collect();
        let mut usage_by_app = BTreeMap::new();
        for app in apps {
            let scan = reads
                .usage_scan(
                    app,
                    start,
                    self.cutoff,
                    limits.usage_page_size,
                    limits.max_usage_records_per_app,
                )
                .await?;
            check_clock(&mut clock, &mut last_clock)?;
            usage_by_app.insert(app.to_owned(), scan);
        }
        // Revalidate the on-disk history before returning even though the lock
        // coordinates only cooperating writers, not hostile same-UID edits.
        self.store.planning_reference()?;
        let finished_at = check_clock(&mut clock, &mut last_clock)?;
        let known_cost_floor = ledger
            .planning_cost_at(finished_at)
            .map_err(|_| ObservationError::LedgerRejected)?;
        reads.check_deadline()?;
        Ok(ReadObservation {
            reference: self.reference,
            binding: ledger.binding().clone(),
            cutoff: self.cutoff,
            finished_at,
            known_cost_floor,
            inventory,
            tracked,
            untracked_ids,
            usage_by_app,
        })
    }
}

fn compare_identity(item: &Cvm, target: &TrackedCvm) -> Result<IdentityMatch, ObservationError> {
    if item.id != target.cvm_id
        || item.app_id.as_ref().is_some_and(|id| id != &target.app_id)
        || item
            .instance_id
            .as_ref()
            .is_some_and(|id| target.instance_id.as_ref().is_some_and(|known| id != known))
    {
        return Err(ObservationError::IdentityConflict);
    }
    Ok(
        if item.app_id.is_some() && item.instance_id.is_some() && target.instance_id.is_some() {
            IdentityMatch::CvmFieldsMatch
        } else {
            IdentityMatch::Incomplete
        },
    )
}
fn wall_time() -> Result<u64, ObservationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ObservationError::ClockRejected)
}
fn check_clock(
    clock: &mut impl FnMut() -> Result<u64, ObservationError>,
    last: &mut u64,
) -> Result<u64, ObservationError> {
    let now = clock()?;
    if now < *last {
        return Err(ObservationError::ClockRejected);
    }
    *last = now;
    Ok(now)
}

#[cfg(test)]
mod tests;
