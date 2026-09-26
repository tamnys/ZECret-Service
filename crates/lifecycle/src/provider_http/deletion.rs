//! Explicit, single-target deletion preparation and dispatch. The operator CLI
//! can select an existing target; no scheduler, creation, retry or automatic
//! activation uses this library capability.
//! A provider status never establishes CVM/disk absence or billing finality.

use super::{CvmDetail, ProviderClient, ProviderHttpError, ScopedReads};
use crate::{
    controller::{DeletionIntentRecord, DeletionOutcome, TrackedCvm},
    persistence::{CommittedDeletionIntent, LedgerStore, StoreError},
    provider_request::ReadRequest,
};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionError {
    Provider(ProviderHttpError),
    Store(StoreError),
    TargetRejected,
    IdentityConflict,
    PriorIntentNeedsReconciliation,
    ClockOrLedgerRejected,
}
impl fmt::Display for DeletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
            Self::TargetRejected => f.write_str("deletion target is not a valid committed CVM"),
            Self::IdentityConflict => {
                f.write_str("deletion readback conflicts with committed target")
            }
            Self::PriorIntentNeedsReconciliation => {
                f.write_str("prior deletion intent requires reconciliation")
            }
            Self::ClockOrLedgerRejected => {
                f.write_str("deletion clock or retained ledger rejected")
            }
        }
    }
}
impl std::error::Error for DeletionError {}
impl From<ProviderHttpError> for DeletionError {
    fn from(value: ProviderHttpError) -> Self {
        Self::Provider(value)
    }
}
impl From<StoreError> for DeletionError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// This concerns CVM fields only, not usage identifiers, storage or an atomic
/// guarantee that provider state cannot change between GET and DELETE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationReadback {
    CvmFieldsMatch,
    IncompleteCvmFields,
    DetailNotFound,
}

/// Authentication alone cannot send DELETE. Only preparation against an
/// already committed ledger target can mint the dispatch capability.
pub struct ScopedDeletion(ScopedReads);

impl ProviderClient {
    /// Delete one explicitly selected, already committed CVM. Local generation,
    /// workspace, target, intent history and clock checks precede authentication
    /// traffic and run again before the target detail read. This retains the
    /// client's original invocation deadline and never scans or retries.
    pub async fn delete_tracked(
        self,
        store: &mut LedgerStore,
        expected_generation: u64,
        cvm_id: &str,
    ) -> Result<DeletionReport, DeletionError> {
        let (_, began_at) = local_target(
            store,
            expected_generation,
            self.workspace_id(),
            cvm_id,
            wall_time,
        )?;
        self.authenticate_deletion()
            .await?
            .prepare_with_clock(store, expected_generation, cvm_id, || {
                let now = wall_time()?;
                if now < began_at {
                    return Err(DeletionError::ClockOrLedgerRejected);
                }
                Ok(now)
            })
            .await?
            .dispatch()
            .await
    }

    /// Explicitly select the deletion path. Ordinary `authenticate` still
    /// produces only `ScopedReads`, with no conversion into this capability.
    pub async fn authenticate_deletion(self) -> Result<ScopedDeletion, ProviderHttpError> {
        self.authenticate().await.map(ScopedDeletion)
    }
}

/// The authenticated client and durable intent are owned together. The writer
/// lock remains held until dispatch completes or this value is dropped. Drop
/// performs no I/O and leaves the committed intent pending.
///
/// ```compile_fail
/// use zrpc_lifecycle::provider_http::deletion::PreparedDeletion;
/// fn duplicate<'a>(value: &PreparedDeletion<'a>) -> PreparedDeletion<'a> { value.clone() }
/// ```
/// ```compile_fail
/// use zrpc_lifecycle::provider_http::ScopedReads;
/// async fn cannot_delete(reads: ScopedReads) { reads.dispatch().await; }
/// ```
pub struct PreparedDeletion<'a> {
    client: ProviderClient,
    intent: CommittedDeletionIntent<'a>,
    readback: PreparationReadback,
}

/// A response may have been observed even when its journal write failed. A
/// failure here never authorizes replay, rolls back the intent, or proves which
/// snapshot survived an uncertain filesystem write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeJournal {
    Committed,
    ClockRejected,
    NotConfirmed(StoreError),
}

pub struct DeletionReport {
    target: TrackedCvm,
    intent_generation: u64,
    readback: PreparationReadback,
    outcome: DeletionOutcome,
    transport_issue: Option<ProviderHttpError>,
    journal: OutcomeJournal,
}
impl DeletionReport {
    pub fn target(&self) -> &TrackedCvm {
        &self.target
    }
    pub fn intent_generation(&self) -> u64 {
        self.intent_generation
    }
    pub fn preparation_readback(&self) -> PreparationReadback {
        self.readback
    }
    pub fn provider_outcome(&self) -> DeletionOutcome {
        self.outcome
    }
    pub fn transport_issue(&self) -> Option<ProviderHttpError> {
        self.transport_issue
    }
    pub fn outcome_journal(&self) -> OutcomeJournal {
        self.journal
    }
    pub fn independent_disk_deletion_verified(&self) -> bool {
        false
    }
    pub fn cleanup_complete(&self) -> bool {
        false
    }
}

impl ScopedDeletion {
    /// `cvm_id` selects an existing exact ledger ID; it cannot introduce a
    /// target or change its canonical path, app, instance, workspace or rate.
    /// Full inventory and billing scans are not prerequisites for this action.
    /// Detail failures/conflicts return before creating any intent. Missing
    /// fields are retained as incomplete, never adopted as new identity proof.
    pub async fn prepare<'a>(
        self,
        store: &'a mut LedgerStore,
        expected_generation: u64,
        cvm_id: &str,
    ) -> Result<PreparedDeletion<'a>, DeletionError> {
        self.prepare_with_clock(store, expected_generation, cvm_id, wall_time)
            .await
    }

    async fn prepare_with_clock<'a>(
        mut self,
        store: &'a mut LedgerStore,
        expected_generation: u64,
        cvm_id: &str,
        mut clock: impl FnMut() -> Result<u64, DeletionError>,
    ) -> Result<PreparedDeletion<'a>, DeletionError> {
        let (target, began_at) = local_target(
            store,
            expected_generation,
            self.0.workspace_id(),
            cvm_id,
            &mut clock,
        )?;
        let readback = match self.0.cvm_detail(&target.cvm_id).await? {
            CvmDetail::NotFound => PreparationReadback::DetailNotFound,
            CvmDetail::Present(item) => {
                if item.app_id.as_ref().is_some_and(|id| id != &target.app_id)
                    || item
                        .instance_id
                        .as_ref()
                        .is_some_and(|id| id != &target.instance_id)
                {
                    return Err(DeletionError::IdentityConflict);
                }
                if item.app_id.is_some() && item.instance_id.is_some() {
                    PreparationReadback::CvmFieldsMatch
                } else {
                    PreparationReadback::IncompleteCvmFields
                }
            }
        };
        let recorded_at = clock()?;
        if recorded_at < began_at {
            return Err(DeletionError::ClockOrLedgerRejected);
        }
        self.0.check_deadline()?;
        let intent = store.prepare_deletion(
            expected_generation,
            self.0.workspace_id(),
            &target.cvm_id,
            recorded_at,
        )?;
        // A deadline expiring during synchronous fsync leaves the intent pending
        // rather than authorizing a late request with a renewed network budget.
        self.0.check_deadline()?;
        Ok(PreparedDeletion {
            client: self.0.0,
            intent,
            readback,
        })
    }
}

fn local_target(
    store: &LedgerStore,
    expected_generation: u64,
    workspace_id: &str,
    cvm_id: &str,
    clock: impl FnOnce() -> Result<u64, DeletionError>,
) -> Result<(TrackedCvm, u64), DeletionError> {
    if store.planning_reference()?.generation() != expected_generation {
        return Err(StoreError::InvalidState.into());
    }
    let ledger = store.ledger()?;
    if workspace_id != ledger.workspace_id() {
        return Err(ProviderHttpError::WorkspaceMismatch.into());
    }
    let target = ledger
        .tracked_cvms()
        .find(|cvm| cvm.cvm_id == cvm_id)
        .cloned()
        .ok_or(DeletionError::TargetRejected)?;
    if ledger
        .deletion_intents()
        .iter()
        .any(|intent| intent.target.cvm_id == target.cvm_id)
    {
        return Err(DeletionError::PriorIntentNeedsReconciliation);
    }
    ReadRequest::Detail {
        cvm_id: &target.cvm_id,
    }
    .path_and_query()
    .map_err(|_| DeletionError::TargetRejected)?;
    let began_at = clock()?;
    ledger
        .planning_cost_at(began_at)
        .map_err(|_| DeletionError::ClockOrLedgerRejected)?;
    Ok((target, began_at))
}

impl PreparedDeletion<'_> {
    pub fn intent_record(&self) -> &DeletionIntentRecord {
        self.intent.record()
    }
    pub fn preparation_readback(&self) -> PreparationReadback {
        self.readback
    }

    /// Consume one prepared capability, sending at most one DELETE. No target,
    /// URL, method, caller clock, automatic retry or response body is accepted.
    /// Cancellation leaves the intent pending and aborts the owned HTTP driver.
    pub async fn dispatch(self) -> Result<DeletionReport, DeletionError> {
        self.dispatch_with_clock(wall_time).await
    }

    async fn dispatch_with_clock(
        self,
        mut clock: impl FnMut() -> Result<u64, DeletionError>,
    ) -> Result<DeletionReport, DeletionError> {
        self.intent.verify_for_dispatch()?;
        if self.client.workspace_id() != self.intent.workspace_id() {
            return Err(ProviderHttpError::WorkspaceMismatch.into());
        }
        let before = clock()?;
        if before < self.intent.record().recorded_at_unix_seconds {
            return Err(DeletionError::ClockOrLedgerRejected);
        }
        self.client.finish(Ok(()))?;
        let target = self.intent.record().target.clone();
        let intent_generation = self.intent.record().committed_generation;
        let (outcome, transport_issue) = match self.client.delete_status(&self.intent).await {
            Ok(204) => (DeletionOutcome::Initiated204, None),
            Ok(404) => (DeletionOutcome::NotFound404, None),
            Ok(status) => (DeletionOutcome::Rejected { status }, None),
            Err(error) => (DeletionOutcome::TransportUncertain, Some(error)),
        };
        // No await or spawned finalizer separates the observed outcome from its
        // durable write. Even an expired network budget must allow journaling.
        let journal = match clock() {
            Ok(now) if now >= before => match self.intent.finish(outcome, now) {
                Ok(()) => OutcomeJournal::Committed,
                Err(error) => OutcomeJournal::NotConfirmed(error),
            },
            _ => OutcomeJournal::ClockRejected,
        };
        Ok(DeletionReport {
            target,
            intent_generation,
            readback: self.readback,
            outcome,
            transport_issue,
            journal,
        })
    }
}

impl ProviderClient {
    async fn delete_status(
        &self,
        intent: &CommittedDeletionIntent<'_>,
    ) -> Result<u16, ProviderHttpError> {
        self.finish(Ok(()))?;
        let path = ReadRequest::Detail {
            cvm_id: &intent.record().target.cvm_id,
        }
        .path_and_query()
        .map_err(|_| ProviderHttpError::InvalidConfiguration)?;
        let exchange = async {
            let (response, _driver) = self.exchange_headers(path, hyper::Method::DELETE).await?;
            // Never read or retain provider bodies/Location, follow redirects,
            // or turn DELETE 204/404 into absence/storage/finality evidence.
            let status = response.status().as_u16();
            // The HTTP parser also accepts extension codes above the retained
            // journal's supported 100..=599 range. Reject those as an uncertain
            // exchange rather than fabricate a journal persistence failure.
            if !(100..=599).contains(&status) {
                return Err(ProviderHttpError::UnexpectedStatus);
            }
            Ok(status)
        };
        let result = tokio::time::timeout_at(self.deadline, exchange)
            .await
            .map_err(|_| ProviderHttpError::DeadlineExceeded)?;
        self.finish(result)
    }
}

fn wall_time() -> Result<u64, DeletionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DeletionError::ClockOrLedgerRejected)
}

#[cfg(test)]
mod tests;
