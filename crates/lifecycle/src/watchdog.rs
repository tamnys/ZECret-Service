//! One explicitly invoked pass over an existing, writer-locked experiment.
//! This capability can send real DELETE requests. It creates no resources or
//! jobs and grants no authority for later invocations. Reports are observations,
//! never activation, independent disk evidence or billing-finality receipts.

mod policy;
pub use policy::{DeleteReason, PolicyDecision, ReserveProjection, WatchdogPolicy};

use crate::{
    LifecycleError,
    controller::{DeletionOutcome, ExperimentBinding, TrackedCvm},
    observation::{ObservationError, ObservationLimits, ObservationSession},
    persistence::{CommittedLedgerReference, LedgerStore, StoreError},
    provider_http::{
        ProviderClient, ProviderHttpError,
        deletion::{DeletionError, DeletionReport, OutcomeJournal, PreparationReadback},
    },
    provider_request::ReadRequest,
    provider_scan::{InventoryAccumulator, UsageAccumulator},
};
use serde::Serialize;
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

#[derive(Debug)]
pub enum WatchdogError {
    Store(StoreError),
    Provider(ProviderHttpError),
    Observation(ObservationError),
    Policy(LifecycleError),
    ExperimentMismatch,
    ClockRejected,
}
impl fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => e.fmt(f),
            Self::Provider(e) => e.fmt(f),
            Self::Observation(e) => e.fmt(f),
            Self::Policy(e) => e.fmt(f),
            Self::ExperimentMismatch => {
                f.write_str("watchdog experiment does not match the original binding")
            }
            Self::ClockRejected => f.write_str("watchdog clock is invalid or moved backwards"),
        }
    }
}
impl std::error::Error for WatchdogError {}
impl From<StoreError> for WatchdogError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<ProviderHttpError> for WatchdogError {
    fn from(value: ProviderHttpError) -> Self {
        Self::Provider(value)
    }
}
impl From<ObservationError> for WatchdogError {
    fn from(value: ObservationError) -> Self {
        Self::Observation(value)
    }
}
impl From<LifecycleError> for WatchdogError {
    fn from(value: LifecycleError) -> Self {
        Self::Policy(value)
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    SkippedDeletionDue,
    Committed,
    Incomplete,
    Preempted,
}

#[derive(Debug, Serialize)]
pub struct ObservationReport {
    pub status: ObservationStatus,
    pub issue: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeletionAttempt {
    pub intent_generation: u64,
    pub prior_intent_generation: Option<u64>,
    pub preparation_readback: &'static str,
    pub provider_outcome: DeletionOutcome,
    pub transport_issue: Option<String>,
    pub journal_committed: bool,
    pub journal_issue: Option<String>,
}
impl From<&DeletionReport> for DeletionAttempt {
    fn from(report: &DeletionReport) -> Self {
        Self {
            intent_generation: report.intent_generation(),
            prior_intent_generation: report.prior_intent_generation(),
            preparation_readback: match report.preparation_readback() {
                PreparationReadback::CvmFieldsMatch => "cvm_fields_match",
                PreparationReadback::IncompleteCvmFields => "incomplete_cvm_fields",
                PreparationReadback::DetailNotFound => "detail_not_found",
            },
            provider_outcome: report.provider_outcome(),
            transport_issue: report.transport_issue().map(|e| e.to_string()),
            journal_committed: matches!(report.outcome_journal(), OutcomeJournal::Committed),
            journal_issue: match report.outcome_journal() {
                OutcomeJournal::Committed => None,
                OutcomeJournal::ClockRejected => Some("deletion outcome clock rejected".into()),
                OutcomeJournal::NotConfirmed(e) => Some(e.to_string()),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TargetReport {
    pub target: TrackedCvm,
    pub deletion: Option<DeletionAttempt>,
    pub issue: Option<String>,
}

/// Serialize-only report. Nothing consumes a restored report as a capability.
#[derive(Debug, Serialize)]
pub struct WatchdogReport {
    pub mode: &'static str,
    pub simulation: bool,
    pub original_binding: ExperimentBinding,
    pub source_committed_reference: CommittedLedgerReference,
    pub final_committed_reference: Option<CommittedLedgerReference>,
    pub started_at_unix_millis: u64,
    pub finished_at_unix_millis: Option<u64>,
    pub initial_decision: PolicyDecision,
    pub final_decision: Option<PolicyDecision>,
    pub observation: ObservationReport,
    pub targets: Vec<TargetReport>,
    pub retained_target_count: usize,
    pub deletion_dispatch_started: bool,
    pub invocation_completed: bool,
    pub stopped_reason: Option<String>,
    pub future_invocation_authorized: bool,
    pub cleanup_complete: bool,
    pub independent_disk_deletion_verified: bool,
    pub billing_reconciled: bool,
    pub deployment_enabled: bool,
    pub private_mode_accepted: bool,
}

fn wall_millis() -> Result<u64, WatchdogError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(WatchdogError::ClockRejected)
}

fn observe_clock(
    last: &mut u64,
    clock: &mut impl FnMut() -> Result<u64, WatchdogError>,
) -> Result<(Instant, u64), WatchdogError> {
    // Anchor before the wall-clock read, so conversion does not add the time
    // spent calculating or validating the policy to the network cutoff.
    let instant = Instant::now();
    let now = clock()?;
    if now < *last {
        return Err(WatchdogError::ClockRejected);
    }
    *last = now;
    Ok((instant, now))
}

fn provider_stops_pass(error: ProviderHttpError) -> bool {
    matches!(
        error,
        ProviderHttpError::InvalidConfiguration
            | ProviderHttpError::WorkspaceMismatch
            | ProviderHttpError::Unauthorized
            | ProviderHttpError::Forbidden
            | ProviderHttpError::DeadlineExceeded
    )
}

fn observation_stops_pass(error: ObservationError) -> bool {
    match error {
        // A phase deadline is expected when preempting optional reads. Other
        // scopes/identities cannot be ignored merely because cleanup is due.
        ObservationError::Provider(ProviderHttpError::DeadlineExceeded) => false,
        ObservationError::Provider(e) => provider_stops_pass(e),
        _ => true,
    }
}

fn stop(report: &mut WatchdogReport, reason: String) {
    report.invocation_completed = false;
    if report.stopped_reason.is_none() {
        report.stopped_reason = Some(reason);
    }
}

/// Explicitly selects all already retained targets at the current committed
/// generation. Each target gets at most one first or latest-linked attempt.
/// All configuration is mandatory. No clocks, endpoints or new target IDs can
/// be supplied here. The caller must retain and protect the original ledger.
pub async fn run_once(
    client: ProviderClient,
    store: &mut LedgerStore,
    experiment_id: &str,
    policy: WatchdogPolicy,
    limits: ObservationLimits,
) -> Result<WatchdogReport, WatchdogError> {
    run_with_clock(client, store, experiment_id, policy, limits, wall_millis).await
}

async fn run_with_clock(
    client: ProviderClient,
    store: &mut LedgerStore,
    experiment_id: &str,
    policy: WatchdogPolicy,
    limits: ObservationLimits,
    mut clock: impl FnMut() -> Result<u64, WatchdogError>,
) -> Result<WatchdogReport, WatchdogError> {
    policy.validate(client.invocation_budget())?;
    InventoryAccumulator::new(limits.inventory_page_size, limits.max_inventory_records)
        .map_err(|_| ObservationError::InvalidConfiguration)?;
    UsageAccumulator::new(limits.usage_page_size, limits.max_usage_records_per_app)
        .map_err(|_| ObservationError::InvalidConfiguration)?;
    let reference = store.planning_reference()?;
    let ledger = store.ledger()?;
    if experiment_id != ledger.binding().experiment_id() {
        return Err(WatchdogError::ExperimentMismatch);
    }
    if client.workspace_id() != ledger.binding().workspace_id() {
        return Err(ProviderHttpError::WorkspaceMismatch.into());
    }
    for target in ledger.tracked_cvms() {
        ReadRequest::Detail {
            cvm_id: &target.cvm_id,
        }
        .path_and_query()
        .map_err(|_| ObservationError::InvalidConfiguration)?;
    }
    let mut last_clock = clock()?;
    let decision = policy.evaluate(ledger, last_clock)?;
    let mut report = WatchdogReport {
        mode: "explicit_whole_experiment_watchdog",
        simulation: false,
        original_binding: ledger.binding().clone(),
        source_committed_reference: reference,
        final_committed_reference: None,
        started_at_unix_millis: last_clock,
        finished_at_unix_millis: None,
        initial_decision: decision,
        final_decision: None,
        observation: ObservationReport {
            status: ObservationStatus::SkippedDeletionDue,
            issue: None,
        },
        targets: Vec::new(),
        retained_target_count: ledger.tracked_cvms().count(),
        deletion_dispatch_started: false,
        invocation_completed: true,
        stopped_reason: None,
        future_invocation_authorized: false,
        cleanup_complete: false,
        independent_disk_deletion_verified: false,
        billing_reconciled: false,
        deployment_enabled: false,
        private_mode_accepted: false,
    };
    // From this point onward, preserve a partial report even when a later
    // operation fails. Durable observations/intents are never rolled back.
    if let Err(error) = execute(
        &client,
        store,
        &policy,
        limits,
        &mut report,
        &mut last_clock,
        &mut clock,
    )
    .await
    {
        stop(&mut report, error.to_string());
    }
    match store.planning_reference() {
        Ok(reference) => report.final_committed_reference = Some(reference),
        Err(error) => stop(&mut report, error.to_string()),
    }
    match observe_clock(&mut last_clock, &mut clock) {
        Ok((_, now)) => {
            report.finished_at_unix_millis = Some(now);
            match store
                .ledger()
                .map_err(WatchdogError::from)
                .and_then(|ledger| policy.evaluate(ledger, now).map_err(WatchdogError::from))
            {
                Ok(decision) => {
                    if decision.deletion_required() && !report.deletion_dispatch_started {
                        stop(
                            &mut report,
                            "cleanup is due and dispatch did not start".into(),
                        );
                    }
                    report.final_decision = Some(decision);
                }
                Err(error) => stop(&mut report, error.to_string()),
            }
        }
        Err(error) => stop(&mut report, error.to_string()),
    }
    Ok(report)
}

async fn execute(
    client: &ProviderClient,
    store: &mut LedgerStore,
    policy: &WatchdogPolicy,
    limits: ObservationLimits,
    report: &mut WatchdogReport,
    last_clock: &mut u64,
    clock: &mut impl FnMut() -> Result<u64, WatchdogError>,
) -> Result<(), WatchdogError> {
    if !report.initial_decision.deletion_required() {
        let (anchor, now) = observe_clock(last_clock, clock)?;
        let trigger = policy.next_trigger_unix_millis(store.ledger()?, now)?;
        let cutoff = anchor
            .checked_add(policy.reconciliation_budget)
            .zip(
                client
                    .invocation_deadline()
                    .checked_sub(policy.deletion_dispatch_budget),
            )
            .zip(anchor.checked_add(Duration::from_millis(trigger.saturating_sub(now))))
            .map(|((reconciliation, reserved), trigger)| reconciliation.min(reserved).min(trigger))
            .ok_or(WatchdogError::ClockRejected)?;
        report.observation.status = ObservationStatus::Preempted;
        if cutoff > Instant::now() {
            let session = ObservationSession::new(store)?;
            // Dropping the future aborts its owned HTTP driver. No partial scan
            // is persisted or treated as an accepted usage charge.
            let observation = async {
                let child = client.for_phase(cutoff)?;
                session.observe(child, limits).await
            };
            match tokio::time::timeout_at(cutoff, observation).await {
                Ok(Ok(observation)) => {
                    report.observation.status = ObservationStatus::Incomplete;
                    store.commit_observation(observation)?;
                    report.observation.status = ObservationStatus::Committed;
                }
                Ok(Err(error)) => {
                    report.observation.issue = Some(error.to_string());
                    report.observation.status = if error
                        == ObservationError::Provider(ProviderHttpError::DeadlineExceeded)
                    {
                        ObservationStatus::Preempted
                    } else {
                        ObservationStatus::Incomplete
                    };
                    if observation_stops_pass(error) {
                        return Err(error.into());
                    }
                }
                Err(_) => {
                    report.observation.issue =
                        Some("optional observation phase deadline reached".into())
                }
            }
        }
    }
    let (anchor, now) = observe_clock(last_clock, clock)?;
    let decision = policy.evaluate(store.ledger()?, now)?;
    if !decision.deletion_required() {
        report.invocation_completed = report.observation.status == ObservationStatus::Committed;
        return Ok(());
    }
    // One fixed deadline for the entire set, including authentication/readback.
    // A target transition cannot restart either this phase or the invocation.
    let dispatch_deadline = anchor
        .checked_add(policy.deletion_dispatch_budget)
        .ok_or(WatchdogError::ClockRejected)?
        .min(client.invocation_deadline());
    report.deletion_dispatch_started = true;
    let targets: Vec<_> = store.ledger()?.tracked_cvms().cloned().collect();
    for target in targets {
        observe_clock(last_clock, clock)?;
        let current = store.planning_reference()?;
        let prior = store
            .ledger()?
            .deletion_intents()
            .iter()
            .rev()
            .find(|intent| intent.target == target)
            .map(|intent| intent.committed_generation);
        let child = client.for_phase(dispatch_deadline)?;
        let outcome = match prior {
            Some(prior) => {
                child
                    .retry_tracked(store, current.generation(), &target.cvm_id, prior)
                    .await
            }
            None => {
                child
                    .delete_tracked(store, current.generation(), &target.cvm_id)
                    .await
            }
        };
        let mut item = TargetReport {
            target,
            deletion: None,
            issue: None,
        };
        let fatal = match outcome {
            Ok(deletion) => {
                let attempt = DeletionAttempt::from(&deletion);
                let rejected_scope = matches!(
                    attempt.provider_outcome,
                    DeletionOutcome::Rejected { status: 401 | 403 }
                );
                let fatal = !attempt.journal_committed || rejected_scope;
                if fatal
                    || !matches!(
                        attempt.provider_outcome,
                        DeletionOutcome::Initiated204 | DeletionOutcome::NotFound404
                    )
                {
                    report.invocation_completed = false;
                }
                item.issue = attempt.journal_issue.clone();
                if rejected_scope {
                    item.issue = Some("provider deletion authentication or access rejected".into());
                }
                item.deletion = Some(attempt);
                fatal
            }
            Err(error) => {
                report.invocation_completed = false;
                item.issue = Some(error.to_string());
                match error {
                    DeletionError::Provider(e) => provider_stops_pass(e),
                    _ => true,
                }
            }
        };
        let issue = item.issue.clone();
        report.targets.push(item);
        if fatal {
            stop(
                report,
                issue.unwrap_or_else(|| "deletion outcome journal was not confirmed".into()),
            );
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod observation_tests;
#[cfg(test)]
mod tests;
