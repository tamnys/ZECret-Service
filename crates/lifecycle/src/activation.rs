//! Offline external-controller specification. No unit files, executable command,
//! timers, credentials, provider calls, or live activation are produced.

use crate::{
    CostPlan, DELETE_THRESHOLD_MICROUSD, LifecycleError, PlanInput, TOTAL_CEILING_MICROUSD, add,
    controller::ExperimentBinding,
    duration_cost,
    persistence::{CommittedLedgerReference, LedgerStore},
    plan,
};
use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

const MICROSECONDS_PER_SECOND: u64 = 1_000_000;
// systemd.timer explicitly documents 1us for its best AccuracySec precision.
// Subtract this coalescing window from the operator's interval/deadline rather
// than silently adding it to the accepted cost/deletion-delay assumptions.
const SYSTEMD_ACCURACY_MICROSECONDS: u64 = 1;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    ProposedOnly,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartupRequirement {
    ReconcileFreshLedgerAndProviderBeforeActivation,
    RequestDeletionWithoutExtendingOriginalDeadline,
}

#[derive(Debug, Serialize)]
pub struct TimerProposal {
    pub installation_state: InstallationState,
    pub operator_reference: String,
    /// Proposed [Timer] values, not a runnable unit: no Unit or service exists.
    pub proposed_timer_directives: BTreeMap<String, String>,
    pub role: &'static str,
}

#[derive(Debug, Serialize)]
pub struct IndependentBackstopProposal {
    pub installation_state: InstallationState,
    pub operator_reference: String,
    pub check_no_later_than_utc: String,
    pub execution_requirement: &'static str,
    pub required_actions: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequiredReceipt {
    ReviewedLiveProviderAdapter,
    ExternalPersistentStoreAndCredentialAccess,
    PeriodicAndAbsoluteJobInstallation,
    MeasuredDetectionAndDeletionLatency,
    CompleteResourceReadbackAndIndependentDiskEvidence,
    FinalBillingReconciliation,
    SuccessfulLiveDeletionTest,
    IndependentBackstop,
    ExplicitOperatorActivation,
}

#[derive(Debug, Serialize)]
pub struct CommandContract {
    pub implementation_status: &'static str,
    /// Intentionally absent: inventing an executable would make a broken unit.
    pub executable: Option<String>,
    pub arguments: Option<Vec<String>>,
    pub required_behaviors: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ReserveCalculation {
    pub maximum_poll_interval_seconds: u64,
    pub deletion_latency_upper_bound_seconds: u64,
    pub aggregate_microusd_per_hour: u64,
    pub delayed_cost_microusd: u64,
    pub fee_upper_bounds_microusd: u64,
    pub cost_at_trigger_plus_delay_and_fees_microusd: u64,
    pub remaining_reserve_microusd: u64,
    pub timing_evidence_status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ActivationSpecification {
    pub installation_state: InstallationState,
    pub activation_available: bool,
    pub original_binding: ExperimentBinding,
    pub committed_ledger: CommittedLedgerReference,
    pub evaluated_at_unix_seconds: u64,
    pub original_deadline_unix_seconds: u64,
    pub original_deadline_utc: String,
    pub proposed_deletion_start_unix_microseconds: u64,
    pub known_cost_floor_microusd: u64,
    pub cost_plan: CostPlan,
    pub reserve: ReserveCalculation,
    pub periodic: TimerProposal,
    pub absolute_deadline: TimerProposal,
    pub independent_backstop: IndependentBackstopProposal,
    pub command_contract: CommandContract,
    pub required_receipts: Vec<RequiredReceipt>,
    pub operator_deletion_test_reference: String,
    pub limitations: Vec<&'static str>,
}

impl ActivationSpecification {
    /// Advisory requirement only, not an execution/authorization capability.
    /// A future executor must load current policy/cost, not trust this old view.
    pub fn startup_requirement_at(&self, now_unix_seconds: u64) -> StartupRequirement {
        if u128::from(now_unix_seconds) * u128::from(MICROSECONDS_PER_SECOND)
            >= u128::from(self.proposed_deletion_start_unix_microseconds)
            || self.known_cost_floor_microusd >= DELETE_THRESHOLD_MICROUSD
        {
            StartupRequirement::RequestDeletionWithoutExtendingOriginalDeadline
        } else {
            StartupRequirement::ReconcileFreshLedgerAndProviderBeforeActivation
        }
    }
}

fn micros(seconds: u64) -> Result<u64, LifecycleError> {
    seconds
        .checked_mul(MICROSECONDS_PER_SECOND)
        .ok_or(LifecycleError("schedule timestamp overflow"))
}

fn utc_calendar(timestamp_microseconds: u64) -> Result<String, LifecycleError> {
    let value = i64::try_from(timestamp_microseconds)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .ok_or(LifecycleError(
            "schedule timestamp is not representable in UTC",
        ))?;
    // The pinned systemd calendarspec.c defines MIN_YEAR=1970, MAX_YEAR=2199;
    // chrono accepts a wider range than the target calendar parser.
    if !(1970..=2199).contains(&value.year()) {
        return Err(LifecycleError(
            "schedule year is outside the systemd calendar parser range",
        ));
    }
    Ok(value.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string())
}

/// Generate from an actual committed snapshot while its store lock is held.
/// Existing PlanInput validation remains authoritative; no job is installed and
/// no supplied reference string is promoted to a verified external receipt.
pub fn generate(
    store: &LedgerStore,
    input: &PlanInput,
) -> Result<ActivationSpecification, LifecycleError> {
    let reference = store
        .planning_reference()
        .map_err(|_| LifecycleError("committed ledger reference unavailable for planning"))?;
    let ledger = store
        .ledger()
        .map_err(|_| LifecycleError("committed ledger unavailable for planning"))?;
    let (original_start, deadline) = ledger.binding().original_window();
    if input.deletion_deadline_unix_seconds != Some(deadline)
        || input.start_unix_seconds < original_start
    {
        return Err(LifecycleError(
            "activation plan must retain the original experiment window",
        ));
    }
    let known_cost = ledger.planning_cost_at(input.evaluated_at_unix_seconds)?;
    if input.accrued_experiment_microusd < known_cost {
        return Err(LifecycleError(
            "activation plan omits committed or modeled accrued cost",
        ));
    }
    for (id, rate) in ledger.tracked_rates() {
        if !input
            .existing_resources
            .iter()
            .any(|r| r.resource_id == id && r.remaining_microusd_per_hour >= rate)
        {
            return Err(LifecycleError(
                "activation plan omits a tracked resource or its conservative rate",
            ));
        }
    }
    let cost_plan = plan(input)?;
    let controls = input
        .external_controls
        .as_ref()
        .ok_or(LifecycleError("external controls required"))?;
    let mut hourly = add(
        input.quote.compute_microusd_per_hour,
        input
            .quote
            .disk_microusd_per_gib_hour
            .checked_mul(input.quote.disk_gib)
            .ok_or(LifecycleError("cost overflow"))?,
    )?;
    for resource in &input.existing_resources {
        hourly = add(hourly, resource.remaining_microusd_per_hour)?;
    }
    let delay_seconds = add(
        controls.maximum_poll_interval_seconds,
        controls.deletion_latency_upper_bound_seconds,
    )?;
    let delayed_cost = duration_cost(hourly, delay_seconds)?;
    let trigger_delay_fees = add(
        add(DELETE_THRESHOLD_MICROUSD, delayed_cost)?,
        cost_plan.fee_upper_bounds_microusd,
    )?;
    let remaining_reserve = TOTAL_CEILING_MICROUSD
        .checked_sub(trigger_delay_fees)
        .ok_or(LifecycleError(
            "activation timing exceeds the original total ceiling reserve",
        ))?;
    let interval = micros(controls.maximum_poll_interval_seconds)?
        .checked_sub(SYSTEMD_ACCURACY_MICROSECONDS)
        .filter(|value| *value > 0)
        .ok_or(LifecycleError(
            "operator poll interval cannot contain timer accuracy window",
        ))?;
    let lead = add(
        micros(controls.deletion_latency_upper_bound_seconds)?,
        SYSTEMD_ACCURACY_MICROSECONDS,
    )?;
    let original_start_microseconds = micros(original_start)?;
    let proposed_start = micros(deadline)?
        .checked_sub(lead)
        .filter(|value| *value >= original_start_microseconds)
        .ok_or(LifecycleError(
            "deletion latency does not fit the original experiment window",
        ))?;
    let original_deadline_utc = utc_calendar(micros(deadline)?)?;
    let deletion_start_utc = utc_calendar(proposed_start)?;
    let common = BTreeMap::from([
        ("AccuracySec".to_owned(), "1us".to_owned()),
        ("RandomizedDelaySec".to_owned(), "0".to_owned()),
    ]);
    let mut periodic = common.clone();
    periodic.insert("OnActiveSec".to_owned(), format!("{interval}us"));
    periodic.insert("OnUnitActiveSec".to_owned(), format!("{interval}us"));
    let mut absolute = common;
    absolute.insert("OnCalendar".to_owned(), deletion_start_utc.clone());
    absolute.insert("Persistent".to_owned(), "true".to_owned());
    Ok(ActivationSpecification {
        installation_state: InstallationState::ProposedOnly,
        activation_available: false,
        original_binding: ledger.binding().clone(),
        committed_ledger: reference,
        evaluated_at_unix_seconds: input.evaluated_at_unix_seconds,
        original_deadline_unix_seconds: deadline,
        original_deadline_utc,
        proposed_deletion_start_unix_microseconds: proposed_start,
        known_cost_floor_microusd: input.accrued_experiment_microusd,
        reserve: ReserveCalculation {
            maximum_poll_interval_seconds: controls.maximum_poll_interval_seconds,
            deletion_latency_upper_bound_seconds: controls.deletion_latency_upper_bound_seconds,
            aggregate_microusd_per_hour: hourly,
            delayed_cost_microusd: delayed_cost,
            fee_upper_bounds_microusd: cost_plan.fee_upper_bounds_microusd,
            cost_at_trigger_plus_delay_and_fees_microusd: trigger_delay_fees,
            remaining_reserve_microusd: remaining_reserve,
            timing_evidence_status: "operator assumptions; no scheduler or live deletion latency has been verified",
        },
        cost_plan,
        periodic: TimerProposal {
            installation_state: InstallationState::ProposedOnly,
            operator_reference: controls.watchdog_reference.clone(),
            proposed_timer_directives: periodic,
            role: "reconcile current cumulative cost and request deletion at the original trigger",
        },
        absolute_deadline: TimerProposal {
            installation_state: InstallationState::ProposedOnly,
            operator_reference: controls.absolute_deadline_job_reference.clone(),
            proposed_timer_directives: absolute,
            role: "request deletion early enough for the supplied latency assumption; never extend the original deadline",
        },
        independent_backstop: IndependentBackstopProposal {
            installation_state: InstallationState::ProposedOnly,
            operator_reference: controls.independent_backstop_reference.clone(),
            check_no_later_than_utc: deletion_start_utc,
            execution_requirement: "independent operator-controlled host or manual reminder, outside both CVM and primary scheduler",
            required_actions: vec![
                "load the same original binding and latest committed ledger; retain costs from every attempt",
                "check whether the periodic and absolute jobs actually ran; if overdue, request deletion without extending the deadline",
                "inspect complete workspace inventory, tracked CVM readback, attached disk evidence, and residual charges; stop is insufficient",
            ],
        },
        command_contract: CommandContract {
            implementation_status: "unimplemented live command; specification cannot be activated",
            executable: None,
            arguments: None,
            required_behaviors: vec![
                "on every startup, immediately check the current original deadline and cumulative cost before waiting for a timer",
                "open the original-bound external store under its writer lock; credentials must remain outside the guest",
                "reconcile current provider workspace identity, all tracked attempts, complete inventory and billing pages",
                "request deletion at the cost trigger or proposed deletion-start time; persist uncertain outcomes and retry reconciliation without resetting budget or deadline",
                "do not treat HTTP 204, a stopped CVM, inventory absence alone, or mock evidence as final disk/billing cleanup",
                "exit after each bounded operation so the periodic service can reactivate; actual runtime and detection bounds need measured evidence",
            ],
        },
        required_receipts: vec![
            RequiredReceipt::ReviewedLiveProviderAdapter,
            RequiredReceipt::ExternalPersistentStoreAndCredentialAccess,
            RequiredReceipt::PeriodicAndAbsoluteJobInstallation,
            RequiredReceipt::MeasuredDetectionAndDeletionLatency,
            RequiredReceipt::CompleteResourceReadbackAndIndependentDiskEvidence,
            RequiredReceipt::FinalBillingReconciliation,
            RequiredReceipt::SuccessfulLiveDeletionTest,
            RequiredReceipt::IndependentBackstop,
            RequiredReceipt::ExplicitOperatorActivation,
        ],
        operator_deletion_test_reference: controls.successful_deletion_test_reference.clone(),
        limitations: vec![
            "proposed settings only; no unit, command, timer, credential, API request, approval, or resource has been created",
            "Persistent=true catches missed calendar runs after reactivation; it cannot ensure timely deletion during downtime or replace an explicit startup policy check",
            "monotonic periodic timers pause during suspension and do not gain persistence from the calendar job",
            "AccuracySec=1us still permits kernel timer slack and scheduling delay; an already-active service is not restarted by a timer",
            "operator references and cost/timing assumptions are not verified installation, deletion, disk, or billing receipts",
            "local file ownership remains trusted; the committed reference is not authenticated or independent cloud evidence",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        controller::{ExperimentLedger, TrackedCvm},
        persistence::create_original_binding,
    };
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.codex-tmp/lifecycle-activation-tests");
            fs::create_dir_all(&base).unwrap();
            let path = fs::canonicalize(base).unwrap().join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn input() -> PlanInput {
        serde_json::from_str(include_str!("../../../deploy/plan.fixture.json")).unwrap()
    }
    fn setup(temp: &Temp, input: &PlanInput) -> LedgerStore {
        let binding = ExperimentBinding::new(
            "experiment".into(),
            "workspace".into(),
            input.start_unix_seconds,
            input.deletion_deadline_unix_seconds.unwrap(),
        )
        .unwrap();
        let ledger = ExperimentLedger::new(binding, 0).unwrap();
        let original = temp.0.join("original.json");
        create_original_binding(&original, &temp.0.join("state"), &ledger).unwrap();
        LedgerStore::initialize(&original).unwrap()
    }

    #[test]
    fn fixture_proposal_has_exact_utc_and_no_runnable_or_armed_command() {
        let temp = Temp::new();
        let input = input();
        let store = setup(&temp, &input);
        let spec = generate(&store, &input).unwrap();
        assert_eq!(spec.original_deadline_utc, "2026-10-02 16:00:00.000000 UTC");
        assert_eq!(
            spec.absolute_deadline.proposed_timer_directives["OnCalendar"],
            "2026-10-02 15:59:59.999999 UTC"
        );
        assert_eq!(
            spec.periodic.proposed_timer_directives["OnUnitActiveSec"],
            "3599999999us"
        );
        assert_eq!(
            spec.absolute_deadline.proposed_timer_directives["Persistent"],
            "true"
        );
        assert!(
            !spec
                .periodic
                .proposed_timer_directives
                .contains_key("Persistent")
        );
        assert_eq!(spec.reserve.remaining_reserve_microusd, 4_756_880);
        assert!(!spec.activation_available);
        assert!(
            spec.command_contract.executable.is_none() && spec.command_contract.arguments.is_none()
        );
        assert_eq!(spec.installation_state, InstallationState::ProposedOnly);
        assert_eq!(spec.committed_ledger.generation(), 0);
    }

    #[test]
    fn retry_changes_snapshot_but_never_renews_original_deadline_or_budget() {
        let temp = Temp::new();
        let mut input = input();
        let mut store = setup(&temp, &input);
        let before = generate(&store, &input).unwrap();
        let mut next = store.ledger().unwrap().clone();
        next.begin_attempt("retry".into(), input.start_unix_seconds + 60)
            .unwrap();
        store.commit(&next).unwrap();
        input.evaluated_at_unix_seconds += 60;
        input.start_unix_seconds += 60;
        let after = generate(&store, &input).unwrap();
        assert_eq!(after.original_binding, before.original_binding);
        assert_eq!(
            after.absolute_deadline.proposed_timer_directives,
            before.absolute_deadline.proposed_timer_directives
        );
        assert_eq!(after.committed_ledger.generation(), 1);
        input.deletion_deadline_unix_seconds =
            Some(input.deletion_deadline_unix_seconds.unwrap() + 60);
        assert!(generate(&store, &input).is_err());
    }

    #[test]
    fn reserve_accounts_for_cadence_deletion_latency_and_every_fee() {
        let temp = Temp::new();
        let mut input = input();
        let store = setup(&temp, &input);
        input.quote.other_total_upper_bound_microusd = Some(4_756_880);
        assert_eq!(
            generate(&store, &input)
                .unwrap()
                .reserve
                .remaining_reserve_microusd,
            0
        );
        input.quote.other_total_upper_bound_microusd = Some(4_756_881);
        assert!(generate(&store, &input).is_err());
        input.quote.other_total_upper_bound_microusd = Some(0);
        input
            .external_controls
            .as_mut()
            .unwrap()
            .maximum_poll_interval_seconds = 20 * 3600;
        assert!(generate(&store, &input).is_ok());
        input
            .external_controls
            .as_mut()
            .unwrap()
            .deletion_latency_upper_bound_seconds = 3600;
        assert!(generate(&store, &input).is_err());
    }

    #[test]
    fn latency_moves_proposed_deletion_earlier_and_missed_deadline_never_waits() {
        let temp = Temp::new();
        let mut input = input();
        let store = setup(&temp, &input);
        input
            .external_controls
            .as_mut()
            .unwrap()
            .deletion_latency_upper_bound_seconds = 60;
        let spec = generate(&store, &input).unwrap();
        assert_eq!(
            spec.absolute_deadline.proposed_timer_directives["OnCalendar"],
            "2026-10-02 15:58:59.999999 UTC"
        );
        assert_eq!(
            spec.startup_requirement_at(spec.original_deadline_unix_seconds),
            StartupRequirement::RequestDeletionWithoutExtendingOriginalDeadline
        );
        assert_eq!(
            spec.startup_requirement_at(spec.original_deadline_unix_seconds + 1),
            StartupRequirement::RequestDeletionWithoutExtendingOriginalDeadline
        );
        assert_eq!(
            spec.startup_requirement_at(input.evaluated_at_unix_seconds),
            StartupRequirement::ReconcileFreshLedgerAndProviderBeforeActivation
        );
        assert_eq!(
            spec.independent_backstop.check_no_later_than_utc,
            spec.absolute_deadline.proposed_timer_directives["OnCalendar"]
        );
    }

    #[test]
    fn pending_persistence_and_missing_tracked_costs_cannot_create_a_specification() {
        let temp = Temp::new();
        let mut input = input();
        let mut store = setup(&temp, &input);
        fs::write(temp.0.join("state/pending.json"), b"interrupted").unwrap();
        assert!(generate(&store, &input).is_err());
        store.discard_uncommitted_draft().unwrap();
        let mut next = store.ledger().unwrap().clone();
        next.begin_attempt("first".into(), input.start_unix_seconds)
            .unwrap();
        next.track_cvm(
            "workspace",
            "first",
            TrackedCvm {
                cvm_id: "one".into(),
                app_id: "app".into(),
                instance_id: "instance".into(),
                created_at_unix_seconds: input.start_unix_seconds,
                compute_and_disk_microusd_per_hour: 243_120,
            },
        )
        .unwrap();
        store.commit(&next).unwrap();
        assert!(generate(&store, &input).is_err());
        input.evaluated_at_unix_seconds += 60;
        input.start_unix_seconds += 60;
        assert!(generate(&store, &input).is_err());
    }

    #[test]
    fn maintained_utc_conversion_handles_epoch_leap_day_and_overflow() {
        assert_eq!(utc_calendar(0).unwrap(), "1970-01-01 00:00:00.000000 UTC");
        assert_eq!(
            utc_calendar(1_709_251_199_999_999).unwrap(),
            "2024-02-29 23:59:59.999999 UTC"
        );
        assert!(utc_calendar(u64::MAX).is_err());
        let unsupported = DateTime::parse_from_rfc3339("2200-01-01T00:00:00Z")
            .unwrap()
            .timestamp_micros();
        assert!(utc_calendar(u64::try_from(unsupported).unwrap()).is_err());
    }
}
