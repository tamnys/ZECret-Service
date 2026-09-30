//! Arithmetic for an explicitly configured external watchdog invocation.
//! Inputs are operator assumptions, not measured-evidence or activation receipts.
//! No timer, network operation, default interval or cleanup proof is produced.

use crate::{
    DELETE_THRESHOLD_MICROUSD, LifecycleError, TOTAL_CEILING_MICROUSD, controller::ExperimentLedger,
};
use serde::Serialize;
use std::time::Duration;

const MILLIS_PER_SECOND: u64 = 1_000;
const MILLIS_PER_HOUR: u128 = 3_600_000;

/// Every timing and fee assumption must be explicitly supplied. Detection time
/// includes scheduling delay and reconciliation; it is not a timer interval.
/// The deletion bound includes dispatch, provider completion and readback.
#[derive(Debug, Clone)]
pub struct WatchdogPolicy {
    pub maximum_detection_interval: Duration,
    pub deletion_latency_upper_bound: Duration,
    pub scheduler_delay_allowance: Duration,
    pub reconciliation_budget: Duration,
    pub deletion_dispatch_budget: Duration,
    pub fee_upper_bounds_microusd: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteReason {
    DeletionStartReached,
    CostThresholdReached,
    ReserveInsufficient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReserveProjection {
    #[serde(serialize_with = "exact_decimal")]
    pub delayed_cost_microusd: u128,
    pub fee_upper_bounds_microusd: u64,
    #[serde(serialize_with = "exact_decimal")]
    pub cost_at_trigger_plus_delay_and_fees_microusd: u128,
    pub total_ceiling_microusd: u64,
    pub fits: bool,
}

fn exact_decimal<S: serde::Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    // Keep values outside JSON's commonly supported integer range reviewable
    // without truncation, floating point or a report-conversion failure.
    serializer.collect_str(value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDecision {
    pub evaluated_at_unix_millis: u64,
    pub original_deadline_unix_millis: u64,
    /// A mathematically pre-epoch start is represented as zero and is already
    /// due. A start before experiment creation is otherwise retained verbatim.
    pub deletion_start_unix_millis: u64,
    pub conservative_cost_microusd: u64,
    pub aggregate_microusd_per_hour: u64,
    pub reserve: ReserveProjection,
    pub reasons: Vec<DeleteReason>,
}

impl PolicyDecision {
    pub fn deletion_required(&self) -> bool {
        !self.reasons.is_empty()
    }
}

struct CheckedPolicy {
    detection_ms: u64,
    deletion_ms: u64,
    scheduler_ms: u64,
    phase_total_ms: u64,
}

fn milliseconds(duration: Duration) -> Result<u64, LifecycleError> {
    if duration.subsec_nanos() % 1_000_000 != 0 {
        return Err(LifecycleError(
            "watchdog timing requires exact whole milliseconds",
        ));
    }
    u64::try_from(duration.as_millis())
        .map_err(|_| LifecycleError("watchdog duration exceeds millisecond representation"))
}

impl WatchdogPolicy {
    fn checked(&self) -> Result<CheckedPolicy, LifecycleError> {
        let detection_ms = milliseconds(self.maximum_detection_interval)?;
        let deletion_ms = milliseconds(self.deletion_latency_upper_bound)?;
        let scheduler_ms = milliseconds(self.scheduler_delay_allowance)?;
        let reconciliation_ms = milliseconds(self.reconciliation_budget)?;
        let dispatch_ms = milliseconds(self.deletion_dispatch_budget)?;
        if detection_ms == 0
            || deletion_ms == 0
            || reconciliation_ms == 0
            || dispatch_ms == 0
            || reconciliation_ms > detection_ms
            || dispatch_ms > deletion_ms
            || scheduler_ms > detection_ms
        {
            return Err(LifecycleError(
                "watchdog phase budgets do not fit supplied timing bounds",
            ));
        }
        if reconciliation_ms
            .checked_add(scheduler_ms)
            .is_none_or(|total| total > detection_ms)
        {
            return Err(LifecycleError(
                "watchdog reconciliation and scheduler delay exceed detection bound",
            ));
        }
        let phase_total_ms = reconciliation_ms
            .checked_add(dispatch_ms)
            .ok_or(LifecycleError("watchdog phase budget overflow"))?;
        Ok(CheckedPolicy {
            detection_ms,
            deletion_ms,
            scheduler_ms,
            phase_total_ms,
        })
    }

    pub fn validate(&self, invocation_budget: Duration) -> Result<(), LifecycleError> {
        let checked = self.checked()?;
        if checked.phase_total_ms > milliseconds(invocation_budget)? {
            return Err(LifecycleError(
                "watchdog phases exceed the invocation budget",
            ));
        }
        Ok(())
    }

    /// Earliest already-known trigger while the caller retains the ledger
    /// lock. This bounds optional observation without introducing polling.
    /// Cost uses the existing ledger's monotone, whole-second cost model.
    pub(super) fn next_trigger_unix_millis(
        &self,
        ledger: &ExperimentLedger,
        now_unix_millis: u64,
    ) -> Result<u64, LifecycleError> {
        let decision = self.evaluate(ledger, now_unix_millis)?;
        if decision.deletion_required() {
            return Ok(now_unix_millis);
        }
        let candidate = decision.deletion_start_unix_millis;
        let mut low = now_unix_millis / MILLIS_PER_SECOND;
        let mut high = candidate / MILLIS_PER_SECOND;
        if ledger.planning_cost_at(high)? < DELETE_THRESHOLD_MICROUSD {
            return Ok(candidate);
        }
        // Current cost is below the threshold and high reaches it. Narrow the
        // first triggering whole second without adding timestamps together.
        while low < high {
            let middle = low + (high - low) / 2;
            if ledger.planning_cost_at(middle)? >= DELETE_THRESHOLD_MICROUSD {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        let cost_trigger = low.checked_mul(MILLIS_PER_SECOND).ok_or(LifecycleError(
            "watchdog cost trigger overflows milliseconds",
        ))?;
        Ok(candidate.min(cost_trigger))
    }

    /// Evaluate current original-bound state without invoking the deployment
    /// planner: stale quotes, exceeded costs and overdue deadlines cannot veto
    /// cleanup. Retained provider usage remains unjoined and unaccepted here.
    /// Millisecond timing does not increase the retained ledger clock's
    /// whole-second precision; its existing planning function supplies the cost.
    pub fn evaluate(
        &self,
        ledger: &ExperimentLedger,
        now_unix_millis: u64,
    ) -> Result<PolicyDecision, LifecycleError> {
        let checked = self.checked()?;
        let conservative_cost_microusd =
            ledger.planning_cost_at(now_unix_millis / MILLIS_PER_SECOND)?;
        let (_, deadline) = ledger.binding().original_window();
        let deadline_ms = deadline
            .checked_mul(MILLIS_PER_SECOND)
            .ok_or(LifecycleError(
                "original watchdog deadline overflows milliseconds",
            ))?;
        let aggregate_microusd_per_hour =
            ledger.tracked_rates().try_fold(0_u64, |sum, (_, rate)| {
                sum.checked_add(rate)
                    .ok_or(LifecycleError("aggregate watchdog resource rate overflow"))
            })?;
        // Design section 13 and the retained adapter timing contract require
        // $45 + ceil(rate * (detection + deletion) / hour) + fees <= $50.
        // Milliseconds are retained through multiplication and rounded upward.
        let delay_ms = u128::from(checked.detection_ms) + u128::from(checked.deletion_ms);
        // Divide the duration into whole hours and a remainder before scaling.
        // The final exact cost fits u128 for u64 rates and millisecond bounds,
        // even when an undivided rate * duration intermediate would not.
        let hourly = u128::from(aggregate_microusd_per_hour);
        let whole_cost = hourly
            .checked_mul(delay_ms / MILLIS_PER_HOUR)
            .ok_or(LifecycleError("watchdog reserve arithmetic overflow"))?;
        let partial_cost = hourly
            .checked_mul(delay_ms % MILLIS_PER_HOUR)
            .ok_or(LifecycleError("watchdog reserve arithmetic overflow"))?
            .div_ceil(MILLIS_PER_HOUR);
        let delayed_cost_microusd = whole_cost
            .checked_add(partial_cost)
            .ok_or(LifecycleError("watchdog reserve arithmetic overflow"))?;
        let cost_at_trigger_plus_delay_and_fees_microusd = u128::from(DELETE_THRESHOLD_MICROUSD)
            .checked_add(delayed_cost_microusd)
            .and_then(|cost| cost.checked_add(u128::from(self.fee_upper_bounds_microusd)))
            .ok_or(LifecycleError("watchdog reserve arithmetic overflow"))?;
        let fits =
            cost_at_trigger_plus_delay_and_fees_microusd <= u128::from(TOTAL_CEILING_MICROUSD);
        let lead_ms = u128::from(checked.deletion_ms) + u128::from(checked.scheduler_ms);
        // Underflow means the mathematically required start is before Unix
        // epoch; every representable invocation is then already due.
        let deletion_start_unix_millis =
            u64::try_from(u128::from(deadline_ms).saturating_sub(lead_ms))
                .map_err(|_| LifecycleError("watchdog deletion start overflows milliseconds"))?;
        let mut reasons = Vec::new();
        if u128::from(now_unix_millis) + lead_ms >= u128::from(deadline_ms) {
            reasons.push(DeleteReason::DeletionStartReached);
        }
        if conservative_cost_microusd >= DELETE_THRESHOLD_MICROUSD {
            reasons.push(DeleteReason::CostThresholdReached);
        }
        if !fits {
            // An insufficient reserve is a reason to clean up early, not to
            // refuse cleanup or silently increase the original cost ceiling.
            reasons.push(DeleteReason::ReserveInsufficient);
        }
        Ok(PolicyDecision {
            evaluated_at_unix_millis: now_unix_millis,
            original_deadline_unix_millis: deadline_ms,
            deletion_start_unix_millis,
            conservative_cost_microusd,
            aggregate_microusd_per_hour,
            reserve: ReserveProjection {
                delayed_cost_microusd,
                fee_upper_bounds_microusd: self.fee_upper_bounds_microusd,
                cost_at_trigger_plus_delay_and_fees_microusd,
                total_ceiling_microusd: TOTAL_CEILING_MICROUSD,
                fits,
            },
            reasons,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MAX_LIFETIME_SECONDS,
        controller::{ExperimentBinding, TrackedCvm, UsageRecord},
    };

    const START: u64 = 1_000;

    fn policy() -> WatchdogPolicy {
        // Synthetic arithmetic inputs only, never production timing defaults.
        WatchdogPolicy {
            maximum_detection_interval: Duration::from_millis(1_000),
            deletion_latency_upper_bound: Duration::from_millis(2_000),
            scheduler_delay_allowance: Duration::ZERO,
            reconciliation_budget: Duration::from_millis(300),
            deletion_dispatch_budget: Duration::from_millis(500),
            fee_upper_bounds_microusd: 0,
        }
    }

    fn ledger(start: u64, duration: u64, rate: u64) -> ExperimentLedger {
        let binding = ExperimentBinding::new(
            "synthetic-watchdog".into(),
            "workspace".into(),
            start,
            start + duration,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 0).unwrap();
        ledger.begin_attempt("first".into(), start).unwrap();
        ledger
            .track_cvm(
                "workspace",
                "first",
                TrackedCvm {
                    cvm_id: "one".into(),
                    app_id: "app".into(),
                    instance_id: Some("instance".into()),
                    created_at_unix_seconds: start,
                    compute_and_disk_microusd_per_hour: rate,
                },
            )
            .unwrap();
        ledger
    }

    #[test]
    fn exact_phase_budgets_are_required_without_defaults_or_truncation() {
        let baseline = policy();
        assert!(baseline.validate(Duration::from_millis(800)).is_ok());
        assert!(baseline.validate(Duration::from_millis(799)).is_err());
        assert!(
            baseline
                .validate(Duration::from_nanos(800_000_001))
                .is_err()
        );
        let mut sequential = baseline.clone();
        sequential.scheduler_delay_allowance = Duration::from_millis(700);
        assert!(sequential.validate(Duration::from_millis(800)).is_ok());
        sequential.scheduler_delay_allowance = Duration::from_millis(701);
        assert!(sequential.validate(Duration::from_millis(800)).is_err());
        sequential.maximum_detection_interval = Duration::from_millis(u64::MAX);
        sequential.scheduler_delay_allowance = Duration::from_millis(u64::MAX);
        assert!(sequential.validate(Duration::from_millis(800)).is_err());
        for field in ["detection", "deletion", "reconciliation", "dispatch"] {
            let mut invalid = baseline.clone();
            match field {
                "detection" => invalid.maximum_detection_interval = Duration::ZERO,
                "deletion" => invalid.deletion_latency_upper_bound = Duration::ZERO,
                "reconciliation" => invalid.reconciliation_budget = Duration::ZERO,
                _ => invalid.deletion_dispatch_budget = Duration::ZERO,
            }
            assert!(
                invalid.validate(Duration::from_secs(10)).is_err(),
                "{field}"
            );
        }
        for field in [
            "reconciliation",
            "dispatch",
            "scheduler",
            "fraction",
            "representation",
            "sum",
        ] {
            let mut invalid = baseline.clone();
            match field {
                "reconciliation" => invalid.reconciliation_budget = Duration::from_millis(1_001),
                "dispatch" => invalid.deletion_dispatch_budget = Duration::from_millis(2_001),
                "scheduler" => invalid.scheduler_delay_allowance = Duration::from_millis(1_001),
                "fraction" => invalid.scheduler_delay_allowance = Duration::from_nanos(1),
                "representation" => {
                    invalid.maximum_detection_interval = Duration::from_secs(u64::MAX)
                }
                _ => {
                    invalid.maximum_detection_interval = Duration::from_millis(u64::MAX);
                    invalid.deletion_latency_upper_bound = Duration::from_millis(u64::MAX);
                    invalid.reconciliation_budget = Duration::from_millis(u64::MAX);
                }
            }
            assert!(
                invalid.validate(Duration::from_millis(u64::MAX)).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn exact_deadline_start_and_overdue_evaluation_preserve_original_policy() {
        let ledger = ledger(START, MAX_LIFETIME_SECONDS, 243_120);
        let before = serde_json::to_value(&ledger).unwrap();
        let mut policy = policy();
        policy.deletion_latency_upper_bound = Duration::from_millis(2_500);
        policy.scheduler_delay_allowance = Duration::from_millis(250);
        let deadline = (START + MAX_LIFETIME_SECONDS) * 1_000;
        let deletion_start = deadline - 2_750;
        assert!(
            !policy
                .evaluate(&ledger, deletion_start - 1)
                .unwrap()
                .deletion_required()
        );
        for now in [deletion_start, deadline, deadline + 1] {
            let decision = policy.evaluate(&ledger, now).unwrap();
            assert!(
                decision
                    .reasons
                    .contains(&DeleteReason::DeletionStartReached)
            );
            assert_eq!(decision.original_deadline_unix_millis, deadline);
            assert_eq!(decision.deletion_start_unix_millis, deletion_start);
        }
        assert_eq!(serde_json::to_value(&ledger).unwrap(), before);
        assert!(policy.evaluate(&ledger, START * 1_000 - 1).is_err());
    }

    #[test]
    fn insufficient_reserve_and_recorded_cost_request_early_cleanup() {
        let ledger = ledger(START, MAX_LIFETIME_SECONDS, 243_120);
        let mut policy = policy();
        let first = policy.evaluate(&ledger, START * 1_000).unwrap();
        assert_eq!(first.reserve.delayed_cost_microusd, 203);
        policy.fee_upper_bounds_microusd = 5_000_000 - 203;
        assert!(
            policy
                .evaluate(&ledger, START * 1_000)
                .unwrap()
                .reserve
                .fits
        );
        policy.fee_upper_bounds_microusd += 1;
        let reserve = policy.evaluate(&ledger, START * 1_000).unwrap();
        assert_eq!(reserve.reasons, [DeleteReason::ReserveInsufficient]);
        assert!(!reserve.reserve.fits);
        policy.fee_upper_bounds_microusd = 0;
        for (amount, micros, due) in [
            ("44.999999", 44_999_999, false),
            ("45", 45_000_000, true),
            ("50.01", 50_010_000, true),
        ] {
            let mut charged = ledger.clone();
            charged
                .record_usage(UsageRecord {
                    billing_key: "retained-known-cost".into(),
                    app_id: "app".into(),
                    instance_id: "instance".into(),
                    usage_type: "storage".into(),
                    cost_usd_decimal: amount.into(),
                })
                .unwrap();
            let cost = policy.evaluate(&charged, START * 1_000).unwrap();
            assert_eq!(
                cost.reasons.contains(&DeleteReason::CostThresholdReached),
                due
            );
            assert_eq!(cost.conservative_cost_microusd, micros);
        }
    }

    #[test]
    fn millisecond_reserve_rounding_and_all_tracked_rates_are_retained() {
        let mut ledger = ledger(START, MAX_LIFETIME_SECONDS, 1);
        ledger
            .track_cvm(
                "workspace",
                "first",
                TrackedCvm {
                    cvm_id: "two".into(),
                    app_id: "app2".into(),
                    instance_id: Some("instance2".into()),
                    created_at_unix_seconds: START,
                    compute_and_disk_microusd_per_hour: 1,
                },
            )
            .unwrap();
        let policy = WatchdogPolicy {
            maximum_detection_interval: Duration::from_millis(1),
            deletion_latency_upper_bound: Duration::from_millis(1),
            reconciliation_budget: Duration::from_millis(1),
            deletion_dispatch_budget: Duration::from_millis(1),
            ..policy()
        };
        policy.validate(Duration::from_millis(2)).unwrap();
        let decision = policy.evaluate(&ledger, START * 1_000).unwrap();
        assert_eq!(decision.aggregate_microusd_per_hour, 2);
        assert_eq!(decision.reserve.delayed_cost_microusd, 1);
        assert_eq!(
            decision
                .reserve
                .cost_at_trigger_plus_delay_and_fees_microusd,
            45_000_001
        );
    }

    #[test]
    fn lead_before_start_or_unix_epoch_is_due_without_renewing_deadline() {
        for start in [0, START] {
            let ledger = ledger(start, 1, 1);
            let decision = policy().evaluate(&ledger, start * 1_000).unwrap();
            assert_eq!(decision.original_deadline_unix_millis, (start + 1) * 1_000);
            assert_eq!(
                decision.deletion_start_unix_millis,
                (start * 1_000).saturating_sub(1_000)
            );
            assert_eq!(decision.reasons, [DeleteReason::DeletionStartReached]);
        }
    }

    #[test]
    fn overflow_is_rejected_and_large_representable_costs_are_not_wrapped() {
        let start = u64::MAX / 1_000;
        let late = ledger(start, 1, 1);
        assert!(policy().evaluate(&late, start * 1_000).is_err());
        let mut huge = ledger(START, 1, u64::MAX);
        let mut policy = policy();
        policy.maximum_detection_interval = Duration::from_millis(u64::MAX);
        policy.deletion_latency_upper_bound = Duration::from_millis(u64::MAX);
        let decision = policy.evaluate(&huge, START * 1_000).unwrap();
        assert!(decision.reserve.delayed_cost_microusd > u128::from(u64::MAX));
        assert!(
            decision
                .reasons
                .contains(&DeleteReason::ReserveInsufficient)
        );
        let reported = serde_json::to_value(&decision).unwrap();
        assert_eq!(
            reported["reserve"]["delayed_cost_microusd"],
            decision.reserve.delayed_cost_microusd.to_string()
        );
        huge.track_cvm(
            "workspace",
            "first",
            TrackedCvm {
                cvm_id: "two".into(),
                app_id: "app2".into(),
                instance_id: Some("instance2".into()),
                created_at_unix_seconds: START,
                compute_and_disk_microusd_per_hour: 1,
            },
        )
        .unwrap();
        assert!(policy.evaluate(&huge, START * 1_000).is_err());
    }

    #[test]
    fn next_trigger_finds_exact_cost_second_and_returns_now_if_already_due() {
        // 3,600,000 microUSD/hour = 1,000 microUSD/second. $45 is
        // reached after exactly 45,000 seconds in the retained cost model.
        for start in [START, u64::MAX / 1_000 - MAX_LIFETIME_SECONDS - 1] {
            let ledger = ledger(start, MAX_LIFETIME_SECONDS, 3_600_000);
            let trigger = (start + 45_000) * 1_000;
            for now in [start * 1_000, start * 1_000 + 999, trigger - 1] {
                assert_eq!(
                    policy().next_trigger_unix_millis(&ledger, now).unwrap(),
                    trigger
                );
            }
            for now in [trigger, trigger + 123] {
                assert_eq!(
                    policy().next_trigger_unix_millis(&ledger, now).unwrap(),
                    now
                );
            }
        }
    }

    #[test]
    fn next_trigger_retains_fractional_deadline_and_immediate_reserve_failure() {
        let ledger = ledger(START, MAX_LIFETIME_SECONDS, 243_120);
        let mut policy = policy();
        policy.deletion_latency_upper_bound = Duration::from_millis(2_500);
        policy.scheduler_delay_allowance = Duration::from_millis(250);
        let candidate = (START + MAX_LIFETIME_SECONDS) * 1_000 - 2_750;
        for now in [START * 1_000, candidate - 1] {
            assert_eq!(
                policy.next_trigger_unix_millis(&ledger, now).unwrap(),
                candidate
            );
        }
        assert_eq!(
            policy
                .next_trigger_unix_millis(&ledger, candidate + 1)
                .unwrap(),
            candidate + 1
        );
        policy.fee_upper_bounds_microusd = 5_000_000;
        assert_eq!(
            policy
                .next_trigger_unix_millis(&ledger, START * 1_000)
                .unwrap(),
            START * 1_000
        );
    }
}
