//! Offline timing arithmetic. Configured timeouts and delay allowances remain
//! operator assumptions, not measured scheduler or provider-completion evidence.

use crate::{
    LifecycleError,
    watchdog::{PolicyDecision, WatchdogPolicy},
};
use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;
use std::time::Duration;

// systemd's documented best timer accuracy, not an inferred scheduling bound:
// https://github.com/systemd/systemd/blob/v255/man/systemd.timer.xml
const TIMER_ACCURACY_MICROSECONDS: u64 = 1;
const MICROSECONDS_PER_MILLISECOND: u64 = 1_000;

#[derive(Debug, Serialize)]
pub struct ScheduleTiming {
    pub maximum_detection_interval_ms: u64,
    pub deletion_latency_ms: u64,
    pub catch_up_allowance_ms: u64,
    pub process_runtime_bound_ms: u64,
    pub manager_delay_allowance_ms: u64,
    pub reconciliation_budget_ms: u64,
    pub dispatch_budget_ms: u64,
    pub invocation_budget_ms: u64,
    pub timer_accuracy_microseconds: u64,
    pub periodic_gap_microseconds: u64,
    pub absolute_calendar_utc: String,
    pub watchdog_due_at_unix_millis: u64,
    pub original_deadline_unix_millis: u64,
}

fn milliseconds(duration: Duration) -> Result<u64, LifecycleError> {
    if duration.subsec_nanos() % 1_000_000 != 0 {
        return Err(LifecycleError(
            "schedule timing requires exact whole milliseconds",
        ));
    }
    u64::try_from(duration.as_millis())
        .map_err(|_| LifecycleError("schedule duration exceeds millisecond representation"))
}

fn calendar(timestamp_millis: u64) -> Result<String, LifecycleError> {
    let value = i64::try_from(timestamp_millis)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .ok_or(LifecycleError(
            "schedule timestamp is not representable in UTC",
        ))?;
    // The target parser uses MIN_YEAR=1970 and MAX_YEAR=2199:
    // https://github.com/systemd/systemd/blob/v255/src/shared/calendarspec.c
    if !(1970..=2199).contains(&value.year()) {
        return Err(LifecycleError(
            "schedule year is outside the systemd calendar parser range",
        ));
    }
    Ok(value.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string())
}

/// Account for a timer event arriving while the shared service is still running.
/// OnUnitInactiveSec resumes after the service becomes inactive or failed, so
/// the complete catch-up assumption is T + I + J + R + A <= S. J must include
/// manager/launch delay, timer slack and timeout-to-inactive overshoot outside T.
/// The watchdog separately requires R + S <= P and accounts for P + L in cost.
pub(super) fn derive(
    policy: &WatchdogPolicy,
    invocation_budget: Duration,
    process_runtime_bound: Duration,
    manager_delay_allowance: Duration,
    decision: &PolicyDecision,
) -> Result<ScheduleTiming, LifecycleError> {
    policy.validate(invocation_budget)?;
    let invocation_budget_ms = milliseconds(invocation_budget)?;
    let process_runtime_bound_ms = milliseconds(process_runtime_bound)?;
    let manager_delay_allowance_ms = milliseconds(manager_delay_allowance)?;
    if process_runtime_bound_ms == 0 || process_runtime_bound_ms < invocation_budget_ms {
        return Err(LifecycleError(
            "service runtime bound cannot be shorter than the invocation budget",
        ));
    }
    let maximum_detection_interval_ms = milliseconds(policy.maximum_detection_interval)?;
    let deletion_latency_ms = milliseconds(policy.deletion_latency_upper_bound)?;
    let catch_up_allowance_ms = milliseconds(policy.scheduler_delay_allowance)?;
    let reconciliation_budget_ms = milliseconds(policy.reconciliation_budget)?;
    let dispatch_budget_ms = milliseconds(policy.deletion_dispatch_budget)?;
    let occupied_ms = process_runtime_bound_ms
        .checked_add(manager_delay_allowance_ms)
        .and_then(|total| total.checked_add(reconciliation_budget_ms))
        .ok_or(LifecycleError("schedule catch-up arithmetic overflow"))?;
    let periodic_gap_microseconds = catch_up_allowance_ms
        .checked_mul(MICROSECONDS_PER_MILLISECOND)
        .zip(occupied_ms.checked_mul(MICROSECONDS_PER_MILLISECOND))
        .and_then(|(available, occupied)| available.checked_sub(occupied))
        .and_then(|remaining| remaining.checked_sub(TIMER_ACCURACY_MICROSECONDS))
        .filter(|gap| *gap > 0)
        .ok_or(LifecycleError(
            "schedule catch-up allowance cannot contain work, delays and a positive timer gap",
        ))?;
    let due = u128::from(decision.original_deadline_unix_millis)
        .saturating_sub(u128::from(deletion_latency_ms) + u128::from(catch_up_allowance_ms));
    if u128::from(decision.deletion_start_unix_millis) != due {
        return Err(LifecycleError(
            "schedule decision does not match the supplied watchdog timing",
        ));
    }
    // Do not subtract accuracy from this event: a sole invocation before the
    // watchdog's due threshold could finish without dispatching cleanup. Its
    // accuracy and a dropped event's catch-up delay are already included in S.
    let absolute_calendar_utc = calendar(decision.deletion_start_unix_millis)?;
    Ok(ScheduleTiming {
        maximum_detection_interval_ms,
        deletion_latency_ms,
        catch_up_allowance_ms,
        process_runtime_bound_ms,
        manager_delay_allowance_ms,
        reconciliation_budget_ms,
        dispatch_budget_ms,
        invocation_budget_ms,
        timer_accuracy_microseconds: TIMER_ACCURACY_MICROSECONDS,
        periodic_gap_microseconds,
        absolute_calendar_utc,
        watchdog_due_at_unix_millis: decision.deletion_start_unix_millis,
        original_deadline_unix_millis: decision.original_deadline_unix_millis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{ExperimentBinding, ExperimentLedger};
    use chrono::TimeZone;

    fn policy() -> WatchdogPolicy {
        // Synthetic values chosen to exercise exact arithmetic, not defaults.
        WatchdogPolicy {
            maximum_detection_interval: Duration::from_millis(120_000),
            deletion_latency_upper_bound: Duration::from_millis(60_000),
            scheduler_delay_allowance: Duration::from_millis(60_000),
            reconciliation_budget: Duration::from_millis(1_000),
            deletion_dispatch_budget: Duration::from_millis(2_000),
            fee_upper_bounds_microusd: 0,
        }
    }

    fn decision(policy: &WatchdogPolicy, deadline: u64, now: u64) -> PolicyDecision {
        let start = deadline.saturating_sub(3_600);
        let binding =
            ExperimentBinding::new("synthetic".into(), "workspace".into(), start, deadline)
                .unwrap();
        policy
            .evaluate(&ExperimentLedger::new(binding, 0).unwrap(), now * 1_000)
            .unwrap()
    }

    fn derive_fixture(
        policy: &WatchdogPolicy,
        decision: &PolicyDecision,
    ) -> Result<ScheduleTiming, LifecycleError> {
        derive(
            policy,
            Duration::from_millis(3_000),
            Duration::from_millis(5_000),
            Duration::from_millis(1_000),
            decision,
        )
    }

    #[test]
    fn catch_up_equation_and_calendar_match_watchdog_without_early_trigger() {
        let policy = policy();
        let deadline = Utc
            .with_ymd_and_hms(2028, 3, 1, 0, 0, 0)
            .unwrap()
            .timestamp() as u64;
        let decision = decision(&policy, deadline, deadline - 3_600);
        let timing = derive_fixture(&policy, &decision).unwrap();
        assert_eq!(timing.periodic_gap_microseconds, 52_999_999);
        assert_eq!(
            timing.absolute_calendar_utc,
            "2028-02-29 23:58:00.000000 UTC"
        );
        assert_eq!(
            timing.watchdog_due_at_unix_millis,
            decision.deletion_start_unix_millis
        );
        assert_eq!(
            (timing.process_runtime_bound_ms
                + timing.manager_delay_allowance_ms
                + timing.reconciliation_budget_ms)
                * 1_000
                + timing.periodic_gap_microseconds
                + timing.timer_accuracy_microseconds,
            timing.catch_up_allowance_ms * 1_000
        );
        assert_eq!(
            timing.watchdog_due_at_unix_millis
                + timing.catch_up_allowance_ms
                + timing.deletion_latency_ms,
            timing.original_deadline_unix_millis
        );
        assert!(
            timing.reconciliation_budget_ms + timing.catch_up_allowance_ms
                <= timing.maximum_detection_interval_ms
        );
        assert_eq!(timing.dispatch_budget_ms, 2_000);
        assert_eq!(timing.invocation_budget_ms, 3_000);
    }

    #[test]
    fn overdue_and_pre_epoch_due_keep_original_calendar_for_startup_catch_up() {
        let policy = policy();
        let old = decision(&policy, 3_600, 3_601);
        assert!(old.deletion_required());
        let timing = derive_fixture(&policy, &old).unwrap();
        assert_eq!(
            timing.absolute_calendar_utc,
            "1970-01-01 00:58:00.000000 UTC"
        );
        assert_eq!(timing.original_deadline_unix_millis, 3_600_000);
        let pre_epoch = decision(&policy, 60, 0);
        assert!(pre_epoch.deletion_required());
        let timing = derive_fixture(&policy, &pre_epoch).unwrap();
        assert_eq!(
            timing.absolute_calendar_utc,
            "1970-01-01 00:00:00.000000 UTC"
        );
        assert_eq!(timing.original_deadline_unix_millis, 60_000);
    }

    #[test]
    fn nonpositive_gap_and_mismatched_decision_are_rejected() {
        let mut policy = policy();
        for allowance in [0, 6_999, 7_000] {
            policy.scheduler_delay_allowance = Duration::from_millis(allowance);
            let decision = decision(&policy, 3_600, 0);
            assert!(derive_fixture(&policy, &decision).is_err());
        }
        policy.scheduler_delay_allowance = Duration::from_millis(7_001);
        let mut decision = decision(&policy, 3_600, 0);
        assert_eq!(
            derive_fixture(&policy, &decision)
                .unwrap()
                .periodic_gap_microseconds,
            999
        );
        decision.deletion_start_unix_millis -= 1;
        assert!(derive_fixture(&policy, &decision).is_err());
    }

    #[test]
    fn runtime_and_delay_inputs_preserve_exact_milliseconds_and_network_budget() {
        let policy = policy();
        let decision = decision(&policy, 3_600, 0);
        let budget = Duration::from_millis(3_000);
        for runtime in [
            Duration::ZERO,
            Duration::from_millis(2_999),
            Duration::from_nanos(3_000_000_001),
            Duration::MAX,
        ] {
            assert!(derive(&policy, budget, runtime, Duration::ZERO, &decision).is_err());
        }
        assert!(derive(&policy, budget, budget, Duration::ZERO, &decision).is_ok());
        for delay in [Duration::from_nanos(1), Duration::MAX] {
            assert!(derive(&policy, budget, budget, delay, &decision).is_err());
        }
        assert!(
            derive(
                &policy,
                Duration::from_millis(2_999),
                budget,
                Duration::ZERO,
                &decision
            )
            .is_err()
        );
    }

    #[test]
    fn overflowing_microseconds_and_unsupported_calendar_year_fail_closed() {
        let mut policy = policy();
        policy.scheduler_delay_allowance = Duration::from_millis(u64::MAX / 1_000 + 1);
        policy.maximum_detection_interval =
            policy.scheduler_delay_allowance + policy.reconciliation_budget;
        let overflow = decision(&policy, 3_600, 0);
        assert!(derive_fixture(&policy, &overflow).is_err());
        assert_eq!(calendar(0).unwrap(), "1970-01-01 00:00:00.000000 UTC");
        let last = Utc
            .with_ymd_and_hms(2199, 12, 31, 23, 59, 59)
            .unwrap()
            .timestamp_millis() as u64;
        assert_eq!(
            calendar(last + 999).unwrap(),
            "2199-12-31 23:59:59.999000 UTC"
        );
        assert!(calendar(last + 1_000).is_err());
        assert!(calendar(u64::MAX).is_err());
    }
}
