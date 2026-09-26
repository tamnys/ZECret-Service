//! Synthetic TLS and controlled clock transitions only. Real CLI invocations
//! always use the system clock and the fixed provider origin.
use super::*;
use crate::{
    DELETE_THRESHOLD_MICROUSD, MAX_LIFETIME_SECONDS,
    controller::ExperimentLedger,
    persistence::create_original_binding,
    provider_http::tests::{AUTH, Server, response},
};
use std::{
    fs,
    num::NonZeroUsize,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const HOST: &str = "cloud-api.phala.com";
const WORKSPACE: &str = "wks_synthetic_only";
const EXPERIMENT: &str = "synthetic-watchdog-observation";
const APP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INVENTORY: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/inventory.json");
const DETAIL: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/cvm-detail.json");
const USAGE: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/usage.json");
const EMPTY_USAGE: &str = r#"{"usage":[],"total":0,"total_cost":0}"#;
const PARTIAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n";

struct Fixture(PathBuf);
impl Fixture {
    fn new(start: u64, deadline: u64, initial: u64, rate: u64) -> Self {
        Self::with_targets(start, deadline, initial, rate, false)
    }
    fn with_targets(start: u64, deadline: u64, initial: u64, rate: u64, two: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.codex-tmp/watchdog-observation-tests");
        fs::create_dir_all(&base).unwrap();
        let path = fs::canonicalize(base).unwrap().join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let binding =
            ExperimentBinding::new(EXPERIMENT.into(), WORKSPACE.into(), start, deadline).unwrap();
        let mut ledger = ExperimentLedger::new(binding, initial).unwrap();
        ledger.begin_attempt("first".into(), start).unwrap();
        ledger
            .track_cvm(
                WORKSPACE,
                "first",
                TrackedCvm {
                    cvm_id: "synthetic-cvm-1".into(),
                    app_id: APP.into(),
                    instance_id: "1".repeat(40),
                    created_at_unix_seconds: start,
                    compute_and_disk_microusd_per_hour: rate,
                },
            )
            .unwrap();
        if two {
            ledger
                .track_cvm(
                    WORKSPACE,
                    "first",
                    TrackedCvm {
                        cvm_id: "synthetic-cvm-2".into(),
                        app_id: APP.into(),
                        instance_id: "2".repeat(40),
                        created_at_unix_seconds: start,
                        compute_and_disk_microusd_per_hour: rate,
                    },
                )
                .unwrap();
        }
        create_original_binding(&fixture.original(), &fixture.0.join("store"), &ledger).unwrap();
        drop(LedgerStore::initialize(&fixture.original()).unwrap());
        fixture
    }
    fn fresh() -> Self {
        let now = wall_millis().unwrap() / 1000;
        Self::new(now, now + MAX_LIFETIME_SECONDS, 17, 1)
    }
    fn original(&self) -> PathBuf {
        self.0.join("original.json")
    }
    fn open(&self) -> LedgerStore {
        LedgerStore::open(&self.original()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // This test owns the newly created disposable synthetic directory.
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn policy() -> WatchdogPolicy {
    // Relationships fit the existing 60-second synthetic server invocation.
    WatchdogPolicy {
        maximum_detection_interval: Duration::from_secs(60),
        deletion_latency_upper_bound: Duration::from_secs(40),
        scheduler_delay_allowance: Duration::ZERO,
        reconciliation_budget: Duration::from_secs(10),
        deletion_dispatch_budget: Duration::from_secs(40),
        fee_upper_bounds_microusd: 0,
    }
}
fn limits() -> ObservationLimits {
    ObservationLimits {
        inventory_page_size: 30,
        usage_page_size: 500,
        max_inventory_records: NonZeroUsize::new(2).unwrap(),
        max_usage_records_per_app: NonZeroUsize::new(2).unwrap(),
    }
}
fn bound() -> usize {
    [AUTH.len(), INVENTORY.len(), DETAIL.len(), USAGE.len()]
        .into_iter()
        .max()
        .unwrap()
}

#[tokio::test]
async fn complete_optional_observation_is_committed_without_charging_or_adopting() {
    let fixture = Fixture::fresh();
    let mut store = fixture.open();
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", INVENTORY),
            response("200 OK", DETAIL),
            response("200 OK", USAGE),
            response("200 OK", EMPTY_USAGE),
        ],
        HOST,
    )
    .await;
    let report = run_once(
        server.client(bound()),
        &mut store,
        EXPERIMENT,
        policy(),
        limits(),
    )
    .await
    .unwrap();
    assert!(report.invocation_completed);
    assert_eq!(report.observation.status, ObservationStatus::Committed);
    assert!(!report.initial_decision.deletion_required());
    assert!(!report.final_decision.unwrap().deletion_required());
    assert!(report.targets.is_empty());
    assert_eq!(report.final_committed_reference.unwrap().generation(), 1);
    let ledger = store.ledger().unwrap();
    assert_eq!(ledger.tracked_cvms().count(), 1);
    assert!(ledger.deletion_intents().is_empty());
    assert_eq!(
        ledger.observations()[0].untracked_inventory_ids,
        ["synthetic-cvm-partial"]
    );
    assert_eq!(ledger.observations()[0].usage_by_app[APP].len(), 2);
    assert!(
        serde_json::to_value(ledger).unwrap()["usage"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(!report.billing_reconciled && !report.cleanup_complete);
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.starts_with("GET "))
    );
}

#[tokio::test]
async fn optional_failure_without_trigger_reports_incomplete_without_mutation() {
    let fixture = Fixture::fresh();
    let mut store = fixture.open();
    let before = serde_json::to_value(store.ledger().unwrap()).unwrap();
    let server = Server::start(
        vec![response("200 OK", AUTH), response("503 Unavailable", "")],
        HOST,
    )
    .await;
    let report = run_once(
        server.client(bound()),
        &mut store,
        EXPERIMENT,
        policy(),
        limits(),
    )
    .await
    .unwrap();
    assert!(!report.invocation_completed);
    assert_eq!(report.observation.status, ObservationStatus::Incomplete);
    assert!(report.targets.is_empty());
    assert_eq!(
        serde_json::to_value(store.ledger().unwrap()).unwrap(),
        before
    );
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn optional_phase_timeout_keeps_original_dispatch_reserve() {
    let fixture = Fixture::fresh();
    let mut store = fixture.open();
    let server = Server::start(vec![PARTIAL.to_vec()], HOST).await;
    let client = server.client(bound());
    let original_deadline = client.invocation_deadline();
    let task = tokio::spawn(async move {
        let report = run_once(client, &mut store, EXPERIMENT, policy(), limits())
            .await
            .unwrap();
        (report, store)
    });
    server.wait_requests(1).await;
    tokio::time::pause();
    tokio::time::advance(policy().reconciliation_budget).await;
    let (report, store) = task.await.unwrap();
    assert!(Instant::now() < original_deadline);
    tokio::time::resume();
    assert!(!report.invocation_completed);
    assert_eq!(report.observation.status, ObservationStatus::Preempted);
    assert!(store.ledger().unwrap().observations().is_empty());
    assert!(store.ledger().unwrap().deletion_intents().is_empty());
    server.wait_closed(1).await;
}

#[tokio::test]
async fn time_and_cost_crossings_preempt_optional_reads_then_dispatch() {
    // Controlled wall transitions stay behind real time so the existing real
    // durable-intent/outcome clock checks still run unchanged. The test-only
    // callback is private; the CLI has no clock injection option.
    for cost_trigger in [false, true] {
        let now = wall_millis().unwrap() / 1000;
        let before = now - 60;
        let trigger = before + 5;
        let configured = policy();
        let deadline = if cost_trigger {
            before - 3600 + MAX_LIFETIME_SECONDS
        } else {
            trigger + configured.deletion_latency_upper_bound.as_secs()
        };
        let fixture = Fixture::new(
            before - 3600,
            deadline,
            if cost_trigger {
                DELETE_THRESHOLD_MICROUSD - 3605
            } else {
                0
            },
            if cost_trigger { 3600 } else { 1 },
        );
        let mut store = fixture.open();
        assert_eq!(
            configured
                .next_trigger_unix_millis(store.ledger().unwrap(), before * 1000)
                .unwrap(),
            trigger * 1000
        );
        let server = Server::start(
            vec![
                PARTIAL.to_vec(),
                response("200 OK", AUTH),
                response("404 Not Found", ""),
                b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            ],
            HOST,
        )
        .await;
        let client = server.client(bound());
        let task = tokio::spawn(async move {
            let mut samples = 0;
            let report =
                run_with_clock(client, &mut store, EXPERIMENT, configured, limits(), || {
                    samples += 1;
                    if samples <= 2 {
                        Ok(before * 1000)
                    } else {
                        wall_millis()
                    }
                })
                .await
                .unwrap();
            (report, store)
        });
        server.wait_requests(1).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(trigger - before)).await;
        tokio::time::resume();
        let (report, store) = task.await.unwrap();
        assert!(!report.initial_decision.deletion_required());
        assert_eq!(report.observation.status, ObservationStatus::Preempted);
        assert!(report.invocation_completed, "{report:?}");
        assert_eq!(report.targets.len(), 1);
        assert!(
            report
                .final_decision
                .unwrap()
                .reasons
                .contains(&if cost_trigger {
                    DeleteReason::CostThresholdReached
                } else {
                    DeleteReason::DeletionStartReached
                })
        );
        assert!(store.ledger().unwrap().observations().is_empty());
        assert_eq!(store.ledger().unwrap().deletion_intents().len(), 1);
        assert_eq!(server.requests.lock().unwrap().len(), 4);
    }
}

#[tokio::test]
async fn later_target_cannot_renew_original_invocation_after_partial_progress() {
    let now = wall_millis().unwrap() / 1000;
    let fixture = Fixture::with_targets(now - MAX_LIFETIME_SECONDS - 1, now - 1, 0, 1, true);
    let mut store = fixture.open();
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("404 Not Found", ""),
            b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            PARTIAL.to_vec(),
        ],
        HOST,
    )
    .await;
    let client = server.client(bound());
    let original = client.invocation_deadline();
    // Age the synthetic 60-second invocation by half before the pass. Its
    // remaining budget is now shorter than the explicit 40-second dispatch.
    tokio::time::pause();
    tokio::time::advance(client.invocation_budget() / 2).await;
    tokio::time::resume();
    let task = tokio::spawn(async move {
        let report = run_once(client, &mut store, EXPERIMENT, policy(), limits())
            .await
            .unwrap();
        (report, store)
    });
    server.wait_requests(4).await;
    tokio::time::pause();
    tokio::time::advance(original.saturating_duration_since(Instant::now())).await;
    let (report, store) = task.await.unwrap();
    // A renewed dispatch would run ten seconds beyond the original budget.
    // Half of that separation tolerates timer granularity while detecting it.
    assert!(Instant::now() < original + policy().reconciliation_budget / 2);
    tokio::time::resume();
    assert!(!report.invocation_completed);
    assert_eq!(report.targets.len(), 2);
    assert_eq!(
        report.targets[0]
            .deletion
            .as_ref()
            .unwrap()
            .provider_outcome,
        DeletionOutcome::Initiated204
    );
    assert!(report.targets[1].deletion.is_none());
    assert_eq!(store.ledger().unwrap().deletion_intents().len(), 1);
    assert_eq!(server.requests.lock().unwrap().len(), 4);
    assert_eq!(report.retained_target_count, 2);
}

#[tokio::test]
async fn backwards_clock_stops_before_optional_network_work() {
    let fixture = Fixture::fresh();
    let mut store = fixture.open();
    let server = Server::start(vec![], HOST).await;
    let now = wall_millis().unwrap();
    let mut first = true;
    let report = run_with_clock(
        server.client(bound()),
        &mut store,
        EXPERIMENT,
        policy(),
        limits(),
        || {
            if first {
                first = false;
                Ok(now)
            } else {
                Ok(now - 1)
            }
        },
    )
    .await
    .unwrap();
    assert!(!report.invocation_completed);
    assert_eq!(
        report.stopped_reason.as_deref(),
        Some("watchdog clock is invalid or moved backwards")
    );
    assert!(server.requests.lock().unwrap().is_empty());
    assert_eq!(store.planning_reference().unwrap().generation(), 0);
}
