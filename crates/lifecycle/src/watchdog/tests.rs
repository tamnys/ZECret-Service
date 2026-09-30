//! Whole-ledger execution against a synthetic loopback TLS provider only.
//! These tests create no provider resources, credentials or external jobs.

use super::*;
use crate::{
    MAX_LIFETIME_SECONDS,
    controller::{
        DeletionOutcome, DeletionRetryRecord, ExperimentBinding, ExperimentLedger, TrackedCvm,
    },
    persistence::{StoreError, create_original_binding},
    provider_http::tests::{AUTH, Server, response},
    reconciliation::ObservedDetail,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{
    fs,
    num::NonZeroUsize,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

const HOST: &str = "cloud-api.phala.com";
const WORKSPACE: &str = "wks_synthetic_only";
const EXPERIMENT: &str = "synthetic-watchdog";
const START: u64 = 1_767_225_600;
const FIRST: &str = "synthetic-cvm-1";
const SECOND: &str = "synthetic-cvm-2";
const DETAIL: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/cvm-detail.json");

struct Fixture(PathBuf);
impl Fixture {
    fn new(two_targets: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.codex-tmp/watchdog-runner-tests");
        fs::create_dir_all(&base).unwrap();
        let path = fs::canonicalize(base).unwrap().join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let binding = ExperimentBinding::new(
            EXPERIMENT.into(),
            WORKSPACE.into(),
            START,
            START + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 0).unwrap();
        ledger.begin_attempt("first".into(), START).unwrap();
        ledger
            .track_cvm(WORKSPACE, "first", target(FIRST, "1", START))
            .unwrap();
        if two_targets {
            ledger
                .begin_attempt("partial-creation".into(), START + 1)
                .unwrap();
            ledger
                .track_cvm(
                    WORKSPACE,
                    "partial-creation",
                    target(SECOND, "2", START + 1),
                )
                .unwrap();
        }
        create_original_binding(&fixture.original(), &fixture.store(), &ledger).unwrap();
        drop(LedgerStore::initialize(&fixture.original()).unwrap());
        fixture
    }
    fn original(&self) -> PathBuf {
        self.0.join("original.json")
    }
    fn store(&self) -> PathBuf {
        self.0.join("state")
    }
    fn open(&self) -> LedgerStore {
        LedgerStore::open(&self.original()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Owned disposable fixture state only; no real ledger/provider data.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn target(id: &str, instance: &str, created: u64) -> TrackedCvm {
    TrackedCvm {
        cvm_id: id.into(),
        app_id: "a".repeat(40),
        instance_id: Some(instance.repeat(40)),
        created_at_unix_seconds: created,
        compute_and_disk_microusd_per_hour: 243_120,
    }
}

fn detail(id: &str, instance: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(DETAIL).unwrap();
    value["id"] = id.into();
    value["instance_id"] = instance.repeat(40).into();
    serde_json::to_string(&value).unwrap()
}

fn policy() -> WatchdogPolicy {
    // Explicit test phases fit the shared synthetic TLS fixture's 60-second
    // invocation budget. None of these values becomes a production default.
    WatchdogPolicy {
        maximum_detection_interval: Duration::from_secs(60),
        deletion_latency_upper_bound: Duration::from_secs(60),
        scheduler_delay_allowance: Duration::ZERO,
        reconciliation_budget: Duration::from_secs(10),
        deletion_dispatch_budget: Duration::from_secs(40),
        fee_upper_bounds_microusd: 0,
    }
}

fn limits() -> ObservationLimits {
    ObservationLimits {
        inventory_page_size: 2,
        usage_page_size: 2,
        max_inventory_records: NonZeroUsize::new(2).unwrap(),
        max_usage_records_per_app: NonZeroUsize::new(2).unwrap(),
    }
}

fn body_bound() -> usize {
    [
        AUTH.len(),
        DETAIL.len(),
        detail(FIRST, "1").len(),
        detail(SECOND, "2").len(),
    ]
    .into_iter()
    .max()
    .unwrap()
}

fn delete_reply(status: u16) -> Vec<u8> {
    if status == 204 {
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()
    } else {
        response(&format!("{status} Synthetic"), "UNRETAINED_PROVIDER_BODY")
    }
}

fn one_target_replies(id: &str, instance: &str, deletion: Vec<u8>) -> Vec<Vec<u8>> {
    vec![
        response("200 OK", AUTH),
        response("200 OK", &detail(id, instance)),
        deletion,
    ]
}

fn request_methods(server: &Server) -> Vec<String> {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.lines().next().unwrap().to_owned())
        .collect()
}

#[derive(Deserialize)]
struct Snapshot {
    generation: u64,
    ledger: Box<RawValue>,
}

#[tokio::test]
async fn due_startup_deletes_all_tracked_attempts_without_optional_scans() {
    let fixture = Fixture::new(true);
    let original = fs::read(fixture.original()).unwrap();
    let mut store = fixture.open();
    let binding = store.ledger().unwrap().binding().clone();
    let original_path = fixture.original();
    let state = fixture.store();
    let pending_seen = Arc::new(AtomicUsize::new(0));
    let seen = pending_seen.clone();
    let mut replies = one_target_replies(FIRST, "1", delete_reply(204));
    replies.extend(one_target_replies(SECOND, "2", delete_reply(404)));
    let server = Server::start_with_observer(replies, HOST, move |request| {
        if !request.starts_with("DELETE ") {
            return;
        }
        assert!(matches!(
            LedgerStore::open(&original_path),
            Err(StoreError::Locked)
        ));
        let index = seen.fetch_add(1, Ordering::SeqCst);
        let generation = 1 + index as u64 * 2;
        let snapshot: Snapshot = serde_json::from_slice(
            &fs::read(state.join(format!("ledger-{generation:020}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.generation, generation);
        let ledger =
            ExperimentLedger::from_json(snapshot.ledger.get().as_bytes(), &binding).unwrap();
        assert_eq!(ledger.deletion_intents().len(), index + 1);
        assert!(ledger.deletion_intents()[index].outcome.is_none());
        assert!(ledger.deletion_intents()[index].retry.is_none());
    })
    .await;
    let report = run_once(
        server.client(body_bound()),
        &mut store,
        EXPERIMENT,
        policy(),
        limits(),
    )
    .await
    .unwrap();
    assert!(report.invocation_completed);
    assert!(!report.future_invocation_authorized);
    assert!(
        !report.cleanup_complete
            && !report.independent_disk_deletion_verified
            && !report.billing_reconciled
    );
    assert!(!report.deployment_enabled && !report.private_mode_accepted);
    assert!(report.initial_decision.deletion_required());
    assert_eq!(
        report.observation.status,
        ObservationStatus::SkippedDeletionDue
    );
    assert_eq!(report.targets.len(), 2);
    for (index, expected) in [DeletionOutcome::Initiated204, DeletionOutcome::NotFound404]
        .into_iter()
        .enumerate()
    {
        let result = report.targets[index].deletion.as_ref().unwrap();
        assert_eq!(result.provider_outcome, expected);
        assert_eq!(result.intent_generation, 1 + index as u64 * 2);
        assert_eq!(result.prior_intent_generation, None);
        assert!(result.journal_committed);
        assert!(report.targets[index].issue.is_none());
    }
    server.wait_closed(6).await;
    assert_eq!(
        request_methods(&server),
        [
            "GET /api/v1/auth/me HTTP/1.1",
            "GET /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1",
            "DELETE /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1",
            "GET /api/v1/auth/me HTTP/1.1",
            "GET /api/v1/cvms/synthetic%2Dcvm%2D2 HTTP/1.1",
            "DELETE /api/v1/cvms/synthetic%2Dcvm%2D2 HTTP/1.1",
        ]
    );
    assert_eq!(pending_seen.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(fixture.original()).unwrap(), original);
    assert!(store.ledger().unwrap().observations().is_empty());
    assert_eq!(store.planning_reference().unwrap().generation(), 4);
    drop(store);
    assert_eq!(fixture.open().ledger().unwrap().deletion_intents().len(), 2);
}

#[tokio::test]
async fn due_cleanup_selects_latest_linked_retry_and_preserves_pending_history() {
    let fixture = Fixture::new(false);
    let mut store = fixture.open();
    drop(store.prepare_deletion(0, WORKSPACE, FIRST, START).unwrap());
    drop(
        store
            .prepare_deletion_retry(
                1,
                WORKSPACE,
                FIRST,
                DeletionRetryRecord {
                    prior_intent_generation: 1,
                    started_at_unix_seconds: START + 1,
                    readback_at_unix_seconds: START + 1,
                    detail: ObservedDetail::NotFound,
                },
                START + 1,
            )
            .unwrap(),
    );
    let prior = store.ledger().unwrap().deletion_intents().to_vec();
    let server = Server::start(one_target_replies(FIRST, "1", delete_reply(204)), HOST).await;
    let report = run_once(
        server.client(body_bound()),
        &mut store,
        EXPERIMENT,
        policy(),
        limits(),
    )
    .await
    .unwrap();
    assert!(report.invocation_completed);
    let attempted = report.targets[0].deletion.as_ref().unwrap();
    assert_eq!(attempted.prior_intent_generation, Some(2));
    assert_eq!(attempted.intent_generation, 3);
    assert_eq!(store.ledger().unwrap().deletion_intents()[..2], prior);
    assert!(
        store.ledger().unwrap().deletion_intents()[..2]
            .iter()
            .all(|intent| intent.outcome.is_none())
    );
    server.wait_closed(3).await;
    assert_eq!(request_methods(&server).len(), 3);
}

#[tokio::test]
async fn rejected_or_lost_delete_response_does_not_hide_the_next_target() {
    for reply in [delete_reply(503), Vec::new()] {
        let uncertain = reply.is_empty();
        let fixture = Fixture::new(true);
        let mut store = fixture.open();
        let mut replies = one_target_replies(FIRST, "1", reply);
        replies.extend(one_target_replies(SECOND, "2", delete_reply(204)));
        let server = Server::start(replies, HOST).await;
        let report = run_once(
            server.client(body_bound()),
            &mut store,
            EXPERIMENT,
            policy(),
            limits(),
        )
        .await
        .unwrap();
        assert!(!report.invocation_completed);
        assert_eq!(report.targets.len(), 2);
        let first = report.targets[0].deletion.as_ref().unwrap();
        assert_eq!(
            first.provider_outcome,
            if uncertain {
                DeletionOutcome::TransportUncertain
            } else {
                DeletionOutcome::Rejected { status: 503 }
            }
        );
        assert!(first.journal_committed);
        let second = report.targets[1].deletion.as_ref().unwrap();
        assert_eq!(second.provider_outcome, DeletionOutcome::Initiated204);
        assert!(second.journal_committed);
        server.wait_closed(6).await;
        assert_eq!(
            request_methods(&server)
                .iter()
                .filter(|line| line.starts_with("DELETE "))
                .count(),
            2
        );
        assert_eq!(store.ledger().unwrap().deletion_intents().len(), 2);
    }
}

#[tokio::test]
async fn authentication_or_target_identity_conflict_stops_remaining_mutations() {
    for target_conflict in [false, true] {
        let fixture = Fixture::new(true);
        let mut store = fixture.open();
        let original = serde_json::to_value(store.ledger().unwrap()).unwrap();
        let replies = if target_conflict {
            vec![
                response("200 OK", AUTH),
                response("200 OK", &detail(FIRST, "9")),
            ]
        } else {
            vec![response(
                "200 OK",
                r#"{"workspace":{"id":"another-workspace"}}"#,
            )]
        };
        let count = replies.len();
        let server = Server::start(replies, HOST).await;
        let report = run_once(
            server.client(body_bound()),
            &mut store,
            EXPERIMENT,
            policy(),
            limits(),
        )
        .await
        .unwrap();
        assert!(!report.invocation_completed);
        assert!(
            report
                .targets
                .iter()
                .all(|target| target.deletion.is_none())
        );
        assert!(report.targets.iter().any(|target| target.issue.is_some()));
        server.wait_closed(count).await;
        assert_eq!(request_methods(&server).len(), count);
        assert_eq!(
            serde_json::to_value(store.ledger().unwrap()).unwrap(),
            original
        );
    }
}

#[tokio::test]
async fn invalid_experiment_policy_or_limits_fails_before_authentication() {
    for case in ["experiment", "policy", "inventory", "usage"] {
        let fixture = Fixture::new(true);
        let mut store = fixture.open();
        let original = serde_json::to_value(store.ledger().unwrap()).unwrap();
        let mut policy = policy();
        let mut limits = limits();
        let experiment = if case == "experiment" {
            "other"
        } else {
            EXPERIMENT
        };
        match case {
            "policy" => policy.reconciliation_budget = Duration::ZERO,
            "inventory" => limits.inventory_page_size = 0,
            "usage" => limits.usage_page_size = 5_001,
            _ => (),
        }
        let server = Server::start(vec![], HOST).await;
        assert!(
            run_once(
                server.client(body_bound()),
                &mut store,
                experiment,
                policy,
                limits
            )
            .await
            .is_err(),
            "{case}"
        );
        assert!(request_methods(&server).is_empty());
        assert_eq!(
            serde_json::to_value(store.ledger().unwrap()).unwrap(),
            original
        );
    }
}
