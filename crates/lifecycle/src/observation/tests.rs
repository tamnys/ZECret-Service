use super::*;
use crate::{
    MAX_LIFETIME_SECONDS,
    controller::ExperimentLedger,
    persistence::create_original_binding,
    provider_http::tests::{AUTH, Server, response},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const START: u64 = 1_767_225_600;
const CUTOFF: u64 = START + MAX_LIFETIME_SECONDS + 3600;
const WORKSPACE: &str = "wks_synthetic_only";
const APP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INVENTORY: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/inventory.json");
const DETAIL: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/cvm-detail.json");
const USAGE: &str = include_str!("../../../../tests/fixtures/phala-lifecycle/usage.json");
const EMPTY_USAGE: &str = r#"{"usage":[],"total":0,"total_cost":0}"#;

struct Fixture {
    root: PathBuf,
    original: PathBuf,
}
impl Fixture {
    fn new(workspace: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::current_dir()
            .unwrap()
            .join(".codex-tmp/observation-tests");
        fs::create_dir_all(&base).unwrap();
        let root = base.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let original = root.join("original.json");
        let binding = ExperimentBinding::new(
            "synthetic-observation".into(),
            workspace.into(),
            START,
            START + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 17).unwrap();
        ledger.begin_attempt("first".into(), START).unwrap();
        ledger
            .track_cvm(
                workspace,
                "first",
                TrackedCvm {
                    cvm_id: "synthetic-cvm-1".into(),
                    app_id: APP.into(),
                    instance_id: "1".repeat(40),
                    created_at_unix_seconds: START,
                    compute_and_disk_microusd_per_hour: 243_120,
                },
            )
            .unwrap();
        ledger.begin_attempt("later".into(), START + 1).unwrap();
        for (id, app, instance) in [
            ("synthetic-cvm-2", "synthetic-app-2", "2"),
            ("synthetic-cvm-3", APP, "3"),
        ] {
            ledger
                .track_cvm(
                    workspace,
                    "later",
                    TrackedCvm {
                        cvm_id: id.into(),
                        app_id: app.into(),
                        instance_id: instance.repeat(40),
                        created_at_unix_seconds: START + 1,
                        compute_and_disk_microusd_per_hour: 243_120,
                    },
                )
                .unwrap();
        }
        create_original_binding(&original, &root.join("store"), &ledger).unwrap();
        drop(LedgerStore::initialize(&original).unwrap());
        Self { root, original }
    }
    fn bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut result: Vec<_> = fs::read_dir(self.root.join("store"))
            .unwrap()
            .map(|e| {
                let path = e.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        result.push((self.original.clone(), fs::read(&self.original).unwrap()));
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
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
fn fixture_bound() -> usize {
    [AUTH.len(), INVENTORY.len(), DETAIL.len(), USAGE.len()]
        .into_iter()
        .max()
        .unwrap()
}
fn complete_replies(inventory: &str, detail: &str, usage: &str) -> Vec<Vec<u8>> {
    vec![
        response("200 OK", AUTH),
        response("200 OK", inventory),
        response("200 OK", detail),
        response("404 Not Found", ""),
        response("404 Not Found", ""),
        response("200 OK", usage),
        response("200 OK", EMPTY_USAGE),
        response("200 OK", EMPTY_USAGE),
    ]
}

#[tokio::test]
async fn complete_reads_preserve_all_history_and_never_attribute_usage_or_prove_cleanup() {
    let fixture = Fixture::new(WORKSPACE);
    let before = fixture.bytes();
    let store = LedgerStore::open(&fixture.original).unwrap();
    let initial = serde_json::to_vec(store.ledger().unwrap()).unwrap();
    let server = Server::start(
        complete_replies(INVENTORY, DETAIL, USAGE),
        "cloud-api.phala.com",
    )
    .await;
    let session = ObservationSession::at(&store, CUTOFF).unwrap();
    assert_eq!(session.workspace_id().unwrap(), WORKSPACE);
    let report = session
        .observe_with_clock(server.client(fixture_bound()), limits(), || Ok(CUTOFF))
        .await
        .unwrap();
    assert_eq!(report.reference().generation(), 0);
    assert_eq!(report.usage_cutoff_unix_seconds(), CUTOFF);
    assert_eq!(report.finished_at_unix_seconds(), CUTOFF);
    assert_eq!(report.original_binding(), store.ledger().unwrap().binding());
    assert_eq!(report.inventory().items().len(), 2);
    assert_eq!(report.untracked_inventory_ids(), ["synthetic-cvm-partial"]);
    assert_eq!(report.tracked().len(), 3);
    assert_eq!(
        report.tracked()[0].inventory_identity(),
        Some(IdentityMatch::CvmFieldsMatch)
    );
    assert_eq!(
        report.tracked()[0].detail_identity(),
        Some(IdentityMatch::CvmFieldsMatch)
    );
    assert!(!report.tracked()[0].cvm_absence_observed());
    assert!(report.tracked()[1].cvm_absence_observed());
    assert!(report.tracked()[2].cvm_absence_observed());
    assert_eq!(report.unjoined_usage_by_app().len(), 2);
    assert_eq!(report.unjoined_usage_by_app()[APP].rows().len(), 2);
    assert_eq!(
        report.unjoined_usage_by_app()[APP].rows()[1]
            .cost
            .canonical_identity(),
        "2e-7"
    );
    assert!(!report.billing_reconciled());
    assert!(!report.independent_disk_deletion_verified());
    assert!(!report.cleanup_complete());
    // All three resources keep accruing, including both absent ones. The
    // observed API amounts are not adopted into accounting.
    assert_eq!(
        report.known_cost_floor_microusd(),
        store.ledger().unwrap().planning_cost_at(CUTOFF).unwrap()
    );
    assert!(report.known_cost_floor_microusd() > crate::TOTAL_CEILING_MICROUSD);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 8);
    for (index, app, offset) in [(5, APP, 0), (6, APP, 2), (7, "synthetic-app-2", 0)] {
        let path = ReadRequest::Usage {
            app_id: app,
            start_unix_seconds: START,
            end_unix_seconds: CUTOFF,
            limit: 500,
            offset,
        }
        .path_and_query()
        .unwrap();
        assert!(requests[index].starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    }
    assert!(requests.iter().all(|r| r.starts_with("GET ")));
    assert_eq!(
        initial,
        serde_json::to_vec(store.ledger().unwrap()).unwrap()
    );
    assert_eq!(before, fixture.bytes());
}

#[tokio::test]
async fn wrong_scope_invalid_limits_clock_and_pending_history_precede_network() {
    let fixture = Fixture::new("different-synthetic-workspace");
    let store = LedgerStore::open(&fixture.original).unwrap();
    let server = Server::start(Vec::new(), "cloud-api.phala.com").await;
    assert!(matches!(
        ObservationSession::at(&store, START),
        Err(ObservationError::ClockRejected)
    ));
    let result = ObservationSession::at(&store, CUTOFF)
        .unwrap()
        .observe_with_clock(server.client(fixture_bound()), limits(), || Ok(CUTOFF))
        .await;
    assert!(matches!(
        result,
        Err(ObservationError::Provider(
            ProviderHttpError::WorkspaceMismatch
        ))
    ));
    drop(store);
    let fixture = Fixture::new(WORKSPACE);
    let store = LedgerStore::open(&fixture.original).unwrap();
    let mut bad = limits();
    bad.usage_page_size = 0;
    assert!(matches!(
        ObservationSession::at(&store, CUTOFF)
            .unwrap()
            .observe_with_clock(server.client(fixture_bound()), bad, || Ok(CUTOFF))
            .await,
        Err(ObservationError::InvalidConfiguration)
    ));
    assert!(matches!(
        ObservationSession::at(&store, CUTOFF)
            .unwrap()
            .observe_with_clock(server.client(fixture_bound()), limits(), || Ok(CUTOFF - 1))
            .await,
        Err(ObservationError::ClockRejected)
    ));
    fs::write(
        fixture.root.join("store/pending.json"),
        b"uncommitted fixture",
    )
    .unwrap();
    assert!(matches!(
        ObservationSession::at(&store, CUTOFF),
        Err(ObservationError::Store(StoreError::PendingRecovery))
    ));
    assert!(server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn identity_conflict_or_interrupted_usage_yields_no_completed_report_or_changes() {
    let fixture = Fixture::new(WORKSPACE);
    let store = LedgerStore::open(&fixture.original).unwrap();
    let before = fixture.bytes();
    for is_inventory in [true, false] {
        let inventory = if is_inventory {
            INVENTORY.replace(APP, "conflicting-app")
        } else {
            INVENTORY.into()
        };
        let detail = if is_inventory {
            DETAIL.into()
        } else {
            DETAIL.replace(&"1".repeat(40), &"4".repeat(40))
        };
        let server = Server::start(
            complete_replies(&inventory, &detail, USAGE),
            "cloud-api.phala.com",
        )
        .await;
        assert!(matches!(
            ObservationSession::at(&store, CUTOFF)
                .unwrap()
                .observe_with_clock(server.client(fixture_bound()), limits(), || Ok(CUTOFF))
                .await,
            Err(ObservationError::IdentityConflict)
        ));
        assert_eq!(
            server.requests.lock().unwrap().len(),
            if is_inventory { 2 } else { 3 }
        );
    }
    let mut replies = complete_replies(INVENTORY, DETAIL, USAGE);
    replies[6] = response("404 Not Found", "");
    let server = Server::start(replies, "cloud-api.phala.com").await;
    assert!(matches!(
        ObservationSession::at(&store, CUTOFF)
            .unwrap()
            .observe_with_clock(server.client(fixture_bound()), limits(), || Ok(CUTOFF))
            .await,
        Err(ObservationError::Provider(ProviderHttpError::NotFound))
    ));
    assert_eq!(server.requests.lock().unwrap().len(), 7);
    assert_eq!(fixture.bytes(), before);
}

#[tokio::test]
async fn missing_cvm_fields_and_equal_usage_text_remain_unconfirmed() {
    let fixture = Fixture::new(WORKSPACE);
    let store = LedgerStore::open(&fixture.original).unwrap();
    let inventory = INVENTORY.replace(&format!("\"{APP}\""), "null");
    let detail = DETAIL.replace(&format!("\"{}\"", "1".repeat(40)), "null");
    let usage = USAGE.replace("00000000-0000-4000-8000-000000000001", &"1".repeat(40));
    let bound = fixture_bound().max(usage.len());
    let server = Server::start(
        complete_replies(&inventory, &detail, &usage),
        "cloud-api.phala.com",
    )
    .await;
    let report = ObservationSession::at(&store, CUTOFF)
        .unwrap()
        .observe_with_clock(server.client(bound), limits(), || Ok(CUTOFF))
        .await
        .unwrap();
    assert_eq!(
        report.tracked()[0].inventory_identity(),
        Some(IdentityMatch::Incomplete)
    );
    assert_eq!(
        report.tracked()[0].detail_identity(),
        Some(IdentityMatch::Incomplete)
    );
    assert_eq!(
        report.unjoined_usage_by_app()[APP].rows()[0].instance_id,
        report.tracked()[0].target().instance_id
    );
    assert!(!report.billing_reconciled());
}

#[tokio::test]
async fn writer_lock_is_retained_across_awaits_and_late_clock_rollback_rejects() {
    let fixture = Fixture::new(WORKSPACE);
    let store = LedgerStore::open(&fixture.original).unwrap();
    let server = Server::start(
        complete_replies(INVENTORY, DETAIL, USAGE),
        "cloud-api.phala.com",
    )
    .await;
    let mut clock_calls = 0;
    let result = ObservationSession::at(&store, CUTOFF)
        .unwrap()
        .observe_with_clock(server.client(fixture_bound()), limits(), || {
            assert!(matches!(
                LedgerStore::open(&fixture.original),
                Err(StoreError::Locked)
            ));
            clock_calls += 1;
            Ok(if clock_calls > 2 { CUTOFF - 1 } else { CUTOFF })
        })
        .await;
    assert!(matches!(result, Err(ObservationError::ClockRejected)));
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}
