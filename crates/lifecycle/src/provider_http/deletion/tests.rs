//! Explicitly invoked deletion against a synthetic loopback TLS server and
//! disposable local ledger only. No credentials or provider resources are used.
use super::*;
use crate::{
    MAX_LIFETIME_SECONDS, TOTAL_CEILING_MICROUSD,
    controller::{ExperimentBinding, ExperimentLedger},
    persistence::create_original_binding,
    provider_http::tests::{AUTH, Server, response},
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::time::Instant;

const HOST: &str = "cloud-api.phala.com";
const WORKSPACE: &str = "wks_synthetic_only";
const CVM: &str = "synthetic-cvm-1";
const APP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INSTANCE: &str = "1111111111111111111111111111111111111111";
const START: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z, matching the synthetic detail.
const DETAIL: &str = include_str!("../../../../../tests/fixtures/phala-lifecycle/cvm-detail.json");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new(workspace: &str, id: &str, start: u64) -> Self {
        Self::with_instance(workspace, id, start, Some(INSTANCE))
    }
    fn with_instance(workspace: &str, id: &str, start: u64, instance: Option<&str>) -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.codex-tmp/provider-deletion-tests");
        fs::create_dir_all(&base).unwrap();
        let path = fs::canonicalize(base).unwrap().join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let binding = ExperimentBinding::new(
            "synthetic_deletion".into(),
            workspace.into(),
            start,
            start + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 0).unwrap();
        ledger
            .begin_attempt("synthetic_attempt".into(), start)
            .unwrap();
        ledger
            .track_cvm(
                workspace,
                "synthetic_attempt",
                TrackedCvm {
                    cvm_id: id.into(),
                    app_id: APP.into(),
                    instance_id: instance.map(str::to_owned),
                    created_at_unix_seconds: start,
                    compute_and_disk_microusd_per_hour: 243_120,
                },
            )
            .unwrap();
        create_original_binding(&fixture.original(), &fixture.store(), &ledger).unwrap();
        drop(LedgerStore::initialize(&fixture.original()).unwrap());
        fixture
    }
    fn standard() -> Self {
        Self::new(WORKSPACE, CVM, START)
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
        // This directory was created exclusively by this fixture and contains
        // only its synthetic ledger and intentionally injected failure files.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Deserialize)]
struct Snapshot {
    generation: u64,
    ledger: Box<RawValue>,
}

fn assert_pending(store: &LedgerStore) {
    let intents = store.ledger().unwrap().deletion_intents();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].target.cvm_id, CVM);
    assert!(intents[0].outcome.is_none());
}

fn delete_reply(status: u16) -> Vec<u8> {
    if status == 204 {
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()
    } else if status == 302 {
        b"HTTP/1.1 302 Found\r\nLocation: https://do-not-follow.invalid/\r\nContent-Length: 0\r\n\r\n".to_vec()
    } else {
        response(
            &format!("{status} Synthetic"),
            "PROVIDER_DELETE_BODY_MUST_NOT_BE_RETAINED",
        )
    }
}

async fn authenticate(server: &Server) -> ScopedDeletion {
    server
        .client(AUTH.len().max(DETAIL.len()))
        .authenticate_deletion()
        .await
        .ok()
        .unwrap()
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

fn prior_intent(store: &mut LedgerStore, outcome: Option<DeletionOutcome>) -> u64 {
    let intent = store.prepare_deletion(0, WORKSPACE, CVM, START).unwrap();
    if let Some(outcome) = outcome {
        intent.finish(outcome, START).unwrap();
        2
    } else {
        drop(intent);
        1
    }
}

async fn prepare_retry_with_clock<'a>(
    client: ScopedDeletion,
    store: &'a mut LedgerStore,
    generation: u64,
    clock: impl FnMut() -> Result<u64, DeletionError>,
) -> Result<PreparedDeletion<'a>, DeletionError> {
    client
        .prepare_selected_with_clock(store, generation, CVM, Selection::Retry(1), None, clock)
        .await
}

#[tokio::test]
async fn explicit_retry_preserves_each_prior_outcome_and_commits_link_before_delete() {
    for outcome in [
        None,
        Some(DeletionOutcome::TransportUncertain),
        Some(DeletionOutcome::Rejected { status: 503 }),
        Some(DeletionOutcome::Initiated204),
        Some(DeletionOutcome::NotFound404),
    ] {
        let fixture = Fixture::standard();
        let original_bytes = fs::read(fixture.original()).unwrap();
        let mut store = fixture.open();
        let generation = prior_intent(&mut store, outcome);
        let prior = store.ledger().unwrap().deletion_intents()[0].clone();
        let retained = prior.clone();
        let binding = store.ledger().unwrap().binding().clone();
        let cost = store
            .ledger()
            .unwrap()
            .planning_cost_at(wall_time().unwrap())
            .unwrap();
        let original = fixture.original();
        let snapshot = fixture
            .store()
            .join(format!("ledger-{:020}.json", generation + 1));
        let observed = Arc::new(AtomicBool::new(false));
        let observation = observed.clone();
        let server = Server::start_with_observer(
            vec![
                response("200 OK", AUTH),
                response("200 OK", DETAIL),
                delete_reply(204),
            ],
            HOST,
            move |request| {
                if !request.starts_with("DELETE ") {
                    return;
                }
                assert!(matches!(
                    LedgerStore::open(&original),
                    Err(StoreError::Locked)
                ));
                let snapshot: Snapshot =
                    serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
                assert_eq!(snapshot.generation, generation + 1);
                let ledger =
                    ExperimentLedger::from_json(snapshot.ledger.get().as_bytes(), &binding)
                        .unwrap();
                let intents = ledger.deletion_intents();
                assert_eq!(intents.len(), 2);
                assert_eq!(intents[0], retained);
                let retry = intents[1].retry.as_ref().unwrap();
                assert_eq!(retry.prior_intent_generation, 1);
                assert!(retry.started_at_unix_seconds <= retry.readback_at_unix_seconds);
                assert!(retry.readback_at_unix_seconds <= intents[1].recorded_at_unix_seconds);
                assert!(matches!(&retry.detail, ObservedDetail::Present(cvm) if cvm.id == CVM));
                assert!(intents[1].outcome.is_none());
                observation.store(true, Ordering::SeqCst);
            },
        )
        .await;
        let report = server
            .client(AUTH.len().max(DETAIL.len()))
            .retry_tracked(&mut store, generation, CVM, 1)
            .await
            .unwrap();
        assert_eq!(report.prior_intent_generation(), Some(1));
        assert_eq!(report.intent_generation(), generation + 1);
        assert_eq!(
            report.preparation_readback(),
            PreparationReadback::CvmFieldsMatch
        );
        assert_eq!(report.provider_outcome(), DeletionOutcome::Initiated204);
        assert_eq!(report.outcome_journal(), OutcomeJournal::Committed);
        assert!(!report.cleanup_complete());
        assert!(!report.independent_disk_deletion_verified());
        assert!(observed.load(Ordering::SeqCst));
        server.wait_closed(3).await;
        assert_eq!(
            request_methods(&server),
            [
                "GET /api/v1/auth/me HTTP/1.1",
                "GET /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1",
                "DELETE /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1",
            ]
        );
        assert_eq!(fs::read(fixture.original()).unwrap(), original_bytes);
        assert_eq!(store.ledger().unwrap().deletion_intents()[0], prior);
        assert!(
            store
                .ledger()
                .unwrap()
                .planning_cost_at(wall_time().unwrap())
                .unwrap()
                >= cost
        );
        drop(store);
        assert_eq!(
            fixture.open().ledger().unwrap().deletion_intents()[0],
            prior
        );
    }
}

#[tokio::test]
async fn retry_link_and_local_ledger_failures_send_no_authentication() {
    for case in [
        "missing",
        "wrong_link",
        "stale_link",
        "generation",
        "untracked",
        "draft",
        "history",
        "future",
        "workspace",
    ] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        let mut generation = match case {
            "missing" => 0,
            "future" => {
                drop(
                    store
                        .prepare_deletion(
                            0,
                            WORKSPACE,
                            CVM,
                            wall_time().unwrap() + MAX_LIFETIME_SECONDS,
                        )
                        .unwrap(),
                );
                1
            }
            _ => prior_intent(&mut store, None),
        };
        if case == "stale_link" {
            drop(
                store
                    .prepare_deletion_retry(
                        1,
                        WORKSPACE,
                        CVM,
                        DeletionRetryRecord {
                            prior_intent_generation: 1,
                            started_at_unix_seconds: START,
                            readback_at_unix_seconds: START,
                            detail: ObservedDetail::NotFound,
                        },
                        START,
                    )
                    .unwrap(),
            );
            generation = 2;
        }
        if case == "draft" {
            fs::write(fixture.store().join("pending.json"), b"synthetic draft").unwrap();
        }
        if case == "history" {
            fs::write(
                fixture.store().join("ledger-00000000000000000000.json"),
                b"synthetic corruption",
            )
            .unwrap();
        }
        let server = Server::start(vec![response("200 OK", AUTH)], HOST).await;
        let mut client = server.client(AUTH.len().max(DETAIL.len()));
        if case == "workspace" {
            client.workspace_id = "wrong_workspace".into();
        }
        let error = client
            .retry_tracked(
                &mut store,
                if case == "generation" {
                    generation + 1
                } else {
                    generation
                },
                if case == "untracked" {
                    "not_tracked"
                } else {
                    CVM
                },
                if case == "wrong_link" { 2 } else { 1 },
            )
            .await
            .err()
            .unwrap();
        let expected = match case {
            "missing" | "wrong_link" | "stale_link" => DeletionError::PriorIntentMismatch,
            "generation" | "history" => DeletionError::Store(StoreError::InvalidState),
            "draft" => DeletionError::Store(StoreError::PendingRecovery),
            "untracked" => DeletionError::TargetRejected,
            "future" => DeletionError::ClockOrLedgerRejected,
            "workspace" => DeletionError::Provider(ProviderHttpError::WorkspaceMismatch),
            _ => unreachable!(),
        };
        assert_eq!(error, expected, "{case}");
        assert!(request_methods(&server).is_empty(), "{case}");
    }
}

#[tokio::test]
async fn retry_readback_rejects_conflicts_failures_and_clock_reversal_without_new_intent() {
    for case in [
        "app",
        "instance",
        "workspace",
        "id",
        "forbidden",
        "clock",
        "preauth_clock",
    ] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        prior_intent(&mut store, None);
        let prior = store.ledger().unwrap().deletion_intents().to_vec();
        let detail = match case {
            "app" => DETAIL.replace(APP, "conflicting_app"),
            "instance" => DETAIL.replace(INSTANCE, "conflicting_instance"),
            "workspace" => DETAIL.replace(WORKSPACE, "conflicting_workspace"),
            "id" => DETAIL.replace(CVM, "conflicting_cvm"),
            _ => DETAIL.into(),
        };
        let server = Server::start(
            vec![
                response("200 OK", AUTH),
                response(
                    if case == "forbidden" {
                        "403 Forbidden"
                    } else {
                        "200 OK"
                    },
                    &detail,
                ),
            ],
            HOST,
        )
        .await;
        let mut calls = 0;
        let error = server
            .client(AUTH.len().max(detail.len()))
            .authenticate_deletion()
            .await
            .ok()
            .unwrap()
            .prepare_selected_with_clock(
                &mut store,
                1,
                CVM,
                Selection::Retry(1),
                if case == "preauth_clock" {
                    Some(START + 1)
                } else {
                    None
                },
                || {
                    calls += 1;
                    Ok(if case == "clock" && calls == 2 {
                        START - 1
                    } else {
                        START
                    })
                },
            )
            .await
            .err()
            .unwrap();
        let expected = match case {
            "workspace" => DeletionError::Provider(ProviderHttpError::WorkspaceMismatch),
            "id" => DeletionError::Provider(ProviderHttpError::InvalidResponse),
            "forbidden" => DeletionError::Provider(ProviderHttpError::Forbidden),
            "clock" | "preauth_clock" => DeletionError::ClockOrLedgerRejected,
            _ => DeletionError::IdentityConflict,
        };
        assert_eq!(error, expected, "{case}");
        assert_eq!(store.ledger().unwrap().deletion_intents(), prior);
        assert_eq!(store.planning_reference().unwrap().generation(), 1);
        server
            .wait_closed(if case == "preauth_clock" { 1 } else { 2 })
            .await;
        assert!(
            request_methods(&server)
                .iter()
                .all(|line| line.starts_with("GET "))
        );
    }
}

#[tokio::test]
async fn retry_retains_incomplete_or_missing_detail_without_claiming_cleanup() {
    let incomplete = DETAIL
        .replace(&format!("\"{APP}\""), "null")
        .replace(&format!("\"{INSTANCE}\""), "null");
    for (reply, expected) in [
        (
            response("200 OK", &incomplete),
            PreparationReadback::IncompleteCvmFields,
        ),
        (
            response("404 Not Found", "synthetic detail absent"),
            PreparationReadback::DetailNotFound,
        ),
    ] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        prior_intent(&mut store, None);
        let server = Server::start(
            vec![response("200 OK", AUTH), reply, delete_reply(404)],
            HOST,
        )
        .await;
        let prepared =
            prepare_retry_with_clock(authenticate(&server).await, &mut store, 1, || Ok(START))
                .await
                .ok()
                .unwrap();
        assert_eq!(prepared.preparation_readback(), expected);
        match &prepared.intent_record().retry.as_ref().unwrap().detail {
            ObservedDetail::NotFound => assert_eq!(expected, PreparationReadback::DetailNotFound),
            ObservedDetail::Present(cvm) => {
                assert_eq!(expected, PreparationReadback::IncompleteCvmFields);
                assert!(cvm.app_id.is_none() && cvm.instance_id.is_none());
            }
        }
        let report = prepared.dispatch_with_clock(|| Ok(START)).await.unwrap();
        assert_eq!(report.provider_outcome(), DeletionOutcome::NotFound404);
        assert!(!report.cleanup_complete());
        assert!(!report.independent_disk_deletion_verified());
        assert!(
            store.ledger().unwrap().deletion_intents()[0]
                .outcome
                .is_none()
        );
        server.wait_closed(3).await;
        assert_eq!(request_methods(&server).len(), 3);
    }
}

#[tokio::test]
async fn explicit_entrypoint_persists_before_one_exact_delete_and_blocks_another_invocation() {
    for status in [204, 404, 403, 302, 429, 503] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        let original_bytes = fs::read(fixture.original()).unwrap();
        let binding = store.ledger().unwrap().binding().clone();
        let initial = store
            .ledger()
            .unwrap()
            .planning_cost_at(wall_time().unwrap())
            .unwrap();
        // Cleanup remains available after both the original deadline and cap.
        assert!(wall_time().unwrap() > START + MAX_LIFETIME_SECONDS);
        assert!(initial > TOTAL_CEILING_MICROUSD);
        let original = fixture.original();
        let snapshot = fixture.store().join("ledger-00000000000000000001.json");
        let observed = Arc::new(AtomicBool::new(false));
        let observation = observed.clone();
        let server = Server::start_with_observer(
            vec![
                response("200 OK", AUTH),
                response("200 OK", DETAIL),
                delete_reply(status),
            ],
            HOST,
            move |request| {
                if !request.starts_with("DELETE ") {
                    return;
                }
                assert!(matches!(
                    LedgerStore::open(&original),
                    Err(StoreError::Locked)
                ));
                let snapshot: Snapshot =
                    serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
                assert_eq!(snapshot.generation, 1);
                let ledger =
                    ExperimentLedger::from_json(snapshot.ledger.get().as_bytes(), &binding)
                        .unwrap();
                let intents = ledger.deletion_intents();
                assert_eq!(intents.len(), 1);
                assert_eq!(intents[0].target.cvm_id, CVM);
                assert!(intents[0].outcome.is_none());
                observation.store(true, Ordering::SeqCst);
            },
        )
        .await;
        let report = server
            .client(AUTH.len().max(DETAIL.len()))
            .delete_tracked(&mut store, 0, CVM)
            .await
            .unwrap();
        assert_eq!(
            report.preparation_readback(),
            PreparationReadback::CvmFieldsMatch
        );
        let expected = match status {
            204 => DeletionOutcome::Initiated204,
            404 => DeletionOutcome::NotFound404,
            status => DeletionOutcome::Rejected { status },
        };
        assert_eq!(report.provider_outcome(), expected);
        assert_eq!(report.outcome_journal(), OutcomeJournal::Committed);
        assert_eq!(report.transport_issue(), None);
        assert_eq!(report.intent_generation(), 1);
        assert!(!report.cleanup_complete());
        assert!(!report.independent_disk_deletion_verified());
        assert!(observed.load(Ordering::SeqCst));
        server.wait_closed(3).await;
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[2].starts_with("DELETE /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1\r\n"));
        let headers = requests[2].to_ascii_lowercase();
        assert!(headers.contains("\r\nhost: cloud-api.phala.com\r\n"));
        assert!(headers.contains("\r\nx-phala-version: 2026-06-23\r\n"));
        assert!(headers.contains("\r\nx-phala-workspace: wks_synthetic_only\r\n"));
        assert!(headers.contains("\r\nx-api-key: synthetic_api_key_must_not_escape\r\n"));
        assert!(requests[2].ends_with("\r\n\r\n"));
        drop(requests);
        assert_eq!(fs::read(fixture.original()).unwrap(), original_bytes);
        assert_eq!(store.planning_reference().unwrap().generation(), 2);
        assert_eq!(
            server
                .client(AUTH.len().max(DETAIL.len()))
                .delete_tracked(&mut store, 2, CVM)
                .await
                .err(),
            Some(DeletionError::PriorIntentNeedsReconciliation)
        );
        assert_eq!(
            request_methods(&server),
            [
                "GET /api/v1/auth/me HTTP/1.1",
                "GET /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1",
                "DELETE /api/v1/cvms/synthetic%2Dcvm%2D1 HTTP/1.1",
            ]
        );
        assert!(
            store
                .ledger()
                .unwrap()
                .planning_cost_at(wall_time().unwrap())
                .unwrap()
                >= initial
        );
        drop(store);
        let reopened = fixture.open();
        assert_eq!(
            reopened.ledger().unwrap().deletion_intents()[0]
                .outcome
                .as_ref()
                .unwrap()
                .outcome,
            expected
        );
    }
}

#[tokio::test]
async fn local_rejections_precede_authentication_or_detail_at_each_entrypoint() {
    for before_auth in [true, false] {
        for case in [
            "generation",
            "workspace",
            "untracked",
            "path",
            "future",
            "prior_intent",
            "draft",
            "history",
        ] {
            let fixture = Fixture::new(
                if case == "workspace" {
                    "different_workspace"
                } else {
                    WORKSPACE
                },
                if case == "path" { "../auth/me" } else { CVM },
                if case == "future" {
                    wall_time().unwrap() + MAX_LIFETIME_SECONDS
                } else {
                    START
                },
            );
            let mut store = fixture.open();
            let mut generation = 0;
            if case == "prior_intent" {
                drop(store.prepare_deletion(0, WORKSPACE, CVM, START).unwrap());
                generation = 1;
            }
            if case == "draft" {
                fs::write(
                    fixture.store().join("pending.json"),
                    b"synthetic interrupted write",
                )
                .unwrap();
            }
            if case == "history" {
                fs::write(
                    fixture.store().join("ledger-00000000000000000000.json"),
                    b"synthetic corrupted history",
                )
                .unwrap();
            }
            let server = Server::start(vec![response("200 OK", AUTH)], HOST).await;
            let selected_generation = if case == "generation" { 1 } else { generation };
            let selected_cvm = match case {
                "path" => "../auth/me",
                "untracked" => "not_tracked",
                _ => CVM,
            };
            let result = if before_auth {
                server
                    .client(AUTH.len().max(DETAIL.len()))
                    .delete_tracked(&mut store, selected_generation, selected_cvm)
                    .await
                    .map(|_| ())
            } else {
                authenticate(&server)
                    .await
                    .prepare(&mut store, selected_generation, selected_cvm)
                    .await
                    .map(|_| ())
            };
            let expected = match case {
                "generation" | "history" => DeletionError::Store(StoreError::InvalidState),
                "workspace" => DeletionError::Provider(ProviderHttpError::WorkspaceMismatch),
                "untracked" | "path" => DeletionError::TargetRejected,
                "future" => DeletionError::ClockOrLedgerRejected,
                "prior_intent" => DeletionError::PriorIntentNeedsReconciliation,
                "draft" => DeletionError::Store(StoreError::PendingRecovery),
                _ => unreachable!(),
            };
            assert_eq!(result.err(), Some(expected));
            if before_auth {
                assert!(request_methods(&server).is_empty());
            } else {
                server.wait_closed(1).await;
                assert_eq!(request_methods(&server), ["GET /api/v1/auth/me HTTP/1.1"]);
            }
            assert_eq!(
                store.ledger().unwrap().deletion_intents().len(),
                usize::from(case == "prior_intent")
            );
        }
    }
}

#[tokio::test]
async fn conflicting_detail_fields_or_clock_reversal_create_no_intent() {
    for case in ["app", "instance", "clock"] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        let detail = match case {
            "app" => DETAIL.replace(APP, "conflicting_app"),
            "instance" => DETAIL.replace(INSTANCE, "conflicting_instance"),
            _ => DETAIL.into(),
        };
        let server = Server::start(
            vec![response("200 OK", AUTH), response("200 OK", &detail)],
            HOST,
        )
        .await;
        let mut calls = 0;
        let result = authenticate(&server)
            .await
            .prepare_with_clock(&mut store, 0, CVM, || {
                calls += 1;
                Ok(if case == "clock" && calls == 2 {
                    START - 1
                } else {
                    START
                })
            })
            .await;
        assert_eq!(
            result.err(),
            Some(if case == "clock" {
                DeletionError::ClockOrLedgerRejected
            } else {
                DeletionError::IdentityConflict
            })
        );
        assert!(store.ledger().unwrap().deletion_intents().is_empty());
        assert_eq!(store.planning_reference().unwrap().generation(), 0);
        server.wait_closed(2).await;
        assert!(
            request_methods(&server)
                .iter()
                .all(|line| line.starts_with("GET "))
        );
    }
}

#[tokio::test]
async fn incomplete_detail_and_get_404_remain_distinct_from_delete_outcomes() {
    let incomplete = DETAIL
        .replace(&format!("\"{APP}\""), "null")
        .replace(&format!("\"{INSTANCE}\""), "null");
    for (reply, expected) in [
        (
            response("200 OK", &incomplete),
            PreparationReadback::IncompleteCvmFields,
        ),
        (
            response("404 Not Found", "synthetic detail missing"),
            PreparationReadback::DetailNotFound,
        ),
    ] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        let server = Server::start(
            vec![response("200 OK", AUTH), reply, delete_reply(404)],
            HOST,
        )
        .await;
        let prepared = authenticate(&server)
            .await
            .prepare_with_clock(&mut store, 0, CVM, || Ok(START))
            .await
            .ok()
            .unwrap();
        assert_eq!(prepared.preparation_readback(), expected);
        assert!(prepared.intent_record().outcome.is_none());
        let report = prepared.dispatch_with_clock(|| Ok(START)).await.unwrap();
        assert_eq!(report.preparation_readback(), expected);
        assert_eq!(report.provider_outcome(), DeletionOutcome::NotFound404);
        assert!(!report.cleanup_complete());
        assert!(!report.independent_disk_deletion_verified());
        server.wait_closed(3).await;
        assert_eq!(request_methods(&server).len(), 3);
    }
}

#[tokio::test]
async fn null_instance_can_prepare_exact_tracked_deletion_without_claiming_identity_match() {
    let fixture = Fixture::with_instance(WORKSPACE, CVM, START, None);
    let mut store = fixture.open();
    let detail = DETAIL.replace(&format!("\"{INSTANCE}\""), "null");
    let server = Server::start(
        vec![response("200 OK", AUTH), response("200 OK", &detail)],
        HOST,
    )
    .await;
    let prepared = authenticate(&server)
        .await
        .prepare_with_clock(&mut store, 0, CVM, || Ok(START))
        .await
        .unwrap();
    assert_eq!(
        prepared.preparation_readback(),
        PreparationReadback::IncompleteCvmFields
    );
    drop(prepared);
    assert_pending(&store);
    server.wait_closed(2).await;
    assert!(
        request_methods(&server)
            .iter()
            .all(|method| method.starts_with("GET "))
    );
}

#[tokio::test]
async fn dropping_prepared_or_unpolled_dispatch_leaves_one_pending_intent() {
    for drop_future in [false, true] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        let server = Server::start(
            vec![response("200 OK", AUTH), response("200 OK", DETAIL)],
            HOST,
        )
        .await;
        let prepared = authenticate(&server)
            .await
            .prepare_with_clock(&mut store, 0, CVM, || Ok(START))
            .await
            .ok()
            .unwrap();
        if drop_future {
            drop(prepared.dispatch());
        } else {
            drop(prepared);
        }
        assert_pending(&store);
        server.wait_closed(2).await;
        assert!(
            request_methods(&server)
                .iter()
                .all(|line| line.starts_with("GET "))
        );
        drop(store);
        assert_pending(&fixture.open());
    }
}

#[tokio::test]
async fn cancelling_after_delete_transmission_preserves_pending_and_closes_driver() {
    let fixture = Fixture::standard();
    let mut store = fixture.open();
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", DETAIL),
            b"HTTP/1.1 ".to_vec(),
        ],
        HOST,
    )
    .await;
    let client = authenticate(&server).await;
    let task = tokio::spawn(async move {
        let prepared = client
            .prepare_with_clock(&mut store, 0, CVM, || Ok(START))
            .await
            .ok()
            .unwrap();
        prepared.dispatch_with_clock(|| Ok(START)).await
    });
    server.wait_requests(3).await;
    assert!(matches!(
        LedgerStore::open(&fixture.original()),
        Err(StoreError::Locked)
    ));
    task.abort();
    assert!(task.await.is_err());
    server.wait_closed(3).await;
    assert_pending(&fixture.open());
    assert_eq!(
        request_methods(&server)
            .iter()
            .filter(|line| line.starts_with("DELETE "))
            .count(),
        1
    );
}

#[tokio::test]
async fn retry_cancellation_preserves_both_intents_without_an_automatic_request() {
    for after_transmission in [false, true] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        prior_intent(&mut store, None);
        let prior = store.ledger().unwrap().deletion_intents()[0].clone();
        let server = Server::start(
            vec![
                response("200 OK", AUTH),
                response("200 OK", DETAIL),
                b"HTTP/1.1 ".to_vec(),
            ],
            HOST,
        )
        .await;
        let prepared =
            prepare_retry_with_clock(authenticate(&server).await, &mut store, 1, || Ok(START))
                .await
                .ok()
                .unwrap();
        if after_transmission {
            // Poll the request until the fake provider sees it, then drop its
            // future just as cancellation would. The borrowed writer lock stays
            // held until this future is gone.
            let mut dispatch = Box::pin(prepared.dispatch_with_clock(|| Ok(START)));
            tokio::select! {
                _ = &mut dispatch => panic!("synthetic partial response completed"),
                _ = server.wait_requests(3) => {}
            }
            assert!(matches!(
                LedgerStore::open(&fixture.original()),
                Err(StoreError::Locked)
            ));
            drop(dispatch);
        } else {
            drop(prepared.dispatch());
        }
        let count = if after_transmission { 3 } else { 2 };
        server.wait_closed(count).await;
        assert_eq!(request_methods(&server).len(), count);
        drop(store);
        let reopened = fixture.open();
        let intents = reopened.ledger().unwrap().deletion_intents();
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0], prior);
        assert_eq!(
            intents[1].retry.as_ref().unwrap().prior_intent_generation,
            1
        );
        assert!(intents[1].outcome.is_none());
    }
}

#[tokio::test]
async fn retry_with_expired_original_budget_keeps_durable_intent_without_dispatch() {
    let fixture = Fixture::standard();
    let mut store = fixture.open();
    prior_intent(&mut store, None);
    let server = Server::start(
        vec![response("200 OK", AUTH), response("200 OK", DETAIL)],
        HOST,
    )
    .await;
    let client = server.client(AUTH.len().max(DETAIL.len()));
    let deadline = client.deadline;
    let prepared = prepare_retry_with_clock(
        client.authenticate_deletion().await.ok().unwrap(),
        &mut store,
        1,
        || Ok(START),
    )
    .await
    .ok()
    .unwrap();
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    assert_eq!(
        prepared.dispatch_with_clock(|| Ok(START)).await.err(),
        Some(DeletionError::Provider(ProviderHttpError::DeadlineExceeded))
    );
    tokio::time::resume();
    server.wait_closed(2).await;
    assert_eq!(request_methods(&server).len(), 2);
    drop(store);
    let reopened = fixture.open();
    let intents = reopened.ledger().unwrap().deletion_intents();
    assert_eq!(intents.len(), 2);
    assert!(intents.iter().all(|intent| intent.outcome.is_none()));
}

#[tokio::test]
async fn original_deadline_exhaustion_journals_transport_uncertainty_without_retry() {
    for retry in [false, true] {
        let fixture = Fixture::standard();
        let mut store = fixture.open();
        if retry {
            prior_intent(&mut store, None);
        }
        let server = Server::start(
            vec![
                response("200 OK", AUTH),
                response("200 OK", DETAIL),
                b"HTTP/1.1 ".to_vec(),
            ],
            HOST,
        )
        .await;
        let client = server.client(AUTH.len().max(DETAIL.len()));
        let deadline = client.deadline;
        let client = client.authenticate_deletion().await.ok().unwrap();
        // Spend half the fixture's remaining budget before preparation. A renewed
        // phase budget would then extend beyond the distinct boundary below.
        let spent = deadline.saturating_duration_since(Instant::now()) / 2;
        tokio::time::pause();
        tokio::time::advance(spent).await;
        tokio::time::resume();
        let task = tokio::spawn(async move {
            let prepared = client
                .prepare_selected_with_clock(
                    &mut store,
                    u64::from(retry),
                    CVM,
                    if retry {
                        Selection::Retry(1)
                    } else {
                        Selection::First
                    },
                    None,
                    || Ok(START),
                )
                .await
                .ok()
                .unwrap();
            prepared.dispatch_with_clock(|| Ok(START)).await
        });
        server.wait_requests(3).await;
        tokio::time::pause();
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        let report = task.await.unwrap().unwrap();
        // Allow timer granularity while detecting renewal, using only intervals
        // derived from the explicit synthetic client budget.
        assert!(Instant::now() < deadline + spent);
        tokio::time::resume();
        assert_eq!(
            report.provider_outcome(),
            DeletionOutcome::TransportUncertain
        );
        assert_eq!(
            report.transport_issue(),
            Some(ProviderHttpError::DeadlineExceeded)
        );
        assert_eq!(report.outcome_journal(), OutcomeJournal::Committed);
        server.wait_closed(3).await;
        assert_eq!(
            fixture.open().ledger().unwrap().deletion_intents()[usize::from(retry)]
                .outcome
                .as_ref()
                .unwrap()
                .outcome,
            DeletionOutcome::TransportUncertain
        );
        assert_eq!(request_methods(&server).len(), 3);
        if retry {
            assert!(
                fixture.open().ledger().unwrap().deletion_intents()[0]
                    .outcome
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn lost_reply_or_out_of_range_http_status_stays_uncertain_and_durable() {
    for retry in [false, true] {
        for (reply, expected) in [
            (Vec::new(), ProviderHttpError::HttpFailed),
            (delete_reply(700), ProviderHttpError::UnexpectedStatus),
        ] {
            let fixture = Fixture::standard();
            let mut store = fixture.open();
            if retry {
                prior_intent(&mut store, None);
            }
            let server = Server::start(
                vec![response("200 OK", AUTH), response("200 OK", DETAIL), reply],
                HOST,
            )
            .await;
            let prepared = authenticate(&server)
                .await
                .prepare_selected_with_clock(
                    &mut store,
                    u64::from(retry),
                    CVM,
                    if retry {
                        Selection::Retry(1)
                    } else {
                        Selection::First
                    },
                    None,
                    || Ok(START),
                )
                .await
                .ok()
                .unwrap();
            let report = prepared.dispatch_with_clock(|| Ok(START)).await.unwrap();
            assert_eq!(
                report.provider_outcome(),
                DeletionOutcome::TransportUncertain
            );
            assert_eq!(report.transport_issue(), Some(expected));
            assert_eq!(report.outcome_journal(), OutcomeJournal::Committed);
            assert!(!report.cleanup_complete());
            server.wait_closed(3).await;
            assert_eq!(request_methods(&server).len(), 3);
            drop(store);
            assert_eq!(
                fixture.open().ledger().unwrap().deletion_intents()[usize::from(retry)]
                    .outcome
                    .as_ref()
                    .unwrap()
                    .outcome,
                DeletionOutcome::TransportUncertain
            );
            if retry {
                assert!(
                    fixture.open().ledger().unwrap().deletion_intents()[0]
                        .outcome
                        .is_none()
                );
            }
        }
    }
}

#[tokio::test]
async fn outcome_write_failure_reports_the_status_without_claiming_a_commit() {
    let fixture = Fixture::standard();
    let mut store = fixture.open();
    let pending = fixture.store().join("pending.json");
    let server = Server::start_with_observer(
        vec![
            response("200 OK", AUTH),
            response("200 OK", DETAIL),
            delete_reply(204),
        ],
        HOST,
        move |request| {
            if request.starts_with("DELETE ") {
                fs::write(&pending, b"synthetic concurrent draft").unwrap();
            }
        },
    )
    .await;
    let prepared = authenticate(&server)
        .await
        .prepare_with_clock(&mut store, 0, CVM, || Ok(START))
        .await
        .ok()
        .unwrap();
    let report = prepared.dispatch_with_clock(|| Ok(START)).await.unwrap();
    assert_eq!(report.provider_outcome(), DeletionOutcome::Initiated204);
    assert_eq!(
        report.outcome_journal(),
        OutcomeJournal::NotConfirmed(StoreError::PendingRecovery)
    );
    assert!(!report.cleanup_complete());
    server.wait_closed(3).await;
    assert_pending(&store);
    drop(store);
    let reopened = fixture.open();
    assert!(reopened.has_uncommitted_draft());
    assert_pending(&reopened);
    // The injected draft remains intact until the whole owned fixture drops.
}

#[tokio::test]
async fn clock_reversal_after_response_preserves_observed_status_and_pending_intent() {
    let fixture = Fixture::standard();
    let mut store = fixture.open();
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", DETAIL),
            delete_reply(204),
        ],
        HOST,
    )
    .await;
    let prepared = authenticate(&server)
        .await
        .prepare_with_clock(&mut store, 0, CVM, || Ok(START))
        .await
        .ok()
        .unwrap();
    let mut calls = 0;
    let report = prepared
        .dispatch_with_clock(|| {
            calls += 1;
            Ok(if calls == 1 { START } else { START - 1 })
        })
        .await
        .unwrap();
    assert_eq!(report.provider_outcome(), DeletionOutcome::Initiated204);
    assert_eq!(report.outcome_journal(), OutcomeJournal::ClockRejected);
    assert_eq!(report.transport_issue(), None);
    assert!(!report.cleanup_complete());
    assert_pending(&store);
    server.wait_closed(3).await;
    drop(store);
    assert_pending(&fixture.open());
}
