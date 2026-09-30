//! Persistence proofs use completed reads from the synthetic loopback TLS
//! fixture. Historical DTOs are statements, never constructors for live reads.
use super::*;
use crate::{
    MAX_LIFETIME_SECONDS,
    controller::TrackedCvm,
    observation::{ObservationLimits, ObservationSession},
    provider_http::tests::{AUTH, Server, response},
};
use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
};

const WORKSPACE: &str = "wks_synthetic_only";
const START: u64 = 1000;
const EMPTY_INVENTORY: &str = r#"{"items":[],"total":0,"page":1,"page_size":30,"pages":1}"#;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.codex-tmp/persisted-observation-tests");
        fs::create_dir_all(&base).unwrap();
        let path = fs::canonicalize(base).unwrap().join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let binding = ExperimentBinding::new(
            "synthetic_observation".into(),
            WORKSPACE.into(),
            START,
            START + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 1).unwrap();
        ledger.begin_attempt("first".into(), START).unwrap();
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
        // Only this test's newly created synthetic state is removed.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

async fn read(store: &LedgerStore) -> ReadObservation {
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", EMPTY_INVENTORY),
        ],
        "cloud-api.phala.com",
    )
    .await;
    let observation = ObservationSession::new(store)
        .unwrap()
        .observe(
            server.client(AUTH.len().max(EMPTY_INVENTORY.len())),
            ObservationLimits {
                inventory_page_size: 30,
                usage_page_size: 500,
                max_inventory_records: NonZeroUsize::new(1).unwrap(),
                max_usage_records_per_app: NonZeroUsize::new(1).unwrap(),
            },
        )
        .await
        .unwrap();
    server.wait_closed(2).await;
    observation
}

fn new_cvm() -> TrackedCvm {
    TrackedCvm {
        cvm_id: "synthetic_new_cvm".into(),
        app_id: "synthetic_app".into(),
        instance_id: Some("synthetic_instance".into()),
        created_at_unix_seconds: START,
        compute_and_disk_microusd_per_hour: 1,
    }
}

#[tokio::test]
async fn observation_snapshot_is_durable_before_its_reference_escapes_and_keeps_original() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.original()).unwrap();
    let mut store = fixture.open();
    let observation = read(&store).await;
    let now = observation.finished_at_unix_seconds();
    let expected = ObservationRecord::from_read(&observation, now).unwrap();
    let mut points = Vec::new();
    let reference = store
        .commit_observation_with_clock_and_hook(observation, &mut || Ok(now), &mut |point| {
            assert!(matches!(
                LedgerStore::open(&fixture.original()),
                Err(StoreError::Locked)
            ));
            points.push(point);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        points,
        [
            CommitPoint::DraftCreated,
            CommitPoint::DraftWritten,
            CommitPoint::DraftSynced,
            CommitPoint::SnapshotLinked,
            CommitPoint::DirectorySynced,
            CommitPoint::DraftRemoved
        ]
    );
    assert_eq!(reference.generation(), 1);
    assert_eq!(reference.original_binding_path, fixture.original());
    assert_eq!(
        reference.snapshot_path,
        fixture.store().join(snapshot_name(1))
    );
    assert!(!fixture.store().join(PENDING).exists());
    assert_eq!(store.ledger().unwrap().observations(), &[expected.clone()]);
    assert!(store.ledger().unwrap().deletion_intents().is_empty());
    assert_eq!(fs::read(fixture.original()).unwrap(), original);
    drop(store);
    let store = fixture.open();
    assert_eq!(store.ledger().unwrap().observations(), &[expected]);
    assert_eq!(store.planning_reference().unwrap().generation(), 1);
}

#[tokio::test]
async fn observation_write_interruptions_reopen_without_promotion_or_history_reset() {
    for point in [
        CommitPoint::DraftCreated,
        CommitPoint::DraftWritten,
        CommitPoint::DraftSynced,
        CommitPoint::SnapshotLinked,
        CommitPoint::DirectorySynced,
        CommitPoint::DraftRemoved,
    ] {
        let fixture = Fixture::new();
        let original = fs::read(fixture.original()).unwrap();
        let mut store = fixture.open();
        let observation = read(&store).await;
        let now = observation.finished_at_unix_seconds();
        let result = store.commit_observation_with_clock_and_hook(
            observation,
            &mut || Ok(now),
            &mut |stage| {
                if stage == point {
                    Err(StoreError::Io)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Err(StoreError::Io)));
        assert!(matches!(store.ledger(), Err(StoreError::ReloadRequired)));
        drop(store);
        let mut reopened = fixture.open();
        let committed = matches!(
            point,
            CommitPoint::SnapshotLinked | CommitPoint::DirectorySynced | CommitPoint::DraftRemoved
        );
        assert_eq!(
            reopened.ledger().unwrap().observations().len(),
            usize::from(committed)
        );
        assert_eq!(reopened.generation, u64::from(committed));
        assert_eq!(
            reopened.has_uncommitted_draft(),
            point != CommitPoint::DraftRemoved
        );
        if reopened.has_uncommitted_draft() {
            assert!(matches!(
                reopened.planning_reference(),
                Err(StoreError::PendingRecovery)
            ));
            reopened.discard_uncommitted_draft().unwrap();
        }
        assert_eq!(
            reopened.planning_reference().unwrap().generation(),
            u64::from(committed)
        );
        assert_eq!(
            reopened.ledger().unwrap().observations().len(),
            usize::from(committed)
        );
        assert_eq!(fs::read(fixture.original()).unwrap(), original);
    }
}

#[tokio::test]
async fn commit_clock_before_completed_read_refuses_without_writing() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let before = json_bytes(store.ledger().unwrap()).unwrap();
    let original = fs::read(fixture.original()).unwrap();
    let observation = read(&store).await;
    let earlier = observation
        .finished_at_unix_seconds()
        .checked_sub(1)
        .unwrap();
    let result =
        store.commit_observation_with_clock_and_hook(observation, &mut || Ok(earlier), &mut |_| {
            panic!("clock rejection must precede any snapshot write")
        });
    assert!(matches!(result, Err(StoreError::InvalidState)));
    assert_eq!(store.planning_reference().unwrap().generation(), 0);
    assert_eq!(json_bytes(store.ledger().unwrap()).unwrap(), before);
    assert_eq!(fs::read(fixture.original()).unwrap(), original);
    assert!(!fixture.store().join(PENDING).exists());
    assert!(!fixture.store().join(snapshot_name(1)).exists());
}

#[tokio::test]
async fn historical_statement_cannot_be_inserted_by_generic_commit_or_initialization() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let observation = read(&store).await;
    let record =
        ObservationRecord::from_read(&observation, observation.finished_at_unix_seconds()).unwrap();
    let mut forged = store.ledger().unwrap().clone();
    forged.append_observation(record).unwrap();
    assert_eq!(store.commit(&forged), Err(StoreError::InvalidState));
    assert_eq!(store.generation, 0);
    assert!(!fixture.store().join(snapshot_name(1)).exists());
    assert_eq!(
        create_original_binding(
            &fixture.0.join("forged-original.json"),
            &fixture.0.join("forged-state"),
            &forged
        ),
        Err(StoreError::InvalidState)
    );
    assert!(!fixture.0.join("forged-original.json").exists());
    // Also reject a hand-written original before initialization creates any
    // receipt or state directory; read-only DTOs are not live read capabilities.
    let path = fixture.0.join("handwritten-original.json");
    let original = OriginalRecord {
        binding: forged.binding().clone(),
        store_directory: fixture.0.join("handwritten-state"),
        initial_ledger: to_raw_value(&forged).unwrap(),
    };
    fs::write(&path, json_bytes(&original).unwrap()).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    assert!(matches!(
        LedgerStore::initialize(&path),
        Err(StoreError::InvalidState)
    ));
    assert!(!fixture.0.join("handwritten-state").exists());
}

#[tokio::test]
async fn historical_generation_link_and_combined_mutation_are_rejected_on_write_and_reload() {
    for wrong_generation in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let observation = read(&store).await;
        let mut record =
            ObservationRecord::from_read(&observation, observation.finished_at_unix_seconds())
                .unwrap();
        if wrong_generation {
            // An ordinary intervening snapshot could make this link valid in
            // another history; it is not the actual preceding generation here.
            record.source_generation = 1;
            record.committed_generation = 2;
        }
        let mut forged = store.ledger().unwrap().clone();
        forged.append_observation(record).unwrap();
        if !wrong_generation {
            forged.track_cvm(WORKSPACE, "first", new_cvm()).unwrap();
        }
        assert_eq!(
            store.commit_with_hook(&forged, &mut |_| Ok(())),
            Err(StoreError::InvalidState)
        );
        assert_eq!(store.generation, 0);
        let snapshot = Snapshot {
            generation: 1,
            ledger: to_raw_value(&forged).unwrap(),
        };
        fs::write(
            fixture.store().join(snapshot_name(1)),
            json_bytes(&snapshot).unwrap(),
        )
        .unwrap();
        drop(store);
        assert!(matches!(
            LedgerStore::open(&fixture.original()),
            Err(StoreError::InvalidState)
        ));
    }
}

#[tokio::test]
async fn ordinary_later_tracking_preserves_committed_observation_history() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let observation = read(&store).await;
    store.commit_observation(observation).unwrap();
    let retained = store.ledger().unwrap().observations().to_vec();
    let mut next = store.ledger().unwrap().clone();
    next.track_cvm(WORKSPACE, "first", new_cvm()).unwrap();
    store.commit(&next).unwrap();
    assert_eq!(store.generation, 2);
    assert_eq!(store.ledger().unwrap().observations(), retained);
    drop(store);
    let store = fixture.open();
    assert_eq!(store.ledger().unwrap().observations(), retained);
    assert_eq!(store.ledger().unwrap().tracked_cvms().count(), 1);
}
