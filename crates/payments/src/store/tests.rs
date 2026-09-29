use super::*;
use std::{
    cell::Cell,
    os::unix::fs::PermissionsExt,
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

struct Fixture {
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "zrpc-payments-store-{}-{}",
            std::process::id(),
            u128::from_be_bytes(random),
        ));
        Self { path }
    }

    fn directory(&self) -> PrivateDirectory {
        PrivateDirectory::create(&self.path).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}

fn pending(request: &[u8], state: &[u8]) -> PendingTicket {
    PendingTicket {
        blinded_request: request.to_vec(),
        blinding_state: SecretBytes::new(state.to_vec()),
    }
}

#[test]
fn private_directory_and_existing_store_fail_closed() {
    let fixture = Fixture::new();
    assert!(matches!(
        PrivateDirectory::open(&fixture.path),
        Err(StoreError::PrivateDirectoryRequired)
    ));
    let directory = fixture.directory();
    assert!(matches!(
        RedeemerStore::open(&directory),
        Err(StoreError::MissingOrCorrupt)
    ));
    let store = RedeemerStore::create(&directory).unwrap();
    drop(store);
    assert_eq!(
        fs::metadata(&fixture.path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(fixture.path.join("redeemer.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(matches!(
        RedeemerStore::create(&directory),
        Err(StoreError::AlreadyExists)
    ));
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        PrivateDirectory::open(&fixture.path),
        Err(StoreError::PrivateDirectoryRequired)
    ));
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.path.join("redeemer.sqlite3");
    let mut data = fs::read(&path).unwrap();
    data[0] = 0;
    fs::write(&path, data).unwrap();
    assert!(matches!(
        RedeemerStore::open(&directory),
        Err(StoreError::MissingOrCorrupt)
    ));
}

#[test]
fn private_directory_rejects_replaceable_ancestor() {
    let fixture = Fixture::new();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&fixture.path)
        .unwrap();
    let private_path = fixture.path.join("private");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&private_path)
        .unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        PrivateDirectory::open(&private_path),
        Err(StoreError::PrivateDirectoryRequired)
    ));
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(PrivateDirectory::open(&private_path).is_ok());
}

#[test]
fn bearer_store_directory_inside_checkout_is_rejected() {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "payment-private-dir-{}",
            u128::from_be_bytes(random)
        ));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    assert!(matches!(
        PrivateDirectory::open(&path),
        Err(StoreError::PrivateDirectoryRequired)
    ));
    fs::remove_dir(&path).unwrap();
}

#[test]
fn client_pending_and_ticket_states_survive_restart() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let id = [7; 32];
    let mut client = ClientStore::create(&directory).unwrap();
    let tickets = [
        pending(b"blind-a", b"state-a"),
        pending(b"blind-b", b"state-b"),
    ];
    client.store_prepared(id, &tickets).unwrap();
    assert!(matches!(
        client.store_prepared(id, &[pending(b"changed", b"state-a")]),
        Err(StoreError::AlteredPurchase)
    ));
    drop(client);

    let mut client = ClientStore::open(&directory).unwrap();
    let recovered = client.pending(id).unwrap();
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0].blinding_state.expose(), b"state-a");
    client.store_prepared(id, &tickets).unwrap();
    client
        .collect_verified(
            id,
            &[
                SecretBytes::new(b"token-a".to_vec()),
                SecretBytes::new(b"token-b".to_vec()),
            ],
        )
        .unwrap();
    assert!(client.pending(id).unwrap().is_empty());
    assert_eq!(
        client.balance().unwrap(),
        Balance {
            available: 2,
            uncertain: 0
        }
    );
    assert_eq!(
        client.collect_verified(id, &[SecretBytes::new(b"token-c".to_vec())]),
        Err(StoreError::AlreadyCollected)
    );
    assert!(matches!(
        client.take_available_if(|_| Err(StoreError::InvalidTransition)),
        Err(StoreError::InvalidTransition)
    ));
    assert_eq!(client.balance().unwrap().available, 2);
    let selected = client.take_available_if(|_| Ok(())).unwrap().unwrap();
    assert_eq!(selected.token.expose(), b"token-a");
    assert_eq!(client.balance().unwrap().uncertain, 1);
    drop(client);

    let mut client = ClientStore::open(&directory).unwrap();
    assert_eq!(
        client.balance().unwrap(),
        Balance {
            available: 1,
            uncertain: 1
        }
    );
    client.mark_spent(selected.marker).unwrap();
    assert_eq!(
        client.balance().unwrap(),
        Balance {
            available: 1,
            uncertain: 0
        }
    );
}

#[test]
fn concurrent_clients_can_take_one_ticket_only_once() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let id = [11; 32];
    let mut client = ClientStore::create(&directory).unwrap();
    client
        .store_prepared(id, &[pending(b"blind", b"state")])
        .unwrap();
    client
        .collect_verified(id, &[SecretBytes::new(b"ticket".to_vec())])
        .unwrap();
    drop(client);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = fixture.path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let directory = PrivateDirectory::open(&path).unwrap();
            let mut client = ClientStore::open(&directory).unwrap();
            barrier.wait();
            client.take_available_if(|_| Ok(())).unwrap().is_some()
        }));
    }
    let taken = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|taken| *taken)
        .count();
    assert_eq!(taken, 1);
    assert_eq!(
        ClientStore::open(&directory).unwrap().balance().unwrap(),
        Balance {
            available: 0,
            uncertain: 1,
        }
    );
}

#[test]
fn issuer_authorization_is_exact_and_issuance_is_idempotent() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let id = [9; 32];
    let mut issuer = IssuerStore::create(&directory).unwrap();
    assert_eq!(
        issuer.issue_once(id, [1; 32], || Ok(vec![b"sig".to_vec()])),
        Err(StoreError::UnknownPurchase)
    );
    issuer.authorize(id, 2).unwrap();
    issuer.authorize(id, 2).unwrap();
    assert_eq!(issuer.authorize(id, 3), Err(StoreError::AlteredPurchase));
    assert_eq!(
        issuer.issue_once(id, [1; 32], || Ok(vec![b"one".to_vec()])),
        Err(StoreError::InvalidQuantity)
    );
    drop(issuer);

    let mut issuer = IssuerStore::open(&directory).unwrap();
    let calls = Cell::new(0);
    let first = issuer
        .issue_once(id, [1; 32], || {
            calls.set(calls.get() + 1);
            Ok(vec![b"sig-a".to_vec(), b"sig-b".to_vec()])
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    drop(issuer);

    let mut issuer = IssuerStore::open(&directory).unwrap();
    let again = issuer
        .issue_once(id, [1; 32], || panic!("must not sign twice"))
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(
        issuer.issue_once(id, [2; 32], || panic!("must not sign changed requests")),
        Err(StoreError::AlteredPurchase)
    );
}

#[test]
fn issuer_partial_issuance_rolls_back_after_process_exit() {
    const CHILD_DIR: &str = "ZRPC_PAYMENT_ISSUER_CRASH_DIR";
    let id = [12; 32];
    if let Some(path) = std::env::var_os(CHILD_DIR) {
        let directory = PrivateDirectory::open(Path::new(&path)).unwrap();
        let mut issuer = IssuerStore::open(&directory).unwrap();
        let transaction = issuer
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO issuance_responses(purchase_id, ordinal, blind_signature) VALUES (?1, 0, ?2)",
                params![id.as_slice(), b"partial-signature"],
            )
            .unwrap();
        // Exit without dropping the open transaction, as a process failure
        // would. SQLite must discard the uncommitted partial issuance.
        std::process::exit(99);
    }

    let fixture = Fixture::new();
    let directory = fixture.directory();
    let mut issuer = IssuerStore::create(&directory).unwrap();
    issuer.authorize(id, 2).unwrap();
    drop(issuer);

    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("store::tests::issuer_partial_issuance_rolls_back_after_process_exit")
        .env(CHILD_DIR, &fixture.path)
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(99));

    let mut issuer = IssuerStore::open(&directory).unwrap();
    let row_count: i64 = issuer
        .0
        .query_row("SELECT count(*) FROM issuance_responses", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(row_count, 0);
    let signatures = issuer
        .issue_once(id, [7; 32], || {
            Ok(vec![b"first".to_vec(), b"second".to_vec()])
        })
        .unwrap();
    drop(issuer);
    assert_eq!(
        IssuerStore::open(&directory)
            .unwrap()
            .issue_once(id, [7; 32], || panic!("must replay committed issuance"))
            .unwrap(),
        signatures
    );
}

#[test]
fn redeeming_same_marker_concurrently_admits_once_and_replay_survives_restart() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    RedeemerStore::create(&directory).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = fixture.path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let directory = PrivateDirectory::open(&path).unwrap();
            let mut store = RedeemerStore::open(&directory).unwrap();
            barrier.wait();
            store.admit_verified([3; 32], [4; 32]).unwrap()
        }));
    }
    let mut results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    results.sort_by_key(|result| match result {
        Admission::Accepted => 0,
        Admission::Replay => 1,
    });
    assert_eq!(results, vec![Admission::Accepted, Admission::Replay]);
    let mut reopened = RedeemerStore::open(&directory).unwrap();
    assert_eq!(
        reopened.admit_verified([3; 32], [4; 32]).unwrap(),
        Admission::Replay
    );
    assert_eq!(
        reopened.admit_verified([5; 32], [4; 32]).unwrap(),
        Admission::Accepted
    );
}

#[test]
fn redemption_storage_failure_cannot_admit() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let mut store = RedeemerStore::create(&directory).unwrap();
    store.0.execute_batch("PRAGMA query_only=ON").unwrap();
    assert_eq!(
        store.admit_verified([1; 32], [2; 32]),
        Err(StoreError::StorageUnavailable)
    );
    store.0.execute_batch("PRAGMA query_only=OFF").unwrap();
    assert_eq!(
        store.admit_verified([1; 32], [2; 32]).unwrap(),
        Admission::Accepted
    );
}

#[test]
fn redeemer_open_rejects_schema_that_could_retain_extra_records() {
    for mutation in [
        "ALTER TABLE spent ADD COLUMN purchase_id BLOB",
        "CREATE TABLE redemption_history (ticket_marker BLOB, observed_at TEXT)",
        "CREATE TRIGGER record_redemption AFTER INSERT ON spent BEGIN SELECT 1; END",
    ] {
        let fixture = Fixture::new();
        let directory = fixture.directory();
        let store = RedeemerStore::create(&directory).unwrap();
        store.0.execute_batch(mutation).unwrap();
        drop(store);
        assert!(matches!(
            RedeemerStore::open(&directory),
            Err(StoreError::MissingOrCorrupt)
        ));
    }
}

#[test]
fn client_and_issuer_reject_schema_extensions_that_could_capture_payment_records() {
    for mutation in [
        "ALTER TABLE tickets ADD COLUMN purchase_id BLOB",
        "CREATE TABLE ticket_history (token BLOB)",
        "CREATE TABLE sqliteXhistory (token BLOB)",
        "CREATE TRIGGER record_ticket AFTER INSERT ON tickets BEGIN SELECT 1; END",
    ] {
        let fixture = Fixture::new();
        let directory = fixture.directory();
        let store = ClientStore::create(&directory).unwrap();
        store.0.execute_batch(mutation).unwrap();
        drop(store);
        assert!(matches!(
            ClientStore::open(&directory),
            Err(StoreError::MissingOrCorrupt)
        ));
    }
    for mutation in [
        "ALTER TABLE issuance_responses ADD COLUMN finalized_token BLOB",
        "CREATE TABLE purchase_history (purchase_id BLOB)",
        "CREATE TABLE sqliteXhistory (purchase_id BLOB)",
        "CREATE TRIGGER record_issuance AFTER INSERT ON issuance_responses BEGIN SELECT 1; END",
    ] {
        let fixture = Fixture::new();
        let directory = fixture.directory();
        let store = IssuerStore::create(&directory).unwrap();
        store.0.execute_batch(mutation).unwrap();
        drop(store);
        assert!(matches!(
            IssuerStore::open(&directory),
            Err(StoreError::MissingOrCorrupt)
        ));
    }
}

#[test]
fn private_records_and_debug_output_exclude_sensitive_fields() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let issuer = IssuerStore::create(&directory).unwrap();
    let redeemer = RedeemerStore::create(&directory).unwrap();
    let client = ClientStore::create(&directory).unwrap();
    drop((issuer, redeemer, client));
    let issuer_schema: String = IssuerStore::open(&directory)
        .unwrap()
        .0
        .query_row(
            "SELECT group_concat(sql) FROM sqlite_schema WHERE type='table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let redeemer_schema: String = RedeemerStore::open(&directory)
        .unwrap()
        .0
        .query_row(
            "SELECT group_concat(sql) FROM sqlite_schema WHERE type='table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!issuer_schema.contains("finalized"));
    for forbidden in ["purchase", "request", "response", "ip_address", "timestamp"] {
        assert!(!redeemer_schema.contains(forbidden));
    }
    let sensitive = b"synthetic-sensitive-marker";
    assert!(
        !format!("{:?}", SecretBytes::new(sensitive.to_vec()))
            .contains("synthetic-sensitive-marker")
    );
    assert!(!format!("{:?}", pending(sensitive, sensitive)).contains("synthetic-sensitive-marker"));
}
