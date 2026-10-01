use std::{
    fmt, fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub type PurchaseId = [u8; 32];
type Marker = [u8; 32];

const SCHEMA_VERSION: i64 = 2;
const CLIENT_APPLICATION_ID: i64 = 0x5a50_434c;
const ISSUER_APPLICATION_ID: i64 = 0x5a50_4953;
const REDEEMER_APPLICATION_ID: i64 = 0x5a50_5244;
const CLIENT_PURCHASES_SQL: &str = "CREATE TABLE purchases (purchase_id BLOB PRIMARY KEY CHECK(length(purchase_id)=32), quantity INTEGER NOT NULL CHECK(quantity>0), collected INTEGER NOT NULL DEFAULT 0 CHECK(collected IN (0,1)))";
const CLIENT_PENDING_SQL: &str = "CREATE TABLE pending (purchase_id BLOB NOT NULL REFERENCES purchases(purchase_id), ordinal INTEGER NOT NULL, blinded_request BLOB NOT NULL, blinding_state BLOB NOT NULL, PRIMARY KEY(purchase_id, ordinal))";
const CLIENT_TICKETS_SQL: &str = "CREATE TABLE tickets (marker BLOB PRIMARY KEY CHECK(length(marker)=32), token BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('available','uncertain','spent')))";
const ISSUER_AUTHORIZATIONS_SQL: &str = "CREATE TABLE authorizations (purchase_id BLOB PRIMARY KEY CHECK(length(purchase_id)=32), quantity INTEGER NOT NULL CHECK(quantity>0), request_commitment BLOB NOT NULL CHECK(length(request_commitment)=32))";
const ISSUER_RESPONSES_SQL: &str = "CREATE TABLE issuance_responses (purchase_id BLOB NOT NULL REFERENCES authorizations(purchase_id), ordinal INTEGER NOT NULL, blind_signature BLOB NOT NULL, PRIMARY KEY(purchase_id, ordinal))";
const REDEEMER_TABLE_SQL: &str = "CREATE TABLE spent (issuer_key_id BLOB NOT NULL CHECK(length(issuer_key_id)=32), ticket_marker BLOB NOT NULL CHECK(length(ticket_marker)=32), PRIMARY KEY(issuer_key_id, ticket_marker)) WITHOUT ROWID";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    PrivateDirectoryRequired,
    AlreadyExists,
    MissingOrCorrupt,
    InvalidQuantity,
    BudgetExhausted,
    AlteredPurchase,
    UnknownPurchase,
    AlreadyCollected,
    InvalidTransition,
    StorageUnavailable,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PrivateDirectoryRequired => "private payment directory required",
            Self::AlreadyExists => "payment store already exists",
            Self::MissingOrCorrupt => "payment store missing or corrupt",
            Self::InvalidQuantity => "invalid purchase quantity",
            Self::BudgetExhausted => "free ticket budget exhausted",
            Self::AlteredPurchase => "purchase inputs changed",
            Self::UnknownPurchase => "purchase is not authorized or pending",
            Self::AlreadyCollected => "purchase already collected",
            Self::InvalidTransition => "ticket state changed",
            Self::StorageUnavailable => "payment storage unavailable",
        })
    }
}

impl std::error::Error for StoreError {}

/// An explicitly selected, owner-only directory. Each role receives its own
/// directory and database; paths are not derived from purchase or token bytes.
pub struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    pub fn create(path: &Path) -> Result<Self, StoreError> {
        if !path.is_absolute() {
            return Err(StoreError::PrivateDirectoryRequired);
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| StoreError::PrivateDirectoryRequired)?;
        Self::open(path)
    }

    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if !path.is_absolute() {
            return Err(StoreError::PrivateDirectoryRequired);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| StoreError::PrivateDirectoryRequired)?;
        let canonical = fs::canonicalize(path).map_err(|_| StoreError::PrivateDirectoryRequired)?;
        let resolved =
            fs::symlink_metadata(&canonical).map_err(|_| StoreError::PrivateDirectoryRequired)?;
        let owner = rustix::process::geteuid().as_raw();
        if !metadata.is_dir()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
            || metadata.dev() != resolved.dev()
            || metadata.ino() != resolved.ino()
            || canonical
                .ancestors()
                .any(|parent| parent.join(".git").exists())
            || canonical.ancestors().skip(1).any(|parent| {
                let Ok(entry) = fs::symlink_metadata(parent) else {
                    return true;
                };
                !entry.is_dir()
                    || (entry.uid() != owner && entry.uid() != 0)
                    || (entry.mode() & 0o022 != 0 && entry.mode() & 0o1000 == 0)
            })
        {
            return Err(StoreError::PrivateDirectoryRequired);
        }
        Ok(Self(canonical))
    }

    fn file(&self, name: &'static str) -> PathBuf {
        self.0.join(name)
    }
}

/// Bearer material and client blinding state never use a content-bearing Debug
/// implementation. The bytes are cleared when this wrapper is dropped.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct PendingTicket {
    pub blinded_request: Vec<u8>,
    pub blinding_state: SecretBytes,
}

impl fmt::Debug for PendingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingTicket([redacted])")
    }
}

/// Local purchase metadata needed to re-export a blinded request batch after
/// an interrupted prepare. The purchase identifier never enters a token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PendingPurchase {
    pub purchase_id: PurchaseId,
    pub quantity: u64,
}

impl fmt::Debug for PendingPurchase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingPurchase([redacted])")
    }
}

pub struct SelectedTicket {
    pub marker: Marker,
    pub token: SecretBytes,
}

impl fmt::Debug for SelectedTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelectedTicket([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    pub available: u64,
    pub uncertain: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Accepted,
    Replay,
}

fn ensure_private_file(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::MissingOrCorrupt)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(StoreError::MissingOrCorrupt);
    }
    Ok(())
}

fn connect(
    directory: &PrivateDirectory,
    name: &'static str,
    create: bool,
) -> Result<Connection, StoreError> {
    let path = directory.file(name);
    if create {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => StoreError::AlreadyExists,
                _ => StoreError::StorageUnavailable,
            })?;
    }
    ensure_private_file(&path)?;
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StoreError::MissingOrCorrupt)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;",
        )
        .map_err(|_| {
            if create {
                StoreError::StorageUnavailable
            } else {
                StoreError::MissingOrCorrupt
            }
        })?;
    Ok(connection)
}

fn validate(connection: &Connection, expected_id: i64) -> Result<(), StoreError> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| StoreError::MissingOrCorrupt)?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| StoreError::MissingOrCorrupt)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| StoreError::MissingOrCorrupt)?;
    if application_id != expected_id || schema_version != SCHEMA_VERSION || integrity != "ok" {
        return Err(StoreError::MissingOrCorrupt);
    }
    Ok(())
}

fn validate_schema(
    connection: &Connection,
    expected_tables: &[(&str, &str)],
) -> Result<(), StoreError> {
    // Required-column probes and SQLite integrity checks also accept extra
    // tables, columns, views and triggers that can retain payment records.
    let mut statement = connection
        .prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name")
        .map_err(|_| StoreError::MissingOrCorrupt)?;
    let mut rows = statement
        .query([])
        .map_err(|_| StoreError::MissingOrCorrupt)?;
    for (expected_name, expected_sql) in expected_tables {
        let row = rows
            .next()
            .map_err(|_| StoreError::MissingOrCorrupt)?
            .ok_or(StoreError::MissingOrCorrupt)?;
        let kind: String = row.get(0).map_err(|_| StoreError::MissingOrCorrupt)?;
        let name: String = row.get(1).map_err(|_| StoreError::MissingOrCorrupt)?;
        let sql: String = row.get(2).map_err(|_| StoreError::MissingOrCorrupt)?;
        if kind != "table" || name != *expected_name || sql != *expected_sql {
            return Err(StoreError::MissingOrCorrupt);
        }
    }
    if rows
        .next()
        .map_err(|_| StoreError::MissingOrCorrupt)?
        .is_some()
    {
        return Err(StoreError::MissingOrCorrupt);
    }
    Ok(())
}

fn quantity(value: usize) -> Result<i64, StoreError> {
    if value == 0 {
        return Err(StoreError::InvalidQuantity);
    }
    i64::try_from(value).map_err(|_| StoreError::InvalidQuantity)
}

fn digest(bytes: &[u8]) -> Marker {
    Sha256::digest(bytes).into()
}

pub struct ClientStore(Connection);

impl ClientStore {
    pub fn create(directory: &PrivateDirectory) -> Result<Self, StoreError> {
        let connection = connect(directory, "client.sqlite3", true)?;
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .and_then(|_| connection.execute_batch(CLIENT_PURCHASES_SQL))
            .and_then(|_| connection.execute_batch(CLIENT_PENDING_SQL))
            .and_then(|_| connection.execute_batch(CLIENT_TICKETS_SQL))
            .and_then(|_| {
                connection.execute_batch(
                    "PRAGMA application_id=1515209548;
                     PRAGMA user_version=2;
                     COMMIT;",
                )
            })
            .map_err(|_| StoreError::StorageUnavailable)?;
        validate(&connection, CLIENT_APPLICATION_ID)?;
        validate_schema(
            &connection,
            &[
                ("pending", CLIENT_PENDING_SQL),
                ("purchases", CLIENT_PURCHASES_SQL),
                ("tickets", CLIENT_TICKETS_SQL),
            ],
        )?;
        Ok(Self(connection))
    }

    pub fn open(directory: &PrivateDirectory) -> Result<Self, StoreError> {
        let connection = connect(directory, "client.sqlite3", false)?;
        validate(&connection, CLIENT_APPLICATION_ID)?;
        validate_schema(
            &connection,
            &[
                ("pending", CLIENT_PENDING_SQL),
                ("purchases", CLIENT_PURCHASES_SQL),
                ("tickets", CLIENT_TICKETS_SQL),
            ],
        )?;
        Ok(Self(connection))
    }

    pub fn store_prepared(
        &mut self,
        id: PurchaseId,
        tickets: &[PendingTicket],
    ) -> Result<(), StoreError> {
        let count = quantity(tickets.len())?;
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT quantity FROM purchases WHERE purchase_id=?1",
                [id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::StorageUnavailable)?;
        if let Some(existing) = existing {
            if existing != count {
                return Err(StoreError::AlteredPurchase);
            }
            let mut statement = transaction
                .prepare("SELECT blinded_request, blinding_state FROM pending WHERE purchase_id=?1 ORDER BY ordinal")
                .map_err(|_| StoreError::StorageUnavailable)?;
            let mut rows = statement
                .query([id.as_slice()])
                .map_err(|_| StoreError::StorageUnavailable)?;
            for ticket in tickets {
                let Some(row) = rows.next().map_err(|_| StoreError::StorageUnavailable)? else {
                    return Err(StoreError::AlteredPurchase);
                };
                let request: Vec<u8> = row.get(0).map_err(|_| StoreError::StorageUnavailable)?;
                let state: Vec<u8> = row.get(1).map_err(|_| StoreError::StorageUnavailable)?;
                if request != ticket.blinded_request || state != ticket.blinding_state.expose() {
                    return Err(StoreError::AlteredPurchase);
                }
            }
            if rows
                .next()
                .map_err(|_| StoreError::StorageUnavailable)?
                .is_some()
            {
                return Err(StoreError::AlteredPurchase);
            }
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO purchases(purchase_id, quantity) VALUES (?1, ?2)",
                params![id.as_slice(), count],
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        for (index, ticket) in tickets.iter().enumerate() {
            transaction.execute(
                "INSERT INTO pending(purchase_id, ordinal, blinded_request, blinding_state) VALUES (?1, ?2, ?3, ?4)",
                params![id.as_slice(), i64::try_from(index).map_err(|_| StoreError::InvalidQuantity)?, ticket.blinded_request, ticket.blinding_state.expose()],
            ).map_err(|_| StoreError::StorageUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)
    }

    pub fn pending(&self, id: PurchaseId) -> Result<Vec<PendingTicket>, StoreError> {
        let mut statement = self.0.prepare(
            "SELECT blinded_request, blinding_state FROM pending WHERE purchase_id=?1 ORDER BY ordinal",
        ).map_err(|_| StoreError::StorageUnavailable)?;
        let rows = statement
            .query_map([id.as_slice()], |row| {
                Ok(PendingTicket {
                    blinded_request: row.get(0)?,
                    blinding_state: SecretBytes::new(row.get(1)?),
                })
            })
            .map_err(|_| StoreError::StorageUnavailable)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::StorageUnavailable)
    }

    /// Find durable uncollected purchases, including those whose request file
    /// was never written. A missing pending row is treated as corrupt state.
    pub fn pending_purchases(&self) -> Result<Vec<PendingPurchase>, StoreError> {
        let mut statement = self
            .0
            .prepare(
                "SELECT p.purchase_id, p.quantity, count(n.ordinal)
             FROM purchases p LEFT JOIN pending n ON n.purchase_id=p.purchase_id
             WHERE p.collected=0 GROUP BY p.purchase_id ORDER BY p.purchase_id",
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| StoreError::StorageUnavailable)?;
        rows.map(|row| {
            let (id, quantity, pending_count) = row.map_err(|_| StoreError::StorageUnavailable)?;
            if quantity <= 0 || pending_count != quantity {
                return Err(StoreError::MissingOrCorrupt);
            }
            Ok(PendingPurchase {
                purchase_id: id.try_into().map_err(|_| StoreError::MissingOrCorrupt)?,
                quantity: u64::try_from(quantity).map_err(|_| StoreError::MissingOrCorrupt)?,
            })
        })
        .collect()
    }

    /// Only a future cryptographic finalizer in this crate may call this after
    /// checking every blinded signature against the common issuer configuration.
    pub(crate) fn collect_verified(
        &mut self,
        id: PurchaseId,
        tokens: &[SecretBytes],
    ) -> Result<(), StoreError> {
        let count = quantity(tokens.len())?;
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let purchase: Option<(i64, i64)> = transaction
            .query_row(
                "SELECT quantity, collected FROM purchases WHERE purchase_id=?1",
                [id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::StorageUnavailable)?;
        let Some((expected, collected)) = purchase else {
            return Err(StoreError::UnknownPurchase);
        };
        if collected != 0 {
            return Err(StoreError::AlreadyCollected);
        }
        if expected != count {
            return Err(StoreError::InvalidQuantity);
        }
        for token in tokens {
            transaction
                .execute(
                    "INSERT INTO tickets(marker, token, state) VALUES (?1, ?2, 'available')",
                    params![digest(token.expose()).as_slice(), token.expose()],
                )
                .map_err(|_| StoreError::InvalidTransition)?;
        }
        transaction
            .execute("DELETE FROM pending WHERE purchase_id=?1", [id.as_slice()])
            .map_err(|_| StoreError::StorageUnavailable)?;
        transaction
            .execute(
                "UPDATE purchases SET collected=1 WHERE purchase_id=?1",
                [id.as_slice()],
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)
    }

    pub fn balance(&self) -> Result<Balance, StoreError> {
        let (available, uncertain): (i64, i64) = self.0.query_row(
            "SELECT count(*) FILTER (WHERE state='available'), count(*) FILTER (WHERE state='uncertain') FROM tickets",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|_| StoreError::StorageUnavailable)?;
        Ok(Balance {
            available: u64::try_from(available).map_err(|_| StoreError::StorageUnavailable)?,
            uncertain: u64::try_from(uncertain).map_err(|_| StoreError::StorageUnavailable)?,
        })
    }

    /// Read one available ticket without changing its state. Call this only
    /// after the private transport has passed its release and connection
    /// checks. `claim_available` must succeed before any wire transmission.
    pub fn preview_available(&self) -> Result<Option<SelectedTicket>, StoreError> {
        let selected = self
            .0
            .query_row(
                "SELECT marker, token FROM tickets WHERE state='available' ORDER BY rowid LIMIT 1",
                [],
                |row| {
                    let marker: Vec<u8> = row.get(0)?;
                    Ok(SelectedTicket {
                        marker: marker
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        token: SecretBytes::new(row.get(1)?),
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::StorageUnavailable)?;
        if let Some(ticket) = &selected {
            if digest(ticket.token.expose()) != ticket.marker {
                return Err(StoreError::MissingOrCorrupt);
            }
        }
        Ok(selected)
    }

    /// Commit the uncertain state only for the exact ticket previewed above.
    /// A competing client wins at most once; no alternate ticket is selected.
    pub fn claim_available(&mut self, ticket: &SelectedTicket) -> Result<(), StoreError> {
        if digest(ticket.token.expose()) != ticket.marker {
            return Err(StoreError::MissingOrCorrupt);
        }
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let changed = transaction
            .execute(
                "UPDATE tickets SET state='uncertain' WHERE marker=?1 AND token=?2 AND state='available'",
                params![ticket.marker.as_slice(), ticket.token.expose()],
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition);
        }
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)
    }

    /// Return an exact claim to the available pool only when the caller has
    /// established that transmission was never attempted. A crash between
    /// claim and this call deliberately leaves the ticket uncertain.
    pub fn release_untransmitted(&mut self, ticket: &SelectedTicket) -> Result<(), StoreError> {
        if digest(ticket.token.expose()) != ticket.marker {
            return Err(StoreError::MissingOrCorrupt);
        }
        let changed = self
            .0
            .execute(
                "UPDATE tickets SET state='available' WHERE marker=?1 AND token=?2 AND state='uncertain'",
                params![ticket.marker.as_slice(), ticket.token.expose()],
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    /// Call only after all local release, transport, attestation, and request
    /// checks pass. `validate` checks the selected ticket while the write
    /// transaction is open; failure leaves it available. A successful take
    /// commits the uncertain state before returning a transmissible token.
    /// Concurrent clients cannot take the same ticket.
    pub(crate) fn take_available_if<F>(
        &mut self,
        validate: F,
    ) -> Result<Option<SelectedTicket>, StoreError>
    where
        F: FnOnce(&SelectedTicket) -> Result<(), StoreError>,
    {
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let selected = transaction
            .query_row(
                "SELECT marker, token FROM tickets WHERE state='available' ORDER BY rowid LIMIT 1",
                [],
                |row| {
                    let marker: Vec<u8> = row.get(0)?;
                    Ok(SelectedTicket {
                        marker: marker
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        token: SecretBytes::new(row.get(1)?),
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::StorageUnavailable)?;
        if let Some(ref ticket) = selected {
            validate(ticket)?;
            let changed = transaction
                .execute(
                    "UPDATE tickets SET state='uncertain' WHERE marker=?1 AND state='available'",
                    [ticket.marker.as_slice()],
                )
                .map_err(|_| StoreError::StorageUnavailable)?;
            if changed != 1 {
                return Err(StoreError::InvalidTransition);
            }
        }
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)?;
        Ok(selected)
    }

    pub fn mark_spent(&mut self, marker: Marker) -> Result<(), StoreError> {
        let changed = self
            .0
            .execute(
                "UPDATE tickets SET state='spent' WHERE marker=?1 AND state='uncertain'",
                [marker.as_slice()],
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }
}

pub struct IssuerStore(Connection);

impl IssuerStore {
    pub fn create(directory: &PrivateDirectory) -> Result<Self, StoreError> {
        let connection = connect(directory, "issuer.sqlite3", true)?;
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .and_then(|_| connection.execute_batch(ISSUER_AUTHORIZATIONS_SQL))
            .and_then(|_| connection.execute_batch(ISSUER_RESPONSES_SQL))
            .and_then(|_| {
                connection.execute_batch(
                    "PRAGMA application_id=1515211091;
                     PRAGMA user_version=2;
                     COMMIT;",
                )
            })
            .map_err(|_| StoreError::StorageUnavailable)?;
        validate(&connection, ISSUER_APPLICATION_ID)?;
        validate_schema(
            &connection,
            &[
                ("authorizations", ISSUER_AUTHORIZATIONS_SQL),
                ("issuance_responses", ISSUER_RESPONSES_SQL),
            ],
        )?;
        Ok(Self(connection))
    }

    pub fn open(directory: &PrivateDirectory) -> Result<Self, StoreError> {
        let connection = connect(directory, "issuer.sqlite3", false)?;
        validate(&connection, ISSUER_APPLICATION_ID)?;
        validate_schema(
            &connection,
            &[
                ("authorizations", ISSUER_AUTHORIZATIONS_SQL),
                ("issuance_responses", ISSUER_RESPONSES_SQL),
            ],
        )?;
        Ok(Self(connection))
    }

    pub fn authorize(
        &mut self,
        id: PurchaseId,
        requested_quantity: usize,
        request_commitment: Marker,
    ) -> Result<(), StoreError> {
        self.authorize_with_budget(id, requested_quantity, request_commitment, None)
    }

    /// Reserve free credits atomically with the authorization. An exact
    /// retry remains valid after the budget is exhausted; a new batch does not.
    pub fn authorize_free(
        &mut self,
        id: PurchaseId,
        requested_quantity: usize,
        request_commitment: Marker,
        max_total: usize,
    ) -> Result<(), StoreError> {
        self.authorize_with_budget(id, requested_quantity, request_commitment, Some(max_total))
    }

    fn authorize_with_budget(
        &mut self,
        id: PurchaseId,
        requested_quantity: usize,
        request_commitment: Marker,
        max_total: Option<usize>,
    ) -> Result<(), StoreError> {
        let count = quantity(requested_quantity)?;
        let limit = max_total.map(quantity).transpose()?;
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let existing: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT quantity, request_commitment FROM authorizations WHERE purchase_id=?1",
                [id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::StorageUnavailable)?;
        if let Some((existing_quantity, existing_commitment)) = existing {
            if existing_quantity == count && existing_commitment == request_commitment {
                return Ok(());
            }
            return Err(StoreError::AlteredPurchase);
        }
        if let Some(limit) = limit {
            let total: i64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(quantity), 0) FROM authorizations",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| StoreError::StorageUnavailable)?;
            if count
                > limit
                    .checked_sub(total)
                    .ok_or(StoreError::StorageUnavailable)?
            {
                return Err(StoreError::BudgetExhausted);
            }
        }
        transaction
            .execute(
                "INSERT INTO authorizations(purchase_id, quantity, request_commitment) VALUES (?1, ?2, ?3)",
                params![id.as_slice(), count, request_commitment.as_slice()],
            )
            .map_err(|_| StoreError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)
    }

    /// The signer runs only for a new, authorized commitment. On replay, this
    /// returns the exact previously committed blind signatures.
    pub(crate) fn issue_once<F>(
        &mut self,
        id: PurchaseId,
        request_commitment: Marker,
        sign: F,
    ) -> Result<Vec<Vec<u8>>, StoreError>
    where
        F: FnOnce() -> Result<Vec<Vec<u8>>, StoreError>,
    {
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let authorization: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT quantity, request_commitment FROM authorizations WHERE purchase_id=?1",
                [id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::StorageUnavailable)?;
        let Some((expected, existing_commitment)) = authorization else {
            return Err(StoreError::UnknownPurchase);
        };
        if existing_commitment != request_commitment {
            return Err(StoreError::AlteredPurchase);
        }
        let stored_signatures = {
            let mut statement = transaction.prepare(
                "SELECT blind_signature FROM issuance_responses WHERE purchase_id=?1 ORDER BY ordinal",
            ).map_err(|_| StoreError::StorageUnavailable)?;
            statement
                .query_map([id.as_slice()], |row| row.get(0))
                .map_err(|_| StoreError::StorageUnavailable)?
                .collect::<Result<Vec<Vec<u8>>, _>>()
                .map_err(|_| StoreError::StorageUnavailable)?
        };
        if i64::try_from(stored_signatures.len()).map_err(|_| StoreError::StorageUnavailable)?
            == expected
        {
            return Ok(stored_signatures);
        }
        if !stored_signatures.is_empty() {
            return Err(StoreError::MissingOrCorrupt);
        }
        let signatures = sign()?;
        if i64::try_from(signatures.len()).map_err(|_| StoreError::InvalidQuantity)? != expected {
            return Err(StoreError::InvalidQuantity);
        }
        for (ordinal, signature) in signatures.iter().enumerate() {
            transaction.execute(
                "INSERT INTO issuance_responses(purchase_id, ordinal, blind_signature) VALUES (?1, ?2, ?3)",
                params![id.as_slice(), i64::try_from(ordinal).map_err(|_| StoreError::InvalidQuantity)?, signature],
            ).map_err(|_| StoreError::StorageUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)?;
        Ok(signatures)
    }
}

pub struct RedeemerStore(Connection);

impl RedeemerStore {
    pub fn create(directory: &PrivateDirectory) -> Result<Self, StoreError> {
        let connection = connect(directory, "redeemer.sqlite3", true)?;
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .and_then(|_| connection.execute_batch(REDEEMER_TABLE_SQL))
            .and_then(|_| {
                connection.execute_batch(
                    "PRAGMA application_id=1515213380;
                     PRAGMA user_version=2;
                     COMMIT;",
                )
            })
            .map_err(|_| StoreError::StorageUnavailable)?;
        validate(&connection, REDEEMER_APPLICATION_ID)?;
        validate_schema(&connection, &[("spent", REDEEMER_TABLE_SQL)])?;
        Ok(Self(connection))
    }

    pub fn open(directory: &PrivateDirectory) -> Result<Self, StoreError> {
        let connection = connect(directory, "redeemer.sqlite3", false)?;
        validate(&connection, REDEEMER_APPLICATION_ID)?;
        validate_schema(&connection, &[("spent", REDEEMER_TABLE_SQL)])?;
        Ok(Self(connection))
    }

    /// The future verifier must validate the signature, challenge, allowed
    /// request and issuer key before calling this method. Commit precedes node
    /// dispatch, so node failure after acceptance still consumes the credit.
    pub(crate) fn admit_verified(
        &mut self,
        issuer_key_id: Marker,
        ticket_marker: Marker,
    ) -> Result<Admission, StoreError> {
        let transaction = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::StorageUnavailable)?;
        let inserted = transaction.execute(
            "INSERT INTO spent(issuer_key_id, ticket_marker) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![issuer_key_id.as_slice(), ticket_marker.as_slice()],
        ).map_err(|_| StoreError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| StoreError::StorageUnavailable)?;
        Ok(if inserted == 1 {
            Admission::Accepted
        } else {
            Admission::Replay
        })
    }
}

#[cfg(test)]
mod tests;
