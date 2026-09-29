//! Durable, separate stores for the testnet payment proof of concept.
//!
//! This crate currently contains persistence and internal RFC 9578 wire
//! encoding. Cryptographic issuance and redemption cannot be enabled until the
//! pinned blind RSA dependency resolves and its standard vectors pass. Callers
//! must not treat stored bytes as valid tickets or use this crate to admit RPC
//! traffic until then.

mod challenge;
mod crypto;
mod exchange;
mod http;
mod issuance;
mod store;
mod wire;

pub use issuance::{
    IssuanceError, IssuerPublic, collect_purchase, export_pending_purchase, load_private_key_file,
    mock_settle_purchase, prepare_purchase,
};
pub use store::RedeemerStore;
pub use store::{
    Admission, Balance, ClientStore, IssuerStore, PendingPurchase, PendingTicket, PrivateDirectory,
    PurchaseId, SecretBytes, SelectedTicket, StoreError,
};
