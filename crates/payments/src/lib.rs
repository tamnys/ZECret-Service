//! Durable, separate stores for the testnet payment proof of concept.
//!
//! This crate currently contains persistence and internal RFC 9578 wire
//! encoding. Cryptographic issuance and redemption cannot be enabled until the
//! pinned blind RSA dependency resolves and its standard vectors pass. Callers
//! must not treat stored bytes as valid tickets or use this crate to admit RPC
//! traffic until then.

mod challenge;
mod exchange;
mod http;
mod store;
mod wire;

pub use store::RedeemerStore;
pub use store::{
    Admission, Balance, ClientStore, IssuerStore, PendingTicket, PrivateDirectory, PurchaseId,
    SecretBytes, SelectedTicket, StoreError,
};
