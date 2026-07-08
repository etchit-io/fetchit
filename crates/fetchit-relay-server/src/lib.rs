//! Server-side implementation of the fetchit relay protocol.
//!
//! Routes opaque envelopes between connected clients via WebSocket.
//! Undelivered envelopes are held in a [`transit::TransitStore`]: the
//! in-RAM [`transit::TransitBuffer`] or the durable, blind,
//! `SQLite`-backed [`transit_sqlite::SqliteTransitStore`] (ciphertext
//! only, bounded retention, delete-on-ack). Per-group log records
//! (commits, addressed join results) are held serve-to-many in a
//! [`group_log::GroupLogStore`]: the in-RAM [`group_log::RamGroupLog`]
//! or the durable [`group_log_sqlite::SqliteGroupLog`] sharing the
//! transit store's database file.

#![forbid(unsafe_code)]

pub mod auth;
pub mod blob;
pub mod capability;
pub mod config;
pub mod error;
pub mod forwarding;
pub mod group_log;
pub mod group_log_sqlite;
#[cfg(feature = "fediverse-inbox")]
pub mod inbox;
pub mod metrics;
pub mod pair_record;
pub mod profile;
pub mod ratelimit;
#[cfg(feature = "fediverse-inbox")]
pub mod registry;
#[cfg(feature = "fediverse-inbox")]
pub mod registry_admin;
pub mod server;
pub mod session;
pub mod signature;
pub mod transit;
pub mod transit_sqlite;
pub mod ws;

pub use config::ServerConfig;
pub use error::ServerError;
pub use group_log::RamGroupLog;
pub use group_log_sqlite::SqliteGroupLog;
pub use metrics::Metrics;
pub use server::Server;
pub use session::SessionRegistry;
pub use signature::{AcceptAllVerifier, MlDsa65Verifier, SignatureVerifier};
pub use transit::TransitBuffer;
pub use transit_sqlite::SqliteTransitStore;
