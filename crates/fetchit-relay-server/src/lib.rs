//! Server-side implementation of the fetchit relay protocol.
//!
//! Routes opaque envelopes between connected clients via WebSocket.
//! Undelivered envelopes are held in a [`transit::TransitStore`]: the
//! in-RAM [`transit::TransitBuffer`] or the durable, blind,
//! `SQLite`-backed [`transit_sqlite::SqliteTransitStore`] (ciphertext
//! only, bounded retention, delete-on-ack).

#![forbid(unsafe_code)]

pub mod auth;
pub mod blob;
pub mod capability;
pub mod config;
pub mod error;
pub mod forwarding;
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
pub use metrics::Metrics;
pub use server::Server;
pub use session::SessionRegistry;
pub use signature::{AcceptAllVerifier, MlDsa65Verifier, SignatureVerifier};
pub use transit::TransitBuffer;
pub use transit_sqlite::SqliteTransitStore;
