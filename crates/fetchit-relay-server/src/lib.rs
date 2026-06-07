//! Server-side implementation of the fetchit relay protocol.
//!
//! Routes opaque envelopes between connected clients via WebSocket.
//! Holds undelivered envelopes in a RAM-only transit buffer with a
//! hard TTL; no disk persistence of user data.

#![forbid(unsafe_code)]

pub mod auth;
pub mod capability;
pub mod config;
pub mod error;
#[cfg(feature = "fediverse-inbox")]
pub mod inbox;
pub mod metrics;
pub mod profile;
pub mod ratelimit;
pub mod server;
pub mod session;
pub mod signature;
pub mod transit;
pub mod ws;

pub use config::ServerConfig;
pub use error::ServerError;
pub use metrics::Metrics;
pub use server::Server;
pub use signature::{AcceptAllVerifier, MlDsa65Verifier, SignatureVerifier};
pub use transit::TransitBuffer;
