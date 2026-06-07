//! Consumer-side denylist verifier for fetch>it clients.
//!
//! Used by both `fetchit-chat` (`RelayUrl` + `AgentId` enforcement) and
//! `fetchit-core` / desktop (`XorName` enforcement for the reader UI).
//!
//! Stage 2 of the M3 Relay Federation plan. Periodic refresh from
//! `https://etchit.io/v1/denylist?kind={xor_name,agent_id,relay_url,actor_url}`,
//! ML-DSA-65 signature verification against a hardcoded etchit-io
//! public key, in-memory hot lookup index, and disk persistence for
//! offline boot.
#![forbid(unsafe_code)]

mod cache;
mod consumer;
mod http;
mod index;

pub use consumer::{BlockEvent, DenylistConsumer, TrustError, DEFAULT_POLL_INTERVAL};
pub use http::HttpClient;
#[cfg(feature = "reqwest")]
pub use http::ReqwestClient;
