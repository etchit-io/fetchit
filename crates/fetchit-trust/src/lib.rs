//! Trust service: report queue + signed denylist publisher.
//!
//! Clients (the desktop reader, mobile reader, chat clients, the
//! relay) poll the published denylists and apply them locally. The
//! relay refuses to mint bearer tokens for denylisted agent ids. The
//! reader refuses to render denylisted addresses. Reports submitted to
//! `/v1/report` queue for moderator review, and accepted ones update
//! the published denylist.

#![forbid(unsafe_code)]

pub mod config;
pub mod consumer;
pub mod error;
pub mod server;
pub mod signer;
pub mod storage;
pub mod types;

pub use config::ServerConfig;
pub use consumer::{signing_bytes, verify_signature, VerifiedDenylist};
pub use error::TrustError;
pub use server::Server;
pub use signer::IssuerSigner;
pub use storage::Storage;
pub use types::{
    DenylistEntry, DenylistResponse, DenylistToSign, EntryKind, Report, ReportKind, TargetIdentity,
};

/// Trait queried by chat (`RelayUrl` + `AgentId` enforcement) and the
/// fetch>it reader (`XorName` enforcement) to check whether an entity
/// is on the published safety denylist.
///
/// Implementations: `fetchit-trust-client::DenylistConsumer` is the
/// production impl. Test stubs implement this trait directly.
///
/// The trait is `Send + Sync` so consumers can hold it as
/// `Arc<dyn DenylistQuery>` and share across threads.
pub trait DenylistQuery: Send + Sync {
    /// `true` when `(kind, value)` is on the current denylist
    /// snapshot. `value` MUST be lowercase ASCII for the URL kinds;
    /// the value family matches the [`TargetIdentity::value`]
    /// normalisation contract.
    fn is_blocked(&self, kind: EntryKind, value: &str) -> bool;
}

#[cfg(test)]
mod denylist_query_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::sync::Arc;

    #[test]
    fn dyn_denylist_query_dispatch() {
        struct Stub;
        impl DenylistQuery for Stub {
            fn is_blocked(&self, _: EntryKind, _: &str) -> bool {
                true
            }
        }
        let q: Arc<dyn DenylistQuery> = Arc::new(Stub);
        assert!(q.is_blocked(EntryKind::RelayUrl, "wss://x"));
    }
}
