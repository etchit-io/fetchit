//! Self-serve actor registry + fediverse serving half (M5.1, Component D).
//!
//! Gated behind `fediverse-inbox` like [`crate::inbox`]: the default
//! relay-server (LIT Chat pass-through) ships without it. Operators in
//! the bridge role build with `--features fediverse-inbox`. All response
//! codes match `fetchit-fedi/tests/fixtures/registry-v1/README.md`.
//!
//! Module split (one concept per file):
//! - [`verify`] — pure handle policy + canonical URL + `verify_binding_v2`.
//! - [`store`] — `ActorRegistryStore` impls (FCFS + continuity + epoch).
//! - [`webfinger`] — `acct:` resource parse + JRD.
//! - [`actor_doc`] — `ActivityPub` actor JSON-LD with the embedded attestation.
//! - [`router`] — axum routes + testable inner handlers.

pub mod actor_doc;
pub mod router;
pub mod store;
pub mod store_sqlite;
pub mod verify;
pub mod webfinger;

use fetchit_fedi::attestation::ActorAttestationV2;
use thiserror::Error;

pub use router::{registry_router, RegistryState};
pub use store::InMemoryActorStore;
pub use store_sqlite::SqliteActorStore;
pub use verify::{verify_registration, RegistryConfig};

/// A stored, verified registration. `agent_id_hex` is the continuity
/// key (a handle never silently changes agent); the whole attestation
/// is retained so the `WebFinger` record and actor document can serve it
/// verbatim for offline verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRecord {
    /// Lowercase `[a-z0-9_-]{1,64}` handle.
    pub handle: String,
    /// Canonical actor URL (`https://<domain>/actors/<handle>`).
    pub actor_url: String,
    /// Derived chat agent id (64-hex) from the attested ML-DSA pubkey.
    pub agent_id_hex: String,
    /// RSA `SubjectPublicKeyInfo` DER, served as `publicKeyPem`.
    pub rsa_spki_der: Vec<u8>,
    /// The signed v2 attestation, served under
    /// `PQ_ATTESTATION_V2_PROPERTY_URI` for offline verification.
    pub attestation: ActorAttestationV2,
    /// Server clock at first registration (ms since epoch).
    pub registered_at_ms: u64,
}

/// Store-layer outcome distinct from verification rejection: these map
/// to 409/404, verification failures map to 422.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryStoreError {
    /// POST onto an existing handle (FCFS). Maps to HTTP 409.
    #[error("handle already registered")]
    HandleTaken,
    /// PUT on a handle that was never registered. Maps to HTTP 404.
    #[error("unknown handle")]
    UnknownHandle,
    /// PUT whose derived agent id differs from the stored one. 409.
    #[error("agent id mismatch: a handle never silently changes agent")]
    AgentMismatch,
    /// PUT whose `hint_epoch_ms` is not strictly greater than stored. 409.
    #[error("stale hint epoch")]
    StaleEpoch,
    /// A durable-store backend error (I/O, lock poison, SQL). Maps to
    /// HTTP 500; the detail is for logs, never served to the caller.
    #[error("registry storage error: {0}")]
    Storage(String),
}

/// Verification rejection — every variant maps to HTTP 422 with the
/// `Display` text served back to the user.
#[derive(Debug, Error)]
pub enum RegistryRejection {
    /// Handle failed `[a-z0-9_-]{1,64}` (incl. uppercase) — SO-3.
    #[error("invalid handle: {0}")]
    Handle(String),
    /// `RegisterActorRequest` body did not parse.
    #[error("malformed request body: {0}")]
    Body(String),
    /// SO-4: `rsa_spki_der` is not a parseable RSA public key.
    #[error("invalid RSA SubjectPublicKeyInfo: {0}")]
    Spki(String),
    /// `verify_binding_v2` rejected the attestation.
    #[error("attestation verification failed: {0}")]
    Attestation(String),
    /// PUT path handle did not equal body handle.
    #[error("path handle {path:?} does not match body handle {body:?}")]
    HandleMismatch {
        /// Handle from the URL path.
        path: String,
        /// Handle from the request body.
        body: String,
    },
}

/// In-memory + future durable store of verified registrations. Sync
/// methods: each is a fast local op with no `.await` inside, so an impl
/// holding a `DashMap` shard guard never crosses an await point.
pub trait ActorRegistryStore: Send + Sync {
    /// First-come-first-served insert. `Err(HandleTaken)` if present.
    ///
    /// # Errors
    /// [`RegistryStoreError::HandleTaken`].
    fn register(&self, record: ActorRecord) -> Result<(), RegistryStoreError>;

    /// Update an existing handle: same-agent + strictly-increasing epoch.
    ///
    /// # Errors
    /// [`RegistryStoreError::UnknownHandle`] / `AgentMismatch` / `StaleEpoch`.
    fn update(&self, record: ActorRecord) -> Result<(), RegistryStoreError>;

    /// Fetch by handle for the serving endpoints.
    fn get(&self, handle: &str) -> Option<ActorRecord>;
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::ActorRecord;
    use fetchit_fedi::attestation::ActorAttestationV2;

    /// Build a record with a chosen agent id + epoch. Shared across the
    /// store / webfinger / router tests so they do not each re-spell the
    /// attestation literal.
    pub(crate) fn record_with(handle: &str, agent_id_hex: String, epoch: u64) -> ActorRecord {
        ActorRecord {
            handle: handle.into(),
            actor_url: format!("https://etchit.io/actors/{handle}"),
            agent_id_hex,
            rsa_spki_der: vec![1, 2, 3],
            attestation: ActorAttestationV2 {
                version: 2,
                profile_addr: "a".repeat(64),
                relay_hint: "https://relay.example:8088/".into(),
                hint_epoch_ms: epoch,
                ml_dsa_pubkey: vec![0x42; 4],
                signature: vec![0x41; 4],
            },
            registered_at_ms: 1,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::tests_support::record_with;

    #[test]
    fn record_carries_continuity_key_and_epoch() {
        let r = record_with("josh", "a".repeat(64), 1_750_000_000_000);
        assert_eq!(r.agent_id_hex.len(), 64);
        assert_eq!(r.attestation.hint_epoch_ms, 1_750_000_000_000);
        assert_eq!(r.actor_url, "https://etchit.io/actors/josh");
    }
}
