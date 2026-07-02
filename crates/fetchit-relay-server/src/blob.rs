//! `/v1/blob/{token}` — a generic sealed-ephemeral-blob store. The relay
//! holds an opaque ciphertext under a client-generated token for a short
//! TTL, so a pointer URI (a link-device enrollment offer, a group invite)
//! can carry only `token + relay + sealkey` while the sealed payload rides
//! the relay. The relay never sees plaintext: it stores and serves opaque
//! bytes keyed by an opaque token, preserving the blind-relay invariant.
//!
//! RAM-only (a restart drops every blob; the publisher re-POSTs) and
//! TTL-only (no delete-on-GET, so a retry or a multi-scan re-reads),
//! lazily expired on read. The sealed payload carries its own `exp` — the
//! real freshness gate, enforced client-side on open; the relay cannot
//! read it, so this fixed TTL just bounds how long an unclaimed blob
//! occupies RAM.

use crate::server::ServerState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use dashmap::DashMap;
use fetchit_relay_proto::{derive_agent_id, AgentId};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard ceiling on a stored blob, matching `MAX_PAIR_RECORD_V4_BODY_BYTES`.
/// A link-device offer seals to ~3.3 KB; a group-invite bootstrap blob is
/// larger and grows with membership, so the shared cap fits the bigger
/// consumer.
pub const MAX_BLOB_BYTES: usize = 128 * 1024;

/// Fixed relay-side TTL. The sealed payload carries its own `exp` (the real
/// freshness gate, checked client-side on open); the relay cannot read it,
/// so this fixed cap just bounds how long an unclaimed blob occupies RAM.
/// One hour is ample for an enrollment or invite handshake taking minutes.
pub const BLOB_TTL_MS: u64 = 60 * 60 * 1000;

/// Per-token publish ceiling. Keyed on the token so one publisher cannot
/// hammer the store under a single token; a token is claimed once and
/// written a handful of times at most.
pub const BLOB_MAX_PER_MIN: u32 = 30;

/// Min / max token length (base64url of a random id the client generates).
const TOKEN_MIN_LEN: usize = 16;
const TOKEN_MAX_LEN: usize = 128;

struct StoredBlob {
    ciphertext: Vec<u8>,
    expiry_ms: u64,
}

/// In-RAM `token -> sealed ciphertext` store with a fixed TTL. RAM-only,
/// matching the pair-record posture: a relay restart drops every blob.
#[derive(Default)]
pub struct BlobStore {
    by_token: DashMap<String, StoredBlob>,
}

impl BlobStore {
    /// Empty store wrapped in an `Arc` for `ServerState`.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_token: DashMap::new(),
        })
    }

    /// Store `ciphertext` under `token`, expiring at `expiry_ms`. Overwrites
    /// any existing blob for the same token (the publisher owns its token).
    pub fn put(&self, token: String, ciphertext: Vec<u8>, expiry_ms: u64) {
        self.by_token.insert(
            token,
            StoredBlob {
                ciphertext,
                expiry_ms,
            },
        );
    }

    /// The stored ciphertext for `token` if present and not yet expired at
    /// `now_ms`. An expired entry is removed and reported absent (lazy
    /// expiry, so no background sweep is needed).
    #[must_use]
    pub fn get(&self, token: &str, now_ms: u64) -> Option<Vec<u8>> {
        if let Some(b) = self.by_token.get(token) {
            if now_ms < b.expiry_ms {
                return Some(b.ciphertext.clone());
            }
        }
        // Expired (or absent): drop an expired entry, report absent.
        self.by_token.remove_if(token, |_, b| now_ms >= b.expiry_ms);
        None
    }

    /// Count of stored blobs. Test-only.
    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    /// `true` when empty. Paired with [`Self::len`] per clippy; both
    /// test-only.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A token must be a plausible base64url id: bounded length, URL-safe
/// alphabet only, so it is safe as a path segment and cheap to reject.
fn valid_token(token: &str) -> bool {
    (TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

/// Hash the opaque token into the existing per-`AgentId` limiter's key
/// (reusing `derive_agent_id` purely as a 32-byte hash; no agent identity
/// is implied). Per-token limiting bounds hammering a single token; a
/// multi-token flood is bounded by the 128 KB cap and the RAM-only TTL
/// store, with a byte-cap / background sweep left as a shared relay-
/// hardening follow-up.
fn ratelimit_key(token: &str) -> AgentId {
    AgentId::from_bytes(derive_agent_id(token.as_bytes()))
}

/// POST `/v1/blob/{token}`. Body is the opaque sealed ciphertext; the
/// client generates the token. Size cap -> token validate -> per-token
/// rate-limit -> store with the fixed TTL. The relay never inspects the
/// body.
pub async fn post_blob(
    State(state): State<Arc<ServerState>>,
    Path(token): Path<String>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    if body.len() > MAX_BLOB_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if !valid_token(&token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !state
        .ratelimit
        .allow(&ratelimit_key(&token), BLOB_MAX_PER_MIN)
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state
        .blobs
        .put(token, body.to_vec(), now_ms().saturating_add(BLOB_TTL_MS));
    Ok(StatusCode::OK)
}

/// GET `/v1/blob/{token}`. Returns the opaque ciphertext (octet-stream) or
/// 404 when absent or expired.
pub async fn get_blob(
    State(state): State<Arc<ServerState>>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if !valid_token(&token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    match state.blobs.get(&token, now_ms()) {
        Some(ct) => Ok(([(header::CONTENT_TYPE, "application/octet-stream")], ct)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_ciphertext_before_expiry() {
        let store = BlobStore::new();
        store.put("token-abc-0123456".to_string(), vec![1, 2, 3], 1_000);
        assert_eq!(store.get("token-abc-0123456", 999), Some(vec![1, 2, 3]));
    }

    #[test]
    fn get_after_expiry_is_none_and_evicts() {
        let store = BlobStore::new();
        store.put("token-abc-0123456".to_string(), vec![9], 1_000);
        // At the expiry instant it is already gone (strict `now < expiry`).
        assert_eq!(store.get("token-abc-0123456", 1_000), None);
        assert!(store.is_empty(), "expired blob must be evicted on read");
    }

    #[test]
    fn get_unknown_token_is_none() {
        let store = BlobStore::new();
        assert_eq!(store.get("token-abc-0123456", 0), None);
    }

    #[test]
    fn put_overwrites_same_token() {
        let store = BlobStore::new();
        store.put("token-abc-0123456".to_string(), vec![1], 1_000);
        store.put("token-abc-0123456".to_string(), vec![2], 2_000);
        assert_eq!(store.get("token-abc-0123456", 1_500), Some(vec![2]));
    }

    #[test]
    fn valid_token_accepts_base64url_bounds() {
        assert!(valid_token(&"a".repeat(TOKEN_MIN_LEN)));
        assert!(valid_token(&"A1_-".repeat(4)));
        // too short, too long, and non-url-safe are rejected
        assert!(!valid_token(&"a".repeat(TOKEN_MIN_LEN - 1)));
        assert!(!valid_token(&"a".repeat(TOKEN_MAX_LEN + 1)));
        assert!(!valid_token("has/slash/and+plus===="));
    }

    #[test]
    fn ratelimit_key_is_deterministic_per_token() {
        assert_eq!(
            ratelimit_key("token-abc-0123456"),
            ratelimit_key("token-abc-0123456")
        );
        assert_ne!(
            ratelimit_key("token-abc-0123456"),
            ratelimit_key("token-xyz-0123456")
        );
    }
}
