//! `/v1/pair-record` endpoints (Reachability V1, TB1) — the relay's
//! signed reachability pointer from `agent_id` to the agent's advertised
//! relay set. Mirrors the `profile` index discipline: RAM-only, monotonic
//! `issued_at_ms` per agent, every record end-to-end verifiable by the
//! consumer from the signed body returned here.
//!
//! The record type and the *stateless* signature/derivation verify live
//! in [`fetchit_relay_proto::pair_record`]; this module owns the relay
//! side: store, serve, and the policy the proto deliberately leaves to
//! the caller — the per-agent monotonic watermark and the per-sender
//! publish rate limit.

use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use dashmap::DashMap;
use fetchit_relay_proto::identity::AGENT_ID_LEN;
use fetchit_relay_proto::pair_record::{verify_pair_record, PairRecordError, PairRecordV1};
use fetchit_relay_proto::AgentId;
use std::sync::Arc;

/// Hard ceiling on a `/v1/pair-record` POST body. A record carries an
/// ML-DSA-65 pubkey (~1952 raw), an ML-KEM-768 pubkey (~1184 raw), and a
/// ~3309-byte signature — all standard-base64 — plus up to four relay
/// URLs: ~11 KB in practice. 16 KB absorbs growth while keeping a garbage
/// POST from blowing up RAM (well below axum's default).
pub const MAX_PAIR_RECORD_BODY_BYTES: usize = 16 * 1024;

/// Per-agent publish ceiling. Publishing is rare (on connect + region
/// change); 30/min tolerates reconnect churn while bounding a holder of a
/// valid key from hammering the verify path. Enforced on the
/// *authenticated* agent (post-verify) so an attacker cannot grief a
/// victim's bucket with spoofed POSTs.
pub const PAIR_RECORD_MAX_PER_MIN: u32 = 30;

/// In-memory `agent_id_hex -> PairRecordV1`. RAM-only, matching the
/// profile index posture: a relay restart drops every record and
/// publishers re-POST on next connect.
#[derive(Default)]
pub struct PairRecordIndex {
    by_agent: DashMap<String, PairRecordV1>,
}

impl PairRecordIndex {
    /// Construct an empty index wrapped in an `Arc` so `ServerState` can
    /// hold it without further wrapping.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_agent: DashMap::new(),
        })
    }

    /// Current record for `agent_id_hex`, if one exists.
    #[must_use]
    pub fn get(&self, agent_id_hex: &str) -> Option<PairRecordV1> {
        self.by_agent.get(agent_id_hex).map(|r| r.clone())
    }

    /// Current stored `issued_at_ms` for the monotonic ratchet.
    #[must_use]
    pub fn current_issued_at(&self, agent_id_hex: &str) -> Option<u64> {
        self.by_agent.get(agent_id_hex).map(|r| r.issued_at_ms)
    }

    /// Store `record` keyed by its `agent_id_hex`. The caller must have
    /// already verified the signature + agent-id derivation +
    /// monotonicity. Prefer [`Self::put_if_newer`] on the write path —
    /// this primitive does no watermark check and is for tests / callers
    /// that have already ratcheted under their own lock.
    pub fn put(&self, record: PairRecordV1) {
        self.by_agent.insert(record.agent_id_hex.clone(), record);
    }

    /// Atomically store `record` iff its `issued_at_ms` is strictly
    /// greater than any record currently held for the same agent. Returns
    /// `Err(current)` — the stored watermark — when the record is not
    /// newer, so the caller can surface the 409 `current_issued_at_ms`
    /// contract.
    ///
    /// The compare-and-store runs inside `DashMap`'s per-key entry lock, so
    /// two concurrent same-agent POSTs cannot both observe a stale
    /// watermark and let the lower `issued_at_ms` win the write (the
    /// check-then-`put` TOCTOU). The loser is rejected, not silently
    /// overwritten.
    pub fn put_if_newer(&self, record: PairRecordV1) -> Result<(), u64> {
        use dashmap::mapref::entry::Entry;
        match self.by_agent.entry(record.agent_id_hex.clone()) {
            Entry::Occupied(mut e) => {
                let current = e.get().issued_at_ms;
                if record.issued_at_ms <= current {
                    return Err(current);
                }
                e.insert(record);
                Ok(())
            }
            Entry::Vacant(e) => {
                e.insert(record);
                Ok(())
            }
        }
    }

    /// Count of stored records. Test-only.
    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_agent.len()
    }

    /// `true` when no records exist. Paired with [`Self::len`] because
    /// clippy insists on the pair; both are test-only.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_agent.is_empty()
    }
}

/// Why a `/v1/pair-record` POST was rejected, carrying the matching HTTP
/// status and body.
#[derive(Debug)]
pub enum PairRecordHttpError {
    /// Body exceeds [`MAX_PAIR_RECORD_BODY_BYTES`]. 413.
    BodyTooLarge,
    /// JSON parse failure. 400.
    Malformed(&'static str),
    /// Proto-level verify failure (signature / derivation / relay-url /
    /// field format). Status derived per `verify_status`.
    Verify(PairRecordError),
    /// Per-sender publish rate exceeded. 429.
    RateLimited,
    /// `issued_at_ms` was not strictly greater than the stored value. 409
    /// plus `{ "current_issued_at_ms": <prev> }` — the pinned contract, so
    /// the publisher bumps its logical clock to `prev + 1` and retries
    /// once with no extra GET.
    NonMonotonic {
        /// The relay's current stored watermark; the publisher retries at
        /// `current_issued_at_ms + 1`.
        current_issued_at_ms: u64,
    },
}

impl PairRecordHttpError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Malformed(_) => StatusCode::BAD_REQUEST,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::NonMonotonic { .. } => StatusCode::CONFLICT,
            Self::Verify(e) => verify_status(e),
        }
    }

    /// The JSON body for this error. The `NonMonotonic` case carries the
    /// relay's current watermark under the exact contract field name; all
    /// others carry `{ "ok": false, "error": <msg> }`.
    fn json_body(&self) -> serde_json::Value {
        match self {
            Self::NonMonotonic {
                current_issued_at_ms,
            } => serde_json::json!({ "current_issued_at_ms": current_issued_at_ms }),
            Self::BodyTooLarge => {
                serde_json::json!({ "ok": false, "error": "pair-record body exceeds 16 KB" })
            }
            Self::RateLimited => {
                serde_json::json!({ "ok": false, "error": "per-sender publish rate exceeded" })
            }
            Self::Malformed(why) => serde_json::json!({ "ok": false, "error": why }),
            Self::Verify(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
        }
    }
}

/// Map a proto [`PairRecordError`] to an HTTP status. Impersonation — the
/// claimed id does not derive from the pubkey, or the signature does not
/// verify — is **403**; malformed fields/URLs are **400**; a backend
/// crypto fault is **500** (the relay's problem, not the client's).
pub(crate) fn verify_status(e: &PairRecordError) -> StatusCode {
    match e {
        PairRecordError::AgentIdMismatch | PairRecordError::SignatureInvalid => {
            StatusCode::FORBIDDEN
        }
        PairRecordError::VerifyBackend(_) => StatusCode::INTERNAL_SERVER_ERROR,
        PairRecordError::EmptyRelays
        | PairRecordError::TooManyRelays { .. }
        | PairRecordError::RelayUrlTooLong { .. }
        | PairRecordError::RelayUrlInvalid
        | PairRecordError::RelayUrlHasCredentials
        | PairRecordError::InvalidAgentIdHex
        | PairRecordError::Base64(_)
        | PairRecordError::PubkeyParse(_)
        | PairRecordError::SignatureParse(_)
        | PairRecordError::FieldTooLong { .. } => StatusCode::BAD_REQUEST,
    }
}

impl IntoResponse for PairRecordHttpError {
    fn into_response(self) -> axum::response::Response {
        (self.status(), Json(self.json_body())).into_response()
    }
}

/// Decode a verified `agent_id_hex` into the [`AgentId`] the rate limiter
/// keys on. After [`verify_pair_record`] succeeds the hex is guaranteed
/// lowercase 64-hex deriving from the pubkey, so this only fails on an
/// internal invariant break — surfaced as `Malformed` defensively.
fn agent_id_from_hex(hex_str: &str) -> Result<AgentId, PairRecordHttpError> {
    let raw =
        hex::decode(hex_str).map_err(|_| PairRecordHttpError::Malformed("agent_id_hex not hex"))?;
    let arr: [u8; AGENT_ID_LEN] = raw
        .try_into()
        .map_err(|_| PairRecordHttpError::Malformed("agent_id_hex wrong length"))?;
    Ok(AgentId::from_bytes(arr))
}

/// POST `/v1/pair-record`. Body cap -> stateless proto verify (sig +
/// derivation + relay-URL rules) -> per-sender rate limit on the
/// authenticated agent -> strict-greater watermark -> store.
pub async fn post_pair_record(
    State(state): State<Arc<ServerState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, PairRecordHttpError> {
    if body.len() > MAX_PAIR_RECORD_BODY_BYTES {
        return Err(PairRecordHttpError::BodyTooLarge);
    }
    let record: PairRecordV1 = serde_json::from_slice(&body)
        .map_err(|_| PairRecordHttpError::Malformed("invalid JSON body"))?;

    // Authenticate FIRST: the record's `agent_id_hex` is only trustworthy
    // after the signature + derivation check. Rate-limiting before this
    // would let an attacker grief a victim's bucket with spoofed POSTs.
    verify_pair_record(&record).map_err(PairRecordHttpError::Verify)?;

    let agent = agent_id_from_hex(&record.agent_id_hex)?;
    if !state.ratelimit.allow(&agent, PAIR_RECORD_MAX_PER_MIN) {
        return Err(PairRecordHttpError::RateLimited);
    }

    // Atomic compare-and-store: the watermark check and the write share
    // DashMap's per-key lock, so concurrent same-agent POSTs can't both
    // pass a stale read and let the lower issued_at_ms win.
    state
        .pair_records
        .put_if_newer(record)
        .map_err(|current_issued_at_ms| PairRecordHttpError::NonMonotonic {
            current_issued_at_ms,
        })?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET `/v1/pair-record/{agent_id}`. Returns the current signed record
/// verbatim (the consumer re-verifies end-to-end) or 404.
pub async fn get_pair_record(
    State(state): State<Arc<ServerState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<PairRecordV1>, StatusCode> {
    state
        .pair_records
        .get(&agent_id.to_ascii_lowercase())
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mk_record(agent_hex: &str, issued: u64) -> PairRecordV1 {
        PairRecordV1 {
            record_version: fetchit_relay_proto::pair_record::RECORD_VERSION_V1,
            agent_id_hex: agent_hex.to_string(),
            ml_dsa_pubkey_b64: "AA".to_string(),
            kem_pubkey_b64: "AA".to_string(),
            advertised_relays: vec!["https://relay.example".to_string()],
            issued_at_ms: issued,
            sig_b64: "AA".to_string(),
        }
    }

    // ── store ─────────────────────────────────────────────────────────

    #[test]
    fn put_then_get_returns_record() {
        let idx = PairRecordIndex::new();
        let id = hex::encode([0xaa; 32]);
        idx.put(mk_record(&id, 7));
        assert_eq!(idx.get(&id).unwrap().issued_at_ms, 7);
    }

    #[test]
    fn get_unknown_is_none() {
        let idx = PairRecordIndex::new();
        assert!(idx.get(&hex::encode([0x11; 32])).is_none());
    }

    #[test]
    fn current_issued_at_tracks_the_latest_put() {
        let idx = PairRecordIndex::new();
        let id = hex::encode([0xbb; 32]);
        assert_eq!(idx.current_issued_at(&id), None);
        idx.put(mk_record(&id, 3));
        idx.put(mk_record(&id, 9));
        assert_eq!(idx.current_issued_at(&id), Some(9));
    }

    #[test]
    fn put_if_newer_is_a_compare_and_swap() {
        let idx = PairRecordIndex::new();
        let id = hex::encode([0xcc; 32]);
        // First write into a vacant slot always wins.
        assert_eq!(idx.put_if_newer(mk_record(&id, 100)), Ok(()));
        // Strictly-greater replaces.
        assert_eq!(idx.put_if_newer(mk_record(&id, 101)), Ok(()));
        assert_eq!(idx.current_issued_at(&id), Some(101));
        // Equal is rejected, returning the stored watermark.
        assert_eq!(idx.put_if_newer(mk_record(&id, 101)), Err(101));
        // Older is rejected; the store is unchanged.
        assert_eq!(idx.put_if_newer(mk_record(&id, 50)), Err(101));
        assert_eq!(idx.current_issued_at(&id), Some(101));
    }

    #[test]
    fn put_if_newer_under_concurrency_keeps_the_max() {
        // Many threads race to publish the same agent with issued_at in
        // 1..=n in scrambled order. Regardless of interleave, the highest
        // issued_at must end up stored and the watermark must never
        // regress (the property the read-then-put TOCTOU violated).
        let n: u64 = 64;
        let idx = PairRecordIndex::new(); // already an Arc<Self>
        let id = hex::encode([0xab; 32]);
        let mut handles = Vec::new();
        for k in 0..n {
            // Scramble arrival order so the max is not written last.
            let issued = ((k * 37) % n) + 1;
            let idx = std::sync::Arc::clone(&idx);
            let id = id.clone();
            handles.push(std::thread::spawn(move || {
                let _ = idx.put_if_newer(mk_record(&id, issued));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(idx.current_issued_at(&id), Some(n));
    }

    // ── error -> status mapping ───────────────────────────────────────

    #[test]
    fn impersonation_errors_are_403() {
        assert_eq!(
            verify_status(&PairRecordError::AgentIdMismatch),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            verify_status(&PairRecordError::SignatureInvalid),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn backend_fault_is_500_client_format_is_400() {
        assert_eq!(
            verify_status(&PairRecordError::VerifyBackend("boom".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        for e in [
            PairRecordError::EmptyRelays,
            PairRecordError::TooManyRelays { n: 9 },
            PairRecordError::RelayUrlInvalid,
            PairRecordError::RelayUrlHasCredentials,
            PairRecordError::RelayUrlTooLong { len: 999 },
            PairRecordError::InvalidAgentIdHex,
            PairRecordError::Base64("x".into()),
            PairRecordError::PubkeyParse("x".into()),
            PairRecordError::SignatureParse("x".into()),
            PairRecordError::FieldTooLong { len: 1 },
        ] {
            assert_eq!(verify_status(&e), StatusCode::BAD_REQUEST, "{e:?}");
        }
    }

    #[test]
    fn http_error_statuses() {
        assert_eq!(
            PairRecordHttpError::BodyTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            PairRecordHttpError::Malformed("x").status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            PairRecordHttpError::RateLimited.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            PairRecordHttpError::NonMonotonic {
                current_issued_at_ms: 5
            }
            .status(),
            StatusCode::CONFLICT
        );
    }

    // ── the pinned watermark-reject contract ──────────────────────────

    #[test]
    fn nonmonotonic_body_carries_current_issued_at_ms_exact_field() {
        // Alice's Task 3 retry path reads this exact field to bump its
        // logical clock to value+1; the name is the contract.
        let body = PairRecordHttpError::NonMonotonic {
            current_issued_at_ms: 1_718_000_000_123,
        }
        .json_body();
        assert_eq!(
            body,
            serde_json::json!({ "current_issued_at_ms": 1_718_000_000_123u64 })
        );
    }

    #[test]
    fn other_error_bodies_are_ok_false_with_message() {
        let b = PairRecordHttpError::Malformed("invalid JSON body").json_body();
        assert_eq!(b["ok"], serde_json::json!(false));
        assert_eq!(b["error"], serde_json::json!("invalid JSON body"));
    }

    #[test]
    fn agent_id_from_hex_roundtrips_a_valid_id() {
        let id = hex::encode([0x42; AGENT_ID_LEN]);
        let agent = agent_id_from_hex(&id).unwrap();
        assert_eq!(agent.0, [0x42; AGENT_ID_LEN]);
    }

    #[test]
    fn agent_id_from_hex_rejects_wrong_length() {
        let err = agent_id_from_hex(&hex::encode([0x42; 31])).unwrap_err();
        assert!(matches!(err, PairRecordHttpError::Malformed(_)));
    }
}
