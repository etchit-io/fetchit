//! `/v1/forwarding` endpoints (Reachability V1, TB2) — a signed
//! redirect from an agent's old relay to its new relay set, so a peer
//! holding a stale hint can re-resolve a deposit target after the owner
//! migrated regions.
//!
//! Unlike a pair-record, a [`ForwardingRecordV1`] carries no key
//! material — its signature is verified against the agent's ML-DSA-65
//! pubkey, which the relay obtains from the **stored pair-record** for
//! that agent (Option A, confirmed in the Reachability V1 plan). A
//! forwarding record means "I used to be reachable here"; if the relay
//! holds no pair-record for the agent it never knew them, so the POST is
//! refused **412 Precondition Failed**. In the normal migration sequence
//! (publish pair-record at the new relay, then write the forwarding
//! record at the old one) the old relay still holds the agent's fresh
//! pair-record at forwarding-write time, so 412 never fires.
//!
//! Records are RAM-only with a ~30-day TTL swept by the server's
//! background sweeper. The watermark is a **separate** per-agent ratchet
//! from the pair-record's: a high pair `issued_at_ms` must not block a
//! legitimate forwarding record. The consumer re-verifies every record
//! end-to-end (defense in depth).

use crate::pair_record::verify_status;
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dashmap::DashMap;
use fetchit_relay_proto::identity::AGENT_ID_LEN;
use fetchit_relay_proto::pair_record::{
    verify_forwarding_record, ForwardingRecordV1, PairRecordError,
};
use fetchit_relay_proto::AgentId;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard ceiling on a `/v1/forwarding` POST body. A forwarding record is
/// an agent-id hex, up to four relay URLs, a timestamp, and a ~3309-byte
/// ML-DSA-65 signature (standard-base64) — ~6 KB in practice. 8 KB
/// absorbs growth while keeping a garbage POST from blowing up RAM.
pub const MAX_FORWARDING_BODY_BYTES: usize = 8 * 1024;

/// Per-agent publish ceiling, enforced on the *authenticated* agent
/// (post-verify) so an attacker cannot grief a victim's bucket. Shares
/// the same per-agent [`crate::ratelimit::RateLimiter`] as pair-records;
/// 30/min tolerates reconnect churn during a migration.
pub const FORWARDING_MAX_PER_MIN: u32 = 30;

/// Time-to-live for a stored forwarding record: ~30 days. After a region
/// change the owner re-publishes its pair-record at the new relay and
/// peers re-pair off that; the forwarding pointer is a transitional aid,
/// not a permanent record, so it self-expires.
pub const FORWARDING_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// A stored record plus the wall-clock instant it was accepted, for the
/// TTL sweep. `stored_at_ms` is the relay's clock, independent of the
/// record's own (issuer-supplied, untrusted) `issued_at_ms`.
struct StoredForwarding {
    record: ForwardingRecordV1,
    stored_at_ms: u64,
}

/// In-memory `agent_id_hex -> StoredForwarding`. RAM-only, matching the
/// pair/profile index posture: a relay restart drops every record.
#[derive(Default)]
pub struct ForwardingIndex {
    by_agent: DashMap<String, StoredForwarding>,
}

impl ForwardingIndex {
    /// Construct an empty index wrapped in an `Arc` so `ServerState` can
    /// hold it without further wrapping.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_agent: DashMap::new(),
        })
    }

    /// Current non-expired record for `agent_id_hex` at `now_ms`, if one
    /// exists and has not aged past [`FORWARDING_TTL_MS`]. Expired
    /// records read as absent even before the sweeper evicts them.
    #[must_use]
    pub fn get_live(&self, agent_id_hex: &str, now_ms: u64) -> Option<ForwardingRecordV1> {
        self.by_agent.get(agent_id_hex).and_then(|s| {
            if now_ms.saturating_sub(s.stored_at_ms) > FORWARDING_TTL_MS {
                None
            } else {
                Some(s.record.clone())
            }
        })
    }

    /// Atomically store `record` (stamped `stored_at_ms = now_ms`) iff its
    /// `issued_at_ms` is strictly greater than any record currently held
    /// for the same agent. Returns `Err(current)` — the stored forwarding
    /// watermark — when not newer, for the 409 `current_issued_at_ms`
    /// contract.
    ///
    /// The compare-and-store runs inside `DashMap`'s per-key entry lock so
    /// concurrent same-agent writes can't both pass a stale read and let
    /// the lower `issued_at_ms` win (the check-then-`put` TOCTOU).
    pub fn put_if_newer(&self, record: ForwardingRecordV1, now_ms: u64) -> Result<(), u64> {
        use dashmap::mapref::entry::Entry;
        match self.by_agent.entry(record.agent_id_hex.clone()) {
            Entry::Occupied(mut e) => {
                let current = e.get().record.issued_at_ms;
                if record.issued_at_ms <= current {
                    return Err(current);
                }
                e.insert(StoredForwarding {
                    record,
                    stored_at_ms: now_ms,
                });
                Ok(())
            }
            Entry::Vacant(e) => {
                e.insert(StoredForwarding {
                    record,
                    stored_at_ms: now_ms,
                });
                Ok(())
            }
        }
    }

    /// Evict every record older than [`FORWARDING_TTL_MS`] at `now_ms`.
    /// Returns the number evicted (for the sweeper's logging).
    #[must_use]
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        let before = self.by_agent.len();
        self.by_agent
            .retain(|_, s| now_ms.saturating_sub(s.stored_at_ms) <= FORWARDING_TTL_MS);
        before.saturating_sub(self.by_agent.len())
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

/// Why a `/v1/forwarding` POST was rejected, carrying the matching HTTP
/// status and body.
#[derive(Debug)]
pub enum ForwardingHttpError {
    /// Body exceeds [`MAX_FORWARDING_BODY_BYTES`]. 413.
    BodyTooLarge,
    /// JSON parse failure. 400.
    Malformed(&'static str),
    /// No pair-record on file for the agent, so the relay has no pubkey
    /// to verify against. 412 — the agent was never known here.
    NoPairRecord,
    /// The stored pair-record's pubkey would not base64-decode. 500 —
    /// the relay's own invariant broke (a verified record was stored),
    /// not the client's fault.
    StoredKeyUndecodable,
    /// Proto-level verify failure (signature / derivation / relay-url /
    /// field format). Status derived per [`verify_status`].
    Verify(PairRecordError),
    /// Per-sender publish rate exceeded. 429.
    RateLimited,
    /// `issued_at_ms` was not strictly greater than the stored value. 409
    /// plus `{ "current_issued_at_ms": <prev> }`, same shape as
    /// pair-record, so the publisher bumps its logical clock and retries.
    NonMonotonic {
        /// The relay's current stored forwarding watermark.
        current_issued_at_ms: u64,
    },
}

impl ForwardingHttpError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Malformed(_) => StatusCode::BAD_REQUEST,
            Self::NoPairRecord => StatusCode::PRECONDITION_FAILED,
            Self::StoredKeyUndecodable => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::NonMonotonic { .. } => StatusCode::CONFLICT,
            Self::Verify(e) => verify_status(e),
        }
    }

    fn json_body(&self) -> serde_json::Value {
        match self {
            Self::NonMonotonic {
                current_issued_at_ms,
            } => serde_json::json!({ "current_issued_at_ms": current_issued_at_ms }),
            Self::BodyTooLarge => {
                serde_json::json!({ "ok": false, "error": "forwarding body exceeds 8 KB" })
            }
            Self::NoPairRecord => serde_json::json!({
                "ok": false,
                "error": "no pair-record on file for agent; publish a pair-record first"
            }),
            Self::StoredKeyUndecodable => {
                serde_json::json!({ "ok": false, "error": "stored pair-record key undecodable" })
            }
            Self::RateLimited => {
                serde_json::json!({ "ok": false, "error": "per-sender publish rate exceeded" })
            }
            Self::Malformed(why) => serde_json::json!({ "ok": false, "error": why }),
            Self::Verify(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
        }
    }
}

impl IntoResponse for ForwardingHttpError {
    fn into_response(self) -> axum::response::Response {
        (self.status(), Json(self.json_body())).into_response()
    }
}

/// Decode a verified `agent_id_hex` into the [`AgentId`] the rate limiter
/// keys on.
fn agent_id_from_hex(hex_str: &str) -> Result<AgentId, ForwardingHttpError> {
    let raw =
        hex::decode(hex_str).map_err(|_| ForwardingHttpError::Malformed("agent_id_hex not hex"))?;
    let arr: [u8; AGENT_ID_LEN] = raw
        .try_into()
        .map_err(|_| ForwardingHttpError::Malformed("agent_id_hex wrong length"))?;
    Ok(AgentId::from_bytes(arr))
}

/// POST `/v1/forwarding`. Body cap -> require a stored pair-record
/// (412) -> verify the forwarding signature against that pubkey -> per
/// sender rate limit -> strict-greater forwarding watermark -> store
/// stamped with the relay clock.
pub async fn post_forwarding(
    State(state): State<Arc<ServerState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ForwardingHttpError> {
    if body.len() > MAX_FORWARDING_BODY_BYTES {
        return Err(ForwardingHttpError::BodyTooLarge);
    }
    let record: ForwardingRecordV1 = serde_json::from_slice(&body)
        .map_err(|_| ForwardingHttpError::Malformed("invalid JSON body"))?;

    // Option A: the relay must already hold a pair-record for this agent
    // to obtain the ML-DSA-65 pubkey the forwarding sig is verified
    // against. No pair-record => the agent was never reachable here =>
    // the pointer is meaningless and abusable; refuse 412.
    // INVARIANT (future-defense): the pair-record is read here and the
    // forwarding record is stored further down without re-checking it.
    // Today that is race-free because `PairRecordIndex` has no removal
    // path — a pair-record only ever moves forward. IF a pair-record
    // DELETE/tombstone endpoint is ever added, a concurrent delete
    // between this `get` and the `put_if_newer` below could store a
    // forwarding record for an agent whose pair-record just vanished;
    // gate the store against that (the consumer re-verifies end-to-end
    // regardless, so it is a defense-in-depth concern, not a breach).
    let pair = state
        .pair_records
        .get(&record.agent_id_hex.to_ascii_lowercase())
        .ok_or(ForwardingHttpError::NoPairRecord)?;
    let pubkey = B64
        .decode(&pair.ml_dsa_pubkey_b64)
        .map_err(|_| ForwardingHttpError::StoredKeyUndecodable)?;

    // Authenticate (sig + derivation + relay-url rules) before touching
    // the rate-limiter or watermark.
    verify_forwarding_record(&record, &pubkey).map_err(ForwardingHttpError::Verify)?;

    let agent = agent_id_from_hex(&record.agent_id_hex)?;
    if !state.ratelimit.allow(&agent, FORWARDING_MAX_PER_MIN) {
        return Err(ForwardingHttpError::RateLimited);
    }

    state
        .forwarding
        .put_if_newer(record, now_ms())
        .map_err(|current_issued_at_ms| ForwardingHttpError::NonMonotonic {
            current_issued_at_ms,
        })?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET `/v1/forwarding/{agent_id}`. Returns the current non-expired
/// signed record verbatim (the consumer re-verifies end-to-end) or 404.
pub async fn get_forwarding(
    State(state): State<Arc<ServerState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<ForwardingRecordV1>, StatusCode> {
    get_live_unsuperseded(&state, &agent_id.to_ascii_lowercase(), now_ms())
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Live forwarding record for `agent_id_hex`, additionally suppressed
/// when the agent's stored pair-record is **newer** than the forwarding
/// record — both timestamps come from the same issuer's ratchet, so the
/// freshest signed statement wins. An agent that migrated A→B and
/// returned inside the TTL re-publishes its pair-record at A; that
/// retires the stale moved-to-B pointer here (deposits buffer+Ack
/// again, GET reads 404) without removing anything: the stored record
/// keeps holding the forwarding watermark, so a captured older record
/// still 409s on replay, and the no-removal invariant on both indexes
/// stands. A tie reads as not superseded (today's Moved behavior).
#[must_use]
pub fn get_live_unsuperseded(
    state: &ServerState,
    agent_id_hex: &str,
    now_ms: u64,
) -> Option<ForwardingRecordV1> {
    let fwd = state.forwarding.get_live(agent_id_hex, now_ms)?;
    // A forwarding POST requires a stored pair-record (412) and
    // pair-records have no removal path, so a live forwarding record
    // implies the pair lookup hits; the None arm (serve unsuppressed)
    // is defensive.
    if let Some(pair) = state.pair_records.get(agent_id_hex) {
        if pair.issued_at_ms > fwd.issued_at_ms {
            return None;
        }
    }
    Some(fwd)
}

/// Relay wall-clock in unix-epoch milliseconds. Mirrors the convention in
/// `ws.rs` / `capability.rs`: a clock fault saturates to `u64::MAX`,
/// which fails safe here (everything reads as expired).
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mk_record(agent_hex: &str, issued: u64) -> ForwardingRecordV1 {
        ForwardingRecordV1 {
            agent_id_hex: agent_hex.to_string(),
            moved_to_relays: vec!["https://relay.example".to_string()],
            issued_at_ms: issued,
            sig_b64: "AA".to_string(),
        }
    }

    // ── store ─────────────────────────────────────────────────────────

    #[test]
    fn put_if_newer_is_a_compare_and_swap() {
        let idx = ForwardingIndex::new();
        let id = hex::encode([0xaa; 32]);
        assert_eq!(idx.put_if_newer(mk_record(&id, 100), 1_000), Ok(()));
        assert_eq!(idx.put_if_newer(mk_record(&id, 101), 1_001), Ok(()));
        assert_eq!(idx.put_if_newer(mk_record(&id, 101), 1_002), Err(101));
        assert_eq!(idx.put_if_newer(mk_record(&id, 50), 1_003), Err(101));
        assert_eq!(idx.get_live(&id, 1_004).unwrap().issued_at_ms, 101);
    }

    #[test]
    fn get_live_hides_expired_before_sweep() {
        let idx = ForwardingIndex::new();
        let id = hex::encode([0xbb; 32]);
        idx.put_if_newer(mk_record(&id, 1), 0).unwrap();
        // Within TTL: visible.
        assert!(idx.get_live(&id, FORWARDING_TTL_MS).is_some());
        // One ms past TTL: reads as absent even though still stored.
        assert!(idx.get_live(&id, FORWARDING_TTL_MS + 1).is_none());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn sweep_evicts_only_expired() {
        let idx = ForwardingIndex::new();
        let fresh = hex::encode([0xcc; 32]);
        let stale = hex::encode([0xdd; 32]);
        idx.put_if_newer(mk_record(&stale, 1), 0).unwrap();
        idx.put_if_newer(mk_record(&fresh, 1), FORWARDING_TTL_MS)
            .unwrap();
        // Sweep at a point where `stale` is expired but `fresh` is not.
        let evicted = idx.sweep_expired(FORWARDING_TTL_MS + 1);
        assert_eq!(evicted, 1);
        assert!(idx.get_live(&fresh, FORWARDING_TTL_MS + 1).is_some());
        assert!(idx.get_live(&stale, FORWARDING_TTL_MS + 1).is_none());
    }

    #[test]
    fn put_if_newer_under_concurrency_keeps_the_max() {
        let n: u64 = 64;
        let idx = ForwardingIndex::new(); // already an Arc<Self>
        let id = hex::encode([0xab; 32]);
        let mut handles = Vec::new();
        for k in 0..n {
            let issued = ((k * 37) % n) + 1;
            let idx = std::sync::Arc::clone(&idx);
            let id = id.clone();
            handles.push(std::thread::spawn(move || {
                let _ = idx.put_if_newer(mk_record(&id, issued), 1_000);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(idx.get_live(&id, 1_001).unwrap().issued_at_ms, n);
    }

    // ── error -> status mapping ───────────────────────────────────────

    #[test]
    fn http_error_statuses() {
        assert_eq!(
            ForwardingHttpError::BodyTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ForwardingHttpError::Malformed("x").status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ForwardingHttpError::NoPairRecord.status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            ForwardingHttpError::StoredKeyUndecodable.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ForwardingHttpError::RateLimited.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ForwardingHttpError::NonMonotonic {
                current_issued_at_ms: 7
            }
            .status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn nonmonotonic_body_carries_current_issued_at_ms_exact_field() {
        let body = ForwardingHttpError::NonMonotonic {
            current_issued_at_ms: 42,
        }
        .json_body();
        assert_eq!(body, serde_json::json!({ "current_issued_at_ms": 42 }));
    }

    #[test]
    fn no_pair_record_body_is_ok_false_with_message() {
        let body = ForwardingHttpError::NoPairRecord.json_body();
        assert_eq!(body["ok"], serde_json::json!(false));
        assert!(body["error"].as_str().unwrap().contains("pair-record"));
    }

    #[test]
    fn impersonation_verify_errors_are_403() {
        assert_eq!(
            ForwardingHttpError::Verify(PairRecordError::AgentIdMismatch).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ForwardingHttpError::Verify(PairRecordError::SignatureInvalid).status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn agent_id_from_hex_roundtrips_and_rejects_bad_length() {
        let id = hex::encode([0x5a; 32]);
        assert!(agent_id_from_hex(&id).is_ok());
        assert!(matches!(
            agent_id_from_hex("abcd"),
            Err(ForwardingHttpError::Malformed(_))
        ));
    }
}
