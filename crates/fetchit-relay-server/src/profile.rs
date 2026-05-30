//! `/v1/profile` index endpoints — the relay's cache pointer from
//! `agent_id` to the latest `profile_addr` on Autonomi. Specced in
//! `docs/profile-manifest-v1.md` § 4.
//!
//! The endpoints are a discovery hint, not the trust root: every
//! fetched profile manifest is verified end-to-end by the consumer
//! using the signed body returned here. The relay just holds the
//! latest record per `agent_id` and enforces monotonic
//! `issued_at_ms` so a stale record can't roll back a newer one.

use crate::server::ServerState;
use crate::signature::SignatureVerifier;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use dashmap::DashMap;
use fetchit_relay_proto::derive_agent_id;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Domain-separation prefix on profile-manifest + profile-index
/// signatures. Must byte-match `fetchit_chat::profile::SIGN_DOMAIN_PROFILE`
/// and the relay-envelope signing prefix in etch>it's `profile_publish`.
/// Drift between any of these three breaks the whole v3 chain.
pub const SIGN_DOMAIN_PROFILE: &[u8] = b"fetchit/profile-manifest/v1";

/// Hard ceiling on the POST body. v3 envelopes are ~5 KB once
/// base64-encoded; the cap is set well above that to absorb any
/// future field additions without code change, and well below the
/// 32 MB axum default so a malicious client can't blow up RAM
/// with garbage POSTs.
pub const MAX_PROFILE_BODY_BYTES: usize = 32 * 1024;

/// 64 `'0'` characters — the canonical tombstone value for
/// `profile_addr`. A POST carrying this address marks the record
/// as deleted; subsequent GETs return 404 until a higher
/// `issued_at_ms` undeletes.
const TOMBSTONE_PROFILE_ADDR: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Wire shape of POST `/v1/profile` and the verbatim GET response.
///
/// `agent_id` and `profile_addr` are lowercase 64-hex.
/// `kem_pubkey`, `ml_dsa_pubkey`, `sig` are base64url-no-pad
/// raw bytes. `issued_at_ms` is monotonic per `agent_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileIndexRecord {
    /// 64-hex `agent_id`. Must equal `derive_agent_id(decode(ml_dsa_pubkey))`.
    pub agent_id: String,
    /// 64-hex Autonomi address where the signed manifest lives, OR
    /// the all-zeros tombstone sentinel.
    pub profile_addr: String,
    /// base64url-no-pad of the raw 1184-byte ML-KEM-768 public key.
    pub kem_pubkey: String,
    /// base64url-no-pad of the raw 1952-byte ML-DSA-65 public key.
    pub ml_dsa_pubkey: String,
    /// Unix epoch ms. Strictly greater than the previously stored
    /// value for this `agent_id` (or the record is rejected 409).
    pub issued_at_ms: u64,
    /// base64url-no-pad ML-DSA-65 signature over
    /// `SIGN_DOMAIN_PROFILE || jcs_canonical(record sans sig)`.
    pub sig: String,
}

/// In-memory `agent_id -> ProfileIndexRecord`. No persistence; the
/// relay is RAM-only per its operating posture. A future relay
/// restart drops every record; publishers re-POST on next launch,
/// or consumers fall through to the Autonomi resolution path.
#[derive(Default)]
pub struct ProfileIndex {
    by_agent: DashMap<String, ProfileIndexRecord>,
}

impl ProfileIndex {
    /// Construct an empty index wrapped in an `Arc` so the
    /// `ServerState` can hold it without further wrapping.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_agent: DashMap::new(),
        })
    }

    /// Return the current record for `agent_id` if one exists AND
    /// it is not a tombstone. Tombstoned records exist in the map
    /// so future POSTs can monotonic-check against them, but GETs
    /// surface 404 for them.
    #[must_use]
    pub fn get_live(&self, agent_id: &str) -> Option<ProfileIndexRecord> {
        self.by_agent.get(agent_id).and_then(|r| {
            if r.profile_addr == TOMBSTONE_PROFILE_ADDR {
                None
            } else {
                Some(r.clone())
            }
        })
    }

    /// Return the current `issued_at_ms` whether or not the record
    /// is tombstoned. Used to enforce monotonicity across the
    /// undelete path.
    #[must_use]
    pub fn current_issued_at(&self, agent_id: &str) -> Option<u64> {
        self.by_agent.get(agent_id).map(|r| r.issued_at_ms)
    }

    /// Store `record` keyed by its `agent_id`. Caller is responsible
    /// for having already verified the sig + `agent_id` derivation +
    /// monotonicity.
    pub fn put(&self, record: ProfileIndexRecord) {
        self.by_agent.insert(record.agent_id.clone(), record);
    }

    /// Count of currently-stored records (including tombstones).
    /// Used in tests; production code shouldn't depend on this.
    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_agent.len()
    }

    /// `true` when no records (or tombstones) exist. Paired with
    /// [`Self::len`] because clippy insists on the pair existing
    /// together; production code uses neither, both are test-only.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_agent.is_empty()
    }
}

/// Reasons a POST is rejected. Stringly-typed enough for human
/// logs while carrying the matching HTTP status.
#[derive(Debug)]
pub enum ProfileError {
    /// Body exceeds [`MAX_PROFILE_BODY_BYTES`]. 413.
    BodyTooLarge,
    /// JSON shape, field-format, or canonicalisation failure. 400.
    Malformed(&'static str),
    /// `agent_id` field does not equal `derive_agent_id(ml_dsa_pubkey)`. 400.
    AgentIdMismatch,
    /// ML-DSA-65 signature did not verify against the canonical body. 400.
    SigVerifyFailed,
    /// `issued_at_ms` is not strictly greater than the stored value. 409.
    NonMonotonic,
}

impl ProfileError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Malformed(_) | Self::AgentIdMismatch | Self::SigVerifyFailed => {
                StatusCode::BAD_REQUEST
            }
            Self::NonMonotonic => StatusCode::CONFLICT,
        }
    }

    fn body(&self) -> &str {
        match self {
            Self::BodyTooLarge => "profile body exceeds 32 KB",
            Self::Malformed(why) => why,
            Self::AgentIdMismatch => "agent_id does not match derive_agent_id(ml_dsa_pubkey)",
            Self::SigVerifyFailed => "ml-dsa-65 signature verify failed",
            Self::NonMonotonic => "issued_at_ms must be strictly greater than the stored value",
        }
    }
}

impl IntoResponse for ProfileError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status(),
            Json(serde_json::json!({ "ok": false, "error": self.body() })),
        )
            .into_response()
    }
}

/// Re-derive `agent_id` from the embedded `ml_dsa_pubkey` and
/// verify the ML-DSA-65 signature over the canonical body.
///
/// Returns the decoded `ml_dsa_pubkey_bytes` on success so callers
/// don't have to re-decode for any downstream use.
pub fn verify_record(
    record: &ProfileIndexRecord,
    verifier: &dyn SignatureVerifier,
) -> Result<Vec<u8>, ProfileError> {
    let pubkey_bytes = B64URL
        .decode(&record.ml_dsa_pubkey)
        .map_err(|_| ProfileError::Malformed("ml_dsa_pubkey: not base64url-no-pad"))?;
    let sig_bytes = B64URL
        .decode(&record.sig)
        .map_err(|_| ProfileError::Malformed("sig: not base64url-no-pad"))?;
    let embedded_agent_id_bytes = hex::decode(&record.agent_id)
        .map_err(|_| ProfileError::Malformed("agent_id: not 64-hex"))?;
    if embedded_agent_id_bytes.len() != 32 {
        return Err(ProfileError::Malformed("agent_id: must be 32 bytes"));
    }
    let mut embedded_arr = [0u8; 32];
    embedded_arr.copy_from_slice(&embedded_agent_id_bytes);
    let derived = derive_agent_id(&pubkey_bytes);
    if derived != embedded_arr {
        return Err(ProfileError::AgentIdMismatch);
    }
    let canonical = canonical_bytes_sans_sig(record)?;
    let mut sign_input = Vec::with_capacity(SIGN_DOMAIN_PROFILE.len() + canonical.len());
    sign_input.extend_from_slice(SIGN_DOMAIN_PROFILE);
    sign_input.extend_from_slice(&canonical);
    if !verifier.verify_ml_dsa_65(&pubkey_bytes, &sign_input, &sig_bytes) {
        return Err(ProfileError::SigVerifyFailed);
    }
    Ok(pubkey_bytes)
}

/// JCS-canonicalise the record value with the `sig` field stripped.
/// Round-trips via `serde_json::Value` so the field order on the
/// strongly-typed struct doesn't affect canonical output.
fn canonical_bytes_sans_sig(record: &ProfileIndexRecord) -> Result<Vec<u8>, ProfileError> {
    let mut v = serde_json::to_value(record)
        .map_err(|_| ProfileError::Malformed("record not JSON-serialisable"))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sig");
    }
    serde_jcs::to_vec(&v).map_err(|_| ProfileError::Malformed("jcs canonicalisation failed"))
}

/// POST `/v1/profile`. Validates body size, verifies the signature,
/// enforces monotonic `issued_at_ms`, then stores the record.
pub async fn post_profile(
    State(state): State<Arc<ServerState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ProfileError> {
    if body.len() > MAX_PROFILE_BODY_BYTES {
        return Err(ProfileError::BodyTooLarge);
    }
    let record: ProfileIndexRecord =
        serde_json::from_slice(&body).map_err(|_| ProfileError::Malformed("invalid JSON body"))?;
    verify_record(&record, state.verifier.as_ref())?;
    if let Some(prev) = state.profiles.current_issued_at(&record.agent_id) {
        if record.issued_at_ms <= prev {
            return Err(ProfileError::NonMonotonic);
        }
    }
    state.profiles.put(record);
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET `/v1/profile/{agent_id}`. Returns the current record verbatim
/// or 404 when the agent has no record or the latest entry is a
/// tombstone.
pub async fn get_profile(
    State(state): State<Arc<ServerState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<ProfileIndexRecord>, StatusCode> {
    state
        .profiles
        .get_live(&agent_id.to_ascii_lowercase())
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// DELETE `/v1/profile/{agent_id}` — POST-shaped body carrying the
/// tombstone sentinel for `profile_addr`. Same verify pipeline as
/// POST plus a hard check that `profile_addr` IS the tombstone (so
/// you can't accidentally tombstone via DELETE while pointing at a
/// real Autonomi address).
pub async fn delete_profile(
    State(state): State<Arc<ServerState>>,
    Path(agent_id_path): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ProfileError> {
    if body.len() > MAX_PROFILE_BODY_BYTES {
        return Err(ProfileError::BodyTooLarge);
    }
    let record: ProfileIndexRecord =
        serde_json::from_slice(&body).map_err(|_| ProfileError::Malformed("invalid JSON body"))?;
    if record.profile_addr != TOMBSTONE_PROFILE_ADDR {
        return Err(ProfileError::Malformed(
            "DELETE body must carry the all-zeros tombstone profile_addr",
        ));
    }
    if record.agent_id != agent_id_path.to_ascii_lowercase() {
        return Err(ProfileError::Malformed(
            "agent_id in body must match path parameter",
        ));
    }
    verify_record(&record, state.verifier.as_ref())?;
    if let Some(prev) = state.profiles.current_issued_at(&record.agent_id) {
        if record.issued_at_ms <= prev {
            return Err(ProfileError::NonMonotonic);
        }
    }
    state.profiles.put(record);
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signature::AcceptAllVerifier;

    fn mk_record(agent_id_byte: u8, issued: u64, profile_addr: &str) -> ProfileIndexRecord {
        ProfileIndexRecord {
            agent_id: hex::encode([agent_id_byte; 32]),
            profile_addr: profile_addr.to_string(),
            kem_pubkey: B64URL.encode([1u8; 1184]),
            ml_dsa_pubkey: B64URL.encode([2u8; 1952]),
            issued_at_ms: issued,
            sig: B64URL.encode([3u8; 3309]),
        }
    }

    #[test]
    fn put_then_get_live_returns_record() {
        let idx = ProfileIndex::new();
        let r = mk_record(0xaa, 1, "1".repeat(64).as_str());
        idx.put(r.clone());
        let got = idx.get_live(&r.agent_id).unwrap();
        assert_eq!(got.profile_addr, r.profile_addr);
    }

    #[test]
    fn get_live_returns_none_for_tombstone() {
        let idx = ProfileIndex::new();
        idx.put(mk_record(0xbb, 1, TOMBSTONE_PROFILE_ADDR));
        assert!(idx.get_live(&hex::encode([0xbb; 32])).is_none());
    }

    #[test]
    fn current_issued_at_sees_tombstones_for_monotonicity() {
        // A tombstone still counts toward the issued_at_ms ratchet —
        // an undelete must out-rank the tombstone or the new record
        // is rejected.
        let idx = ProfileIndex::new();
        idx.put(mk_record(0xcc, 5, TOMBSTONE_PROFILE_ADDR));
        assert_eq!(idx.current_issued_at(&hex::encode([0xcc; 32])), Some(5));
    }

    #[test]
    fn canonical_bytes_strip_the_sig_field() {
        // Two records identical except for sig must produce
        // byte-identical canonical bytes — otherwise the verify
        // pipeline would require the signer to predict the signature
        // before computing it.
        let a = mk_record(0xdd, 1, "1".repeat(64).as_str());
        let mut b = a.clone();
        b.sig = B64URL.encode([0u8; 3309]);
        assert_eq!(
            canonical_bytes_sans_sig(&a).unwrap(),
            canonical_bytes_sans_sig(&b).unwrap(),
        );
    }

    #[test]
    fn verify_rejects_agent_id_mismatch() {
        // Record claims an agent_id that doesn't derive from the
        // embedded ml_dsa_pubkey. AcceptAllVerifier would gladly
        // pass the sig check, so this asserts the agent_id derivation
        // gate fires first.
        let mut r = mk_record(0x00, 1, "1".repeat(64).as_str());
        r.agent_id = hex::encode([0xff; 32]); // wrong: doesn't derive from pubkey
        let v = AcceptAllVerifier;
        let err = verify_record(&r, &v).unwrap_err();
        assert!(matches!(err, ProfileError::AgentIdMismatch));
    }

    #[test]
    fn verify_rejects_malformed_pubkey_b64() {
        let mut r = mk_record(0x00, 1, "1".repeat(64).as_str());
        r.ml_dsa_pubkey = "not-base64url***".to_string();
        let v = AcceptAllVerifier;
        let err = verify_record(&r, &v).unwrap_err();
        assert!(matches!(err, ProfileError::Malformed(_)));
    }

    #[test]
    fn verify_rejects_malformed_agent_id_hex() {
        let mut r = mk_record(0x00, 1, "1".repeat(64).as_str());
        r.agent_id = "not-hex".to_string();
        let v = AcceptAllVerifier;
        let err = verify_record(&r, &v).unwrap_err();
        assert!(matches!(err, ProfileError::Malformed(_)));
    }

    #[test]
    fn sign_domain_matches_locked_spec_value() {
        // This constant must byte-match fetchit-chat::profile::
        // SIGN_DOMAIN_PROFILE and etch>it's relay-envelope signing
        // prefix. The literal is the canonical version from
        // docs/profile-manifest-v1.md § 2.
        assert_eq!(SIGN_DOMAIN_PROFILE, b"fetchit/profile-manifest/v1");
        assert_eq!(SIGN_DOMAIN_PROFILE.len(), 27);
    }
}
