//! v3 pairing — consumer side of the share-URI handoff.
//!
//! Phase 1c of QR pairing per `docs/qr-pairing-v1.md`. Given a parsed
//! [`V3ShareUri`], fetch the offerer's profile-index record from the
//! relay, verify the embedded ML-DSA-65 signature, and surface the
//! KEM pubkey + ML-DSA pubkey the chat path needs to bootstrap a
//! Conversation with the new peer.
//!
//! The full `ProfileManifest` (`display_name`, avatar, bio, links) lives
//! on Autonomi at `profile_addr` and is fetched in phase 4 via the
//! `ant-core` integration. For phase 1c we have enough from the
//! relay-index record alone to add a contact and DM them — the
//! `display_name` comes through as empty and the avatar / bio fill
//! in once phase 4 lands.

use crate::error::ChatError;
use crate::messages::StoredContactCard;
use crate::profile::{from_v3_share_uri, V3ShareUri, V3ShareUriError, SIGN_DOMAIN_PROFILE};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use fetchit_relay_proto::derive_agent_id;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Wire shape of the relay's `GET /v1/profile/{agent_id}` response.
/// Mirrors `fetchit_relay_server::profile::ProfileIndexRecord` —
/// these two structs are intentionally separate so neither crate
/// depends on the other's surface, but the field set + JSON shape
/// MUST match byte-for-byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileIndexRecord {
    /// 64-hex lowercase `agent_id`.
    pub agent_id: String,
    /// 64-hex lowercase Autonomi `profile_addr` pointing to the
    /// signed JSON manifest. All-zeros means the profile was
    /// tombstoned on the relay; phase 1c rejects this with
    /// [`PairError::Tombstoned`].
    pub profile_addr: String,
    /// base64url-no-pad of the raw 1184-byte ML-KEM-768 public key.
    pub kem_pubkey: String,
    /// base64url-no-pad of the raw 1952-byte ML-DSA-65 public key.
    pub ml_dsa_pubkey: String,
    /// Unix epoch milliseconds the record was minted.
    pub issued_at_ms: u64,
    /// base64url-no-pad ML-DSA-65 signature over
    /// `SIGN_DOMAIN_PROFILE || jcs_canonical(record sans sig)`.
    pub sig: String,
}

/// Reasons a pair-accept can fail.
#[derive(Debug, Error)]
pub enum PairError {
    /// URI didn't parse as v3 share-URI.
    #[error("share URI: {0}")]
    Uri(#[from] V3ShareUriError),
    /// HTTP transport to the relay failed.
    #[error("relay fetch: {0}")]
    Http(#[from] reqwest::Error),
    /// Relay returned a non-success status. Carries the status code
    /// so the UI can distinguish "not found yet" (404 → offerer
    /// hasn't published) from "service is broken" (5xx).
    #[error("relay returned {0}")]
    RelayStatus(u16),
    /// Relay's JSON response did not parse as `ProfileIndexRecord`.
    #[error("relay response: {0}")]
    Decode(String),
    /// The offerer's `agent_id` in the URI did NOT match the
    /// `agent_id` the relay returned. Indicates the relay is
    /// serving a different identity for that path, or the URI was
    /// tampered with after generation.
    #[error("URI agent_id does not match relay record")]
    AgentIdMismatch,
    /// `derive_agent_id(ml_dsa_pubkey)` ≠ the embedded `agent_id`.
    /// Indicates the relay's record itself is internally
    /// inconsistent (the relay would normally reject such records
    /// on POST; surfacing here defends against a misbehaving or
    /// downgraded relay).
    #[error("relay record's pubkey doesn't derive its claimed agent_id")]
    DerivationMismatch,
    /// `profile_addr` was the all-zeros tombstone — the offerer has
    /// deleted their profile.
    #[error("offerer's profile was tombstoned")]
    Tombstoned,
    /// ML-DSA-65 signature did not verify against the canonical
    /// body + embedded pubkey.
    #[error("signature verification failed")]
    SigVerifyFailed,
    /// Field decode (b64url / hex) failed.
    #[error("field decode: {0}")]
    FieldDecode(String),
    /// saorsa-pqc rejected the encoded public key or signature
    /// bytes (wrong length, bad format).
    #[error("pqc: {0}")]
    Pqc(String),
}

const ALL_ZEROS_PROFILE_ADDR: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// JCS-canonicalise the record value with the `sig` field stripped.
/// Round-trips via `serde_json::Value` so the field order on the
/// strongly-typed struct doesn't affect canonical output.
fn canonical_bytes_sans_sig(
    record: &ProfileIndexRecord,
) -> std::result::Result<Vec<u8>, PairError> {
    let mut v = serde_json::to_value(record)
        .map_err(|_| PairError::Decode("record not JSON-serialisable".into()))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sig");
    }
    serde_jcs::to_vec(&v).map_err(|e| PairError::Decode(format!("jcs: {e}")))
}

/// Verify a relay-returned index record. Mirrors the server-side
/// `verify_record` pipeline (re-derive `agent_id`, ML-DSA verify
/// over `SIGN_DOMAIN_PROFILE || jcs_canonical(record sans sig)`)
/// but runs locally so the consumer doesn't have to trust the relay.
///
/// Returns the decoded `ml_dsa_pubkey_bytes` on success.
///
/// # Errors
/// One of the [`PairError`] variants per the spec; the relevant
/// ones at this stage are `Tombstoned`, `DerivationMismatch`,
/// `SigVerifyFailed`, and the various field-decode failures.
pub fn verify_index_record(record: &ProfileIndexRecord) -> std::result::Result<Vec<u8>, PairError> {
    if record.profile_addr == ALL_ZEROS_PROFILE_ADDR {
        return Err(PairError::Tombstoned);
    }
    let pubkey_bytes = B64URL
        .decode(&record.ml_dsa_pubkey)
        .map_err(|e| PairError::FieldDecode(format!("ml_dsa_pubkey b64: {e}")))?;
    let sig_bytes = B64URL
        .decode(&record.sig)
        .map_err(|e| PairError::FieldDecode(format!("sig b64: {e}")))?;
    let embedded_agent_id = hex::decode(&record.agent_id)
        .map_err(|e| PairError::FieldDecode(format!("agent_id hex: {e}")))?;
    if embedded_agent_id.len() != 32 {
        return Err(PairError::FieldDecode(format!(
            "agent_id: expected 32 bytes, got {}",
            embedded_agent_id.len()
        )));
    }
    let mut embedded_arr = [0u8; 32];
    embedded_arr.copy_from_slice(&embedded_agent_id);
    if derive_agent_id(&pubkey_bytes) != embedded_arr {
        return Err(PairError::DerivationMismatch);
    }

    let canonical = canonical_bytes_sans_sig(record)?;
    let mut sign_input = Vec::with_capacity(SIGN_DOMAIN_PROFILE.len() + canonical.len());
    sign_input.extend_from_slice(SIGN_DOMAIN_PROFILE);
    sign_input.extend_from_slice(&canonical);

    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pubkey_bytes)
        .map_err(|e| PairError::Pqc(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| PairError::Pqc(e.to_string()))?;
    let ok = dsa
        .verify(&pk, &sign_input, &sig)
        .map_err(|e| PairError::Pqc(e.to_string()))?;
    if !ok {
        return Err(PairError::SigVerifyFailed);
    }
    Ok(pubkey_bytes)
}

/// HTTP GET `{relay}/v1/profile/{agent_id}` and return the
/// deserialised + verified record. The `agent_id` in the path is
/// taken from the parsed URI; the relay's response is verified
/// against itself (sig + `derive_agent_id`) and then cross-checked
/// against the URI's `agent_id` so a man-in-the-middle relay can't
/// substitute a different identity.
///
/// # Errors
/// One of the [`PairError`] variants per the spec.
pub async fn fetch_index_record(
    uri: &V3ShareUri,
    http: &reqwest::Client,
) -> std::result::Result<ProfileIndexRecord, PairError> {
    let path = format!("v1/profile/{}", uri.agent_id);
    let url = uri.relay.join(&path).map_err(|e| {
        PairError::Decode(format!(
            "could not build relay URL from {} + {path}: {e}",
            uri.relay
        ))
    })?;
    let resp = http
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(PairError::RelayStatus(resp.status().as_u16()));
    }
    let record: ProfileIndexRecord = resp
        .json()
        .await
        .map_err(|e| PairError::Decode(format!("relay JSON: {e}")))?;
    if record.agent_id != uri.agent_id {
        return Err(PairError::AgentIdMismatch);
    }
    verify_index_record(&record)?;
    Ok(record)
}

/// Convenience: parse a v3 share URI string + fetch + verify in one
/// call. Returns the validated record so the caller can persist it
/// however it sees fit.
///
/// # Errors
/// Same variants as [`fetch_index_record`] plus URI-parse failures
/// via the [`PairError::Uri`] variant.
pub async fn fetch_from_uri(
    uri_str: &str,
    http: &reqwest::Client,
) -> std::result::Result<(V3ShareUri, ProfileIndexRecord), PairError> {
    let uri = from_v3_share_uri(uri_str)?;
    let record = fetch_index_record(&uri, http).await?;
    Ok((uri, record))
}

/// Convert a verified [`ProfileIndexRecord`] into the existing
/// [`StoredContactCard`] shape so the chat path can use it
/// immediately. `display_name` is empty until phase 4 fetches the
/// full `ProfileManifest` from Autonomi (which carries the rich
/// display fields); for now the `agent_id` is enough to DM with and
/// the UI falls back to its existing short-`agent_id` label.
#[must_use]
pub fn record_into_stored_contact(record: &ProfileIndexRecord) -> StoredContactCard {
    StoredContactCard {
        agent_id_hex: record.agent_id.clone(),
        display_name: String::new(),
        kem_public_key_b64: record.kem_pubkey.clone(),
        agent_public_key_b64: Some(record.ml_dsa_pubkey.clone()),
        // M3 R-tail-5: v3 profile pairing doesn't yet thread relay
        // hints from `ProfileManifest.relays` into `StoredContactCard`;
        // legacy v1 fallback applies (send path synthesizes the local
        // primary URL). Wire-up tracked alongside the M3 profile
        // republish work in apps/fetchit-desktop/src-tauri.
        rendezvous_hints: None,
    }
}

/// Build a legacy `x0x://agent/<base64>` share URI from a verified
/// v3 [`ProfileIndexRecord`] so the desktop shell can hand it to
/// x0xd's `/agent/card/import` endpoint and populate the
/// daemon-backed contact list. The synthetic card has an empty
/// `display_name` and `addresses` — both fields x0xd treats as
/// optional metadata for its contact-row UX; KEM and ML-DSA keys
/// live in [`crate::messages::StoredContactCard`] on the layout
/// side, which is the actual source of truth for the encrypted-DM
/// send path. This dual-write closes the bug where a v3-paired
/// contact was invisible to `chat_contacts` (which reads x0xd).
///
/// # Errors
/// Returns [`PairError::Pqc`] if `agent_id` is not 64-char hex,
/// or [`PairError::Decode`] if `to_share_uri` fails to JSON-encode.
pub fn record_to_legacy_share_uri(record: &ProfileIndexRecord) -> Result<String, PairError> {
    use crate::identity::{AgentCard, AgentId};
    let agent_id =
        AgentId::parse(record.agent_id.clone()).map_err(|e| PairError::Pqc(e.to_string()))?;
    let card = AgentCard {
        agent_id,
        display_name: String::new(),
        created_at: None,
        addresses: Vec::new(),
        extra: serde_json::Value::Null,
    };
    card.to_share_uri()
        .map_err(|e| PairError::Decode(e.to_string()))
}

/// Convenience wrapper that maps `PairError` into the
/// crate-wide [`ChatError`] so the Tauri command layer doesn't
/// have to know about two error types.
impl From<PairError> for ChatError {
    fn from(e: PairError) -> Self {
        ChatError::Invalid(e.to_string())
    }
}

/// Result of a successful pair-accept — `agent_id` of the imported
/// contact (ready for the UI to navigate to) plus the verified
/// [`ProfileIndexRecord`] so the desktop shell can dual-write the
/// contact into x0xd via [`record_to_legacy_share_uri`].
pub struct PairAccepted {
    /// 64-hex lowercase `agent_id` of the new contact.
    pub agent_id_hex: String,
    /// Verified profile-index record from the relay. Exposed so the
    /// caller can populate ancillary stores (x0xd's
    /// `/agent/card/import`) without re-fetching.
    pub record: ProfileIndexRecord,
}

/// End-to-end pair-accept: parse → fetch → verify → persist as a
/// `StoredContactCard` under the supplied store layout.
///
/// # Errors
/// One of the [`PairError`] variants on any step (surfaced via
/// the conversion to `ChatError`). The persist step fails if the
/// layout's contacts directory is unwritable.
pub async fn pair_accept(
    uri_str: &str,
    http: &reqwest::Client,
    layout: &crate::local_store::StoreLayout,
) -> crate::error::Result<PairAccepted> {
    let (_uri, record) = fetch_from_uri(uri_str, http).await?;
    let stored = record_into_stored_contact(&record);
    let agent_id_hex = stored.agent_id_hex.clone();
    stored.save(layout)?;
    Ok(PairAccepted {
        agent_id_hex,
        record,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use saorsa_pqc::api::sig::MlDsaSecretKey;
    use serde_json::Value;

    fn mk_signed_record(
        dsa: &MlDsa,
        sk: &MlDsaSecretKey,
        pk_bytes: &[u8],
        profile_addr: &str,
        issued_at_ms: u64,
    ) -> ProfileIndexRecord {
        let agent_id = hex::encode(derive_agent_id(pk_bytes));
        let unsigned = ProfileIndexRecord {
            agent_id: agent_id.clone(),
            profile_addr: profile_addr.to_string(),
            kem_pubkey: B64URL.encode([0u8; 1184]),
            ml_dsa_pubkey: B64URL.encode(pk_bytes),
            issued_at_ms,
            sig: String::new(),
        };
        let mut v = serde_json::to_value(&unsigned).unwrap();
        v.as_object_mut().unwrap().remove("sig");
        let canonical = serde_jcs::to_vec(&v).unwrap();
        let mut sign_input = Vec::with_capacity(SIGN_DOMAIN_PROFILE.len() + canonical.len());
        sign_input.extend_from_slice(SIGN_DOMAIN_PROFILE);
        sign_input.extend_from_slice(&canonical);
        let sig_bytes = dsa.sign(sk, &sign_input).unwrap().to_bytes();
        ProfileIndexRecord {
            sig: B64URL.encode(sig_bytes),
            ..unsigned
        }
    }

    #[test]
    fn verify_passes_for_a_valid_signed_record() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let r = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"a".repeat(64), 1);
        verify_index_record(&r).expect("happy path verify");
    }

    #[test]
    fn record_to_legacy_share_uri_round_trips_agent_id() {
        // Build a record with a fresh keypair, ask the helper for an
        // x0x:// URI, decode it back via the legacy AgentCard parser,
        // and confirm the agent_id survives. This is the wire shape
        // x0xd's /agent/card/import accepts.
        use crate::identity::AgentCard;
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let r = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"a".repeat(64), 1);
        let uri = record_to_legacy_share_uri(&r).expect("synthetic uri");
        assert!(uri.starts_with("x0x://agent/"), "got {uri}");
        let card = AgentCard::from_share_uri(&uri).expect("decode");
        assert_eq!(card.agent_id.0, r.agent_id);
        assert_eq!(card.display_name, "");
        assert!(card.addresses.is_empty());
    }

    #[test]
    fn record_to_legacy_share_uri_rejects_bogus_agent_id() {
        // Synthetic records that pre-date the validation layer should
        // surface a parse error rather than panic.
        let bogus = ProfileIndexRecord {
            agent_id: "not-hex".into(),
            profile_addr: "x".into(),
            kem_pubkey: String::new(),
            ml_dsa_pubkey: String::new(),
            issued_at_ms: 0,
            sig: String::new(),
        };
        match record_to_legacy_share_uri(&bogus) {
            Err(PairError::Pqc(_)) => {}
            other => panic!("expected Pqc parse error, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_tombstoned_record() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let r = mk_signed_record(&dsa, &sk, &pk.to_bytes(), ALL_ZEROS_PROFILE_ADDR, 1);
        match verify_index_record(&r) {
            Err(PairError::Tombstoned) => {}
            other => panic!("expected Tombstoned, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_swapped_agent_id() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let mut r = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"a".repeat(64), 1);
        r.agent_id = "f".repeat(64);
        match verify_index_record(&r) {
            Err(PairError::DerivationMismatch) => {}
            other => panic!("expected DerivationMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let mut r = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"a".repeat(64), 1);
        let mut sig_bytes = B64URL.decode(&r.sig).unwrap();
        sig_bytes[0] ^= 0xff;
        r.sig = B64URL.encode(&sig_bytes);
        match verify_index_record(&r) {
            Err(PairError::SigVerifyFailed) => {}
            other => panic!("expected SigVerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn record_to_stored_contact_preserves_keys() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let r = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"b".repeat(64), 1);
        let card = record_into_stored_contact(&r);
        assert_eq!(card.agent_id_hex, r.agent_id);
        assert_eq!(card.kem_public_key_b64, r.kem_pubkey);
        assert_eq!(
            card.agent_public_key_b64.as_deref(),
            Some(r.ml_dsa_pubkey.as_str())
        );
        assert_eq!(card.display_name, ""); // filled by phase 4 Autonomi fetch
    }

    /// Spins a wiremock relay, returns a signed record on GET, and
    /// verifies `fetch_index_record` parses + cross-checks
    /// `agent_id` + runs the verifier end-to-end. The negative
    /// branches (404, `agent_id` mismatch, tombstone) are covered by
    /// the unit tests on `verify_index_record` plus a separate
    /// network-error test below.
    #[tokio::test]
    async fn fetch_index_record_against_wiremock_happy_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let record = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"c".repeat(64), 42);

        Mock::given(method("GET"))
            .and(path(format!("/v1/profile/{}", record.agent_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(&record))
            .mount(&server)
            .await;

        let uri = V3ShareUri {
            agent_id: record.agent_id.clone(),
            profile_addr: record.profile_addr.clone(),
            relay: url::Url::parse(&format!("{}/", server.uri())).unwrap(),
        };
        let http = reqwest::Client::new();
        let got = fetch_index_record(&uri, &http).await.unwrap();
        assert_eq!(got.agent_id, record.agent_id);
        assert_eq!(got.issued_at_ms, 42);
    }

    #[tokio::test]
    async fn fetch_index_record_returns_404_when_offerer_not_yet_published() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let uri = V3ShareUri {
            agent_id: "a".repeat(64),
            profile_addr: "b".repeat(64),
            relay: url::Url::parse(&format!("{}/", server.uri())).unwrap(),
        };
        let http = reqwest::Client::new();
        match fetch_index_record(&uri, &http).await {
            Err(PairError::RelayStatus(404)) => {}
            other => panic!("expected RelayStatus(404), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_index_record_rejects_when_relay_returns_a_different_agent_id() {
        // Defends against a misbehaving relay that serves someone
        // else's record under our queried path. The consumer cross-
        // checks the URI's agent_id against the response.
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let real_record = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"d".repeat(64), 1);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&real_record))
            .mount(&server)
            .await;

        let uri = V3ShareUri {
            agent_id: "a".repeat(64), // wrong: doesn't match the real record
            profile_addr: "d".repeat(64),
            relay: url::Url::parse(&format!("{}/", server.uri())).unwrap(),
        };
        let http = reqwest::Client::new();
        match fetch_index_record(&uri, &http).await {
            Err(PairError::AgentIdMismatch) => {}
            other => panic!("expected AgentIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn pair_error_to_chat_error_preserves_message() {
        let pe = PairError::Tombstoned;
        let ce: ChatError = pe.into();
        assert!(ce.to_string().contains("tombstoned"));
    }

    #[test]
    fn record_serialization_matches_relay_server_shape() {
        // Pin the on-the-wire field set so the two crates' separate
        // ProfileIndexRecord definitions can't drift. The relay's
        // verify path JCS-canonicalises this object; if a field
        // is renamed or added on either side without the other,
        // sig verification silently breaks. This test guards
        // against that — the field list here must match
        // fetchit_relay_server::profile::ProfileIndexRecord exactly.
        let r = ProfileIndexRecord {
            agent_id: "a".repeat(64),
            profile_addr: "b".repeat(64),
            kem_pubkey: "k".to_string(),
            ml_dsa_pubkey: "m".to_string(),
            issued_at_ms: 1,
            sig: "s".to_string(),
        };
        let v: Value = serde_json::to_value(&r).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        // Canonical key set — drift on either side breaks pairing.
        assert!(keys.contains(&"agent_id"));
        assert!(keys.contains(&"profile_addr"));
        assert!(keys.contains(&"kem_pubkey"));
        assert!(keys.contains(&"ml_dsa_pubkey"));
        assert!(keys.contains(&"issued_at_ms"));
        assert!(keys.contains(&"sig"));
        assert_eq!(keys.len(), 6, "no extra fields allowed; got {keys:?}");
    }
}
