//! Signed pairing records that let relay servers verify a client owns
//! the ML-DSA-65 key it claims.
//!
//! Two record types share this module:
//!
//! - [`PairRecordV1`] — the initial registration card: agent id, ML-DSA
//!   pubkey, ML-KEM-768 pubkey, preferred relays, and a timestamp.
//! - [`ForwardingRecordV1`] — a lightweight migration card that an agent
//!   signs when it switches relay sets without reissuing its full key
//!   material.
//!
//! Both record types carry a detached ML-DSA-65 signature (`sig_b64`)
//! over a **canonical signing input** defined below. The canonical
//! layout is frozen wire format: changing it requires a v2 migration,
//! not a patch.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for [`PairRecordV1`] signing inputs.
///
/// **Frozen.** Relay servers and third-party verifiers depend on this
/// exact byte string; changing it is a v2 migration.
pub const PAIR_RECORD_DOMAIN: &[u8] = b"fetchit-pair-record-v1";

/// Domain separator for [`ForwardingRecordV1`] signing inputs.
///
/// **Frozen.** Same constraint as [`PAIR_RECORD_DOMAIN`].
pub const FORWARDING_DOMAIN: &[u8] = b"fetchit-forwarding-v1";

/// Maximum number of relay URLs in either record type.
const MAX_RELAYS: usize = 4;

/// Maximum byte length of a single relay URL.
const MAX_URL_BYTES: usize = 256;

/// A signed pairing record binding an agent's ML-DSA-65 identity key
/// and ML-KEM-768 encryption key to a set of preferred relay URLs.
///
/// The `sig_b64` field is an ML-DSA-65 signature over the canonical
/// signing input produced by [`pair_signing_input`]. Verify with
/// [`verify_pair_record`].
///
/// # Wire representation
///
/// All byte fields are stored as base64 strings (standard alphabet,
/// padded). The struct serialises directly with serde; no serde-with
/// wrappers are needed because callers pass already-encoded strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRecordV1 {
    /// Lowercase 64-hex SHA-256 agent id derived from the ML-DSA-65
    /// pubkey via [`crate::derive_agent_id`].
    pub agent_id_hex: String,
    /// ML-DSA-65 public key, STANDARD base64-encoded.
    pub ml_dsa_pubkey_b64: String,
    /// ML-KEM-768 public key, STANDARD base64-encoded.
    pub kem_pubkey_b64: String,
    /// Preferred relay URLs in priority order (1..=4 entries, each
    /// a valid http/https URL of at most 256 bytes).
    pub advertised_relays: Vec<String>,
    /// Millisecond timestamp at record issuance. The issuer must
    /// maintain a monotonically increasing watermark per agent; this
    /// module does not enforce that -- see [`verify_pair_record`].
    pub issued_at_ms: u64,
    /// ML-DSA-65 signature over [`pair_signing_input`], STANDARD
    /// base64-encoded.
    pub sig_b64: String,
}

/// A signed forwarding record redirecting an agent's relay set.
///
/// Forwarding records carry no key material; the verifier supplies the
/// agent's known ML-DSA-65 pubkey (from the stored [`PairRecordV1`] or
/// an out-of-band key exchange). Verify with
/// [`verify_forwarding_record`].
///
/// # Wire representation
///
/// Same rules as [`PairRecordV1`]: plain serde, no serde-with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingRecordV1 {
    /// Lowercase 64-hex agent id.
    pub agent_id_hex: String,
    /// New relay URLs in priority order (1..=4 entries, same URL
    /// constraints as [`PairRecordV1::advertised_relays`]).
    pub moved_to_relays: Vec<String>,
    /// Millisecond timestamp at record issuance. Monotonicity is the
    /// caller's responsibility; this module does not enforce it.
    pub issued_at_ms: u64,
    /// ML-DSA-65 signature over [`forwarding_signing_input`], STANDARD
    /// base64-encoded.
    pub sig_b64: String,
}

/// Errors from pairing-record construction or verification.
#[derive(Debug, Error)]
pub enum PairRecordError {
    /// `relays` was empty (minimum is 1).
    #[error("relay list must contain at least one entry")]
    EmptyRelays,
    /// `relays` contains more than 4 entries.
    #[error("relay list has {n} entries; maximum is 4")]
    TooManyRelays {
        /// Actual relay count.
        n: usize,
    },
    /// A relay URL exceeds 256 bytes.
    #[error("relay URL is {len} bytes; maximum is 256")]
    RelayUrlTooLong {
        /// Offending URL byte length.
        len: usize,
    },
    /// A relay URL is not a valid http/https URL with a non-empty host.
    #[error("relay URL is not a valid http/https URL with a host")]
    RelayUrlInvalid,
    /// `agent_id_hex` is not lowercase 64-hex.
    #[error("agent_id_hex must be lowercase 64-hex")]
    InvalidAgentIdHex,
    /// A base64 field could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(String),
    /// An ML-DSA-65 public key was rejected by the backend.
    #[error("ML-DSA pubkey parse error: {0}")]
    PubkeyParse(String),
    /// An ML-DSA-65 signature was structurally invalid.
    #[error("ML-DSA signature parse error: {0}")]
    SignatureParse(String),
    /// The ML-DSA backend returned an error during verification.
    #[error("ML-DSA verify backend error: {0}")]
    VerifyBackend(String),
    /// The signature does not verify over the canonical signing input.
    #[error("signature does not verify")]
    SignatureInvalid,
    /// A field's byte length exceeds `u32::MAX`.
    #[error("field is {len} bytes; exceeds u32::MAX")]
    FieldTooLong {
        /// Offending field byte length.
        len: usize,
    },
}

/// Build the canonical signing input for a [`PairRecordV1`].
///
/// Layout (length-prefixed, `lp(x)` = `u32_be(len)` || bytes):
/// ```text
/// PAIR_RECORD_DOMAIN
/// || lp(agent_id_hex)
/// || lp(ml_dsa_pubkey raw bytes)
/// || lp(kem_pubkey raw bytes)
/// || u32_be(n_relays)
/// || lp(relay_str)*
/// || u64_be(issued_at_ms)
/// ```
///
/// `ml_dsa_pubkey` and `kem_pubkey` are the **raw bytes** (the caller
/// passes pre-decoded slices here; base64 decoding happens in
/// [`verify_pair_record`]).
///
/// All validation rules (hex format, relay count, URL validity) are
/// enforced here so unsigned garbage can never reach a signer.
///
/// # Errors
///
/// [`PairRecordError`] if any field fails validation.
pub fn pair_signing_input(
    agent_id_hex: &str,
    ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    relays: &[String],
    issued_at_ms: u64,
) -> Result<Vec<u8>, PairRecordError> {
    validate_agent_id_hex(agent_id_hex)?;
    validate_relays(relays)?;

    let mut out = Vec::new();
    out.extend_from_slice(PAIR_RECORD_DOMAIN);
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    push_lp(&mut out, ml_dsa_pubkey)?;
    push_lp(&mut out, kem_pubkey)?;
    let n = u32::try_from(relays.len())
        .map_err(|_| PairRecordError::TooManyRelays { n: relays.len() })?;
    out.extend_from_slice(&n.to_be_bytes());
    for relay in relays {
        push_lp(&mut out, relay.as_bytes())?;
    }
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    Ok(out)
}

/// Build the canonical signing input for a [`ForwardingRecordV1`].
///
/// Layout:
/// ```text
/// FORWARDING_DOMAIN
/// || lp(agent_id_hex)
/// || u32_be(n_relays)
/// || lp(relay_str)*
/// || u64_be(issued_at_ms)
/// ```
///
/// All validation rules are enforced here; see [`pair_signing_input`]
/// for the rationale.
///
/// # Errors
///
/// [`PairRecordError`] if any field fails validation.
pub fn forwarding_signing_input(
    agent_id_hex: &str,
    relays: &[String],
    issued_at_ms: u64,
) -> Result<Vec<u8>, PairRecordError> {
    validate_agent_id_hex(agent_id_hex)?;
    validate_relays(relays)?;

    let mut out = Vec::new();
    out.extend_from_slice(FORWARDING_DOMAIN);
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    let n = u32::try_from(relays.len())
        .map_err(|_| PairRecordError::TooManyRelays { n: relays.len() })?;
    out.extend_from_slice(&n.to_be_bytes());
    for relay in relays {
        push_lp(&mut out, relay.as_bytes())?;
    }
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    Ok(out)
}

/// Verify a [`PairRecordV1`] by decoding its fields, deriving the
/// agent id from the ML-DSA-65 pubkey, reconstructing the canonical
/// signing input, and checking the ML-DSA-65 signature.
///
/// The agent id is derived from the pubkey (not trusted from the
/// `agent_id_hex` field) so a record claiming someone else's id cannot
/// pass verification.
///
/// **Watermark monotonicity** (`issued_at_ms` must be greater than the
/// previous record for this agent) is intentionally NOT checked here.
/// This function is stateless; callers that maintain per-agent watermarks
/// must enforce the anti-replay property themselves.
///
/// # Errors
///
/// [`PairRecordError`] if any decoding, derivation, or signature check
/// fails.
pub fn verify_pair_record(record: &PairRecordV1) -> Result<(), PairRecordError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    let ml_dsa_pubkey = STANDARD
        .decode(&record.ml_dsa_pubkey_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;
    let kem_pubkey = STANDARD
        .decode(&record.kem_pubkey_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;
    let sig_bytes = STANDARD
        .decode(&record.sig_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;

    let derived_hex = hex::encode(crate::derive_agent_id(&ml_dsa_pubkey));
    if derived_hex != record.agent_id_hex {
        return Err(PairRecordError::SignatureInvalid);
    }

    let input = pair_signing_input(
        &record.agent_id_hex,
        &ml_dsa_pubkey,
        &kem_pubkey,
        &record.advertised_relays,
        record.issued_at_ms,
    )?;

    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &ml_dsa_pubkey)
        .map_err(|e| PairRecordError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| PairRecordError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| PairRecordError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(PairRecordError::SignatureInvalid);
    }
    Ok(())
}

/// Verify a [`ForwardingRecordV1`] using a caller-supplied ML-DSA-65
/// pubkey.
///
/// Forwarding records carry no key material; the caller must supply the
/// agent's known pubkey (from a previously verified [`PairRecordV1`] or
/// an equivalent source). The agent id is derived from that pubkey and
/// compared to `record.agent_id_hex`; then the canonical signing input
/// is reconstructed and the signature checked.
///
/// **Watermark monotonicity** is NOT enforced here; same rationale as
/// [`verify_pair_record`].
///
/// # Errors
///
/// [`PairRecordError`] if decoding, derivation, or signature check
/// fails.
pub fn verify_forwarding_record(
    record: &ForwardingRecordV1,
    expected_pubkey: &[u8],
) -> Result<(), PairRecordError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    let sig_bytes = STANDARD
        .decode(&record.sig_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;

    let derived_hex = hex::encode(crate::derive_agent_id(expected_pubkey));
    if derived_hex != record.agent_id_hex {
        return Err(PairRecordError::SignatureInvalid);
    }

    let input = forwarding_signing_input(
        &record.agent_id_hex,
        &record.moved_to_relays,
        record.issued_at_ms,
    )?;

    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, expected_pubkey)
        .map_err(|e| PairRecordError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| PairRecordError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| PairRecordError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(PairRecordError::SignatureInvalid);
    }
    Ok(())
}

fn validate_agent_id_hex(s: &str) -> Result<(), PairRecordError> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(PairRecordError::InvalidAgentIdHex)
    }
}

fn validate_relays(relays: &[String]) -> Result<(), PairRecordError> {
    if relays.is_empty() {
        return Err(PairRecordError::EmptyRelays);
    }
    if relays.len() > MAX_RELAYS {
        return Err(PairRecordError::TooManyRelays { n: relays.len() });
    }
    for relay in relays {
        if relay.len() > MAX_URL_BYTES {
            return Err(PairRecordError::RelayUrlTooLong { len: relay.len() });
        }
        let parsed = relay
            .parse::<url::Url>()
            .map_err(|_| PairRecordError::RelayUrlInvalid)?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(PairRecordError::RelayUrlInvalid);
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(PairRecordError::RelayUrlInvalid);
        }
    }
    Ok(())
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PairRecordError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| PairRecordError::FieldTooLong { len: bytes.len() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const RELAY_A: &str = "https://relay-a.fetchit.io";
    const RELAY_B: &str = "https://relay-b.fetchit.io";

    fn fake_agent_hex() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    fn relays_one() -> Vec<String> {
        vec![RELAY_A.to_string()]
    }

    fn relays_two() -> Vec<String> {
        vec![RELAY_A.to_string(), RELAY_B.to_string()]
    }

    // -- canonical layout tests -------------------------------------------

    #[test]
    fn pair_signing_input_layout_is_canonical() {
        let agent_hex = fake_agent_hex();
        let ml_dsa_pk = [0xAA_u8, 0xBB, 0xCC];
        let kem_pk = [0x11_u8, 0x22];
        let relays = relays_one();
        let ts: u64 = 1_000_000;

        let got = pair_signing_input(&agent_hex, &ml_dsa_pk, &kem_pk, &relays, ts).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(PAIR_RECORD_DOMAIN);
        // lp(agent_id_hex)
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(agent_hex.as_bytes());
        // lp(ml_dsa_pubkey raw)
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&ml_dsa_pk);
        // lp(kem_pubkey raw)
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&kem_pk);
        // u32_be(n_relays)
        expected.extend_from_slice(&1u32.to_be_bytes());
        // lp(relay) — RELAY_A is 26 bytes, known at compile time
        expected.extend_from_slice(&26u32.to_be_bytes());
        expected.extend_from_slice(RELAY_A.as_bytes());
        // u64_be(issued_at_ms)
        expected.extend_from_slice(&ts.to_be_bytes());

        assert_eq!(got, expected);
    }

    #[test]
    fn forwarding_signing_input_layout_is_canonical() {
        let agent_hex = fake_agent_hex();
        let relays = relays_two();
        let ts: u64 = 2_000_000;

        let got = forwarding_signing_input(&agent_hex, &relays, ts).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(FORWARDING_DOMAIN);
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(agent_hex.as_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        // Both relays are 26 bytes each, known at compile time
        for relay in &relays {
            expected.extend_from_slice(&26u32.to_be_bytes());
            expected.extend_from_slice(relay.as_bytes());
        }
        expected.extend_from_slice(&ts.to_be_bytes());

        assert_eq!(got, expected);
    }

    // -- real-keypair round-trip tests ------------------------------------

    #[test]
    fn pair_record_sign_and_verify_round_trip() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let kem_pk = vec![0x55_u8; 32];
        let relays = relays_two();
        let ts: u64 = 42;

        let input = pair_signing_input(&agent_hex, &pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            agent_id_hex: agent_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        verify_pair_record(&record).unwrap();
    }

    #[test]
    fn forwarding_record_sign_and_verify_round_trip() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let relays = relays_one();
        let ts: u64 = 99;

        let input = forwarding_signing_input(&agent_hex, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = ForwardingRecordV1 {
            agent_id_hex: agent_hex,
            moved_to_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        verify_forwarding_record(&record, &pk_bytes).unwrap();
    }

    // -- rejection tests --------------------------------------------------

    #[test]
    fn pair_verify_rejects_wrong_key_signature() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let (other_pk, _) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let other_pk_bytes = other_pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&other_pk_bytes));
        let kem_pk = vec![0x00_u8; 8];
        let relays = relays_one();
        let ts = 1u64;

        // sign with sk (key A), but embed other_pk (key B) and its derived id
        let input = pair_signing_input(&agent_hex, &other_pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            agent_id_hex: agent_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&other_pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays.clone(),
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        // verify derives id from other_pk, id matches, but sig was made with sk not other_sk
        let err = verify_pair_record(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::SignatureInvalid),
            "got {err:?}"
        );

        // Also verify the original pk case: sign input built for pk but claim other_pk
        let agent_hex_a = hex::encode(crate::derive_agent_id(&pk_bytes));
        let input_a = pair_signing_input(&agent_hex_a, &pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_a = dsa.sign(&sk, &input_a).unwrap().to_bytes();
        // put wrong pubkey in record (other_pk) but same sig -- id mismatch path
        let record2 = PairRecordV1 {
            agent_id_hex: agent_hex_a.clone(),
            ml_dsa_pubkey_b64: STANDARD.encode(&other_pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays.clone(),
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_a),
        };
        let err2 = verify_pair_record(&record2).unwrap_err();
        assert!(
            matches!(err2, PairRecordError::SignatureInvalid),
            "got {err2:?}"
        );
    }

    #[test]
    fn pair_verify_rejects_derived_id_mismatch() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, signing_sk) = dsa.generate_keypair().unwrap();
        let (target_pk, _) = dsa.generate_keypair().unwrap();
        let pk_raw = pk.to_bytes();
        let target_raw = target_pk.to_bytes();
        // Use target's agent id but sign under pk's key
        let target_hex = hex::encode(crate::derive_agent_id(&target_raw));
        let kem_pk = vec![0x00_u8; 8];
        let relays = relays_one();
        let ts = 1u64;

        let input = pair_signing_input(&target_hex, &pk_raw, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&signing_sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            agent_id_hex: target_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&pk_raw),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        let err = verify_pair_record(&record).unwrap_err();
        // derived id from pk_raw != claimed target_hex
        assert!(
            matches!(err, PairRecordError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn signing_input_rejects_empty_relays() {
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &[], 0).unwrap_err();
        assert!(matches!(err, PairRecordError::EmptyRelays));

        let err2 = forwarding_signing_input(&fake_agent_hex(), &[], 0).unwrap_err();
        assert!(matches!(err2, PairRecordError::EmptyRelays));
    }

    #[test]
    fn signing_input_rejects_five_relays() {
        let five: Vec<String> = (0..5)
            .map(|i| format!("https://r{i}.example.com"))
            .collect();
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &five, 0).unwrap_err();
        assert!(matches!(err, PairRecordError::TooManyRelays { n: 5 }));

        let err2 = forwarding_signing_input(&fake_agent_hex(), &five, 0).unwrap_err();
        assert!(matches!(err2, PairRecordError::TooManyRelays { n: 5 }));
    }

    #[test]
    fn signing_input_rejects_257_byte_relay_url() {
        // https:// (8) + 246 a's + .io (3) = 257 bytes total
        let url_257 = format!("https://{}.io", "a".repeat(246));
        assert_eq!(url_257.len(), 257);
        let relays = vec![url_257.clone()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(
            matches!(err, PairRecordError::RelayUrlTooLong { len: 257 }),
            "got {err:?}"
        );

        let err2 = forwarding_signing_input(&fake_agent_hex(), &relays, 0).unwrap_err();
        assert!(
            matches!(err2, PairRecordError::RelayUrlTooLong { len: 257 }),
            "got {err2:?}"
        );
    }

    #[test]
    fn signing_input_rejects_file_scheme() {
        let relays = vec!["file:///etc/passwd".to_string()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(matches!(err, PairRecordError::RelayUrlInvalid));
    }

    #[test]
    fn signing_input_rejects_missing_host() {
        // url crate rejects https with an empty host as a parse error
        let relays = vec!["https://".to_string()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(matches!(err, PairRecordError::RelayUrlInvalid));
    }

    #[test]
    fn signing_input_rejects_uppercase_agent_hex() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(upper.len(), 64);
        let err = pair_signing_input(upper, &[], &[], &relays_one(), 0).unwrap_err();
        assert!(matches!(err, PairRecordError::InvalidAgentIdHex));

        let err2 = forwarding_signing_input(upper, &relays_one(), 0).unwrap_err();
        assert!(matches!(err2, PairRecordError::InvalidAgentIdHex));
    }

    #[test]
    fn pair_record_serde_json_round_trip() {
        let record = PairRecordV1 {
            agent_id_hex: fake_agent_hex(),
            ml_dsa_pubkey_b64: STANDARD.encode([0xAA_u8; 8]),
            kem_pubkey_b64: STANDARD.encode([0xBB_u8; 8]),
            advertised_relays: relays_one(),
            issued_at_ms: 12345,
            sig_b64: STANDARD.encode([0xCC_u8; 8]),
        };
        let json = serde_json::to_string(&record).unwrap();
        let recovered: PairRecordV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(record, recovered);
    }

    #[test]
    fn forwarding_record_serde_json_round_trip() {
        let record = ForwardingRecordV1 {
            agent_id_hex: fake_agent_hex(),
            moved_to_relays: relays_two(),
            issued_at_ms: 99999,
            sig_b64: STANDARD.encode([0xDD_u8; 8]),
        };
        let json = serde_json::to_string(&record).unwrap();
        let recovered: ForwardingRecordV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(record, recovered);
    }

    #[test]
    fn forwarding_verify_rejects_wrong_expected_pubkey() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let (other_pk, _) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let other_pk_bytes = other_pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let relays = relays_one();
        let ts = 7u64;

        let input = forwarding_signing_input(&agent_hex, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = ForwardingRecordV1 {
            agent_id_hex: agent_hex,
            moved_to_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        // supply wrong pubkey -- derived id won't match
        let err = verify_forwarding_record(&record, &other_pk_bytes).unwrap_err();
        assert!(
            matches!(err, PairRecordError::SignatureInvalid),
            "got {err:?}"
        );
    }
}
