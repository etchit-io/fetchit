//! Per-request agent auth for the bridge's mutating social endpoints
//! (M7 P1) — `bridge-auth-v1`.
//!
//! The bridge holds no private keys, so every state-changing request
//! (record a follow, confirm an accepted follower, unfollow, drain
//! pending inbound follows) is signed ON THE DEVICE with the same
//! ML-DSA-65 agent key whose attestation the actor registered with.
//! The bridge verifies against the `ml_dsa_pubkey` inside the STORED
//! actor document's v2 attestation — the key was bound to the handle at
//! registration (`verify_attestation` + domain lock), so a valid
//! signature here proves "the registered owner of this handle".
//!
//! ## Wire shape
//!
//! Three headers on the request:
//!
//! ```text
//! X-Fetchit-Agent: <64-hex agent id>
//! X-Fetchit-Ts:    <unix milliseconds, decimal>
//! X-Fetchit-Sig:   <STANDARD base64 ML-DSA-65 signature>
//! ```
//!
//! The signature verifies over the x0x 0.29 external-agent-sign framing
//! (`fetchit_relay_proto::agent_sign_input`) of the canonical request
//! bytes:
//!
//! ```text
//! b"fetchit-bridge-auth-v1" || 0x00
//!   || method || 0x00 || path || 0x00
//!   || u64_be(ts_ms) || sha256(body)
//! ```
//!
//! `method` is uppercase; `path` is the exact request path (no query;
//! none of the authed endpoints use one). The body hash pins the
//! payload; the timestamp bounds replay to ±[`MAX_SKEW_MS`]. A
//! sliding-window nonce cache is deliberately deferred — within the
//! skew window a replayed request re-applies an idempotent state
//! transition (flagged for cross-review; see the spec).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaVariant};

use fetchit_fedi::bridge_auth::MAX_SKEW_MS;

/// Why a request failed authentication. Rendered as `401`/`403` by the
/// route layer; variants exist so tests and metrics can distinguish.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// A required header is missing or malformed.
    BadHeader(&'static str),
    /// `X-Fetchit-Ts` is outside the skew window.
    StaleTimestamp,
    /// The agent id in the header does not match the actor's registered
    /// attestation key.
    AgentMismatch,
    /// The signature failed cryptographic verification.
    BadSignature,
    /// The stored actor document is unusable (no v2 attestation / bad key).
    ActorUnusable(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadHeader(h) => write!(f, "missing or malformed header {h}"),
            Self::StaleTimestamp => write!(f, "timestamp outside skew window"),
            Self::AgentMismatch => write!(f, "agent id does not own this handle"),
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::ActorUnusable(e) => write!(f, "stored actor unusable: {e}"),
        }
    }
}

use fetchit_fedi::bridge_auth::canonical_request;

/// Parsed auth headers.
#[derive(Debug)]
pub struct AuthHeaders {
    /// Claimed 64-hex agent id.
    pub agent_id_hex: String,
    /// Client-asserted unix-ms timestamp.
    pub ts_ms: u64,
    /// Decoded ML-DSA-65 signature bytes.
    pub sig: Vec<u8>,
}

/// Extract + shape-check the three auth headers.
///
/// # Errors
/// [`AuthError::BadHeader`] naming the offending header.
pub fn parse_headers(headers: &axum::http::HeaderMap) -> Result<AuthHeaders, AuthError> {
    let get = |name: &'static str| -> Result<&str, AuthError> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::BadHeader(name))
    };
    let agent_id_hex = get("x-fetchit-agent")?.to_ascii_lowercase();
    if agent_id_hex.len() != 64 || !agent_id_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AuthError::BadHeader("x-fetchit-agent"));
    }
    let ts_ms: u64 = get("x-fetchit-ts")?
        .parse()
        .map_err(|_| AuthError::BadHeader("x-fetchit-ts"))?;
    let sig = B64
        .decode(get("x-fetchit-sig")?)
        .map_err(|_| AuthError::BadHeader("x-fetchit-sig"))?;
    Ok(AuthHeaders {
        agent_id_hex,
        ts_ms,
        sig,
    })
}

/// Verify a parsed request against the actor's registered attestation
/// key.
///
/// `expected_agent_id_hex` and `ml_dsa_pubkey` come from the STORED
/// actor record (registration already proved the binding); `now_ms` is
/// injected for testability.
///
/// # Errors
/// The [`AuthError`] variant describing the first failed check. Skew is
/// checked before crypto so clock-drifted clients get a clear error
/// without burning a verify.
pub fn verify_request(
    hdrs: &AuthHeaders,
    expected_agent_id_hex: &str,
    ml_dsa_pubkey: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    now_ms: u64,
) -> Result<(), AuthError> {
    if hdrs.agent_id_hex != expected_agent_id_hex.to_ascii_lowercase() {
        return Err(AuthError::AgentMismatch);
    }
    if now_ms.abs_diff(hdrs.ts_ms) > MAX_SKEW_MS {
        return Err(AuthError::StaleTimestamp);
    }
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, ml_dsa_pubkey)
        .map_err(|e| AuthError::ActorUnusable(format!("attestation pubkey: {e}")))?;
    let sig = saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &hdrs.sig)
        .map_err(|_| AuthError::BadSignature)?;
    // x0x 0.29 mandatory-context framing: clients sign through the
    // Signer trait, so the signature is over agent_sign_input(canonical).
    let framed =
        fetchit_relay_proto::agent_sign_input(&canonical_request(method, path, hdrs.ts_ms, body));
    match dsa.verify(&pk, &framed, &sig) {
        Ok(true) => Ok(()),
        _ => Err(AuthError::BadSignature),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use sha2::{Digest, Sha256};

    fn keypair() -> (
        saorsa_pqc::api::sig::MlDsaPublicKey,
        saorsa_pqc::api::sig::MlDsaSecretKey,
        Vec<u8>,
    ) {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        (pk, sk, pk_bytes)
    }

    fn sign(sk: &saorsa_pqc::api::sig::MlDsaSecretKey, canonical: &[u8]) -> Vec<u8> {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        dsa.sign(sk, &fetchit_relay_proto::agent_sign_input(canonical))
            .unwrap()
            .to_bytes()
            .clone()
    }

    fn hdrs(agent: &str, ts: u64, sig: &[u8]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-fetchit-agent", agent.parse().unwrap());
        h.insert("x-fetchit-ts", ts.to_string().parse().unwrap());
        h.insert("x-fetchit-sig", B64.encode(sig).parse().unwrap());
        h
    }

    const METHOD: &str = "POST";
    const PATH: &str = "/actors/josh/following";
    const BODY: &[u8] = br#"{"target":"@a@b.example"}"#;
    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn happy_path_verifies() {
        let (_pk, sk, pk_bytes) = keypair();
        let agent = hex::encode(Sha256::digest(&pk_bytes));
        let canonical = canonical_request(METHOD, PATH, NOW, BODY);
        let sig = sign(&sk, &canonical);
        let parsed = parse_headers(&hdrs(&agent, NOW, &sig)).unwrap();
        verify_request(&parsed, &agent, &pk_bytes, METHOD, PATH, BODY, NOW).unwrap();
    }

    #[test]
    fn tampered_body_method_path_or_ts_fails() {
        let (_pk, sk, pk_bytes) = keypair();
        let agent = hex::encode(Sha256::digest(&pk_bytes));
        let canonical = canonical_request(METHOD, PATH, NOW, BODY);
        let sig = sign(&sk, &canonical);
        let parsed = parse_headers(&hdrs(&agent, NOW, &sig)).unwrap();
        for (m, p, b) in [
            ("DELETE", PATH, BODY),
            (METHOD, "/actors/eve/following", BODY),
            (METHOD, PATH, b"{}".as_slice()),
        ] {
            assert_eq!(
                verify_request(&parsed, &agent, &pk_bytes, m, p, b, NOW),
                Err(AuthError::BadSignature),
                "must fail for ({m}, {p})"
            );
        }
        // shifted-but-in-window timestamp still fails crypto (ts is signed)
        let parsed2 = parse_headers(&hdrs(&agent, NOW + 1, &sig)).unwrap();
        assert_eq!(
            verify_request(&parsed2, &agent, &pk_bytes, METHOD, PATH, BODY, NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn stale_timestamp_rejected_before_crypto() {
        let (_pk, sk, pk_bytes) = keypair();
        let agent = hex::encode(Sha256::digest(&pk_bytes));
        let old = NOW - MAX_SKEW_MS - 1;
        let canonical = canonical_request(METHOD, PATH, old, BODY);
        let sig = sign(&sk, &canonical);
        let parsed = parse_headers(&hdrs(&agent, old, &sig)).unwrap();
        assert_eq!(
            verify_request(&parsed, &agent, &pk_bytes, METHOD, PATH, BODY, NOW),
            Err(AuthError::StaleTimestamp)
        );
    }

    #[test]
    fn wrong_agent_or_key_rejected() {
        let (_pk, sk, pk_bytes) = keypair();
        let (_pk2, _sk2, other_pk_bytes) = keypair();
        let agent = hex::encode(Sha256::digest(&pk_bytes));
        let other_agent = hex::encode(Sha256::digest(&other_pk_bytes));
        let canonical = canonical_request(METHOD, PATH, NOW, BODY);
        let sig = sign(&sk, &canonical);
        // header claims an agent that doesn't own the handle
        let parsed = parse_headers(&hdrs(&agent, NOW, &sig)).unwrap();
        assert_eq!(
            verify_request(&parsed, &other_agent, &pk_bytes, METHOD, PATH, BODY, NOW),
            Err(AuthError::AgentMismatch)
        );
        // right agent id, but the stored key is someone else's
        assert_eq!(
            verify_request(&parsed, &agent, &other_pk_bytes, METHOD, PATH, BODY, NOW),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn header_shape_errors_are_specific() {
        let mut h = HeaderMap::new();
        assert!(matches!(
            parse_headers(&h),
            Err(AuthError::BadHeader("x-fetchit-agent"))
        ));
        h.insert("x-fetchit-agent", "zz".parse().unwrap());
        assert!(matches!(
            parse_headers(&h),
            Err(AuthError::BadHeader("x-fetchit-agent"))
        ));
    }

    #[test]
    fn unwrapped_signature_rejected() {
        // A signature over the RAW canonical bytes (no 0.29 agent-sign
        // framing) must NOT verify — catches a client that forgot the
        // Signer-trait wrap.
        let (_pk, sk, pk_bytes) = keypair();
        let agent = hex::encode(Sha256::digest(&pk_bytes));
        let canonical = canonical_request(METHOD, PATH, NOW, BODY);
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let raw_sig = dsa.sign(&sk, &canonical).unwrap().to_bytes().clone();
        let parsed = parse_headers(&hdrs(&agent, NOW, &raw_sig)).unwrap();
        assert_eq!(
            verify_request(&parsed, &agent, &pk_bytes, METHOD, PATH, BODY, NOW),
            Err(AuthError::BadSignature)
        );
    }
}
