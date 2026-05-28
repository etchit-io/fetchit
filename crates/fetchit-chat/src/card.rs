//! Extended share-card v2 — additive fields on top of x0xd's
//! `AgentCard` JSON. The user-facing URI stays `x0x://agent/<base64>`;
//! we add three signed fields that fetchit-chat reads and x0xd
//! preserves as unknown JSON.

use crate::chat_crypto::{ml_dsa_verify, SIGN_DOMAIN_CARD};
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use serde::{Deserialize, Serialize};

/// Current schema version of the v2 card extension.
pub const CARD_VERSION: u16 = 1;
/// User-facing scheme prefix for the share URI.
pub const URI_PREFIX: &str = "x0x://agent/";

/// The fetchit-namespaced fields tucked into an x0x share-card's JSON.
/// All three fields together form the v2 extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardExtension {
    /// Card v2 schema version. Currently 1.
    #[serde(rename = "fetchit_card_version")]
    pub version: u16,
    /// ML-KEM-768 public key (base64).
    #[serde(rename = "fetchit_kem_public_key_b64")]
    pub kem_public_key_b64: String,
    /// ML-DSA-65 signature over canonical card bytes excluding this signature.
    #[serde(rename = "fetchit_card_signature_b64")]
    pub signature_b64: String,
}

/// Bytes signed for `CardExtension.signature_b64`:
/// `concat(SIGN_DOMAIN_CARD, postcard({ x0x_card_json, fetchit_card_version, kem_public_key_b64 }))`.
/// We use postcard on a tuple of those three values so signer and
/// verifier compute byte-identical strings.
#[derive(Serialize, Deserialize)]
struct SignedCardBody<'a> {
    /// The x0x card JSON as it appears on the wire BEFORE the extension
    /// fields are added. Serializing the whole card and then extracting
    /// would also work, but signing-known-good-bytes is safer.
    x0x_card_canonical_json: &'a [u8],
    version: u16,
    kem_public_key_b64: &'a str,
}

/// Add the fetchit-chat v2 fields to an existing x0x share-card JSON.
/// The card JSON is taken in its post-x0xd-generation shape (i.e. the
/// `card` field of `GET /agent/card`'s response).
///
/// Returns the augmented JSON value (caller serializes + b64-encodes
/// to produce the final `x0x://agent/<…>` URI).
///
/// # Errors
/// `ChatError::Invalid` on JSON shape errors or signer failures.
pub async fn extend_with_fetchit_fields<S: Signer + ?Sized>(
    x0x_card: &serde_json::Value,
    kem_public_key: &[u8],
    signer: &S,
) -> Result<serde_json::Value, ChatError> {
    let x0x_obj = x0x_card
        .as_object()
        .ok_or_else(|| ChatError::Invalid("x0x card must be a JSON object".into()))?;
    let canonical_x0x_bytes = canonical_json(x0x_card)?;
    let kem_b64 = B64.encode(kem_public_key);

    let to_sign = SignedCardBody {
        x0x_card_canonical_json: &canonical_x0x_bytes,
        version: CARD_VERSION,
        kem_public_key_b64: &kem_b64,
    };
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_CARD.len() + 256);
    sign_bytes.extend_from_slice(SIGN_DOMAIN_CARD);
    sign_bytes.extend_from_slice(
        &postcard::to_allocvec(&to_sign)
            .map_err(|e| ChatError::Invalid(format!("postcard: {e}")))?,
    );
    let sig = signer
        .sign(&sign_bytes)
        .await
        .map_err(|e| ChatError::Invalid(format!("card sign: {e}")))?;

    let mut out = serde_json::Map::with_capacity(x0x_obj.len() + 3);
    for (k, v) in x0x_obj {
        out.insert(k.clone(), v.clone());
    }
    out.insert(
        "fetchit_card_version".into(),
        serde_json::Value::from(CARD_VERSION),
    );
    out.insert(
        "fetchit_kem_public_key_b64".into(),
        serde_json::Value::String(kem_b64),
    );
    out.insert(
        "fetchit_card_signature_b64".into(),
        serde_json::Value::String(B64.encode(sig)),
    );
    Ok(serde_json::Value::Object(out))
}

/// Encode an extended-card JSON value as the `x0x://agent/<base64>` URI.
///
/// # Errors
/// JSON serialization errors.
pub fn extended_card_to_uri(card_json: &serde_json::Value) -> Result<String, ChatError> {
    let bytes = serde_json::to_vec(card_json)
        .map_err(|e| ChatError::Invalid(format!("card to_vec: {e}")))?;
    Ok(format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Decode an extended-card URI back into a JSON value.
///
/// # Errors
/// Bad URI, base64 errors, JSON errors.
pub fn extended_card_from_uri(uri: &str) -> Result<serde_json::Value, ChatError> {
    let body = uri
        .strip_prefix(URI_PREFIX)
        .ok_or_else(|| ChatError::Invalid("not an x0x://agent/ URI".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| ChatError::Invalid(format!("base64: {e}")))?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|e| ChatError::Invalid(format!("card from_slice: {e}")))?;
    Ok(value)
}

/// Verify the fetchit-v2 fields on an extended card.
///
/// Returns the validated `CardExtension`. Caller is responsible for
/// also verifying the wider x0x card data (`agent_id` matches the
/// signing key, etc.).
///
/// # Errors
/// `ChatError::Invalid` if fields are missing / malformed / signature
/// verification fails.
pub fn verify_card_extension(
    card_json: &serde_json::Value,
    agent_public_key_bytes: &[u8],
) -> Result<CardExtension, ChatError> {
    let obj = card_json
        .as_object()
        .ok_or_else(|| ChatError::Invalid("card must be a JSON object".into()))?;
    let version = obj
        .get("fetchit_card_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ChatError::Invalid("missing fetchit_card_version".into()))?;
    if version != u64::from(CARD_VERSION) {
        return Err(ChatError::Invalid(format!(
            "unsupported card version: {version}"
        )));
    }
    let kem_b64 = obj
        .get("fetchit_kem_public_key_b64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ChatError::Invalid("missing fetchit_kem_public_key_b64".into()))?;
    let sig_b64 = obj
        .get("fetchit_card_signature_b64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ChatError::Invalid("missing fetchit_card_signature_b64".into()))?;

    // Reconstruct the x0x-card-only JSON (without the three v2 fields)
    // so we sign the same canonical bytes the issuer signed.
    let mut x0x_only = obj.clone();
    x0x_only.remove("fetchit_card_version");
    x0x_only.remove("fetchit_kem_public_key_b64");
    x0x_only.remove("fetchit_card_signature_b64");
    let x0x_only_value = serde_json::Value::Object(x0x_only);
    let canonical_x0x_bytes = canonical_json(&x0x_only_value)?;

    let to_sign = SignedCardBody {
        x0x_card_canonical_json: &canonical_x0x_bytes,
        version: CARD_VERSION,
        kem_public_key_b64: kem_b64,
    };
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_CARD.len() + 256);
    sign_bytes.extend_from_slice(SIGN_DOMAIN_CARD);
    sign_bytes.extend_from_slice(
        &postcard::to_allocvec(&to_sign)
            .map_err(|e| ChatError::Invalid(format!("postcard: {e}")))?,
    );
    let sig = B64
        .decode(sig_b64)
        .map_err(|e| ChatError::Invalid(format!("sig b64: {e}")))?;
    ml_dsa_verify(agent_public_key_bytes, &sign_bytes, &sig)?;

    Ok(CardExtension {
        // `version` (u64) was checked equal to `u64::from(CARD_VERSION)` above,
        // so we can assign the typed constant directly instead of a fallible cast.
        version: CARD_VERSION,
        kem_public_key_b64: kem_b64.to_owned(),
        signature_b64: sig_b64.to_owned(),
    })
}

/// Canonical JSON encoding: keys sorted recursively. Deterministic so
/// signer + verifier produce byte-identical inputs.
///
/// Known deviations from RFC 8785 (JCS): keys are sorted in bytewise UTF-8
/// order rather than UTF-16 code-unit order, which differs only for
/// supplementary-plane code points in object keys — safe for x0xd cards
/// (ASCII keys today), but a future contributor adding non-ASCII keys must
/// revisit this. The recursion also has no explicit depth guard; x0xd cards
/// have a fixed shallow shape, so this is not a live risk, but this encoder
/// is not safe for adversarial unconstrained JSON.
fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, ChatError> {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf)?;
    Ok(buf)
}

#[allow(clippy::expect_used)] // `.expect("key from same map")` is provably infallible
fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), ChatError> {
    use std::io::Write;
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
        }
        serde_json::Value::Number(n) => write!(out, "{n}")
            .map_err(|e| ChatError::Invalid(format!("write canonical num: {e}")))?,
        serde_json::Value::String(s) => {
            let encoded = serde_json::to_string(s)
                .map_err(|e| ChatError::Invalid(format!("canonical str: {e}")))?;
            out.extend_from_slice(encoded.as_bytes());
        }
        serde_json::Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(obj) => {
            out.push(b'{');
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let kj = serde_json::to_string(k)
                    .map_err(|e| ChatError::Invalid(format!("canonical key: {e}")))?;
                out.extend_from_slice(kj.as_bytes());
                out.push(b':');
                write_canonical(obj.get(*k).expect("key from same map"), out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_client::MlDsaSigner;

    fn fake_x0x_card() -> serde_json::Value {
        serde_json::json!({
            "agent_id": "0".repeat(64),
            "machine_id": "1".repeat(64),
            "user_id": null,
            "display_name": "Alice",
            "addresses": [],
            "dm_capabilities": { "kem_algorithm": "ML-KEM-768" }
        })
    }

    #[tokio::test]
    async fn extend_then_verify_round_trip() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
            .await
            .unwrap();
        let pk = signer.public_key();
        let ext = verify_card_extension(&extended, &pk).unwrap();
        assert_eq!(ext.version, 1);
        let decoded = B64.decode(&ext.kem_public_key_b64).unwrap();
        assert_eq!(decoded, kem_pub);
    }

    #[tokio::test]
    async fn tampered_kem_field_fails_verify() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let mut extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
            .await
            .unwrap();
        extended["fetchit_kem_public_key_b64"] =
            serde_json::Value::String(B64.encode(vec![0xbb; 1184]));
        let pk = signer.public_key();
        assert!(verify_card_extension(&extended, &pk).is_err());
    }

    #[tokio::test]
    async fn tampered_x0x_field_fails_verify() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let mut extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
            .await
            .unwrap();
        extended["display_name"] = serde_json::Value::String("Mallory".into());
        let pk = signer.public_key();
        assert!(verify_card_extension(&extended, &pk).is_err());
    }

    #[tokio::test]
    async fn uri_round_trip() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
            .await
            .unwrap();
        let uri = extended_card_to_uri(&extended).unwrap();
        assert!(uri.starts_with(URI_PREFIX));
        let recovered = extended_card_from_uri(&uri).unwrap();
        assert_eq!(recovered, extended);
    }
}
