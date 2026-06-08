//! Extended share-card v2 — additive fields on top of x0xd's
//! `AgentCard` JSON. The user-facing URI stays `x0x://agent/<base64>`;
//! we add four signed fields that fetchit-chat reads and x0xd
//! preserves as unknown JSON.

use crate::chat_crypto::{ml_dsa_verify, SIGN_DOMAIN_CARD};
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Current schema version of the v2 card extension.
pub const CARD_VERSION: u16 = 1;
/// User-facing scheme prefix for the share URI.
pub const URI_PREFIX: &str = "x0x://agent/";

/// Schema-freeze contract (M0 honesty floor): the v1 fields below
/// are wire-stable forever. Bumping `CARD_VERSION` is forbidden
/// without a coordinated migration across etchit-desktop +
/// etchit-android (per `PINS.md`). New fields go through the
/// reserved [`CardExtension::v2_rendezvous_hints`] slot, which is
/// designed to be ignorable by v1 readers and populated by M2+
/// writers without changing `version`. Schema churn destroys the
/// social graph permanently — every paste-imported contact carries
/// the schema version it was signed under.
///
/// The fetchit-namespaced fields tucked into an x0x share-card's JSON.
/// All four required fields together form the v2 extension; the
/// reserved hints field is forward-compat only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardExtension {
    /// Card v2 schema version. Currently 1.
    #[serde(rename = "fetchit_card_version")]
    pub version: u16,
    /// ML-KEM-768 public key (base64).
    #[serde(rename = "fetchit_kem_public_key_b64")]
    pub kem_public_key_b64: String,
    /// Issuer's ML-DSA-65 public key (base64). Lets receivers verify
    /// the card signature without an out-of-band key lookup.
    #[serde(rename = "fetchit_agent_public_key_b64")]
    pub agent_public_key_b64: String,
    /// ML-DSA-65 signature over canonical card bytes excluding this signature.
    #[serde(rename = "fetchit_card_signature_b64")]
    pub signature_b64: String,
    /// Reserved v2-rendezvous-hints slot (M2 Direct mode populates).
    /// v1 readers ignore this; v2 writers may populate without
    /// bumping `version`. Forward-compatible by construction.
    /// `None` and an empty `RendezvousHints` are wire-distinct —
    /// `serde(default, skip_serializing_if = "Option::is_none")`
    /// means a card minted without the field round-trips identically.
    #[serde(
        rename = "fetchit_rendezvous_hints",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub v2_rendezvous_hints: Option<RendezvousHints>,
}

/// Forward-compat rendezvous hints reserved for M2 Direct mode.
/// In M1 this slot is always `None`; M2 writers may populate it with
/// ant-quic NAT-traversal hints (last-seen IP:port, STUN data, etc.).
/// The on-wire shape is intentionally minimal: a version byte plus an
/// opaque JSON payload so the schema can grow without a re-issued
/// card.
///
/// v1 readers MUST ignore unknown hint payloads. Adding required
/// fields to this struct in the future is permitted only if
/// `RendezvousHints.v` bumps to 2 AND the old `RendezvousHints { v: 1, .. }`
/// shape remains deserializable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousHints {
    /// Hint-schema version. Currently always 1 when populated;
    /// future M2 hint shapes bump this without touching
    /// `CARD_VERSION`.
    pub v: u8,
    /// Opaque hint payload. Specific keys are defined alongside the
    /// M2 Direct mode work; v1 readers leave this untouched.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
}

const MAX_HINT_RELAYS: usize = 8;
const MAX_HINT_URL_LEN: usize = 256;

/// V1 payload for the [`RendezvousHints::data`] slot.
///
/// Ordered list of `wss://` relay URLs the card issuer can be reached
/// on. First entry is the issuer's primary; subsequent entries are
/// fallbacks the issuer advertises in advanced mode.
///
/// Decoder validation:
/// - `relays` non-empty.
/// - Each entry parses as a `wss://` URL.
/// - Each entry <= 256 chars (`DoS` guard).
/// - `relays.len()` <= 8 (`DoS` guard).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousHintsV1 {
    /// Ordered list of `wss://` URLs.
    pub relays: Vec<String>,
}

impl RendezvousHintsV1 {
    /// Parse a [`RendezvousHints::data`] JSON value into
    /// `RendezvousHintsV1`, applying all decoder validations.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] on decode failure or validator rejection.
    pub fn from_value(v: &serde_json::Value) -> Result<Self, ChatError> {
        let parsed: Self = serde_json::from_value(v.clone())
            .map_err(|e| ChatError::Invalid(format!("hints decode: {e}")))?;
        if parsed.relays.is_empty() {
            return Err(ChatError::Invalid("hints.relays empty".into()));
        }
        if parsed.relays.len() > MAX_HINT_RELAYS {
            return Err(ChatError::Invalid(format!(
                "hints.relays >{MAX_HINT_RELAYS}"
            )));
        }
        for url in &parsed.relays {
            if url.len() > MAX_HINT_URL_LEN {
                return Err(ChatError::Invalid("hints url too long".into()));
            }
            if !url.starts_with("wss://") {
                return Err(ChatError::Invalid(format!(
                    "hints url scheme not wss: {url}"
                )));
            }
        }
        Ok(parsed)
    }

    /// Re-encode `RendezvousHintsV1` as a `serde_json::Value` suitable
    /// for the outer [`RendezvousHints::data`] slot.
    #[must_use]
    #[allow(clippy::expect_used)] // RendezvousHintsV1 has no non-string-keyed map; serde_json::to_value is provably infallible
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("RendezvousHintsV1 serializes")
    }
}

/// Bytes signed for `CardExtension.signature_b64`:
/// `concat(SIGN_DOMAIN_CARD, postcard({ x0x_card_json, fetchit_card_version,
/// kem_public_key_b64, agent_public_key_b64 }))`. We use postcard on a tuple
/// of these values so signer and verifier compute byte-identical strings.
///
/// The `agent_public_key_b64` field (v2-additive) carries the issuer's
/// ML-DSA-65 public key so receivers can self-verify the card signature
/// without an out-of-band key lookup. It is part of the signed body so
/// the receiver can be sure the pubkey it imports is the same one that
/// signed the card.
#[derive(Serialize, Deserialize)]
struct SignedCardBody<'a> {
    /// The x0x card JSON as it appears on the wire BEFORE the extension
    /// fields are added. Serializing the whole card and then extracting
    /// would also work, but signing-known-good-bytes is safer.
    x0x_card_canonical_json: &'a [u8],
    version: u16,
    kem_public_key_b64: &'a str,
    agent_public_key_b64: &'a str,
}

/// Add the fetchit-chat v2 fields to an existing x0x share-card JSON.
/// The card JSON is taken in its post-x0xd-generation shape (i.e. the
/// `card` field of `GET /agent/card`'s response).
///
/// `hints` is the optional [`RendezvousHintsV1`] payload to populate
/// the forward-compat [`CardExtension::v2_rendezvous_hints`] slot.
/// `Some(_)` writes `{"v": 1, "data": <hints>}` under
/// `fetchit_rendezvous_hints`; `None` omits the field entirely so the
/// wire shape matches a v1 card byte-for-byte. Hints are NOT covered
/// by the card signature — they are additive runtime metadata, not a
/// signed identity claim.
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
    hints: Option<RendezvousHintsV1>,
) -> Result<serde_json::Value, ChatError> {
    let x0x_obj = x0x_card
        .as_object()
        .ok_or_else(|| ChatError::Invalid("x0x card must be a JSON object".into()))?;
    let canonical_x0x_bytes = canonical_json(x0x_card)?;
    let kem_b64 = B64.encode(kem_public_key);
    let agent_pk_b64 = B64.encode(signer.public_key());

    let to_sign = SignedCardBody {
        x0x_card_canonical_json: &canonical_x0x_bytes,
        version: CARD_VERSION,
        kem_public_key_b64: &kem_b64,
        agent_public_key_b64: &agent_pk_b64,
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

    let mut out = serde_json::Map::with_capacity(x0x_obj.len() + 5);
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
        "fetchit_agent_public_key_b64".into(),
        serde_json::Value::String(agent_pk_b64),
    );
    out.insert(
        "fetchit_card_signature_b64".into(),
        serde_json::Value::String(B64.encode(sig)),
    );
    if let Some(h) = hints {
        let wrapped = RendezvousHints {
            v: 1,
            data: h.to_value(),
        };
        out.insert(
            "fetchit_rendezvous_hints".into(),
            serde_json::to_value(&wrapped)
                .map_err(|e| ChatError::Invalid(format!("hints to_value: {e}")))?,
        );
    }
    Ok(serde_json::Value::Object(out))
}

/// First byte of the URI body identifying the encoding of the rest.
/// `0x02` = DEFLATE-compressed JSON (current). A leading `b'{'` (0x7B)
/// or `b'['` is treated as legacy uncompressed JSON for backwards
/// compatibility — there are no shipped consumers of either form yet,
/// but the read path stays permissive so an existing test fixture or
/// pasted URI keeps importing.
const FORMAT_TAG_DEFLATE: u8 = 0x02;

/// Hard ceiling on the inflated JSON. A real card is ~12 KB today and
/// the architectural floor is in the same ballpark; 256 KB is well
/// above any plausible card and well below "OOM the renderer".
/// Decompression that hits this limit is rejected rather than
/// truncated — a truncated JSON would deserialize partially and the
/// caller would see a confusing parse error instead of the real
/// problem.
const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024;

/// Hard ceiling on the URI body after base64 decode, applied BEFORE
/// any decompressor runs. Stops a malicious URI from forcing a large
/// allocation or eating CPU just to be rejected later.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Encode an extended-card JSON value as the `x0x://agent/<base64>`
/// URI. The body is `0x02 | DEFLATE(JSON)`, URL-safe base64-encoded —
/// the v2 card carries ~4 KB of redundant ASCII (x0xd ships its KEM
/// pubkey as a JSON int array AND we re-publish it base64-encoded),
/// which DEFLATE compresses to a few hundred bytes.
///
/// # Errors
/// JSON serialization errors; DEFLATE failures (should not happen in
/// practice with an in-memory writer).
pub fn extended_card_to_uri(card_json: &serde_json::Value) -> Result<String, ChatError> {
    let json = serde_json::to_vec(card_json)
        .map_err(|e| ChatError::Invalid(format!("card to_vec: {e}")))?;
    let mut encoder = DeflateEncoder::new(Vec::with_capacity(json.len()), Compression::best());
    encoder
        .write_all(&json)
        .map_err(|e| ChatError::Invalid(format!("deflate write: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| ChatError::Invalid(format!("deflate finish: {e}")))?;
    let mut body = Vec::with_capacity(1 + compressed.len());
    body.push(FORMAT_TAG_DEFLATE);
    body.extend_from_slice(&compressed);
    Ok(format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(body)))
}

/// Decode an extended-card URI back into a JSON value. Accepts both
/// the DEFLATE-tagged form ([`FORMAT_TAG_DEFLATE`]) and a plain JSON
/// body so legacy fixtures keep parsing.
///
/// # Errors
/// Bad URI, base64 errors, DEFLATE errors, JSON errors.
pub fn extended_card_from_uri(uri: &str) -> Result<serde_json::Value, ChatError> {
    let body = uri
        .strip_prefix(URI_PREFIX)
        .ok_or_else(|| ChatError::Invalid("not an x0x://agent/ URI".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| ChatError::Invalid(format!("base64: {e}")))?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(ChatError::Invalid(format!(
            "share card body too large: {} > {MAX_BODY_BYTES}",
            bytes.len()
        )));
    }
    let json_bytes = match bytes.first() {
        Some(&FORMAT_TAG_DEFLATE) => {
            // Bound the inflate output. Without a cap, a small
            // DEFLATE-bombed body could inflate to gigabytes and OOM
            // the renderer. `Read::take` clips the underlying reader;
            // hitting the cap means the input was either malicious or
            // bigger than we ever expect to handle, so reject rather
            // than truncate.
            let capped =
                std::io::Read::take(DeflateDecoder::new(&bytes[1..]), MAX_DECOMPRESSED_BYTES + 1);
            let mut decoder = capped;
            let mut out = Vec::with_capacity(bytes.len() * 4);
            decoder
                .read_to_end(&mut out)
                .map_err(|e| ChatError::Invalid(format!("deflate read: {e}")))?;
            if u64::try_from(out.len()).unwrap_or(u64::MAX) > MAX_DECOMPRESSED_BYTES {
                return Err(ChatError::Invalid(format!(
                    "share card decompresses past {MAX_DECOMPRESSED_BYTES} bytes"
                )));
            }
            out
        }
        // Legacy: no leading tag, body is JSON directly.
        _ => bytes,
    };
    serde_json::from_slice(&json_bytes)
        .map_err(|e| ChatError::Invalid(format!("card from_slice: {e}")))
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
    let agent_pk_b64 = obj
        .get("fetchit_agent_public_key_b64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ChatError::Invalid("missing fetchit_agent_public_key_b64".into()))?;
    let sig_b64 = obj
        .get("fetchit_card_signature_b64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ChatError::Invalid("missing fetchit_card_signature_b64".into()))?;

    // Reconstruct the x0x-card-only JSON so we hash the same canonical
    // bytes the issuer signed. `extend_with_fetchit_fields` computes
    // `canonical_x0x_bytes` from the bare x0x card BEFORE adding any
    // `fetchit_*` field, including the reserved `fetchit_rendezvous_hints`
    // slot. Verify must strip ALL five `fetchit_*` slots to match;
    // omitting the hints field here breaks any card minted with
    // [`RendezvousHintsV1`] populated.
    let mut x0x_only = obj.clone();
    x0x_only.remove("fetchit_card_version");
    x0x_only.remove("fetchit_kem_public_key_b64");
    x0x_only.remove("fetchit_agent_public_key_b64");
    x0x_only.remove("fetchit_card_signature_b64");
    x0x_only.remove("fetchit_rendezvous_hints");
    let x0x_only_value = serde_json::Value::Object(x0x_only);
    let canonical_x0x_bytes = canonical_json(&x0x_only_value)?;

    let to_sign = SignedCardBody {
        x0x_card_canonical_json: &canonical_x0x_bytes,
        version: CARD_VERSION,
        kem_public_key_b64: kem_b64,
        agent_public_key_b64: agent_pk_b64,
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
        agent_public_key_b64: agent_pk_b64.to_owned(),
        signature_b64: sig_b64.to_owned(),
        // The verify path does NOT cover the reserved hints field —
        // hints are forward-compat opaque payload not part of the
        // signed body. v1 readers materialise hints as None; v2
        // writers will populate after re-signing.
        v2_rendezvous_hints: None,
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
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, None)
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
        let mut extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, None)
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
        let mut extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, None)
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
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, None)
            .await
            .unwrap();
        let uri = extended_card_to_uri(&extended).unwrap();
        assert!(uri.starts_with(URI_PREFIX));
        let recovered = extended_card_from_uri(&uri).unwrap();
        assert_eq!(recovered, extended);
    }

    #[tokio::test]
    async fn uri_is_shorter_than_uncompressed() {
        let signer = MlDsaSigner::generate().unwrap();
        // Use a card with a JSON int-array kem field — the shape x0xd
        // actually emits — so the compression win is realistic.
        let mut card = fake_x0x_card();
        card["dm_capabilities"] = serde_json::json!({
            "kem_algorithm": "ML-KEM-768",
            "kem_public_key": (0..1184_u32).map(|i| u8::try_from(i % 256).expect("modulo 256")).collect::<Vec<u8>>(),
        });
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&card, &kem_pub, &signer, None)
            .await
            .unwrap();
        let compressed_uri = extended_card_to_uri(&extended).unwrap();
        let raw_json_bytes = serde_json::to_vec(&extended).unwrap();
        let uncompressed_b64_len = URI_PREFIX.len() + URL_SAFE_NO_PAD.encode(&raw_json_bytes).len();
        assert!(
            compressed_uri.len() < uncompressed_b64_len,
            "compressed={} >= uncompressed={}",
            compressed_uri.len(),
            uncompressed_b64_len,
        );
        // Round-trips through the decoder.
        let recovered = extended_card_from_uri(&compressed_uri).unwrap();
        assert_eq!(recovered, extended);
    }

    #[tokio::test]
    async fn decompression_bomb_is_rejected() {
        // 1 MB of identical bytes compresses to a few hundred bytes
        // but blows past MAX_DECOMPRESSED_BYTES on inflate.
        let bomb = vec![b'a'; 1_000_000];
        let mut encoder = DeflateEncoder::new(Vec::<u8>::new(), Compression::best());
        encoder.write_all(&bomb).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(
            compressed.len() < bomb.len() / 100,
            "compressor not actually compressing"
        );
        let mut body = vec![FORMAT_TAG_DEFLATE];
        body.extend_from_slice(&compressed);
        let uri = format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(body));
        let err = extended_card_from_uri(&uri).expect_err("must reject");
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    #[tokio::test]
    async fn oversized_body_rejected_before_decode() {
        // A body well above MAX_BODY_BYTES should be rejected on the
        // base64 step, before the decoder is even invoked.
        let oversized = vec![0xff; MAX_BODY_BYTES + 1];
        let uri = format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(oversized));
        let err = extended_card_from_uri(&uri).expect_err("must reject");
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    #[tokio::test]
    async fn legacy_uncompressed_uri_still_decodes() {
        // A URI from before the DEFLATE format was introduced: plain
        // JSON, URL-safe base64, no leading format tag.
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, None)
            .await
            .unwrap();
        let raw = serde_json::to_vec(&extended).unwrap();
        let legacy_uri = format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
        let recovered = extended_card_from_uri(&legacy_uri).unwrap();
        assert_eq!(recovered, extended);
    }

    /// M0 schema-freeze contract: a v1 card minted without the
    /// reserved v2-rendezvous-hints slot serialises to the EXACT
    /// same JSON it always did — no `fetchit_rendezvous_hints` key
    /// appears on the wire. Forward-compat by absence.
    #[tokio::test]
    async fn schema_freeze_v1_card_omits_hints_field_on_wire() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, None)
            .await
            .unwrap();
        let json = serde_json::to_string(&extended).unwrap();
        // The wire output of a v1 card must not include the reserved
        // M2 field — a downstream consumer that's never heard of
        // hints must be able to decode the body byte-for-byte
        // identically to the pre-freeze shape.
        assert!(
            !json.contains("fetchit_rendezvous_hints"),
            "v1 card must omit hints field on wire, got: {json}"
        );
    }

    /// M0 schema-freeze contract: a v2 card with populated hints
    /// can be decoded by any reader that knows the v1 shape — the
    /// hints field is opaque to v1 and falls into the `extra` JSON.
    /// We exercise the strict `CardExtension` parser separately and
    /// confirm it round-trips when the field is present.
    #[tokio::test]
    async fn schema_freeze_v2_card_round_trips_through_strict_parser() {
        let kem_pub_b64 = B64.encode(vec![0xaa; 1184]);
        let agent_pk_b64 = B64.encode(vec![0xbb; 1952]);
        let sig_b64 = B64.encode(vec![0xcc; 3309]);
        let v2_with_hints = CardExtension {
            version: 1,
            kem_public_key_b64: kem_pub_b64.clone(),
            agent_public_key_b64: agent_pk_b64.clone(),
            signature_b64: sig_b64.clone(),
            v2_rendezvous_hints: Some(RendezvousHints {
                v: 1,
                data: serde_json::json!({ "future_quic_hint": "ignored-by-v1" }),
            }),
        };
        let wire = serde_json::to_string(&v2_with_hints).unwrap();
        // Round-trip through strict parser: hints survive.
        let parsed: CardExtension = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            parsed.v2_rendezvous_hints,
            v2_with_hints.v2_rendezvous_hints
        );
        // And the wire DOES carry the field when populated.
        assert!(
            wire.contains("fetchit_rendezvous_hints"),
            "populated hints must serialise to the wire"
        );
    }

    /// M0 schema-freeze contract: a v1-shape wire JSON (no hints
    /// field) parses into a `CardExtension` with `v2_rendezvous_hints
    /// == None`. Backward-compat in.
    #[test]
    fn schema_freeze_v1_wire_parses_into_default_none_hints() {
        let v1_wire = serde_json::json!({
            "fetchit_card_version": 1,
            "fetchit_kem_public_key_b64": B64.encode(vec![0xaa; 1184]),
            "fetchit_agent_public_key_b64": B64.encode(vec![0xbb; 1952]),
            "fetchit_card_signature_b64": B64.encode(vec![0xcc; 3309]),
        });
        let parsed: CardExtension = serde_json::from_value(v1_wire).unwrap();
        assert_eq!(parsed.v2_rendezvous_hints, None);
    }

    #[test]
    fn rendezvous_hints_v1_rejects_non_wss_scheme() {
        let json = serde_json::json!({ "relays": ["ws://example.com/v1/ws"] });
        let err = RendezvousHintsV1::from_value(&json).unwrap_err();
        assert!(format!("{err}").contains("wss"));
    }

    #[test]
    fn rendezvous_hints_v1_rejects_empty_list() {
        let json = serde_json::json!({ "relays": [] });
        assert!(RendezvousHintsV1::from_value(&json).is_err());
    }

    #[test]
    fn rendezvous_hints_v1_rejects_too_many() {
        let urls: Vec<_> = (0..9)
            .map(|i| format!("wss://r{i}.example/v1/ws"))
            .collect();
        let json = serde_json::json!({ "relays": urls });
        assert!(RendezvousHintsV1::from_value(&json).is_err());
    }

    #[test]
    fn rendezvous_hints_v1_accepts_simple_list() {
        let json = serde_json::json!({ "relays": ["wss://nyc.etchit.io/v1/ws"] });
        let parsed = RendezvousHintsV1::from_value(&json).unwrap();
        assert_eq!(parsed.relays, vec!["wss://nyc.etchit.io/v1/ws".to_string()]);
    }

    /// Task A3: `extend_with_fetchit_fields` accepts `Some(hints)` and
    /// threads them into the emitted card under the
    /// `fetchit_rendezvous_hints` key, wrapped as
    /// `RendezvousHints { v: 1, data: hints.to_value() }`. Round-trip
    /// the resulting JSON through the strict parser, then through
    /// `RendezvousHintsV1::from_value`, and recover the same list.
    #[tokio::test]
    async fn card_with_hints_round_trips() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let hints = RendezvousHintsV1 {
            relays: vec!["wss://nyc.etchit.io/v1/ws".into()],
        };
        let card =
            extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer, Some(hints.clone()))
                .await
                .unwrap();
        let parsed: CardExtension = serde_json::from_value(card).unwrap();
        let wrapped = parsed.v2_rendezvous_hints.expect("hints present");
        assert_eq!(wrapped.v, 1);
        let decoded = RendezvousHintsV1::from_value(&wrapped.data).unwrap();
        assert_eq!(decoded.relays, hints.relays);
    }

    #[test]
    fn rendezvous_hints_v1_rejects_oversized_url() {
        let long = "wss://".to_string() + &"a".repeat(300) + "/ws";
        let json = serde_json::json!({ "relays": [long] });
        assert!(RendezvousHintsV1::from_value(&json).is_err());
    }

    /// M0 schema-freeze contract: a v2-shape wire JSON with hints
    /// parses by code that knows the field; importantly, the hints
    /// field's payload is opaque-by-construction (free-form
    /// `serde_json::Value`), so future hint schema additions don't
    /// require this code to know about them.
    #[test]
    fn schema_freeze_opaque_hint_payload_round_trips() {
        let future_shape = serde_json::json!({
            "fetchit_card_version": 1,
            "fetchit_kem_public_key_b64": B64.encode(vec![0xaa; 1184]),
            "fetchit_agent_public_key_b64": B64.encode(vec![0xbb; 1952]),
            "fetchit_card_signature_b64": B64.encode(vec![0xcc; 3309]),
            "fetchit_rendezvous_hints": {
                "v": 1,
                "data": {
                    // Imagined M2 fields the v1 code has never heard of
                    "stun_observed_ipv4": "203.0.113.7:51820",
                    "last_seen_ms": 1_730_000_000_000_u64,
                    "supported_protocols": ["ant-quic-v0", "ant-quic-v1"]
                }
            }
        });
        let parsed: CardExtension = serde_json::from_value(future_shape).unwrap();
        let hints = parsed.v2_rendezvous_hints.expect("hints present");
        assert_eq!(hints.v, 1);
        // The opaque payload survived round-trip untouched.
        assert_eq!(
            hints.data["stun_observed_ipv4"],
            serde_json::Value::String("203.0.113.7:51820".into())
        );
    }
}
