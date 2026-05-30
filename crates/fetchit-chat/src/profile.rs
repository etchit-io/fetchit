//! Profile manifest v1 — load + verify a signed JSON manifest.
//!
//! See `docs/profile-manifest-v1.md` for the on-the-wire shape and the
//! signing pipeline. This module is the **consumer** half: parse the
//! JSON, re-canonicalise via JCS, and verify the ML-DSA-65 signature
//! against the embedded public key. The publisher side lives in
//! etch>it.
//!
//! No I/O, no network, no caching — pure functions over the JSON. The
//! desktop shell wraps these with a relay-fetch + on-disk cache; the
//! mobile shell does the same with its own cache. Both consume the
//! identical test fixture at `tests/fixtures/profile-manifest-v1/`
//! to confirm parity with etch>it byte-for-byte.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use fetchit_relay_proto::derive_agent_id;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain-separation prefix used as the first input to ML-DSA-65 when
/// signing a profile manifest. Mirrors etch>it's publisher exactly.
pub const SIGN_DOMAIN_PROFILE: &[u8] = b"fetchit/profile-manifest/v1";

/// Reasons a manifest can fail to parse / verify.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// JSON did not parse.
    #[error("manifest json: {0}")]
    Json(#[from] serde_json::Error),

    /// JCS canonicalisation rejected the value.
    #[error("jcs canonicalise: {0}")]
    Jcs(String),

    /// base64url / hex decode failed for one of the binary fields.
    #[error("decode: {0}")]
    Decode(String),

    /// `version` is not `1`.
    #[error("unsupported manifest version {0} (expected 1)")]
    UnsupportedVersion(u64),

    /// A bounded field exceeds its byte cap.
    #[error("{field} exceeds cap ({len} > {cap} bytes)")]
    TooLong {
        /// Which field overflowed.
        field: &'static str,
        /// How many bytes the field actually contained.
        len: usize,
        /// The published cap from the spec.
        cap: usize,
    },

    /// `agent_id` does not match `derive_agent_id(ml_dsa_pubkey_bytes)`.
    #[error("agent_id ({embedded}) does not match derive_agent_id(pubkey) ({derived})")]
    AgentIdMismatch {
        /// Hex of the `agent_id` encoded inside the manifest.
        embedded: String,
        /// Hex of the `agent_id` we re-derived from the embedded pubkey.
        derived: String,
    },

    /// ML-DSA-65 reported the signature as invalid.
    #[error("ml-dsa verify failed (manifest sig does not match canonical || pubkey)")]
    SigVerifyFailed,

    /// saorsa-pqc rejected the encoded public key or signature bytes.
    #[error("pqc: {0}")]
    Pqc(String),
}

/// One entry inside `links[]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLink {
    /// Discriminator: `website` | `image` | `etchit` | `fetchit` | `x0x`.
    pub kind: String,
    /// User-supplied label, ≤ 32 bytes.
    pub label: String,
    /// URL or 64-hex address depending on `kind`.
    pub addr: String,
}

/// Optional avatar metadata pointing at the WebP bytes on Autonomi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileAvatar {
    /// 64-hex Autonomi address of the WebP bytes.
    pub addr: String,
    /// MIME — only `image/webp` is accepted in v1.
    pub mime: String,
    /// Width in pixels, ≤ 256.
    pub w: u16,
    /// Height in pixels, ≤ 256.
    pub h: u16,
    /// Size of the WebP bytes at `addr`.
    pub bytes_len: u32,
}

/// Parsed v1 profile manifest. See `docs/profile-manifest-v1.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManifest {
    /// Format version, always `1`.
    pub version: u8,
    /// 64-hex `agent_id`, must equal `derive_agent_id(ml_dsa_pubkey_bytes)`.
    pub agent_id: String,
    /// UTF-8 display name, ≤ 64 bytes.
    pub display_name: String,
    /// Optional bio, ≤ 280 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// Optional homepage URL, ≤ 256 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Optional cross-app link set, ≤ 8 entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ProfileLink>,
    /// Optional avatar metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<ProfileAvatar>,
    /// base64url-no-pad of the raw 1952-byte ML-DSA-65 public key.
    pub ml_dsa_pubkey: String,
    /// base64url-no-pad of the raw 1184-byte ML-KEM-768 public key.
    pub kem_pubkey: String,
    /// Unix epoch milliseconds the manifest was issued. Monotonic per `agent_id`.
    pub issued_at_ms: u64,
    /// Optional UX freshness hint. Not a security boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// base64url-no-pad of the raw ML-DSA-65 signature over the canonical bytes.
    pub sig: String,
}

const CAP_DISPLAY_NAME: usize = 64;
const CAP_BIO: usize = 280;
const CAP_WEBSITE: usize = 256;
const CAP_LINK_LABEL: usize = 32;
const CAP_LINKS_LEN: usize = 8;

impl ProfileManifest {
    /// Parse a v1 manifest from JSON and enforce field caps.
    ///
    /// Does *not* verify the signature — call [`verify`](Self::verify)
    /// for that. Caps are enforced first so a maliciously oversized
    /// field can't blow up later canonicalisation work.
    pub fn parse(json: &str) -> Result<Self, ProfileError> {
        let m: Self = serde_json::from_str(json)?;
        if m.version != 1 {
            return Err(ProfileError::UnsupportedVersion(m.version.into()));
        }
        cap("display_name", m.display_name.len(), CAP_DISPLAY_NAME)?;
        if let Some(bio) = &m.bio {
            cap("bio", bio.len(), CAP_BIO)?;
        }
        if let Some(w) = &m.website {
            cap("website", w.len(), CAP_WEBSITE)?;
        }
        if m.links.len() > CAP_LINKS_LEN {
            return Err(ProfileError::TooLong {
                field: "links",
                len: m.links.len(),
                cap: CAP_LINKS_LEN,
            });
        }
        for link in &m.links {
            cap("link.label", link.label.len(), CAP_LINK_LABEL)?;
        }
        Ok(m)
    }

    /// Verify the manifest's signature against its embedded public key.
    ///
    /// Steps (matching `docs/profile-manifest-v1.md` § 3):
    ///
    /// 1. Re-canonicalise the manifest with `sig` stripped via JCS.
    /// 2. Concatenate `SIGN_DOMAIN_PROFILE` with the canonical bytes.
    /// 3. Re-derive `agent_id` from `ml_dsa_pubkey` and cross-check
    ///    against the embedded `agent_id`.
    /// 4. ML-DSA-65 verify against (pubkey, `sign_input`, sig).
    ///
    /// Returns the embedded ML-DSA-65 raw public-key bytes on success
    /// so callers don't have to decode them again.
    ///
    /// # Errors
    /// Returns the matching [`ProfileError`] variant for every step.
    pub fn verify(&self) -> Result<Vec<u8>, ProfileError> {
        let pubkey_bytes = B64URL
            .decode(&self.ml_dsa_pubkey)
            .map_err(|e| ProfileError::Decode(format!("ml_dsa_pubkey b64url: {e}")))?;
        let sig_bytes = B64URL
            .decode(&self.sig)
            .map_err(|e| ProfileError::Decode(format!("sig b64url: {e}")))?;

        let embedded_agent_id = hex::decode(&self.agent_id)
            .map_err(|e| ProfileError::Decode(format!("agent_id hex: {e}")))?;
        let mut embedded_arr = [0u8; 32];
        if embedded_agent_id.len() != 32 {
            return Err(ProfileError::Decode(format!(
                "agent_id: expected 32 bytes, got {}",
                embedded_agent_id.len()
            )));
        }
        embedded_arr.copy_from_slice(&embedded_agent_id);
        let derived = derive_agent_id(&pubkey_bytes);
        if derived != embedded_arr {
            return Err(ProfileError::AgentIdMismatch {
                embedded: hex::encode(embedded_arr),
                derived: hex::encode(derived),
            });
        }

        let canonical = canonical_bytes_without_sig(self)?;
        let mut input = Vec::with_capacity(SIGN_DOMAIN_PROFILE.len() + canonical.len());
        input.extend_from_slice(SIGN_DOMAIN_PROFILE);
        input.extend_from_slice(&canonical);

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pubkey_bytes)
            .map_err(|e| ProfileError::Pqc(e.to_string()))?;
        let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
            .map_err(|e| ProfileError::Pqc(e.to_string()))?;
        let ok = dsa
            .verify(&pk, &input, &sig)
            .map_err(|e| ProfileError::Pqc(e.to_string()))?;
        if !ok {
            return Err(ProfileError::SigVerifyFailed);
        }
        Ok(pubkey_bytes)
    }
}

fn cap(field: &'static str, len: usize, cap: usize) -> Result<(), ProfileError> {
    if len > cap {
        return Err(ProfileError::TooLong { field, len, cap });
    }
    Ok(())
}

/// JCS-canonicalise the manifest **with the `sig` field stripped**.
/// Round-trips via `serde_json::Value` so we don't impose a field
/// order on the strongly-typed struct.
fn canonical_bytes_without_sig(m: &ProfileManifest) -> Result<Vec<u8>, ProfileError> {
    let mut v = serde_json::to_value(m)?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sig");
    }
    serde_jcs::to_vec(&v).map_err(|e| ProfileError::Jcs(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/profile-manifest-v1")
            .canonicalize()
            .expect("fixture present (run profile-fixture-gen if missing)")
    }

    fn load_fixture(name: &str) -> (ProfileManifest, Vec<u8>, Vec<u8>) {
        let dir = fixture_root().join(name);
        let json = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        let canonical = std::fs::read(dir.join("canonical.bin")).unwrap();
        let sig = std::fs::read(dir.join("sig.bin")).unwrap();
        (ProfileManifest::parse(&json).unwrap(), canonical, sig)
    }

    #[test]
    fn minimal_parses_and_caps_check() {
        let (m, _canon, _sig) = load_fixture("minimal");
        assert_eq!(m.version, 1);
        assert_eq!(m.display_name, "fixture-alice");
        assert!(m.bio.is_none());
        assert!(m.avatar.is_none());
        assert!(m.links.is_empty());
    }

    #[test]
    fn maximal_parses_every_field() {
        let (m, _canon, _sig) = load_fixture("maximal");
        assert_eq!(m.version, 1);
        assert_eq!(
            m.bio.as_deref(),
            Some("Test fixture profile. Do not trust in production.")
        );
        assert_eq!(m.website.as_deref(), Some("https://example.invalid/alice"));
        assert_eq!(m.links.len(), 5);
        assert!(m.avatar.is_some());
        let avatar = m.avatar.as_ref().unwrap();
        assert_eq!(avatar.mime, "image/webp");
        assert_eq!((avatar.w, avatar.h), (256, 256));
        assert_eq!(avatar.bytes_len, 12345);
    }

    /// Spec § 5 assertion (a): the consumer's JCS implementation must
    /// produce the *exact* bytes the publisher committed. Catches
    /// canonicalisation drift between projects.
    #[test]
    fn minimal_canonical_bytes_match_committed() {
        let (m, expected, _sig) = load_fixture("minimal");
        let actual = canonical_bytes_without_sig(&m).unwrap();
        assert_eq!(actual, expected, "minimal canonical bytes drift");
    }

    /// Spec § 5 assertion (a) for the maximal manifest.
    #[test]
    fn maximal_canonical_bytes_match_committed() {
        let (m, expected, _sig) = load_fixture("maximal");
        let actual = canonical_bytes_without_sig(&m).unwrap();
        assert_eq!(actual, expected, "maximal canonical bytes drift");
    }

    /// Spec § 5 assertion (b) + (c): ML-DSA verify succeeds AND
    /// `agent_id` == `derive_agent_id(pubkey)`.
    #[test]
    fn minimal_verify_passes() {
        let (m, _canon, _sig) = load_fixture("minimal");
        m.verify().expect("minimal fixture must verify");
    }

    /// Spec § 5 assertion (b) + (c) for the maximal manifest.
    #[test]
    fn maximal_verify_passes() {
        let (m, _canon, _sig) = load_fixture("maximal");
        m.verify().expect("maximal fixture must verify");
    }

    /// Spec § 5 assertion (e): the tampered manifest carries the
    /// maximal sig but a flipped `display_name` byte. Verify MUST
    /// reject. The whole point of this fixture: catch impls that
    /// silently verify against an in-memory echo of the input
    /// instead of the actual canonical bytes.
    #[test]
    fn tampered_maximal_verify_rejects() {
        let (m, _canon, _sig) = load_fixture("tampered-maximal");
        match m.verify() {
            Err(ProfileError::SigVerifyFailed) => {}
            other => panic!("tampered fixture must fail verify, got {other:?}"),
        }
    }

    /// Spec § 5 assertion (d): the tampered manifest's canonical
    /// bytes still match what's committed (the tamper is the byte
    /// flip + recompute, which is exactly what an attacker would
    /// produce).
    #[test]
    fn tampered_canonical_bytes_match_committed() {
        let (m, expected, _sig) = load_fixture("tampered-maximal");
        let actual = canonical_bytes_without_sig(&m).unwrap();
        assert_eq!(actual, expected, "tampered canonical bytes drift");
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let (m, _canon, _sig) = load_fixture("minimal");
        let mut v = serde_json::to_value(&m).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("version".into(), serde_json::json!(2));
        let bad = serde_json::to_string(&v).unwrap();
        match ProfileManifest::parse(&bad) {
            Err(ProfileError::UnsupportedVersion(2)) => {}
            other => panic!("expected UnsupportedVersion(2), got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_oversized_display_name() {
        let (m, _canon, _sig) = load_fixture("minimal");
        let mut v = serde_json::to_value(&m).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("display_name".into(), serde_json::json!("X".repeat(65)));
        let bad = serde_json::to_string(&v).unwrap();
        match ProfileManifest::parse(&bad) {
            Err(ProfileError::TooLong {
                field: "display_name",
                len: 65,
                cap: 64,
            }) => {}
            other => panic!("expected TooLong display_name, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_agent_id_swap() {
        let (m, _canon, _sig) = load_fixture("maximal");
        let mut v = serde_json::to_value(&m).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("agent_id".into(), serde_json::json!("0".repeat(64)));
        let bad: ProfileManifest = serde_json::from_value(v).unwrap();
        match bad.verify() {
            Err(ProfileError::AgentIdMismatch { .. }) => {}
            other => panic!("expected AgentIdMismatch, got {other:?}"),
        }
    }
}
