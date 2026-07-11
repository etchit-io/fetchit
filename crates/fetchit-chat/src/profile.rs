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

// `SIGN_DOMAIN_PROFILE` re-exported from `fetchit_relay_proto`
// — single source of truth for the profile-manifest signing-input
// prefix shared by chat client, relay server, and etch>it publisher.
// Existing call sites (`crate::profile::SIGN_DOMAIN_PROFILE`) keep
// resolving via this re-export.
pub use fetchit_relay_proto::SIGN_DOMAIN_PROFILE;

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

    /// `issued_at_ms` is older than the minimum acceptable timestamp.
    /// Indicates an attempted downgrade replay.
    #[error("manifest stale: issued_at_ms {issued} < minimum {minimum}")]
    Stale {
        /// `issued_at_ms` carried by the manifest under test.
        issued: u64,
        /// Minimum acceptable `issued_at_ms` the caller supplied.
        minimum: u64,
    },

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
    /// 5. If `min_issued_at_ms` is `Some(min)`, require
    ///    `self.issued_at_ms >= min` — defends against an adversary
    ///    re-serving a stale-but-validly-signed manifest to downgrade
    ///    `display_name`, `kem_pubkey`, or `profile_addr`. `None`
    ///    skips the freshness check (first-fetch case where no prior
    ///    manifest is on file). The check runs *after* signature
    ///    verification so timing differences don't leak whether a
    ///    forgery attempt was fresh-but-bad-sig vs stale-and-good-sig.
    ///
    /// Returns the embedded ML-DSA-65 raw public-key bytes on success
    /// so callers don't have to decode them again.
    ///
    /// # Errors
    /// Returns the matching [`ProfileError`] variant for every step.
    pub fn verify(&self, min_issued_at_ms: Option<u64>) -> Result<Vec<u8>, ProfileError> {
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

        // Agent-key signature: verify over the external-agent-sign framing.
        // The manifest is signed by the ML-DSA identity via x0xd `/agent/sign`
        // (docs/profile-manifest-v1.md § 2 — "the only signing surface in v1"),
        // which x0x >= 0.29 wraps, so the verifier must reproduce those bytes.
        let input = fetchit_relay_proto::agent_sign_input(&input);
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
        if let Some(min_ts) = min_issued_at_ms {
            if self.issued_at_ms < min_ts {
                return Err(ProfileError::Stale {
                    issued: self.issued_at_ms,
                    minimum: min_ts,
                });
            }
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

/// v3 share URI scheme + path prefix. See `docs/qr-pairing-v1.md` —
/// fetch>it and etch>it implement this byte-for-byte.
pub const V3_SHARE_URI_PREFIX: &str = "fetchit://share/v3/";

/// Maximum total bytes a v3 share URI is allowed to carry. 256 is
/// chosen against QR-version-11-M (~250 byte capacity at level M)
/// with headroom for future optional query parameters.
pub const V3_SHARE_URI_MAX_BYTES: usize = 256;

/// All-zeros 64-hex string, reserved as the tombstone sentinel
/// inside the relay's profile-index — must NEVER appear in a share
/// URI.
const TOMBSTONE_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Decoded v3 share URI — the three pieces a consumer needs to look
/// up + verify the offerer's profile manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3ShareUri {
    /// 64-hex lowercase `agent_id`.
    pub agent_id: String,
    /// 64-hex lowercase Autonomi `profile_addr`.
    pub profile_addr: String,
    /// Base URL of the relay where the offerer's profile-index
    /// record is registered. Stored normalised — trailing slash
    /// stripped, scheme + host only.
    pub relay: url::Url,
}

/// Why parsing a v3 share URI failed. Each variant maps to a
/// surface-level reason the spec doc enumerates so error
/// messages stay consistent across the two repos.
#[derive(Debug, thiserror::Error)]
pub enum V3ShareUriError {
    /// URI doesn't start with the literal v3 prefix.
    #[error("not a v3 share URI: missing `fetchit://share/v3/` prefix")]
    WrongScheme,
    /// URI starts with `fetchit://share/` but a different version.
    #[error("unsupported share-URI version: only v3 is recognised today")]
    UnsupportedVersion,
    /// `agent_id` segment isn't 64 lowercase-hex characters.
    #[error("agent_id segment is not 64 lowercase-hex characters")]
    MalformedAgentId,
    /// `profile_addr` segment isn't 64 lowercase-hex characters, OR is the all-zeros tombstone.
    #[error("profile_addr segment is malformed or is the tombstone sentinel")]
    MalformedProfileAddr,
    /// No `?relay=` query parameter.
    #[error("missing required `relay=` query parameter")]
    MissingRelay,
    /// `relay=` value isn't a parseable http(s) URL.
    #[error("relay= value is not a valid http(s) URL: {0}")]
    MalformedRelay(String),
    /// URI exceeds the 256-byte cap.
    #[error("share URI exceeds the 256-byte cap (got {0} bytes)")]
    TooLong(usize),
}

/// Render a v3 share URI from its three components, applying URL
/// encoding on the relay value. Returns an error only when the
/// resulting URI would exceed `V3_SHARE_URI_MAX_BYTES` — every
/// other constraint (`agent_id` / `profile_addr` shape) is the
/// caller's responsibility to enforce at the call site.
///
/// # Errors
/// [`V3ShareUriError::TooLong`] if the rendered URI exceeds 256
/// bytes.
pub fn to_v3_share_uri(
    agent_id: &str,
    profile_addr: &str,
    relay: &url::Url,
) -> Result<String, V3ShareUriError> {
    let relay_str = relay.as_str().trim_end_matches('/');
    let relay_enc = url::form_urlencoded::byte_serialize(relay_str.as_bytes()).collect::<String>();
    let uri = format!("{V3_SHARE_URI_PREFIX}{agent_id}/{profile_addr}?relay={relay_enc}");
    if uri.len() > V3_SHARE_URI_MAX_BYTES {
        return Err(V3ShareUriError::TooLong(uri.len()));
    }
    Ok(uri)
}

/// Parse a v3 share URI byte string. Validates every component
/// against the contract pinned in `docs/qr-pairing-v1.md`.
///
/// # Errors
/// One of the seven [`V3ShareUriError`] variants per the spec.
pub fn from_v3_share_uri(uri: &str) -> Result<V3ShareUri, V3ShareUriError> {
    if uri.len() > V3_SHARE_URI_MAX_BYTES {
        return Err(V3ShareUriError::TooLong(uri.len()));
    }
    let Some(rest) = uri.strip_prefix(V3_SHARE_URI_PREFIX) else {
        // Distinguish "wrong scheme entirely" from "right scheme
        // but a different version", since callers may want to
        // surface different help text.
        if uri.starts_with("fetchit://share/") {
            return Err(V3ShareUriError::UnsupportedVersion);
        }
        return Err(V3ShareUriError::WrongScheme);
    };
    let Some((path, query)) = rest.split_once('?') else {
        return Err(V3ShareUriError::MissingRelay);
    };
    let mut path_parts = path.split('/');
    let agent_id = path_parts.next().ok_or(V3ShareUriError::MalformedAgentId)?;
    let profile_addr = path_parts
        .next()
        .ok_or(V3ShareUriError::MalformedProfileAddr)?;
    if path_parts.next().is_some() {
        return Err(V3ShareUriError::MalformedProfileAddr);
    }
    if agent_id.len() != 64 || !agent_id.chars().all(is_lower_hex) {
        return Err(V3ShareUriError::MalformedAgentId);
    }
    if profile_addr.len() != 64
        || !profile_addr.chars().all(is_lower_hex)
        || profile_addr == TOMBSTONE_HEX
    {
        return Err(V3ShareUriError::MalformedProfileAddr);
    }
    let mut relay_raw: Option<String> = None;
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        // Unknown query params ignored per spec — leaves room for
        // future minor revisions to add optional params.
        if k == "relay" {
            relay_raw = Some(v.into_owned());
        }
    }
    let relay_str = relay_raw.ok_or(V3ShareUriError::MissingRelay)?;
    let relay =
        url::Url::parse(&relay_str).map_err(|e| V3ShareUriError::MalformedRelay(e.to_string()))?;
    if !matches!(relay.scheme(), "http" | "https") {
        return Err(V3ShareUriError::MalformedRelay(format!(
            "scheme must be http or https, got `{}`",
            relay.scheme()
        )));
    }
    Ok(V3ShareUri {
        agent_id: agent_id.to_string(),
        profile_addr: profile_addr.to_string(),
        relay,
    })
}

fn is_lower_hex(c: char) -> bool {
    matches!(c, '0'..='9' | 'a'..='f')
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
        m.verify(None).expect("minimal fixture must verify");
    }

    /// Spec § 5 assertion (b) + (c) for the maximal manifest.
    #[test]
    fn maximal_verify_passes() {
        let (m, _canon, _sig) = load_fixture("maximal");
        m.verify(None).expect("maximal fixture must verify");
    }

    /// Spec § 5 assertion (e): the tampered manifest carries the
    /// maximal sig but a flipped `display_name` byte. Verify MUST
    /// reject. The whole point of this fixture: catch impls that
    /// silently verify against an in-memory echo of the input
    /// instead of the actual canonical bytes.
    #[test]
    fn tampered_maximal_verify_rejects() {
        let (m, _canon, _sig) = load_fixture("tampered-maximal");
        match m.verify(None) {
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
        match bad.verify(None) {
            Err(ProfileError::AgentIdMismatch { .. }) => {}
            other => panic!("expected AgentIdMismatch, got {other:?}"),
        }
    }

    /// P1 profile-001: an adversary re-serving a stale-but-validly-signed
    /// manifest must not be able to downgrade a contact's `display_name`,
    /// `kem_pubkey`, or `profile_addr`. `verify(Some(min))` rejects with
    /// `Stale` when the manifest's `issued_at_ms` is below `min`.
    #[test]
    fn verify_rejects_stale_manifest() {
        let (m, _canon, _sig) = load_fixture("minimal");
        let issued = m.issued_at_ms;
        let minimum = issued.saturating_add(1);
        match m.verify(Some(minimum)) {
            Err(ProfileError::Stale {
                issued: i,
                minimum: mi,
            }) => {
                assert_eq!(i, issued);
                assert_eq!(mi, minimum);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// Mirror of the rejection test: when the manifest's `issued_at_ms`
    /// is at or above the supplied minimum, verify still succeeds.
    #[test]
    fn verify_accepts_fresh_manifest() {
        let (m, _canon, _sig) = load_fixture("minimal");
        let minimum = m.issued_at_ms.saturating_sub(1);
        m.verify(Some(minimum))
            .expect("issued_at_ms > minimum must verify");
    }

    /// Backward-compat: `None` skips the freshness check entirely.
    /// Same fixture as the existing happy path, but the test exists
    /// in its own right so a future refactor can't accidentally
    /// flip the default behaviour.
    #[test]
    fn verify_with_none_skips_freshness_check() {
        let (m, _canon, _sig) = load_fixture("minimal");
        m.verify(None)
            .expect("None must preserve verify-as-today behavior");
    }

    /// Boundary documentation: the freshness check is strict `<`,
    /// so `issued_at_ms == minimum` is accepted but
    /// `issued_at_ms == minimum - 1` is rejected.
    #[test]
    fn verify_freshness_boundary_is_strict_less_than() {
        let (m, _canon, _sig) = load_fixture("minimal");
        // Equal-to-minimum → accepted.
        m.verify(Some(m.issued_at_ms))
            .expect("issued_at_ms == minimum must verify (boundary is strict <)");
        // One above issued_at_ms → rejected.
        match m.verify(Some(m.issued_at_ms + 1)) {
            Err(ProfileError::Stale { .. }) => {}
            other => panic!("expected Stale at minimum = issued + 1, got {other:?}"),
        }
    }

    // ── v3 share URI ───────────────────────────────────────────

    fn sample_aid() -> String {
        "209574d678357a4987e25162b12f2dcee5ac82a10dfcd394edf9b340c9aa879e".to_string()
    }
    fn sample_addr() -> String {
        "4".repeat(64)
    }
    fn sample_relay() -> url::Url {
        url::Url::parse("http://67.207.94.66:8088").unwrap()
    }

    #[test]
    fn v3_share_uri_round_trips() {
        let uri = to_v3_share_uri(&sample_aid(), &sample_addr(), &sample_relay()).unwrap();
        let parsed = from_v3_share_uri(&uri).unwrap();
        assert_eq!(parsed.agent_id, sample_aid());
        assert_eq!(parsed.profile_addr, sample_addr());
        assert_eq!(parsed.relay.as_str(), "http://67.207.94.66:8088/");
    }

    #[test]
    fn v3_share_uri_reference_example_fits_under_cap() {
        // The reference example documented in
        // `docs/qr-pairing-v1.md` must fit comfortably under the
        // 256-byte cap so a future spec drift surfaces here. The
        // doc claims ~178 bytes; allow a small range against
        // future relay-URL changes.
        let uri = to_v3_share_uri(&sample_aid(), &sample_addr(), &sample_relay()).unwrap();
        assert!(
            uri.len() < 256,
            "uri grew past the QR cap: {} bytes",
            uri.len()
        );
        assert!(
            uri.len() < 200,
            "uri grew unexpectedly: {} bytes",
            uri.len()
        );
    }

    #[test]
    fn v3_share_uri_round_trips_https_relay() {
        let https_relay = url::Url::parse("https://relay.example.com:8443/").unwrap();
        let uri = to_v3_share_uri(&sample_aid(), &sample_addr(), &https_relay).unwrap();
        let parsed = from_v3_share_uri(&uri).unwrap();
        assert_eq!(parsed.relay.scheme(), "https");
        assert_eq!(parsed.relay.host_str(), Some("relay.example.com"));
        assert_eq!(parsed.relay.port(), Some(8443));
    }

    #[test]
    fn v3_share_uri_rejects_wrong_scheme() {
        match from_v3_share_uri("https://example.com/v3/aa/bb?relay=http://x") {
            Err(V3ShareUriError::WrongScheme) => {}
            other => panic!("expected WrongScheme, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_other_version() {
        match from_v3_share_uri("fetchit://share/v9/aa/bb?relay=http://x") {
            Err(V3ShareUriError::UnsupportedVersion) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_uppercase_agent_id() {
        // Generators emit lowercase only so the decoder doesn't
        // have to normalise. Reject uppercase to surface drift
        // early.
        let uri = format!(
            "fetchit://share/v3/{}/{}?relay=http%3A%2F%2Frelay.example",
            sample_aid().to_uppercase(),
            sample_addr(),
        );
        match from_v3_share_uri(&uri) {
            Err(V3ShareUriError::MalformedAgentId) => {}
            other => panic!("expected MalformedAgentId, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_short_agent_id() {
        let uri = format!(
            "fetchit://share/v3/{}/{}?relay=http%3A%2F%2Frelay.example",
            "a".repeat(63),
            sample_addr(),
        );
        match from_v3_share_uri(&uri) {
            Err(V3ShareUriError::MalformedAgentId) => {}
            other => panic!("expected MalformedAgentId, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_tombstone_profile_addr() {
        // The all-zeros profile_addr is reserved as the tombstone
        // sentinel inside the relay's profile-index; it must
        // never appear in a share URI a user could scan.
        let uri = format!(
            "fetchit://share/v3/{}/{}?relay=http%3A%2F%2Frelay.example",
            sample_aid(),
            "0".repeat(64),
        );
        match from_v3_share_uri(&uri) {
            Err(V3ShareUriError::MalformedProfileAddr) => {}
            other => panic!("expected MalformedProfileAddr, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_missing_relay() {
        let uri = format!("fetchit://share/v3/{}/{}", sample_aid(), sample_addr());
        match from_v3_share_uri(&uri) {
            Err(V3ShareUriError::MissingRelay) => {}
            other => panic!("expected MissingRelay, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_non_http_relay_scheme() {
        let uri = format!(
            "fetchit://share/v3/{}/{}?relay=file%3A%2F%2Fexploit",
            sample_aid(),
            sample_addr(),
        );
        match from_v3_share_uri(&uri) {
            Err(V3ShareUriError::MalformedRelay(_)) => {}
            other => panic!("expected MalformedRelay, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_rejects_oversize() {
        // Construct a URI with a relay URL padded out beyond the
        // 256-byte cap. Should fire TooLong on parse.
        let huge_relay = format!("http://{}/", "x".repeat(300));
        let uri = format!(
            "fetchit://share/v3/{}/{}?relay={}",
            sample_aid(),
            sample_addr(),
            url::form_urlencoded::byte_serialize(huge_relay.as_bytes()).collect::<String>(),
        );
        match from_v3_share_uri(&uri) {
            Err(V3ShareUriError::TooLong(n)) => assert!(n > 256),
            other => panic!("expected TooLong, got {other:?}"),
        }
    }

    #[test]
    fn v3_share_uri_ignores_unknown_query_params() {
        // The spec reserves the right to add optional query
        // parameters in a future minor revision; today's parser
        // must accept and ignore unknown keys without erroring.
        let base = to_v3_share_uri(&sample_aid(), &sample_addr(), &sample_relay()).unwrap();
        let with_extra = format!("{base}&future=optional&another=1");
        if with_extra.len() <= V3_SHARE_URI_MAX_BYTES {
            let parsed =
                from_v3_share_uri(&with_extra).expect("unknown params must not break parse");
            assert_eq!(parsed.agent_id, sample_aid());
        }
    }
}
