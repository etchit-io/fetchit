//! Actor identity + Mastodon-compatible JSON-LD representation.
//!
//! Per plan decision [III] and the cross-crate cut documented in
//! `docs/superpowers/plans/2026-06-07-m4-fediverse-impl-plan.md` Stage 1,
//! [`ActorIdentity`] is **pure data**. The factory (RSA-2048 generation,
//! ML-DSA-65 attestation signing, [`StoreLayout`] I/O) lives in
//! `fetchit-chat::Client::mint_actor_identity` so the dep direction
//! stays unidirectional (`chat → fedi`).
//!
//! [`Actor`] is the Mastodon-compatible `application/activity+json`
//! shape — what a fetch>it actor URL serves on GET, and what other
//! `ActivityPub` instances PEM-decode to verify outbound HTTP
//! Signatures. `Actor::to_json_ld` renders the structure; the inverse
//! (`Actor::from_json_ld`) lands with Stage 1.3-b's Mastodon-fixture
//! round-trip tests.

use crate::attestation::MlDsaAttestation;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

/// Property URI for the post-quantum attestation extension that
/// fetch>it actors publish alongside the Mastodon-compatible
/// `publicKey` field.
///
/// **Frozen.** Bumping this is a v2 migration: every previously
/// minted actor's `Actor` JSON-LD would emit a key that fetch>it
/// verifiers wouldn't recognise. The `-v1` suffix matches the
/// [`crate::attestation::DOMAIN_SEPARATOR`] +
/// `fetchit_chat::fedi_identity::FEDI_VAULT_INFO` versioning style.
///
/// The bare URI works as an opaque identifier even before a JSON-LD
/// `@context` doc is published at `https://etchit.io/ns` —
/// Mastodon-class consumers treat unknown keys as literal strings and
/// ignore them. The `@context` doc joins Stage 6 when `etchit.io`
/// grows fetchit-operated endpoints.
pub const PQ_ATTESTATION_PROPERTY_URI: &str = "https://etchit.io/ns#mlDsaAttestation-v1";

/// A fetchit-issued fediverse actor: a stable identity bound to a chat
/// `agent_id_hex`, signed under the chat-identity ML-DSA-65 key.
///
/// Construction goes through [`Self::new`] (fresh mint) or
/// [`Self::from_persisted`] (reload from disk). Both are pure-data
/// constructors; neither touches the network or the filesystem.
///
/// `spki_der` is the `SubjectPublicKeyInfo` DER bytes of the RSA-2048
/// public key — kept alongside the private PEM so [`Actor::from_identity`]
/// can emit `publicKeyPem` without re-parsing the private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorIdentity {
    /// Local-part of the handle (e.g. `"josh"` for `@josh@etchit.io`).
    pub handle: String,
    /// Canonical actor URL (e.g. `https://etchit.io/actors/josh`).
    pub actor_url: url::Url,
    /// 64-hex chat agent id this actor is bound to.
    pub agent_id_hex: String,
    /// RSA-2048 private key in PKCS#8 PEM form. Used by the HTTP
    /// Signature signer when delivering outbound POSTs.
    pub rsa_priv_pem: String,
    /// `SubjectPublicKeyInfo` DER bytes of the RSA-2048 public key.
    /// Persisted alongside the private PEM so JSON-LD rendering does
    /// not need an RSA parser dep.
    pub spki_der: Vec<u8>,
    /// ML-DSA-65 attestation binding the RSA public key (via
    /// [`crate::attestation::signing_input`] over `spki_der`) to the
    /// chat-identity ML-DSA key.
    pub ml_dsa_attestation: MlDsaAttestation,
}

impl ActorIdentity {
    /// Pure-data constructor used by `fetchit_chat::Client::mint_actor_identity`
    /// after it has generated the RSA key and signed the attestation.
    #[must_use]
    pub fn new(
        handle: String,
        actor_url: url::Url,
        agent_id_hex: String,
        rsa_priv_pem: String,
        spki_der: Vec<u8>,
        ml_dsa_attestation: MlDsaAttestation,
    ) -> Self {
        Self {
            handle,
            actor_url,
            agent_id_hex,
            rsa_priv_pem,
            spki_der,
            ml_dsa_attestation,
        }
    }

    /// Symmetric reload after `fetchit_chat::Client::load_actor_identity`
    /// has read the persisted bytes. Field order intentionally mirrors
    /// the on-disk vault layout for grep-clarity in the chat-side loader.
    #[must_use]
    pub fn from_persisted(
        handle: String,
        rsa_priv_pem: String,
        spki_der: Vec<u8>,
        ml_dsa_attestation: MlDsaAttestation,
        actor_url: url::Url,
        agent_id_hex: String,
    ) -> Self {
        Self {
            handle,
            actor_url,
            agent_id_hex,
            rsa_priv_pem,
            spki_der,
            ml_dsa_attestation,
        }
    }
}

/// Mastodon-compatible `application/activity+json` Actor shape.
///
/// Construction goes through [`Self::from_identity`]; rendering goes
/// through [`Self::to_json_ld`]. Stage 1.3-b adds `from_json_ld` for
/// the symmetric decode side once the Mastodon fixture lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// Actor URL — also the JSON-LD `id`.
    pub id: url::Url,
    /// Local-part of the handle. Mastodon's `preferredUsername`.
    pub preferred_username: String,
    /// Inbox URL — typically `<id>/inbox`.
    pub inbox: url::Url,
    /// Outbox URL — typically `<id>/outbox`.
    pub outbox: url::Url,
    /// RSA-2048 public key in PEM (`SubjectPublicKeyInfo`) form.
    pub rsa_public_key_pem: String,
    /// ML-DSA-65 attestation binding the RSA pubkey to the chat
    /// identity. Emitted under [`PQ_ATTESTATION_PROPERTY_URI`].
    pub ml_dsa_attestation: MlDsaAttestation,
}

impl Actor {
    /// Build the Mastodon-shape `Actor` from a minted [`ActorIdentity`].
    /// Derives `inbox`/`outbox` from the actor URL by appending the
    /// canonical suffixes and converts `spki_der` to its PEM envelope.
    ///
    /// # Errors
    ///
    /// - [`ActorError::InboxUrl`] / [`ActorError::OutboxUrl`] when the
    ///   inbox/outbox path append fails (practically unreachable for
    ///   well-formed actor URLs).
    pub fn from_identity(id: &ActorIdentity) -> Result<Self, ActorError> {
        let inbox = append_path(&id.actor_url, "inbox").map_err(ActorError::InboxUrl)?;
        let outbox = append_path(&id.actor_url, "outbox").map_err(ActorError::OutboxUrl)?;
        Ok(Self {
            id: id.actor_url.clone(),
            preferred_username: id.handle.clone(),
            inbox,
            outbox,
            rsa_public_key_pem: spki_der_to_pem(&id.spki_der),
            ml_dsa_attestation: id.ml_dsa_attestation.clone(),
        })
    }

    /// Decode a Mastodon-compatible `application/activity+json`
    /// document into an [`Actor`].
    ///
    /// Keys on the property names defined by the activitystreams +
    /// security/v1 vocabularies (plus our own [`PQ_ATTESTATION_PROPERTY_URI`])
    /// rather than running a strict JSON-LD context expansion. That
    /// makes the decoder **forward-compat with Mastodon evolution** —
    /// every extra Mastodon-specific key (`manuallyApprovesFollowers`,
    /// `summary`, `attachment`, etc.) is silently ignored.
    ///
    /// # Errors
    ///
    /// - [`ActorError::MissingField`] when one of the required fields
    ///   is absent: `id`, `preferredUsername`, `inbox`, `outbox`,
    ///   `publicKey.publicKeyPem`, or the FROZEN PQ attestation key.
    /// - [`ActorError::InvalidField`] when a URL field fails to parse.
    /// - [`ActorError::Attestation`] when the PQ attestation value is
    ///   structurally present but does not deserialize into
    ///   [`MlDsaAttestation`] (e.g. invalid base64 in `ml_dsa_pubkey`
    ///   or `signature`).
    pub fn from_json_ld(value: &Value) -> Result<Self, ActorError> {
        let id_str = required_str(value, "id")?;
        let id = id_str
            .parse::<url::Url>()
            .map_err(|e| ActorError::InvalidField {
                name: "id".into(),
                reason: format!("{e}"),
            })?;
        let preferred_username = required_str(value, "preferredUsername")?.to_string();
        let inbox_str = required_str(value, "inbox")?;
        let inbox = inbox_str
            .parse::<url::Url>()
            .map_err(|e| ActorError::InvalidField {
                name: "inbox".into(),
                reason: format!("{e}"),
            })?;
        let outbox_str = required_str(value, "outbox")?;
        let outbox = outbox_str
            .parse::<url::Url>()
            .map_err(|e| ActorError::InvalidField {
                name: "outbox".into(),
                reason: format!("{e}"),
            })?;

        let pub_key_obj = value
            .get("publicKey")
            .ok_or_else(|| ActorError::MissingField {
                name: "publicKey".into(),
            })?;
        let rsa_public_key_pem = pub_key_obj
            .get("publicKeyPem")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ActorError::MissingField {
                name: "publicKey.publicKeyPem".into(),
            })?
            .to_string();

        let attestation_raw =
            value
                .get(PQ_ATTESTATION_PROPERTY_URI)
                .ok_or_else(|| ActorError::MissingField {
                    name: PQ_ATTESTATION_PROPERTY_URI.into(),
                })?;
        let ml_dsa_attestation: MlDsaAttestation = serde_json::from_value(attestation_raw.clone())
            .map_err(|e| ActorError::Attestation(format!("{e}")))?;

        Ok(Self {
            id,
            preferred_username,
            inbox,
            outbox,
            rsa_public_key_pem,
            ml_dsa_attestation,
        })
    }

    /// Render the Mastodon-compatible JSON-LD document. The result is
    /// what `application/activity+json` consumers expect on GET against
    /// the actor URL.
    #[must_use]
    pub fn to_json_ld(&self) -> Value {
        let actor_url_str = self.id.as_str();
        let key_id = format!("{actor_url_str}#main-key");
        json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1",
            ],
            "id": actor_url_str,
            "type": "Person",
            "preferredUsername": self.preferred_username,
            "inbox": self.inbox.as_str(),
            "outbox": self.outbox.as_str(),
            "publicKey": {
                "id": key_id,
                "owner": actor_url_str,
                "publicKeyPem": self.rsa_public_key_pem,
            },
            PQ_ATTESTATION_PROPERTY_URI: serde_json::to_value(&self.ml_dsa_attestation)
                .unwrap_or(Value::Null),
        })
    }
}

/// Errors from `Actor` construction, rendering, or decoding.
#[derive(Debug, thiserror::Error)]
pub enum ActorError {
    /// Building the inbox URL failed.
    #[error("inbox url construction failed: {0}")]
    InboxUrl(String),
    /// Building the outbox URL failed.
    #[error("outbox url construction failed: {0}")]
    OutboxUrl(String),
    /// A required field is missing from the JSON-LD document.
    #[error("required Actor field missing: {name}")]
    MissingField {
        /// Name of the missing field.
        name: String,
    },
    /// A field was present but failed to parse.
    #[error("Actor field {name} invalid: {reason}")]
    InvalidField {
        /// Field name.
        name: String,
        /// Reason for the parse failure.
        reason: String,
    },
    /// The PQ attestation value failed structural deserialization.
    #[error("Actor PQ attestation decode failed: {0}")]
    Attestation(String),
}

fn required_str<'a>(value: &'a Value, name: &str) -> Result<&'a str, ActorError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ActorError::MissingField { name: name.into() })
}

/// Encode SPKI DER bytes as a SPKI PEM string with the standard
/// `BEGIN PUBLIC KEY` / `END PUBLIC KEY` envelope and 64-char line
/// wrapping (Mastodon's `publicKeyPem` convention; matches what
/// rustcrypto/rsa's `to_public_key_pem` would emit).
#[must_use]
pub fn spki_der_to_pem(der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut pem = String::with_capacity(b64.len() + 64);
    pem.push_str("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // chunk slices b64 (ASCII), so utf8 is guaranteed.
        if let Ok(s) = std::str::from_utf8(chunk) {
            pem.push_str(s);
            pem.push('\n');
        }
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn append_path(base: &url::Url, suffix: &str) -> Result<url::Url, String> {
    let raw = format!("{}/{}", base.as_str().trim_end_matches('/'), suffix);
    raw.parse().map_err(|e| format!("{raw:?}: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_attestation() -> MlDsaAttestation {
        MlDsaAttestation::new(vec![0x11; 8], vec![0x22; 8])
    }

    fn sample_identity() -> ActorIdentity {
        ActorIdentity::new(
            "josh".into(),
            "https://etchit.io/actors/josh".parse().unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n".into(),
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
            sample_attestation(),
        )
    }

    #[test]
    fn new_round_trips_fields() {
        let id = sample_identity();
        assert_eq!(id.handle, "josh");
        assert_eq!(id.actor_url.as_str(), "https://etchit.io/actors/josh");
        assert_eq!(id.agent_id_hex.len(), 64);
        assert!(id.rsa_priv_pem.starts_with("-----BEGIN PRIVATE KEY"));
        assert_eq!(
            id.spki_der,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
        assert_eq!(id.ml_dsa_attestation, sample_attestation());
    }

    #[test]
    fn from_persisted_yields_identical_struct_as_new() {
        let att = sample_attestation();
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let agent = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let spki = vec![0x01, 0x02, 0x03];

        let minted = ActorIdentity::new(
            "josh".into(),
            actor_url.clone(),
            agent.into(),
            "PRIV".into(),
            spki.clone(),
            att.clone(),
        );
        let reloaded = ActorIdentity::from_persisted(
            "josh".into(),
            "PRIV".into(),
            spki,
            att,
            actor_url,
            agent.into(),
        );

        assert_eq!(minted, reloaded);
    }

    #[test]
    fn pq_attestation_property_uri_is_frozen() {
        assert_eq!(
            PQ_ATTESTATION_PROPERTY_URI,
            "https://etchit.io/ns#mlDsaAttestation-v1"
        );
    }

    #[test]
    fn spki_der_to_pem_wraps_envelope_at_64_chars() {
        // 96-byte input → 128-char base64 → 2 lines of 64 chars.
        let der: Vec<u8> = (0..96).collect();
        let pem = spki_der_to_pem(&der);

        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));

        let inner: Vec<&str> = pem.lines().filter(|l| !l.starts_with("----")).collect();
        for line in &inner {
            assert!(
                line.len() <= 64,
                "pem body line too long ({} chars): {line}",
                line.len()
            );
        }
        // Round-trip: stripping headers + newlines yields the original
        // base64, which decodes back to the input bytes.
        let body: String = inner.concat();
        let decoded = B64.decode(body).unwrap();
        assert_eq!(decoded, der);
    }

    #[test]
    fn from_identity_builds_mastodon_shape() {
        let id = sample_identity();
        let actor = Actor::from_identity(&id).unwrap();

        assert_eq!(actor.id, id.actor_url);
        assert_eq!(actor.preferred_username, "josh");
        assert_eq!(actor.inbox.as_str(), "https://etchit.io/actors/josh/inbox");
        assert_eq!(
            actor.outbox.as_str(),
            "https://etchit.io/actors/josh/outbox"
        );
        assert!(actor
            .rsa_public_key_pem
            .starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(actor
            .rsa_public_key_pem
            .ends_with("-----END PUBLIC KEY-----\n"));
        assert_eq!(actor.ml_dsa_attestation, id.ml_dsa_attestation);
    }

    #[test]
    fn to_json_ld_emits_canonical_mastodon_shape() {
        let actor = Actor::from_identity(&sample_identity()).unwrap();
        let v = actor.to_json_ld();

        let id_str = "https://etchit.io/actors/josh";
        assert_eq!(v["id"], id_str);
        assert_eq!(v["type"], "Person");
        assert_eq!(v["preferredUsername"], "josh");
        assert_eq!(v["inbox"], format!("{id_str}/inbox"));
        assert_eq!(v["outbox"], format!("{id_str}/outbox"));

        let pk = &v["publicKey"];
        assert_eq!(pk["id"], format!("{id_str}#main-key"));
        assert_eq!(pk["owner"], id_str);
        assert!(pk["publicKeyPem"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PUBLIC KEY-----"));

        // @context is an array with the activitystreams + security/v1
        // vocabularies. security/v1 is required for strict JSON-LD
        // processors to understand the publicKey/publicKeyPem/owner
        // terms (Alice F1).
        assert_eq!(v["@context"][0], "https://www.w3.org/ns/activitystreams");
        assert_eq!(v["@context"][1], "https://w3id.org/security/v1");

        // PQ attestation under the FROZEN property URI.
        let pq = &v[PQ_ATTESTATION_PROPERTY_URI];
        assert!(pq["ml_dsa_pubkey"].is_string());
        assert!(pq["signature"].is_string());
    }

    #[test]
    fn to_json_ld_includes_security_v1_context() {
        // Mastodon's own Actor JSON-LD emits security/v1 alongside
        // activitystreams because publicKey + publicKeyPem + owner
        // are defined in that vocabulary. Without it a strict
        // JSON-LD processor cannot resolve those terms.
        let actor = Actor::from_identity(&sample_identity()).unwrap();
        let v = actor.to_json_ld();
        let ctx = v["@context"].as_array().expect("@context is array");
        let urls: Vec<&str> = ctx.iter().filter_map(|c| c.as_str()).collect();
        assert!(
            urls.contains(&"https://w3id.org/security/v1"),
            "@context must include w3id security vocabulary; got {urls:?}"
        );
    }
}
