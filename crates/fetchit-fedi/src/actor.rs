//! Actor identity + Mastodon-compatible JSON-LD representation.
//!
//! Per plan decision `[III]` and the cross-crate cut documented in
//! `docs/superpowers/plans/2026-06-07-m4-fediverse-impl-plan.md` Stage 1,
//! [`ActorIdentity`] is **pure data**. The factory (RSA-2048 generation,
//! ML-DSA-65 attestation signing, `StoreLayout` I/O) lives in
//! `fetchit-chat::Client::mint_actor_identity` so the dep direction
//! stays unidirectional (`chat → fedi`).
//!
//! [`Actor`] is the Mastodon-compatible `application/activity+json`
//! shape — what a fetch>it actor URL serves on GET, and what other
//! `ActivityPub` instances PEM-decode to verify outbound HTTP
//! Signatures. `Actor::to_json_ld` renders the structure; the inverse
//! `Actor::from_json_ld` parses it, with Mastodon-fixture round-trip
//! tests verifying both directions.

use crate::attestation::MlDsaAttestation;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::time::Duration;

/// Hard cap on actor JSON-LD response size. Mastodon actors are
/// typically 2-5KB; 64KB comfortably accommodates extension fields
/// without opening a parse-cost / memory inflation door.
pub const MAX_ACTOR_BODY_BYTES: usize = 64 * 1024;

/// Per-call request timeout for [`fetch_actor`]. The internal
/// `reqwest::Client` is built with this as both its connect + request
/// timeout (V-2/V-5 fold owns client construction so no caller-side
/// timeout overrides the floor).
pub const ACTOR_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

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

/// JSON-LD property carrying the v2 attestation (adds the profile
/// address + relay hint to the signed binding). Emitted alongside the
/// frozen v1 property during the transition; verifiers prefer v2.
pub const PQ_ATTESTATION_V2_PROPERTY_URI: &str = "https://etchit.io/ns#mlDsaAttestation-v2";

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
/// The RSA private key (`rsa_priv_pem`) is a long-lived HTTP-Signature
/// signing secret: this type zeroizes it on drop and redacts it from
/// `Debug`. The vault hands its decrypted PEM to [`Self::from_persisted`]
/// by **move** (no second copy), so wiping it here covers the secret's
/// full in-memory lifetime. Each `Clone` owns an independent buffer
/// wiped on its own drop.
#[derive(Clone, PartialEq, Eq)]
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
    /// v2 attestation extending the binding with the profile address
    /// and relay hint (M5.1). `None` on identities minted before v2.
    pub ml_dsa_attestation_v2: Option<crate::attestation::ActorAttestationV2>,
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
            ml_dsa_attestation_v2: None,
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
            ml_dsa_attestation_v2: None,
        }
    }

    /// Attach a v2 attestation (builder-style; mint paths use this).
    #[must_use]
    pub fn with_attestation_v2(mut self, att: crate::attestation::ActorAttestationV2) -> Self {
        self.ml_dsa_attestation_v2 = Some(att);
        self
    }
}

impl std::fmt::Debug for ActorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorIdentity")
            .field("handle", &self.handle)
            .field("actor_url", &self.actor_url)
            .field("agent_id_hex", &self.agent_id_hex)
            .field("rsa_priv_pem", &"<redacted>")
            .field("spki_der", &self.spki_der)
            .field("ml_dsa_attestation", &self.ml_dsa_attestation)
            .field("ml_dsa_attestation_v2", &self.ml_dsa_attestation_v2)
            .finish()
    }
}

impl Drop for ActorIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rsa_priv_pem.zeroize();
    }
}

/// Mastodon-compatible `application/activity+json` Actor shape.
///
/// Construction goes through [`Self::from_identity`]; rendering goes
/// through [`Self::to_json_ld`]; decoding from a fetched JSON-LD document
/// goes through [`Self::from_json_ld`].
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
    /// v2 attestation when the identity carries one. Emitted under
    /// [`PQ_ATTESTATION_V2_PROPERTY_URI`]; absent on pre-M5 documents.
    pub ml_dsa_attestation_v2: Option<crate::attestation::ActorAttestationV2>,
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
            ml_dsa_attestation_v2: id.ml_dsa_attestation_v2.clone(),
        })
    }

    /// Attach a v2 attestation (builder-style; mint paths use this).
    #[must_use]
    pub fn with_attestation_v2(mut self, att: crate::attestation::ActorAttestationV2) -> Self {
        self.ml_dsa_attestation_v2 = Some(att);
        self
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

        // Reject documents whose `type` is outside the ActivityPub
        // Actor-class allowlist. A malicious server could otherwise
        // return a Note or Activity object styled as an Actor;
        // downstream HTTP-Sig verifiers would then trust an unrelated
        // pubkey. Per Alice F2.
        if let Some(type_str) = value.get("type").and_then(Value::as_str) {
            if !is_actor_class_type(type_str) {
                return Err(ActorError::InvalidField {
                    name: "type".into(),
                    reason: format!(
                        "expected one of {{Person, Service, Application, Organization, Group}}; got {type_str:?}"
                    ),
                });
            }
        }

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

        // Bind `publicKey.owner` to the Actor `id`. Tolerant on
        // missing (some implementations elide it), strict on
        // present-but-wrong: a forged Actor that points at someone
        // else's pubkey is rejected at decode time so Stage 2
        // HTTP-Sig verifiers don't have to re-check. Per Alice F1.
        if let Some(owner) = pub_key_obj.get("owner").and_then(Value::as_str) {
            if owner != id_str {
                return Err(ActorError::InvalidField {
                    name: "publicKey.owner".into(),
                    reason: format!("owner {owner:?} does not match Actor id {id_str:?}"),
                });
            }
        }

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

        // v2 is optional on the wire (pre-M5 documents lack it), but
        // present-but-malformed is a hard error, never a silent None.
        let ml_dsa_attestation_v2 = match value.get(PQ_ATTESTATION_V2_PROPERTY_URI) {
            None => None,
            Some(raw) => Some(
                serde_json::from_value::<crate::attestation::ActorAttestationV2>(raw.clone())
                    .map_err(|e| ActorError::Attestation(format!("v2: {e}")))?,
            ),
        };

        Ok(Self {
            id,
            preferred_username,
            inbox,
            outbox,
            rsa_public_key_pem,
            ml_dsa_attestation,
            ml_dsa_attestation_v2,
        })
    }

    /// Render the Mastodon-compatible JSON-LD document. The result is
    /// what `application/activity+json` consumers expect on GET against
    /// the actor URL.
    #[must_use]
    pub fn to_json_ld(&self) -> Value {
        let actor_url_str = self.id.as_str();
        let key_id = format!("{actor_url_str}#main-key");
        let mut v = json!({
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
        });
        if let Some(att2) = &self.ml_dsa_attestation_v2 {
            if let (Some(obj), Ok(val)) = (v.as_object_mut(), serde_json::to_value(att2)) {
                obj.insert(PQ_ATTESTATION_V2_PROPERTY_URI.to_string(), val);
            }
        }
        v
    }

    /// Cryptographically verify the actor's PQ attestation and return
    /// the **derived** chat `agent_id_hex` it binds this actor to.
    ///
    /// Decodes `publicKeyPem` back to the exact SPKI DER bytes that
    /// were signed and delegates to
    /// [`crate::attestation::verify_binding`] (derive-then-verify; see
    /// its docs for why the agent id is derived from the attested
    /// pubkey rather than read from any claim). Parsing a document
    /// ([`Self::from_json_ld`]) is **structural only** — callers that
    /// gate trust on the PQ binding (the relay inbox, any attribution
    /// surface) MUST call this and treat any error as "not a
    /// fetch>it-native actor".
    ///
    /// # Errors
    ///
    /// - [`ActorError::InvalidField`] when `publicKeyPem` is not a
    ///   decodable PEM envelope.
    /// - [`ActorError::AttestationVerify`] when the attestation fails
    ///   cryptographic verification.
    pub fn verify_attestation(&self) -> Result<String, ActorError> {
        let spki_der = spki_pem_to_der(&self.rsa_public_key_pem).map_err(|reason| {
            ActorError::InvalidField {
                name: "publicKey.publicKeyPem".into(),
                reason,
            }
        })?;
        Ok(crate::attestation::verify_binding(
            &self.preferred_username,
            &self.id,
            &spki_der,
            &self.ml_dsa_attestation,
        )?)
    }

    /// Verify the v2 attestation, returning the derived `agent_id_hex`.
    /// Same trust rule as [`Actor::verify_attestation`]: decoding is
    /// structural only, trust requires this call to succeed.
    ///
    /// # Errors
    ///
    /// - [`ActorError::Attestation`] when no v2 attestation is present.
    /// - Otherwise the same failure surface as
    ///   [`Actor::verify_attestation`].
    pub fn verify_attestation_v2(&self) -> Result<String, ActorError> {
        let att = self
            .ml_dsa_attestation_v2
            .as_ref()
            .ok_or_else(|| ActorError::Attestation("no v2 attestation on actor".into()))?;
        let spki_der = spki_pem_to_der(&self.rsa_public_key_pem).map_err(|reason| {
            ActorError::InvalidField {
                name: "publicKey.publicKeyPem".into(),
                reason,
            }
        })?;
        Ok(crate::attestation::verify_binding_v2(
            &self.preferred_username,
            &self.id,
            &spki_der,
            att,
        )?)
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
    /// The PQ attestation failed cryptographic verification
    /// ([`Actor::verify_attestation`]).
    #[error(transparent)]
    AttestationVerify(#[from] crate::attestation::AttestationVerifyError),
}

pub(crate) fn required_str<'a>(value: &'a Value, name: &str) -> Result<&'a str, ActorError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ActorError::MissingField { name: name.into() })
}

/// Allowlist of `type` values acceptable for an `ActivityPub` Actor
/// document. A malicious server returning a `Note` or `Activity`
/// object styled as an Actor is rejected at decode time.
pub(crate) fn is_actor_class_type(type_str: &str) -> bool {
    matches!(
        type_str,
        "Person" | "Service" | "Application" | "Organization" | "Group"
    )
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

/// Decode a `BEGIN PUBLIC KEY` PEM envelope back to the raw SPKI DER
/// bytes. Exact inverse of [`spki_der_to_pem`]: marker lines are
/// stripped and the base64 body decoded verbatim — never re-encoded
/// through an RSA parser — so the bytes handed to attestation
/// verification are byte-identical to the bytes that were signed.
///
/// # Errors
///
/// Returns a description when the envelope has no base64 body or the
/// body is not valid base64.
pub fn spki_pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    if body.is_empty() {
        return Err("PEM body is empty".into());
    }
    B64.decode(body).map_err(|e| format!("PEM base64: {e}"))
}

fn append_path(base: &url::Url, suffix: &str) -> Result<url::Url, String> {
    let raw = format!("{}/{}", base.as_str().trim_end_matches('/'), suffix);
    raw.parse().map_err(|e| format!("{raw:?}: {e}"))
}

/// Errors surfaceable from [`fetch_actor`]. Bounded variant set so
/// callers can render per-cause UI strings + emit
/// bounded-cardinality failure counters.
#[derive(Debug, thiserror::Error)]
pub enum FetchActorError {
    /// SEC-3: actor URL host is an IP literal in private / loopback /
    /// link-local space (or a redirect target landed in that space).
    /// Closes the SSRF surface against cloud-metadata services + LAN
    /// services + loopback.
    #[error("actor host {host} resolves to private / non-routable IP space")]
    PrivateInstance {
        /// Description of the host + IP class that triggered the gate.
        host: String,
    },

    /// SEC-1: response body exceeded [`MAX_ACTOR_BODY_BYTES`] before
    /// the JSON parse. Stops a hostile or misconfigured instance from
    /// inflating memory or parse cost.
    #[error("actor body exceeded {max_bytes} byte cap")]
    BodyTooLarge {
        /// Hard cap that triggered the rejection.
        max_bytes: usize,
    },

    /// `reqwest`-side error (DNS, connect, TLS, body read, timeout).
    /// String form so the variant surface stays bounded.
    #[error("transport: {0}")]
    Transport(String),

    /// HTTPS GET reached the actor host but the host returned a
    /// non-2xx status. `body` is the first 256 bytes of the body for
    /// ops diagnostics.
    #[error("HTTP {status}: {body}")]
    Http {
        /// HTTP status code from the actor URL response.
        status: u16,
        /// First 256 bytes of the response body.
        body: String,
    },

    /// Response body was not valid JSON.
    #[error("JSON parse: {0}")]
    JsonParse(String),

    /// Response was structurally valid JSON but failed
    /// [`Actor::from_json_ld`] decoding (missing required field, etc.).
    #[error("Actor parse: {0}")]
    Parse(#[from] ActorError),

    /// The fetched document claims an `id` it could not self-confirm:
    /// re-fetching AT the claimed id did not return a document naming
    /// itself. Treated as hostile — accepting it would let any host
    /// impersonate an actor it does not control.
    #[error("actor id mismatch: fetched {fetched_from}, document claims {claimed}")]
    IdMismatch {
        /// URL the original fetch was issued against.
        fetched_from: String,
        /// The unconfirmed `id` the document asserted.
        claimed: String,
    },
}

/// Fetch and parse a remote `ActivityPub` Actor JSON-LD document.
///
/// Issues a single HTTPS GET to `actor_url` with
/// `Accept: application/activity+json` (Mastodon's preferred shape) and
/// decodes the response via [`Actor::from_json_ld`].
///
/// # Hardening enforced in code
///
/// All gates owned by this function (no longer caller-configured).
/// The internal `reqwest::Client` is built with
/// `redirect::Policy::none()` and a per-call timeout — V-5 from the
/// polish-sec review folded by owning client construction.
///
/// - **SEC-1**: response body hard-capped at
///   [`MAX_ACTOR_BODY_BYTES`] before JSON parse. Pre-checked against
///   `Content-Length` when present + streamed via chunks with a
///   running size accumulator as a backstop. Surfaces
///   [`FetchActorError::BodyTooLarge`].
/// - **SEC-2**: per-call request timeout of
///   [`ACTOR_FETCH_TIMEOUT`].
/// - **SEC-3**: pre-flight rejects `actor_url` hosts that are IP
///   literals in private / loopback / link-local / unique-local /
///   IPv4-mapped IPv6 space.
/// - **SEC-3 (V-2 fold)**: `tokio::net::lookup_host` resolves the
///   actor hostname upfront; any private/non-routable IP in the
///   resolved set trips [`FetchActorError::PrivateInstance`]. The
///   resolved addresses are pinned via
///   `reqwest::ClientBuilder::resolve_to_addrs` so the connect-time
///   lookup can't TTL=0 rebind to a different (private) IP.
/// - Post-flight rejects responses whose final URL host changed and
///   targets private IP space (backstop).
///
/// # Errors
/// Surfaces every [`FetchActorError`] variant. Inner `reqwest` errors
/// land as [`FetchActorError::Transport`].
pub async fn fetch_actor(actor_url: &url::Url) -> Result<Actor, FetchActorError> {
    let client = pinned_no_redirect_client(actor_url, ACTOR_FETCH_TIMEOUT).await?;
    fetch_actor_at_url(&client, actor_url, ACTOR_FETCH_TIMEOUT).await
}

/// SSRF-hardened client for a single target: private-IP pre-flight
/// (SEC-3), DNS resolve + pin (V-2 fold), no redirects, per-call
/// timeout. Shared by the strict actor fetch and the tolerant lookup
/// fetch ([`crate::lookup::fetch_remote_actor`]).
pub(crate) async fn pinned_no_redirect_client(
    target: &url::Url,
    timeout: Duration,
) -> Result<reqwest::Client, FetchActorError> {
    // SEC-3 pre-flight on the URL itself.
    if let Some(host) = target.host() {
        if let Some(reason) = crate::ssrf::private_ip_reason(&host) {
            return Err(FetchActorError::PrivateInstance { host: reason });
        }
    }
    // V-2 fold: resolve hostname + pin addresses on the client.
    let host_for_pin = target
        .host_str()
        .ok_or_else(|| FetchActorError::Transport("URL has no host".into()))?;
    let port = target.port_or_known_default().unwrap_or(443);
    let pinned = crate::ssrf::resolve_and_pin_host(host_for_pin, port)
        .await
        .map_err(|e| match e {
            crate::ssrf::SsrfError::PrivateAddress { host } => {
                FetchActorError::PrivateInstance { host }
            }
            crate::ssrf::SsrfError::Resolve(msg) => FetchActorError::Transport(msg),
        })?;
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .resolve_to_addrs(host_for_pin, &pinned)
        .build()
        .map_err(|e| FetchActorError::Transport(format!("client builder: {e}")))
}

/// Internal: HTTP fetch + body cap + post-flight + parse. Factored
/// out so wiremock-backed tests can exercise the cap / timeout / parse
/// behavior over `http://127.0.0.1` without tripping the loopback
/// pre-flight that lives in the public [`fetch_actor`].
async fn fetch_actor_at_url(
    http: &reqwest::Client,
    actor_url: &url::Url,
    timeout: Duration,
) -> Result<Actor, FetchActorError> {
    let value = fetch_json_ld_at_url(http, actor_url, timeout).await?;
    Actor::from_json_ld(&value).map_err(FetchActorError::Parse)
}

/// Internal: HTTPS GET + post-flight host check + body cap + JSON
/// parse, without any actor decode. The strict and tolerant decoders
/// both sit on top of this.
pub(crate) async fn fetch_json_ld_at_url(
    http: &reqwest::Client,
    actor_url: &url::Url,
    timeout: Duration,
) -> Result<Value, FetchActorError> {
    let mut resp = http
        .get(actor_url.as_str())
        .header("Accept", "application/activity+json")
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| FetchActorError::Transport(e.to_string()))?;

    // SEC-3 post-flight: only fires when a redirect actually moved
    // host. If host unchanged, the pre-flight already gated this URL.
    let req_host = actor_url.host_str().map(str::to_owned);
    let resp_host = resp.url().host_str().map(str::to_owned);
    if req_host != resp_host {
        if let Some(host) = resp.url().host() {
            if let Some(reason) = crate::ssrf::private_ip_reason(&host) {
                return Err(FetchActorError::PrivateInstance { host: reason });
            }
        }
    }

    let status = resp.status();
    if !status.is_success() {
        let body_full = resp
            .text()
            .await
            .map_err(|e| FetchActorError::Transport(e.to_string()))?;
        let body = body_full.chars().take(256).collect();
        return Err(FetchActorError::Http {
            status: status.as_u16(),
            body,
        });
    }

    // SEC-1 pre-check via Content-Length.
    if let Some(len) = resp.content_length() {
        if len > MAX_ACTOR_BODY_BYTES as u64 {
            return Err(FetchActorError::BodyTooLarge {
                max_bytes: MAX_ACTOR_BODY_BYTES,
            });
        }
    }

    // SEC-1 backstop: streamed accumulator for chunked transfer or
    // dishonest Content-Length.
    let mut body: Vec<u8> = Vec::with_capacity(4096);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FetchActorError::Transport(e.to_string()))?
    {
        if body.len() + chunk.len() > MAX_ACTOR_BODY_BYTES {
            return Err(FetchActorError::BodyTooLarge {
                max_bytes: MAX_ACTOR_BODY_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|e| FetchActorError::JsonParse(e.to_string()))
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

    // ── 5.2-wire-a: fetch_actor ──────────────────────────────────

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Mint a valid actor JSON-LD body via the symmetric
    /// [`Actor::from_identity`] + [`Actor::to_json_ld`] path so
    /// `fetch_actor` tests stay coupled to whatever shape the encoder
    /// emits, not a hand-rolled fixture that drifts.
    fn sample_actor_body() -> String {
        let actor = Actor::from_identity(&sample_identity()).unwrap();
        serde_json::to_string(&actor.to_json_ld()).unwrap()
    }

    #[tokio::test]
    async fn fetch_actor_happy_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/actors/josh"))
            .and(header("Accept", "application/activity+json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sample_actor_body()))
            .mount(&server)
            .await;

        let url: url::Url = format!("{}/actors/josh", server.uri()).parse().unwrap();
        let client = reqwest::Client::new();
        let actor = fetch_actor_at_url(&client, &url, Duration::from_secs(5))
            .await
            .expect("happy path");
        assert_eq!(actor.preferred_username, "josh");
        assert!(actor.inbox.as_str().ends_with("/inbox"));
    }

    #[tokio::test]
    async fn fetch_actor_rejects_private_ipv4_url() {
        let url: url::Url = "https://192.168.1.1/actors/eve".parse().unwrap();
        let err = fetch_actor(&url).await.unwrap_err();
        match err {
            FetchActorError::PrivateInstance { host } => {
                assert!(host.contains("192.168.1.1"), "host = {host}");
            }
            other => panic!("expected PrivateInstance, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_actor_rejects_aws_metadata_url() {
        let url: url::Url = "https://169.254.169.254/latest/meta-data/".parse().unwrap();
        let err = fetch_actor(&url).await.unwrap_err();
        assert!(matches!(err, FetchActorError::PrivateInstance { .. }));
    }

    #[tokio::test]
    async fn fetch_actor_caps_oversized_body() {
        let server = MockServer::start().await;
        let big = "x".repeat(70 * 1024);
        let body = format!(r#"{{"filler":"{big}"}}"#);
        Mock::given(method("GET"))
            .and(path("/actors/eve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let url: url::Url = format!("{}/actors/eve", server.uri()).parse().unwrap();
        let err = fetch_actor_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        match err {
            FetchActorError::BodyTooLarge { max_bytes } => {
                assert_eq!(max_bytes, MAX_ACTOR_BODY_BYTES);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_actor_surfaces_http_on_non_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/actors/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let url: url::Url = format!("{}/actors/missing", server.uri()).parse().unwrap();
        let err = fetch_actor_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        match err {
            FetchActorError::Http { status, body } => {
                assert_eq!(status, 404);
                assert!(body.contains("not found"));
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_actor_surfaces_json_parse_on_malformed_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/actors/garbage"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json-at-all"))
            .mount(&server)
            .await;
        let url: url::Url = format!("{}/actors/garbage", server.uri()).parse().unwrap();
        let err = fetch_actor_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchActorError::JsonParse(_)));
    }

    #[tokio::test]
    async fn fetch_actor_surfaces_actor_parse_on_missing_required_field() {
        let server = MockServer::start().await;
        // Valid JSON but missing `preferredUsername` / `inbox` / etc.
        // Should land as Parse(ActorError) via the From impl.
        Mock::given(method("GET"))
            .and(path("/actors/bare"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"id":"https://x.example/actors/bare"}"#),
            )
            .mount(&server)
            .await;
        let url: url::Url = format!("{}/actors/bare", server.uri()).parse().unwrap();
        let err = fetch_actor_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchActorError::Parse(_)));
    }

    #[test]
    fn spki_pem_to_der_inverts_spki_der_to_pem() {
        let der: Vec<u8> = (0..96).collect();
        assert_eq!(spki_pem_to_der(&spki_der_to_pem(&der)).unwrap(), der);
    }

    #[test]
    fn verify_attestation_passes_after_json_ld_round_trip() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let (att, derived) = crate::attestation::test_attested("josh", &actor_url, &spki_der);
        let identity = ActorIdentity::new(
            "josh".into(),
            actor_url,
            derived.clone(),
            "PRIV".into(),
            spki_der,
            att,
        );
        let actor = Actor::from_identity(&identity).unwrap();
        let parsed = Actor::from_json_ld(&actor.to_json_ld()).unwrap();
        assert_eq!(parsed.verify_attestation().unwrap(), derived);
    }

    #[test]
    fn json_ld_round_trips_v2_attestation() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let (att2, _) = crate::attestation::test_attested_v2(
            "josh",
            &actor_url,
            &[0xDE, 0xAD],
            &"a".repeat(64),
            "https://relay.example/",
            9,
        );
        let actor = Actor::from_identity(&sample_identity())
            .unwrap()
            .with_attestation_v2(att2.clone());
        let v = actor.to_json_ld();
        assert!(v.get(PQ_ATTESTATION_V2_PROPERTY_URI).is_some());
        let parsed = Actor::from_json_ld(&v).unwrap();
        assert_eq!(parsed.ml_dsa_attestation_v2, Some(att2));
    }

    #[test]
    fn json_ld_without_v2_attestation_decodes_to_none() {
        let actor = Actor::from_identity(&sample_identity()).unwrap();
        let v = actor.to_json_ld();
        assert!(v.get(PQ_ATTESTATION_V2_PROPERTY_URI).is_none());
        let parsed = Actor::from_json_ld(&v).unwrap();
        assert_eq!(parsed.ml_dsa_attestation_v2, None);
    }

    #[test]
    fn malformed_v2_attestation_value_is_a_hard_decode_error() {
        let actor = Actor::from_identity(&sample_identity()).unwrap();
        let mut v = actor.to_json_ld();
        v.as_object_mut().unwrap().insert(
            PQ_ATTESTATION_V2_PROPERTY_URI.into(),
            serde_json::json!("garbage"),
        );
        assert!(Actor::from_json_ld(&v).is_err());
    }

    #[test]
    fn verify_attestation_v2_returns_derived_id_and_errors_when_absent() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let (att2, derived) = crate::attestation::test_attested_v2(
            "josh",
            &actor_url,
            &spki_der,
            &"a".repeat(64),
            "https://relay.example/",
            11,
        );
        let identity = ActorIdentity::new(
            "josh".into(),
            actor_url,
            derived.clone(),
            "PRIV".into(),
            spki_der,
            sample_attestation(),
        )
        .with_attestation_v2(att2);
        let actor = Actor::from_identity(&identity).unwrap();
        let parsed = Actor::from_json_ld(&actor.to_json_ld()).unwrap();
        assert_eq!(parsed.verify_attestation_v2().unwrap(), derived);

        let without = Actor::from_identity(&sample_identity()).unwrap();
        assert!(without.verify_attestation_v2().is_err());
    }

    #[test]
    fn verify_attestation_rejects_dummy_attestation() {
        // The "costume" case the inbox gate must drop: a structurally
        // valid doc whose attestation bytes are garbage.
        let actor = Actor::from_identity(&sample_identity()).unwrap();
        assert!(actor.verify_attestation().is_err());
    }
}
