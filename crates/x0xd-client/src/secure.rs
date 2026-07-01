//! Typed wrappers over x0xd's MLS HTTP+SSE surface (TreeKEM-backed since
//! x0xd v0.20.0). Consumed by the fetchit-chat groups module for the
//! encrypted group send/receive path; the daemon owns the MLS ratchet.

use crate::error::X0xdError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// Validate that `group_id` is the 64-hex shape every x0xd
/// `/groups/{group_id}/secure/*` endpoint expects, BEFORE the value
/// is interpolated into a URL path. Without this, an external caller
/// could pass `../` or other path-traversal sequences and target
/// arbitrary x0xd HTTP endpoints from this process — fetchit-chat's
/// `messages::send_private_group` already filters upstream, but
/// etch>it / future tooling consuming `SecureGroupsEndpoint` doesn't.
///
/// Returns the validated `&str` so callsites can chain straight into
/// `format!`. Ascii-hex characters only; any non-hex byte rejects.
fn validate_group_id_hex(s: &str) -> Result<&str, X0xdError> {
    if s.len() != 64 {
        return Err(X0xdError::Invalid(format!(
            "group_id must be 64 hex chars, got {}",
            s.len()
        )));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(X0xdError::Invalid("group_id must be ASCII hex".into()));
    }
    Ok(s)
}

/// One encrypted application-data frame returned by `/secure/encrypt`
/// and accepted by `/secure/decrypt`.
///
/// The wire shape changed in x0xd v0.21.3 (ADR-0012): the real-`TreeKEM`
/// `treekem_group_encrypt` path emits a self-describing
/// `ApplicationCiphertext` that bakes the per-message nonce INTO the
/// `ciphertext_b64` bytes and tags the response with
/// `secure_plane = "treekem"`. The legacy `SignedPublic` AEAD path still
/// returns the 3-field shape (ciphertext + separate `nonce_b64`) with no
/// `secure_plane` tag.
///
/// The struct therefore carries:
/// - `nonce_b64`: `Some(_)` for the legacy AEAD path, `None` when the
///   nonce is embedded in the ciphertext (`TreeKEM`).
/// - `plane`: `Some("treekem")` for the v0.21.3 `TreeKEM` path,
///   `Some("signed_public")` for an explicit legacy tag, `None` when
///   the daemon omits the field (older nodes — treated as legacy).
///
/// Both fields are additive and serialize with `#[serde(default)]` so
/// older snapshots / wire-encoded frames continue to decode without the
/// new fields present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFrame {
    /// Base64-encoded ciphertext. For `TreeKEM` this is a self-describing
    /// `ApplicationCiphertext` (nonce embedded); for the legacy path this
    /// is the raw `ChaCha20-Poly1305` output with `nonce_b64` supplying
    /// the separate per-message nonce.
    pub ciphertext_b64: String,
    /// Base64 12-byte nonce. `None` for the `TreeKEM` path where the
    /// nonce is baked into `ciphertext_b64`; `Some` for the legacy AEAD
    /// path.
    ///
    /// `#[serde(default)]` keeps legacy snapshots that pre-date this
    /// field decoding cleanly. The field is intentionally NOT
    /// `skip_serializing_if = Option::is_none` — fetchit-chat
    /// postcard-encodes the frame into the wire `TransitEnvelope`
    /// ciphertext, and postcard (a positional binary format) requires
    /// the `Option` discriminator byte even when the value is `None`.
    #[serde(default)]
    pub nonce_b64: Option<String>,
    /// MLS epoch (`secret_epoch` on the wire).
    pub secret_epoch: u32,
    /// Secure-group plane: `"treekem"` (v0.21.3 ADR-0012) or
    /// `"signed_public"` (legacy). `None` when the daemon omits the
    /// tag — treated as legacy by the decrypt dispatcher to preserve
    /// the pre-v0.21.3 contract.
    ///
    /// `#[serde(default)]` keeps legacy snapshots decoding cleanly;
    /// `skip_serializing_if` is omitted for the same postcard-positional
    /// reason as `nonce_b64`.
    #[serde(default)]
    pub plane: Option<String>,
}

/// Plane tag emitted by x0xd v0.21.3+ on real-`TreeKEM` groups (ADR-0012).
pub const PLANE_TREEKEM: &str = "treekem";

/// Plane tag for the legacy AEAD path. Older daemons omit the field;
/// the decrypt dispatcher treats `None` and this value identically.
pub const PLANE_SIGNED_PUBLIC: &str = "signed_public";

impl EncryptedFrame {
    /// True when the frame's plane is the v0.21.3 `TreeKEM`
    /// `ApplicationCiphertext` shape (nonce embedded in ciphertext).
    /// `None` and `"signed_public"` both return `false` so the decrypt
    /// path keeps requiring `nonce_b64` for the legacy contract.
    #[must_use]
    pub fn is_treekem(&self) -> bool {
        matches!(self.plane.as_deref(), Some(PLANE_TREEKEM))
    }
}

/// Response shape from `POST /groups` for a private-secure group.
#[derive(Clone, Debug, Deserialize)]
pub struct CreatedGroup {
    /// Hex group id assigned by x0xd.
    pub group_id: String,
    /// Gossip topic the group's encrypted frames publish on. Captured
    /// here for callers that opt into x0xd's `/publish` + `/subscribe`
    /// (the M2 chat path uses `RelayTransport` instead per
    /// `private/m2-decisions.md` Decision 1).
    pub chat_topic: String,
}

#[derive(Deserialize)]
struct CreatedGroupResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    chat_topic: Option<String>,
}

/// Group confidentiality as reported by x0xd `GET /groups/<id>`
/// (`policy.confidentiality`).
///
/// The wire spelling is `snake_case`: upstream's `GroupConfidentiality`
/// carries `#[serde(rename_all = "snake_case")]`, and the daemon
/// serializes `policy` verbatim, so the bytes on the wire are
/// `"mls_encrypted"` / `"signed_public"` (NOT the `CamelCase` variant
/// names). The `#[serde(rename_all = "snake_case")]` here mirrors that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    /// PQ MLS/TreeKEM-encrypted.
    MlsEncrypted,
    /// Plaintext `SignedPublic`.
    SignedPublic,
}

/// `GET /groups/<id>` detail body, narrowed to the only field the
/// cold-cache kind lookup needs. `policy` is `#[serde(default)]` so a
/// list-shaped response (which omits it) deserializes to `None` rather
/// than erroring, and the caller surfaces the missing-policy case.
#[derive(Debug, Clone, Deserialize)]
struct GroupMetaResponse {
    #[serde(default)]
    policy: Option<GroupPolicyMeta>,
}

/// The `policy` sub-object, narrowed to the confidentiality axis.
#[derive(Debug, Clone, Deserialize)]
struct GroupPolicyMeta {
    confidentiality: Confidentiality,
}

/// Endpoint wrapper around the x0xd `/groups` + `/secure/*` surface.
/// Owns its own HTTP client + bearer auth — same pattern as
/// [`crate::X0xdSigner`]. Construct via [`SecureGroupsEndpoint::new`].
pub struct SecureGroupsEndpoint {
    base_url: Url,
    api_token: String,
    http: HttpClient,
}

impl std::fmt::Debug for SecureGroupsEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureGroupsEndpoint")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct CreatePrivateSecureRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    preset: &'static str,
    discoverability: &'static str,
}

#[derive(Serialize)]
struct EncryptRequest<'a> {
    payload_b64: &'a str,
}

#[derive(Deserialize)]
struct EncryptResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    ciphertext_b64: Option<String>,
    #[serde(default)]
    nonce_b64: Option<String>,
    #[serde(default)]
    secret_epoch: Option<u32>,
    #[serde(default)]
    secure_plane: Option<String>,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext_b64: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce_b64: Option<&'a str>,
    secret_epoch: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_agent_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    payload_b64: Option<String>,
}

#[derive(Serialize)]
struct PublishRequest<'a> {
    topic: &'a str,
    payload: &'a str,
}

#[derive(Deserialize)]
struct PublishResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Serialize)]
struct ApplyMetadataEventRequest<'a> {
    event_b64: &'a str,
    sender_agent_id: &'a str,
}

#[derive(Deserialize)]
struct ApplyMetadataEventResponse {
    #[serde(default)]
    applied: bool,
}

#[derive(Serialize)]
struct ApplyJoinResultRequest<'a> {
    event_b64: &'a str,
    sender_agent_id: &'a str,
}

#[derive(Deserialize)]
struct ApplyJoinResultResponse {
    #[serde(default)]
    applied: bool,
}

impl SecureGroupsEndpoint {
    /// Build a new endpoint against an x0xd daemon at `base_url`,
    /// authenticated with `api_token`.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] if the underlying reqwest client
    /// fails to build (timeout/TLS configuration error).
    pub fn new(base_url: Url, api_token: impl Into<String>) -> Result<Self, X0xdError> {
        // no_proxy: loopback-only daemon; never route 127.0.0.1 through
        // an ambient corporate proxy. See version.rs for the rationale.
        let http = HttpClient::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base_url,
            api_token: api_token.into(),
            http,
        })
    }

    /// Create a private MLS group with `TreeKEM` activation
    /// (`preset=private_secure` + `discoverability=Hidden`). Returns
    /// the assigned group id and the gossip chat topic.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] on transport failure,
    /// [`X0xdError::Url`] if the base URL fails to join, or
    /// [`X0xdError::Rejected`] if x0xd returns a non-2xx body or a
    /// body that fails the schema (missing `group_id` / `chat_topic`).
    pub async fn create_private_secure(
        &self,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<CreatedGroup, X0xdError> {
        let url = self.base_url.join("groups").map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&CreatePrivateSecureRequest {
                name,
                display_name,
                preset: "private_secure",
                discoverability: "Hidden",
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /groups returned {status}: {body}"
            )));
        }
        let resp: CreatedGroupResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        let group_id = resp
            .group_id
            .ok_or_else(|| X0xdError::Rejected("x0xd response missing group_id".into()))?;
        let chat_topic = resp
            .chat_topic
            .ok_or_else(|| X0xdError::Rejected("x0xd response missing chat_topic".into()))?;
        Ok(CreatedGroup {
            group_id,
            chat_topic,
        })
    }

    /// Encrypt one application frame under the group's current MLS
    /// epoch. Returns ciphertext + nonce + epoch the recipient needs
    /// to feed to [`Self::decrypt`].
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] on transport
    /// failure or URL join failure, [`X0xdError::Rejected`] if x0xd
    /// returns non-2xx, `ok=false`, or omits one of the response
    /// fields needed to construct an [`EncryptedFrame`].
    pub async fn encrypt(
        &self,
        group_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedFrame, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let payload_b64 = B64.encode(plaintext);
        let path = format!("groups/{group_id}/secure/encrypt");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&EncryptRequest {
                payload_b64: &payload_b64,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /secure/encrypt returned {status}: {body}"
            )));
        }
        let resp: EncryptResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        let ciphertext_b64 = resp
            .ciphertext_b64
            .ok_or_else(|| X0xdError::Rejected("encrypt response missing ciphertext_b64".into()))?;
        let secret_epoch = resp
            .secret_epoch
            .ok_or_else(|| X0xdError::Rejected("encrypt response missing secret_epoch".into()))?;
        // v0.21.3 dispatch: real-TreeKEM (ADR-0012) responses tag
        // `secure_plane: "treekem"` and bake the nonce INTO the
        // self-describing `ApplicationCiphertext` carried in
        // `ciphertext_b64` — no separate `nonce_b64` on the wire. Legacy
        // SignedPublic responses (and pre-v0.21.3 daemons) keep the
        // 3-field shape: require `nonce_b64` there to preserve the AEAD
        // contract.
        let plane = resp.secure_plane;
        let nonce_b64 =
            if matches!(plane.as_deref(), Some(PLANE_TREEKEM)) {
                None
            } else {
                Some(resp.nonce_b64.ok_or_else(|| {
                    X0xdError::Rejected("encrypt response missing nonce_b64".into())
                })?)
            };
        Ok(EncryptedFrame {
            ciphertext_b64,
            nonce_b64,
            secret_epoch,
            plane,
        })
    }

    /// Decrypt one application frame. `sender_agent_id` is optional;
    /// when supplied x0xd checks the membership / identity binding.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] on transport
    /// failure, [`X0xdError::Rejected`] if x0xd returns non-2xx,
    /// `ok=false`, or omits `payload_b64`, or if the base64 payload
    /// is malformed.
    pub async fn decrypt(
        &self,
        group_id: &str,
        frame: &EncryptedFrame,
        sender_agent_id: Option<&str>,
    ) -> Result<Vec<u8>, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let path = format!("groups/{group_id}/secure/decrypt");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        // v0.21.3 dispatch: TreeKEM `treekem_group_decrypt` reads only
        // `ciphertext_b64` (the nonce travels inside the
        // `ApplicationCiphertext`). Legacy SignedPublic still needs
        // `nonce_b64` alongside. Omit the field entirely on the TreeKEM
        // path so the daemon's serde parse does not see a spurious
        // legacy-shape key.
        let nonce_b64 =
            if frame.is_treekem() {
                None
            } else {
                Some(frame.nonce_b64.as_deref().ok_or_else(|| {
                    X0xdError::Invalid("legacy decrypt requires nonce_b64".into())
                })?)
            };
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&DecryptRequest {
                ciphertext_b64: &frame.ciphertext_b64,
                nonce_b64,
                secret_epoch: frame.secret_epoch,
                sender_agent_id,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /secure/decrypt returned {status}: {body}"
            )));
        }
        let resp: DecryptResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        let payload_b64 = resp
            .payload_b64
            .ok_or_else(|| X0xdError::Rejected("decrypt response missing payload_b64".into()))?;
        B64.decode(&payload_b64)
            .map_err(|e| X0xdError::Rejected(format!("decrypt payload base64: {e}")))
    }

    /// Publish a base64-encoded payload onto an x0xd gossip topic.
    ///
    /// The v1.0 fetchit-chat group path does NOT use this (chat
    /// messages tunnel through `RelayTransport` instead per
    /// `private/m2-decisions.md` Decision 1). Kept available so etch>it
    /// and future tooling can address the gossip plane directly.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] on transport
    /// failure, [`X0xdError::Rejected`] if x0xd returns non-2xx or
    /// `ok=false`.
    pub async fn publish(&self, topic: &str, payload_b64: &str) -> Result<(), X0xdError> {
        let url = self.base_url.join("publish").map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&PublishRequest {
                topic,
                payload: payload_b64,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /publish returned {status}: {body}"
            )));
        }
        let resp: PublishResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        Ok(())
    }

    /// Fetch a group's confidentiality kind from x0xd `GET /groups/<id>`.
    ///
    /// This is the authoritative kind source for cold-cache routing in
    /// `fetchit_chat::messages::Endpoint::send_to_group`: given only a
    /// `group_id`, the caller can't tell a private MLS group (route via
    /// `/secure/encrypt`) from a public `SignedPublic` room (route via
    /// `/groups/<id>/send`). `GET /groups/<id>` returns the full group
    /// detail whose `policy.confidentiality` axis answers it.
    ///
    /// # Errors
    /// Returns [`X0xdError::Invalid`] when `group_id` is not the 64-hex
    /// shape (rejected locally, before any HTTP). Returns
    /// [`X0xdError::Http`] / [`X0xdError::Url`] on transport / URL-join
    /// failure, and [`X0xdError::Rejected`] when x0xd returns non-2xx or
    /// a body without a `policy` object (e.g. a list-shaped response).
    pub async fn get_group_confidentiality(
        &self,
        group_id: &str,
    ) -> Result<Confidentiality, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let path = format!("groups/{group_id}");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        let raw = self
            .http
            .get(url)
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd GET /groups/{group_id} returned {status}: {body}"
            )));
        }
        let resp: GroupMetaResponse = raw.json().await?;
        resp.policy
            .map(|p| p.confidentiality)
            .ok_or_else(|| X0xdError::Rejected("group meta response missing policy".into()))
    }

    /// Apply a signed `NamedGroupMetadataEvent` to local MLS state via
    /// x0xd `POST /groups/<id>/apply-metadata-event`, with NO gossip
    /// publish. Engine A's cross-NAT group-join re-injects the joiner's
    /// bridged `member_joined` this way: with the metadata gossip mesh off
    /// (v1 + dual-NAT) a plain `publish` reaches no local apply path, so
    /// the owner must apply directly. The daemon re-runs full membership
    /// authority on the event (ML-DSA signature + single-use
    /// `invite_secret` + inviter-gate), so this is a local-delivery
    /// shortcut, never a validation bypass. `sender_agent_id` must be the
    /// event author (the joiner). Returns whether the daemon applied it
    /// (`false` on an idempotent / already-member `409`).
    ///
    /// # Errors
    /// [`X0xdError::Invalid`] when `group_id` is not 64-hex (rejected
    /// locally before any HTTP — path-traversal guard). [`X0xdError::Http`]
    /// / [`X0xdError::Url`] on transport / URL-join failure, and
    /// [`X0xdError::Rejected`] when x0xd returns a status other than
    /// `200` / `409`.
    pub async fn apply_metadata_event(
        &self,
        group_id: &str,
        event_b64: &str,
        sender_agent_id: &str,
    ) -> Result<bool, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let path = format!("groups/{group_id}/apply-metadata-event");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&ApplyMetadataEventRequest {
                event_b64,
                sender_agent_id,
            })
            .send()
            .await?;
        // 200 = applied, 409 = a valid no-op (idempotent / already a
        // member); both carry `{applied}`. Anything else is a real failure.
        let code = raw.status().as_u16();
        if code != 200 && code != 409 {
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd POST /groups/{group_id}/apply-metadata-event returned {code}: {body}"
            )));
        }
        let resp: ApplyMetadataEventResponse = raw.json().await?;
        Ok(resp.applied)
    }

    /// Apply a bridged engine-A join-result (`MemberAdded` with the inline
    /// `TreeKEM` Welcome) on the local x0xd via
    /// `POST /groups/<id>/join-result/<member>`, so a dual-NAT gossip-off
    /// joiner converges WITHOUT the gossip / direct-message anchor (whose own
    /// fetch DMs the NAT'd owner and never lands). The daemon runs the SAME
    /// verifying path as an inbound join-result DM (`member` must equal this
    /// node and `sender_agent_id` must equal the group creator, then
    /// `apply_named_group_metadata_event` processes the Welcome into the
    /// active `TreeKEM` group), so a forged push fails -- a token-gated
    /// local-delivery shortcut, not a validation bypass.
    ///
    /// `group_id` is the STABLE group id (the `MemberAdded` carries it as its
    /// `group_id`); `member` is the joiner (this node); `event_b64` is the
    /// base64 `serde_json` of the `MemberAdded`; `sender_agent_id` is the
    /// owner/creator (the authenticated bridge sender). Returns whether the
    /// daemon applied it (`false` on a `409` idempotent no-op when this node
    /// is already a member).
    ///
    /// # Errors
    /// [`X0xdError::Invalid`] when `group_id` is not 64-hex (rejected
    /// locally before any HTTP -- path-traversal guard). [`X0xdError::Http`]
    /// / [`X0xdError::Url`] on transport / URL-join failure, and
    /// [`X0xdError::Rejected`] when x0xd returns a status other than
    /// `200` / `409` (e.g. a `400` member / sender / event reject the caller
    /// surfaces rather than silently dropping).
    pub async fn apply_join_result(
        &self,
        group_id: &str,
        member: &str,
        event_b64: &str,
        sender_agent_id: &str,
    ) -> Result<bool, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let path = format!("groups/{group_id}/join-result/{member}");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&ApplyJoinResultRequest {
                event_b64,
                sender_agent_id,
            })
            .send()
            .await?;
        // 200 = applied, 409 = idempotent no-op (already a member); both carry
        // `{applied}`. Anything else (incl. a 400 member / sender / event
        // reject) is a real failure the caller surfaces.
        let code = raw.status().as_u16();
        if code != 200 && code != 409 {
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd POST /groups/{group_id}/join-result/{member} returned {code}: {body}"
            )));
        }
        let resp: ApplyJoinResultResponse = raw.json().await?;
        Ok(resp.applied)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 64-hex group id matching the wire shape x0xd's `POST /groups`
    /// returns. Doubles as a stable URL-path component for the
    /// wiremock matchers below.
    const TEST_GROUP_HEX: &str = "4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e";

    #[tokio::test]
    async fn apply_metadata_event_returns_true_on_200_applied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/groups/{TEST_GROUP_HEX}/apply-metadata-event"
            )))
            .and(body_partial_json(
                serde_json::json!({ "event_b64": "ZXZlbnQ", "sender_agent_id": "aa" }),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "applied": true })),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let applied = endpoint
            .apply_metadata_event(TEST_GROUP_HEX, "ZXZlbnQ", "aa")
            .await
            .unwrap();
        assert!(applied);
    }

    #[tokio::test]
    async fn apply_metadata_event_returns_false_on_409_noop() {
        let server = MockServer::start().await;
        // 409 (idempotent / already a member) is a valid no-op, NOT an error.
        Mock::given(method("POST"))
            .and(path(format!(
                "/groups/{TEST_GROUP_HEX}/apply-metadata-event"
            )))
            .respond_with(
                ResponseTemplate::new(409).set_body_json(serde_json::json!({ "applied": false })),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let applied = endpoint
            .apply_metadata_event(TEST_GROUP_HEX, "ZXZlbnQ", "aa")
            .await
            .unwrap();
        assert!(!applied);
    }

    #[tokio::test]
    async fn apply_metadata_event_rejects_bad_group_id_before_http() {
        // A malformed group_id must never reach HTTP (path-traversal guard);
        // mount nothing so any call would surface as a different error shape.
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint
            .apply_metadata_event("not-hex", "ZXZlbnQ", "aa")
            .await
            .unwrap_err();
        assert!(matches!(err, X0xdError::Invalid(_)));
    }

    #[tokio::test]
    async fn apply_join_result_returns_true_on_200_applied() {
        let server = MockServer::start().await;
        let member = "b".repeat(64);
        let owner = "c".repeat(64);
        Mock::given(method("POST"))
            .and(path(format!(
                "/groups/{TEST_GROUP_HEX}/join-result/{member}"
            )))
            .and(body_partial_json(serde_json::json!({
                "event_b64": "ZXY",
                "sender_agent_id": owner,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "applied": true })),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        assert!(endpoint
            .apply_join_result(TEST_GROUP_HEX, &member, "ZXY", &owner)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn apply_join_result_returns_false_on_409_idempotent() {
        let server = MockServer::start().await;
        let member = "b".repeat(64);
        let owner = "c".repeat(64);
        // 409 = already a member: a valid idempotent no-op, not an error.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409).set_body_json(serde_json::json!({ "applied": false })),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        assert!(!endpoint
            .apply_join_result(TEST_GROUP_HEX, &member, "ZXY", &owner)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn apply_join_result_errs_on_403_reject() {
        let server = MockServer::start().await;
        let member = "b".repeat(64);
        let owner = "c".repeat(64);
        // 403 (member != self / sender != creator) and 404 (unknown local
        // group) are surfaced as errors so the dispatch pump logs + drops:
        // a self-targeted member_added the daemon refused is an anomaly,
        // never a fall-through-to-publish.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("not the creator"))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint
            .apply_join_result(TEST_GROUP_HEX, &member, "ZXY", &owner)
            .await
            .unwrap_err();
        assert!(matches!(err, X0xdError::Rejected(_)));
    }

    #[tokio::test]
    async fn encrypt_rejects_empty_group_id_before_http() {
        // P2 from Bob's review: path-traversal via free-form group_id
        // would otherwise let an external caller target arbitrary
        // x0xd HTTP endpoints from this process. `validate_group_id_hex`
        // rejects locally — no HTTP traffic on a malformed id.
        let server = MockServer::start().await;
        // Mount nothing — any attempted HTTP call would surface as a
        // wiremock-side 404, which is a different X0xdError shape.
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint.encrypt("", b"hi").await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(
                    msg.contains("64 hex chars"),
                    "expected length message, got: {msg}",
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt_rejects_wrong_length_group_id() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        // 63 chars — one short of the expected 64.
        let almost = "a".repeat(63);
        let err = endpoint.encrypt(&almost, b"hi").await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("64 hex chars"), "got: {msg}");
                assert!(msg.contains("63"), "should report observed length: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt_rejects_non_hex_group_id_including_path_traversal() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        // Length 64 but containing `../` — the exact path-traversal
        // shape the validator is here to refuse.
        let traversal = format!("../{}", "a".repeat(61));
        assert_eq!(traversal.len(), 64);
        let err = endpoint.encrypt(&traversal, b"hi").await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("ASCII hex"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_wrong_length_group_id() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        let err = endpoint.decrypt("short", &frame, None).await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("64 hex chars"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_non_hex_group_id() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        // 64 chars but contains a Z (non-hex).
        let mut bad = "a".repeat(63);
        bad.push('Z');
        let err = endpoint.decrypt(&bad, &frame, None).await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("ASCII hex"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_frame_round_trips_via_serde_json() {
        let f = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 7,
            plane: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EncryptedFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn encrypted_frame_round_trips_treekem_shape() {
        // TreeKEM (v0.21.3) — nonce baked into ciphertext, no separate
        // `nonce_b64`. Plane tag distinguishes the dispatch path on
        // decrypt.
        let f = EncryptedFrame {
            ciphertext_b64: "QXBwbGljYXRpb25DaXBoZXJ0ZXh0".into(),
            nonce_b64: None,
            secret_epoch: 11,
            plane: Some(PLANE_TREEKEM.into()),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EncryptedFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
        assert!(back.is_treekem());
        assert!(back.nonce_b64.is_none());
    }

    #[test]
    fn encrypted_frame_rejects_missing_epoch() {
        let bad = r#"{"ciphertext_b64":"Y3Q=","nonce_b64":"bm9uY2U="}"#;
        assert!(serde_json::from_str::<EncryptedFrame>(bad).is_err());
    }

    #[test]
    fn encrypted_frame_legacy_shape_decodes_without_plane() {
        // Pre-v0.21.3 daemons / persisted snapshots omit `plane`; the
        // additive `#[serde(default)]` keeps them decoding cleanly as
        // `plane: None` which `is_treekem()` reports as legacy.
        let legacy = r#"{"ciphertext_b64":"Y3Q=","nonce_b64":"bm9uY2U=","secret_epoch":3}"#;
        let f: EncryptedFrame = serde_json::from_str(legacy).unwrap();
        assert!(!f.is_treekem());
        assert_eq!(f.nonce_b64.as_deref(), Some("bm9uY2U="));
        assert!(f.plane.is_none());
    }

    #[tokio::test]
    async fn create_private_secure_sends_correct_preset_and_discoverability() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .and(body_partial_json(serde_json::json!({
                "name": "alpha",
                "preset": "private_secure",
                "discoverability": "Hidden",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": "abc",
                "chat_topic": "x0x.group.abc.chat/general",
            })))
            .mount(&server)
            .await;

        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let g = endpoint.create_private_secure("alpha", None).await.unwrap();
        assert_eq!(g.group_id, "abc");
        assert_eq!(g.chat_topic, "x0x.group.abc.chat/general");
    }

    #[tokio::test]
    async fn create_private_secure_includes_display_name_when_supplied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .and(body_partial_json(serde_json::json!({
                "name": "alpha",
                "display_name": "Alice",
                "preset": "private_secure",
                "discoverability": "Hidden",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": "abc",
                "chat_topic": "x0x.group.abc.chat/general",
            })))
            .mount(&server)
            .await;

        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        endpoint
            .create_private_secure("alpha", Some("Alice"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_private_secure_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_string(r#"{"ok":false,"error":"name already taken"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint
            .create_private_secure("dup", None)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("422"), "status code not in error: {msg}");
                assert!(
                    msg.contains("name already taken"),
                    "body not in error: {msg}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt_posts_payload_b64_and_parses_frame() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/encrypt"))
            .and(body_partial_json(serde_json::json!({
                "payload_b64": "aGk=",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let f = endpoint.encrypt(TEST_GROUP_HEX, b"hi").await.unwrap();
        assert_eq!(f.secret_epoch, 3);
        assert_eq!(f.ciphertext_b64, "Y3Q=");
        assert_eq!(f.nonce_b64.as_deref(), Some("bm9uY2U="));
        // Legacy daemon — no `secure_plane` tag on the wire.
        assert!(f.plane.is_none());
        assert!(!f.is_treekem());
    }

    #[tokio::test]
    async fn encrypt_returns_treekem_frame_without_nonce() {
        // v0.21.3 ADR-0012: `treekem_group_encrypt` emits a
        // self-describing `ApplicationCiphertext` and tags the response
        // `secure_plane: "treekem"` — no separate `nonce_b64`. The
        // pre-fix client errored with "encrypt response missing
        // nonce_b64"; this test pins the new contract so a regression
        // shows up immediately.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/encrypt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "QXBwQ2lwaGVyVGV4dEJsb2I=",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let f = endpoint.encrypt(TEST_GROUP_HEX, b"hi").await.unwrap();
        assert_eq!(f.ciphertext_b64, "QXBwQ2lwaGVyVGV4dEJsb2I=");
        assert!(
            f.nonce_b64.is_none(),
            "treekem frame must not carry a separate nonce_b64"
        );
        assert_eq!(f.secret_epoch, 7);
        assert_eq!(f.plane.as_deref(), Some("treekem"));
        assert!(f.is_treekem());
    }

    #[tokio::test]
    async fn encrypt_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/encrypt"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string(r#"{"ok":false,"error":"not a member"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint.encrypt(TEST_GROUP_HEX, b"hi").await.unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("403"));
                assert!(msg.contains("not a member"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_posts_full_frame_and_returns_plaintext_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        let plaintext = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap();
        assert_eq!(plaintext, b"hi");
    }

    #[tokio::test]
    async fn decrypt_treekem_frame_omits_nonce_in_request() {
        // v0.21.3: TreeKEM `treekem_group_decrypt` reads only
        // `ciphertext_b64`. Sending `nonce_b64` alongside is harmless
        // today but inconsistent with the new contract — and a future
        // strict-mode daemon could 4xx on it. The mock therefore matches
        // a body that lacks `nonce_b64` while carrying the ciphertext.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "ciphertext_b64": "QXBwQ2lwaGVyVGV4dEJsb2I=",
                "secret_epoch": 7,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "QXBwQ2lwaGVyVGV4dEJsb2I=".into(),
            nonce_b64: None,
            secret_epoch: 7,
            plane: Some(PLANE_TREEKEM.into()),
        };
        let plaintext = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap();
        assert_eq!(plaintext, b"hi");

        // Exact-body assertion: the captured POST must not carry
        // `nonce_b64` — `body_partial_json` is presence-only, so we
        // re-inspect the wiremock-captured request bytes to lock it in.
        let received = server.received_requests().await.unwrap();
        let decrypt = received
            .iter()
            .find(|r| r.url.path().ends_with("/secure/decrypt"))
            .expect("decrypt request was captured");
        let body: serde_json::Value = serde_json::from_slice(&decrypt.body).unwrap();
        assert!(
            body.get("nonce_b64").is_none(),
            "treekem decrypt request must omit nonce_b64: {body}"
        );
    }

    #[tokio::test]
    async fn decrypt_passes_sender_agent_id_when_supplied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "sender_agent_id": "abcd1234",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        endpoint
            .decrypt(TEST_GROUP_HEX, &frame, Some("abcd1234"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decrypt_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"ok":false,"error":"stale epoch"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        let err = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("403"), "status code missing: {msg}");
                assert!(msg.contains("stale epoch"), "body missing: {msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_returns_rejected_when_response_payload_b64_is_malformed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "!!!not-valid-base64!!!",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        let err = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(
                    msg.contains("decrypt payload base64"),
                    "expected base64 context in message: {msg}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_legacy_frame_includes_nonce_in_request() {
        // Conservative-semantic check: when the frame was produced by a
        // legacy (non-TreeKEM) encrypt — `plane == None` — the decrypt
        // request MUST still include `nonce_b64`. The mock matches the
        // legacy body shape and the test verifies the request body
        // afterwards so a future "drop nonce on all paths" regression
        // would not just silently slide past wiremock's partial-match
        // semantics.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: Some("bm9uY2U=".into()),
            secret_epoch: 3,
            plane: None,
        };
        endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap();
        let received = server.received_requests().await.unwrap();
        let decrypt = received
            .iter()
            .find(|r| r.url.path().ends_with("/secure/decrypt"))
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&decrypt.body).unwrap();
        assert_eq!(
            body.get("nonce_b64").and_then(|v| v.as_str()),
            Some("bm9uY2U="),
            "legacy decrypt request must carry nonce_b64: {body}",
        );
    }

    #[tokio::test]
    async fn publish_sends_topic_and_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publish"))
            .and(body_partial_json(serde_json::json!({
                "topic": "x0x.group.G.chat/general",
                "payload": "aGk=",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        endpoint
            .publish("x0x.group.G.chat/general", "aGk=")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn publish_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publish"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_string(r#"{"ok":false,"error":"rate limited"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint.publish("t", "x").await.unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("429"));
                assert!(msg.contains("rate limited"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_group_confidentiality_parses_mls_encrypted() {
        // x0xd `GET /groups/<id>` returns the full group detail with a
        // nested `policy` object. The `confidentiality` axis serializes
        // snake_case (GroupConfidentiality has `#[serde(rename_all =
        // "snake_case")]` upstream), so the wire value is the bare string
        // `"mls_encrypted"`, NOT `"MlsEncrypted"`. This test pins the
        // snake_case contract so a future rename trips it.
        let server = MockServer::start().await;
        let group_path = format!("/groups/{TEST_GROUP_HEX}");
        Mock::given(method("GET"))
            .and(path(&group_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": TEST_GROUP_HEX,
                "policy": { "confidentiality": "mls_encrypted" },
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let conf = endpoint
            .get_group_confidentiality(TEST_GROUP_HEX)
            .await
            .unwrap();
        assert_eq!(conf, Confidentiality::MlsEncrypted);
    }

    #[tokio::test]
    async fn get_group_confidentiality_parses_signed_public() {
        let server = MockServer::start().await;
        let group_path = format!("/groups/{TEST_GROUP_HEX}");
        Mock::given(method("GET"))
            .and(path(&group_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "policy": { "confidentiality": "signed_public" },
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let conf = endpoint
            .get_group_confidentiality(TEST_GROUP_HEX)
            .await
            .unwrap();
        assert_eq!(conf, Confidentiality::SignedPublic);
    }

    #[tokio::test]
    async fn get_group_confidentiality_rejects_missing_policy() {
        // A response without `policy` is a schema violation -> Rejected,
        // matching the "response missing <field>" pattern used by the
        // encrypt/decrypt paths.
        let server = MockServer::start().await;
        let group_path = format!("/groups/{TEST_GROUP_HEX}");
        Mock::given(method("GET"))
            .and(path(&group_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint
            .get_group_confidentiality(TEST_GROUP_HEX)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("policy"), "expected policy context: {msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_group_confidentiality_rejects_wrong_length_group_id() {
        // Path-traversal / malformed id must reject locally before HTTP,
        // same as encrypt/decrypt.
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint
            .get_group_confidentiality("short")
            .await
            .unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("64 hex chars"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
