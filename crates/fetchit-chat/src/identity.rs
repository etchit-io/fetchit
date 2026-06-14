//! Agent identity — read your own, generate shareable cards, import
//! someone else's.

use crate::chat_identity::FetchitIdentity;
use crate::error::{ChatError, Result};
use crate::http::Http;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use fetchit_relay_client::Signer;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 64-character hex agent id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

impl AgentId {
    /// Parse a string into an [`AgentId`], validating the 64-char-hex shape.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ChatError::Invalid(format!(
                "agent id must be 64 hex chars; got {} chars",
                s.len()
            )));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    /// First 8 chars — handy for compact UI display.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(8)]
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Your local agent's identity, as reported by the daemon.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentIdentity {
    /// Your agent's 64-char hex id.
    pub agent_id: AgentId,
    /// Machine fingerprint id.
    pub machine_id: String,
    /// Optional human-readable user id (opt-in).
    #[serde(default)]
    pub user_id: Option<String>,
    /// Public KEM key, base64-encoded.
    #[serde(default)]
    pub kem_public_key_b64: Option<String>,
}

/// A shareable identity card returned by `GET /agent/card`. The
/// daemon emits a structured JSON object; the user-facing share form
/// is `x0x://agent/<base64>` of that JSON, produced by
/// [`AgentCard::to_share_uri`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Whose card this is.
    pub agent_id: AgentId,
    /// Display name baked into the card.
    pub display_name: String,
    /// Unix epoch seconds the card was minted.
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Reachable network addresses for the agent.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Remaining card fields the daemon may have populated.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

impl AgentCard {
    /// Encode the card as the `x0x://agent/<base64>` URI that
    /// users paste between devices.
    pub fn to_share_uri(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(format!("x0x://agent/{}", URL_SAFE_NO_PAD.encode(json)))
    }

    /// Decode a card from the user-facing share URI.
    ///
    /// Accepts both the legacy plain-JSON body and the v2 DEFLATE-tagged
    /// body produced by `Endpoint::extended_share_uri`.
    pub fn from_share_uri(uri: &str) -> Result<Self> {
        let v = crate::card::extended_card_from_uri(uri)?;
        Ok(serde_json::from_value(v)?)
    }
}

/// Endpoint wrapper. Build via [`Client::identity`](crate::Client::identity).
pub struct Endpoint<'a> {
    http: &'a Http,
    chat_identity: Option<&'a Arc<FetchitIdentity>>,
    chat_signer: Option<&'a Arc<dyn Signer>>,
}

#[derive(Deserialize)]
struct CardResponse {
    card: AgentCard,
}

#[derive(Serialize)]
struct ImportRequest<'a> {
    /// x0xd expects the card link (`x0x://agent/...`) or its raw
    /// base64 payload, not the decoded card object. See its
    /// `ImportCardRequest::card: String`.
    card: &'a str,
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(
        http: &'a Http,
        chat_identity: Option<&'a Arc<FetchitIdentity>>,
        chat_signer: Option<&'a Arc<dyn Signer>>,
    ) -> Self {
        Self {
            http,
            chat_identity,
            chat_signer,
        }
    }

    /// Read your local agent identity.
    pub async fn me(&self) -> Result<AgentIdentity> {
        self.http.get_json("/agent").await
    }

    /// Generate a shareable identity card with a chosen display name.
    pub async fn card(&self, display_name: &str) -> Result<AgentCard> {
        let encoded = urlencoding(display_name);
        let path = format!("/agent/card?display_name={encoded}");
        let resp: CardResponse = self.http.get_json(&path).await?;
        Ok(resp.card)
    }

    /// Generate a fetchit v2 extended share URI for this device. The
    /// URI is the stock x0x card JSON plus three signed `fetchit_*`
    /// fields carrying our chat-layer KEM public key, the schema
    /// version, and an ML-DSA-65 signature over the canonical card
    /// bytes.
    ///
    /// Callers (peer binary, desktop UI) should prefer this over the
    /// bare [`AgentCard::to_share_uri`] for sharing with chat peers —
    /// without the extension fields, the receiver cannot decrypt v2
    /// DMs.
    ///
    /// # Errors
    /// HTTP errors fetching the stock card; signing errors; JSON shape
    /// errors. Also returns `ChatError::Invalid("chat state not
    /// built…")` if the client was built without `data_dir` /
    /// `passphrase` (REST-only mode has no chat identity to publish a
    /// KEM pubkey for).
    pub async fn extended_share_uri(&self, display_name: &str) -> Result<String> {
        let card = self.card(display_name).await?;
        let card_value = serde_json::to_value(&card)
            .map_err(|e| ChatError::Invalid(format!("card to value: {e}")))?;
        let identity = self.chat_identity.ok_or_else(|| {
            ChatError::Invalid("chat state not built; cannot publish v2 card".into())
        })?;
        let signer = self.chat_signer.ok_or_else(|| {
            ChatError::Invalid("chat state not built; cannot publish v2 card".into())
        })?;
        let extended = crate::card::extend_with_fetchit_fields(
            &card_value,
            identity.kem_public_key(),
            signer.as_ref(),
            None,
        )
        .await?;
        crate::card::extended_card_to_uri(&extended)
    }

    /// Import a card into the local contacts list. Re-encodes the
    /// supplied card to its `x0x://agent/...` URI form before
    /// posting, since x0xd's import endpoint takes the URI string,
    /// not the decoded object.
    pub async fn import(&self, card: &AgentCard) -> Result<()> {
        let uri = card.to_share_uri()?;
        self.import_uri(&uri).await
    }

    /// Import a card directly from its `x0x://agent/...` URI form.
    /// Cheaper than [`Self::import`] when the caller already has the
    /// URI (the common case for the desktop "Add a contact" flow).
    ///
    /// Inbound URIs may be either legacy plain-JSON or v2 DEFLATE-tagged.
    /// x0xd's `/agent/card/import` endpoint understands only the legacy
    /// form, so any v2-tagged URI is decoded + re-emitted as legacy
    /// before being forwarded; the v2-only fields are persisted
    /// separately by the desktop shell.
    pub async fn import_uri(&self, uri: &str) -> Result<()> {
        let card = AgentCard::from_share_uri(uri)?;
        let legacy_uri = card.to_share_uri()?;
        let _: serde_json::Value = self
            .http
            .post_json("/agent/card/import", &ImportRequest { card: &legacy_uri })
            .await?;
        Ok(())
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn id_str() -> String {
        "a".repeat(64)
    }

    #[test]
    fn parse_accepts_lowercase_hex() {
        let id = AgentId::parse(id_str()).unwrap();
        assert_eq!(id.0.len(), 64);
        assert_eq!(id.short(), "aaaaaaaa");
    }

    #[test]
    fn parse_uppercase_normalises_to_lower() {
        let id = AgentId::parse("A".repeat(64)).unwrap();
        assert!(id.0.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn parse_rejects_short() {
        assert!(AgentId::parse("abc").is_err());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(AgentId::parse("g".repeat(64)).is_err());
    }

    #[test]
    fn card_round_trips_via_share_uri() {
        let card = AgentCard {
            agent_id: AgentId::parse(id_str()).unwrap(),
            display_name: "Alice".into(),
            created_at: Some(1_779_740_234),
            addresses: vec!["1.2.3.4:5483".into()],
            extra: serde_json::Value::Null,
        };
        let uri = card.to_share_uri().unwrap();
        assert!(uri.starts_with("x0x://agent/"));
        let back = AgentCard::from_share_uri(&uri).unwrap();
        assert_eq!(back.display_name, "Alice");
        assert_eq!(back.agent_id, card.agent_id);
    }

    #[test]
    fn from_share_uri_rejects_wrong_scheme() {
        assert!(AgentCard::from_share_uri("http://nope").is_err());
    }

    /// `extended_share_uri` produces a DEFLATE-tagged body; the cross-
    /// device import path passes that URI to [`AgentCard::from_share_uri`]
    /// as a client-side sanity check. The legacy parser would bail with
    /// "expected value at line 1 column 1" — this test guards against
    /// that regression.
    #[test]
    fn from_share_uri_accepts_v2_deflate_body() {
        use crate::card::extended_card_to_uri;

        // Build a v2-merged JSON: legacy x0x card fields + the four
        // fetchit-v2 extension fields. extended_card_to_uri encodes
        // and DEFLATE-compresses the whole object.
        let v2_json = serde_json::json!({
            "agent_id": id_str(),
            "display_name": "Alice",
            "created_at": 1_779_740_234_u64,
            "addresses": ["1.2.3.4:5483"],
            "fetchit_card_version": 1,
            "fetchit_kem_public_key_b64": "AAAA",
            "fetchit_agent_public_key_b64": "AAAA",
            "fetchit_card_signature_b64": "AAAA",
        });
        let uri = extended_card_to_uri(&v2_json).unwrap();
        assert!(uri.starts_with("x0x://agent/"));

        // The legacy AgentCard parser must now accept the DEFLATE body.
        let back = AgentCard::from_share_uri(&uri).expect("v2 URI must parse");
        assert_eq!(back.display_name, "Alice");
        assert_eq!(back.agent_id, AgentId::parse(id_str()).unwrap());
    }
}
