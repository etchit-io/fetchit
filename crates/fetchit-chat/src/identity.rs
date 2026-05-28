//! Agent identity — read your own, generate shareable cards, import
//! someone else's.

use crate::error::{ChatError, Result};
use crate::http::Http;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

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
    pub fn from_share_uri(uri: &str) -> Result<Self> {
        let body = uri
            .strip_prefix("x0x://agent/")
            .ok_or_else(|| ChatError::Invalid("not an x0x://agent/ URI".into()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|e| ChatError::Invalid(format!("base64: {e}")))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Endpoint wrapper. Build via [`Client::identity`](crate::Client::identity).
#[derive(Debug)]
pub struct Endpoint<'a> {
    http: &'a Http,
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
    pub(crate) fn new(http: &'a Http) -> Self {
        Self { http }
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
    pub async fn import_uri(&self, uri: &str) -> Result<()> {
        let _: serde_json::Value = self
            .http
            .post_json("/agent/card/import", &ImportRequest { card: uri })
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
}
