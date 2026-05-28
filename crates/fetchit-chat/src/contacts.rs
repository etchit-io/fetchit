//! Contacts list — list, add, remove, and adjust trust level.

use crate::error::Result;
use crate::http::Http;
use crate::identity::AgentId;
use serde::{Deserialize, Serialize};

/// x0x trust levels, in increasing privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Messages dropped silently — they never know you exist.
    Blocked,
    /// Delivered with annotation; caller decides.
    Unknown,
    /// Delivered normally; not explicitly trusted.
    Known,
    /// Full delivery; can trigger trusted actions.
    Trusted,
}

/// A single contact record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Contact {
    /// Contact's agent id.
    pub agent_id: AgentId,
    /// Optional human-readable label set locally.
    #[serde(default)]
    pub label: Option<String>,
    /// Their declared display name, if known.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Current trust level.
    pub trust_level: TrustLevel,
    /// Unix epoch seconds when you added them.
    #[serde(default)]
    pub added_at: Option<u64>,
    /// Unix epoch seconds of the last interaction.
    #[serde(default)]
    pub last_seen: Option<u64>,
}

/// Endpoint wrapper. Build via [`Client::contacts`](crate::Client::contacts).
#[derive(Debug)]
pub struct Endpoint<'a> {
    http: &'a Http,
}

#[derive(Serialize)]
struct AddRequest<'a> {
    agent_id: &'a str,
    trust_level: TrustLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
}

#[derive(Serialize)]
struct TrustRequest<'a> {
    agent_id: &'a str,
    // The quick-set route on x0xd 0.19+ expects `level`, not
    // `trust_level` — getting this wrong used to 422 silently and the
    // dropdown would snap back to the old value on every refresh.
    level: TrustLevel,
}

#[derive(Deserialize)]
struct ContactsResponse {
    #[serde(default)]
    contacts: Vec<Contact>,
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(http: &'a Http) -> Self {
        Self { http }
    }

    /// List every contact in the local roster.
    pub async fn list(&self) -> Result<Vec<Contact>> {
        let resp: ContactsResponse = self.http.get_json("/contacts").await?;
        Ok(resp.contacts)
    }

    /// Add a contact directly by agent id (alternative to importing a card).
    pub async fn add(
        &self,
        agent_id: &AgentId,
        trust_level: TrustLevel,
        label: Option<&str>,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .http
            .post_json(
                "/contacts",
                &AddRequest {
                    agent_id: &agent_id.0,
                    trust_level,
                    label,
                },
            )
            .await?;
        Ok(())
    }

    /// Remove a contact from the local roster.
    pub async fn remove(&self, agent_id: &AgentId) -> Result<()> {
        let path = format!("/contacts/{}", agent_id.0);
        self.http.delete(&path).await
    }

    /// Adjust a contact's trust level (quick-set endpoint).
    pub async fn set_trust(&self, agent_id: &AgentId, level: TrustLevel) -> Result<()> {
        let _: serde_json::Value = self
            .http
            .post_json(
                "/contacts/trust",
                &TrustRequest {
                    agent_id: &agent_id.0,
                    level,
                },
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn trust_level_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&TrustLevel::Trusted).unwrap(),
            "\"trusted\""
        );
    }

    #[test]
    fn contact_decodes_with_minimal_fields() {
        let json = r#"{"agent_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","trust_level":"known"}"#;
        let c: Contact = serde_json::from_str(json).unwrap();
        assert_eq!(c.trust_level, TrustLevel::Known);
        assert!(c.label.is_none());
        assert!(c.added_at.is_none());
    }

    #[test]
    fn contact_decodes_with_timestamps() {
        let json = r#"{"agent_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","trust_level":"trusted","added_at":1779739867,"last_seen":1779740234}"#;
        let c: Contact = serde_json::from_str(json).unwrap();
        assert_eq!(c.added_at, Some(1_779_739_867));
        assert_eq!(c.last_seen, Some(1_779_740_234));
    }
}
