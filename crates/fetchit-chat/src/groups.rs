//! MLS-encrypted groups — create, invite, send, list.

use crate::error::Result;
use crate::identity::AgentId;
use crate::transport::Http;
use serde::{Deserialize, Serialize};

/// Opaque group identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub String);

/// A group as seen from the local agent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Group {
    /// Stable group id.
    pub group_id: GroupId,
    /// Optional human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Number of members in the local roster.
    #[serde(default)]
    pub member_count: usize,
    /// Whether your agent created this group.
    #[serde(default)]
    pub is_owner: bool,
}

/// A message inside a group.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupMessage {
    /// Group it was sent in.
    pub group_id: GroupId,
    /// Sender.
    pub from: AgentId,
    /// Plaintext (decrypted by the daemon).
    pub body: String,
    /// Unix epoch ms.
    pub timestamp_ms: u64,
    /// `chat`, `system`, etc.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Daemon-assigned message id.
    pub message_id: String,
}

fn default_kind() -> String {
    "chat".to_string()
}

/// A shareable group invite, `x0x://invite/<base64>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupInvite(pub String);

/// Endpoint wrapper. Build via [`Client::groups`](crate::Client::groups).
#[derive(Debug)]
pub struct Endpoint<'a> {
    http: &'a Http,
}

#[derive(Serialize)]
struct CreateRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
}

#[derive(Deserialize)]
struct InviteResponse {
    // x0xd 0.19+ calls the field `invite_link` (the full x0x:// URI),
    // not bare `invite`. Earlier shape would have failed decode
    // silently with "transport: error decoding response body".
    invite_link: String,
}

#[derive(Serialize)]
struct JoinRequest<'a> {
    invite: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
}

#[derive(Deserialize)]
struct GroupsResponse {
    #[serde(default)]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct GroupMessagesResponse {
    #[serde(default)]
    messages: Vec<GroupMessage>,
}

#[derive(Serialize)]
struct SendGroupRequest<'a> {
    body: &'a str,
    kind: &'a str,
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(http: &'a Http) -> Self {
        Self { http }
    }

    /// List groups your agent is a member of.
    pub async fn list(&self) -> Result<Vec<Group>> {
        let resp: GroupsResponse = self.http.get_json("/groups").await?;
        Ok(resp.groups)
    }

    /// Leave or delete a group. The daemon picks based on ownership:
    /// the creator's call removes the group for everyone in the
    /// roster; a non-creator's call leaves it locally only.
    pub async fn leave(&self, group: &GroupId) -> Result<()> {
        let path = format!("/groups/{}", group.0);
        self.http.delete(&path).await
    }

    /// Create a new group with a display name visible to peers.
    pub async fn create(&self, name: &str, display_name: Option<&str>) -> Result<Group> {
        self.http
            .post_json("/groups", &CreateRequest { name, display_name })
            .await
    }

    /// Generate a fresh invite link for a group.
    pub async fn invite(&self, group: &GroupId) -> Result<GroupInvite> {
        let path = format!("/groups/{}/invite", group.0);
        let resp: InviteResponse = self.http.post_json(&path, &serde_json::json!({})).await?;
        Ok(GroupInvite(resp.invite_link))
    }

    /// Accept a `x0x://invite/…` link into the local roster.
    pub async fn join(&self, invite: &GroupInvite, display_name: Option<&str>) -> Result<Group> {
        self.http
            .post_json(
                "/groups/join",
                &JoinRequest {
                    invite: &invite.0,
                    display_name,
                },
            )
            .await
    }

    /// Send a message into a group.
    pub async fn send(&self, group: &GroupId, body: &str) -> Result<Option<String>> {
        let path = format!("/groups/{}/send", group.0);
        let resp: serde_json::Value = self
            .http
            .post_json(&path, &SendGroupRequest { body, kind: "chat" })
            .await?;
        Ok(resp.get("message_id").and_then(|v| v.as_str()).map(String::from))
    }

    /// Fetch the recent message history for a group.
    pub async fn history(&self, group: &GroupId) -> Result<Vec<GroupMessage>> {
        let path = format!("/groups/{}/messages", group.0);
        let resp: GroupMessagesResponse = self.http.get_json(&path).await?;
        Ok(resp.messages)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn group_decodes_daemon_create_response() {
        let json = r#"{"chat_topic":"x0x.group.4d216f18.chat/general","group_id":"4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e","name":"diag-grp","ok":true}"#;
        let g: Group = serde_json::from_str(json).expect("decode");
        assert_eq!(g.name.as_deref(), Some("diag-grp"));
        assert_eq!(g.member_count, 0);
        assert!(!g.is_owner);
    }

    #[test]
    fn groups_list_decodes_daemon_response() {
        let json = r#"{"groups":[{"created_at":1779769097495,"creator":"d8cf933be41c578936cd03eaba1dedf45c3a52165bf7042dcfed808883a97c3c","description":"","group_id":"e2394e8013031dc637a223f18e8a5338df9235560a93ff72db7d4c80a50e497d","member_count":1,"name":"test-grp"}]}"#;
        let resp: GroupsResponse = serde_json::from_str(json).expect("decode");
        assert_eq!(resp.groups.len(), 1);
        assert_eq!(resp.groups[0].member_count, 1);
    }
}
