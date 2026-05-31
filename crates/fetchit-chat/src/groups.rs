//! Public-room groups — create, invite, send, list.
//!
//! M1 ships groups as **public rooms** (UI label). On the wire we
//! send x0xd's existing `public_open` preset value; OUR copy +
//! docstrings name it "public room" everywhere users / forum readers
//! / grep-and-screenshot critics will see. Group messages flow
//! plaintext over the gossip pub/sub — **no MLS**, no forward
//! secrecy, no membership privacy. The module name "groups" survives;
//! the "MLS" framing did not.
//!
//! MLS-encrypted groups (RFC 9420 `TreeKEM` + ML-KEM-768) are the M2
//! deliverable. Lighting them up requires either a client-side MLS
//! state machine in this crate driving x0xd's MLS surface, or a swap
//! to `OpenMLS`. Neither exists today.

use crate::error::Result;
use crate::http::Http;
use crate::identity::AgentId;
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
///
/// The `#[serde(rename(deserialize = …))]` attributes only flip the
/// names we read from the daemon — the serialization shape stays
/// `from` / `timestamp_ms`, which is what the JS frontend's
/// `GroupMessage` type expects when this struct crosses the Tauri
/// IPC boundary.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupMessage {
    /// Group it was sent in.
    pub group_id: GroupId,
    /// Sender. Daemon returns this as `author_agent_id`.
    #[serde(rename(deserialize = "author_agent_id"))]
    pub from: AgentId,
    /// Plaintext.
    pub body: String,
    /// Unix epoch ms. Daemon returns this as bare `timestamp`.
    #[serde(rename(deserialize = "timestamp"))]
    pub timestamp_ms: u64,
    /// `chat`, `system`, etc.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Stable identifier. Synthesised from the signature in
    /// [`Endpoint::history`] when the daemon omits it.
    #[serde(default)]
    pub message_id: String,
    /// Cryptographic signature; used as a de-dup key when `message_id`
    /// is missing.
    #[serde(default)]
    pub signature: String,
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
    /// Daemon's named-group policy preset. We use x0xd's `public_open`
    /// wire value so messages travel over the standard
    /// `/groups/<id>/send` + `/messages` plaintext-over-gossip path.
    /// In OUR UI + docs this is surfaced as "public room" — the
    /// announcement-page grep test reads our copy, not x0xd's. MLS
    /// would require a separate `/secure/encrypt` + `/publish`
    /// orchestration not wired yet (M2).
    preset: &'static str,
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

    /// Create a new "public room" — a group whose messages flow
    /// plaintext-over-gossip on x0xd's side (wire-level preset is
    /// `public_open`, surfaced to users as "public room"). The
    /// `/groups/<id>/send` endpoint accepts plaintext directly. MLS
    /// encryption (RFC 9420 `TreeKEM` + ML-KEM-768) is the M2
    /// deliverable; it would require a client-side MLS state machine
    /// in this crate AND a separate `/secure/encrypt` + `/publish`
    /// flow, neither of which exists today.
    pub async fn create(&self, name: &str, display_name: Option<&str>) -> Result<Group> {
        self.http
            .post_json(
                "/groups",
                &CreateRequest {
                    name,
                    display_name,
                    preset: "public_open",
                },
            )
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
        Ok(resp
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(String::from))
    }

    /// Fetch the recent message history for a group. Daemon-side
    /// messages don't carry a stable `message_id` on public groups, so
    /// we synthesise one from the cryptographic signature (which is
    /// per-message-unique) when the daemon omits it.
    pub async fn history(&self, group: &GroupId) -> Result<Vec<GroupMessage>> {
        let path = format!("/groups/{}/messages", group.0);
        let resp: GroupMessagesResponse = self.http.get_json(&path).await?;
        let messages = resp
            .messages
            .into_iter()
            .map(|mut m| {
                if m.message_id.is_empty() {
                    m.message_id = if m.signature.is_empty() {
                        format!("{}-{}", m.timestamp_ms, m.from)
                    } else {
                        m.signature.clone()
                    };
                }
                m
            })
            .collect();
        Ok(messages)
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

    #[test]
    fn group_message_decodes_daemon_shape() {
        // Real shape from /groups/<id>/messages on a public_open group:
        // `author_agent_id`, bare `timestamp`, no `message_id`, plus
        // signature + other public-message-only fields we ignore.
        let json = r#"{
            "author_agent_id": "4dc0f2f6031ee14f7f25f7d8133aa95389a09d023eaa53d2a8c8e977e2dd6c41",
            "author_user_id": null,
            "body": "hi from alice plaintext",
            "group_id": "bfb13a2ddbe518ef76e1c2941b724e8edb9f8c5f6174a54d6e261124fa71b592",
            "kind": "chat",
            "revision_at_send": 0,
            "signature": "3f429c004adb",
            "state_hash_at_send": "b3b2d2632714f5",
            "timestamp": 1779801025898
        }"#;
        let m: GroupMessage = serde_json::from_str(json).expect("decode");
        assert_eq!(m.body, "hi from alice plaintext");
        assert_eq!(m.timestamp_ms, 1_779_801_025_898);
        assert_eq!(m.kind, "chat");
        assert!(m.from.0.starts_with("4dc0f2f6"));
        assert_eq!(m.signature, "3f429c004adb");
    }

    #[test]
    fn create_request_includes_preset() {
        let req = CreateRequest {
            name: "demo",
            display_name: Some("josh"),
            preset: "public_open",
        };
        let json = serde_json::to_string(&req).expect("encode");
        assert!(
            json.contains("\"preset\":\"public_open\""),
            "preset missing: {json}"
        );
        assert!(json.contains("\"name\":\"demo\""));
        assert!(json.contains("\"display_name\":\"josh\""));
    }
}
