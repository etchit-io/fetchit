//! Public-room groups — create, invite, send, list.
//!
//! M1 ships groups as **public rooms** (UI label). On the wire we
//! send x0xd's existing `public_open` preset value; user-facing copy
//! says "public room". Group messages flow
//! plaintext over the gossip pub/sub — **no MLS**, no forward
//! secrecy, no membership privacy. The module name "groups" survives;
//! the "MLS" framing did not.
//!
//! PQ-encrypted groups (`TreeKEM` + ML-KEM-768 + ML-DSA-65) are the M2
//! deliverable, consumed from x0xd v0.20.x's MLS surface
//! (`preset=private_secure` + `discoverability=Hidden`, backed by
//! `saorsa-mls v0.3.x`). The M2 design lives at
//! `docs/superpowers/specs/2026-06-02-m2-x0xd-mls-adapter-design.md`.
//! fetch>it does not run an in-process MLS state machine; the chat
//! crate drives x0xd's `/secure/encrypt` + `/secure/decrypt` +
//! `/publish` + `/subscribe` endpoints via REST, with the daemon
//! owning the `TreeKEM` ratchet.
//!
//! ## Submodules
//!
//! - [`bridge`] — M2.5 relay-mediated NAT-traversal helpers. Wraps a
//!   signed `NamedGroupMetadataEvent` as an
//!   `EnvelopeKind::X0xdGroupMetadataEvent` payload so the receiving
//!   daemon can `POST /publish` it locally and advance MLS state via
//!   Saorsa pubsub's loopback semantics.
//! - [`bridge_member_removed`]: JSON event builders for member removal
//!   and other owner-side group-metadata mutations.
//! - [`bridge_member_role_updated`]: JSON event builder for member role
//!   changes when gossip can't deliver.

pub mod bridge;
pub mod bridge_group_deleted;
pub mod bridge_member_banned;
pub mod bridge_member_removed;
pub mod bridge_member_role_updated;
pub mod bridge_policy_updated;
pub mod dispatch;
pub mod join_bridge;
pub mod membership;

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::error::{ChatError, Result};
use crate::http::Http;
use crate::identity::{AgentId, AgentIdentity};
use serde::{Deserialize, Serialize};

/// Opaque group identifier.
///
/// `serde(try_from)` routes incoming JSON through [`GroupId::parse`] so
/// daemon responses can't carry an unvalidated string into the same
/// type that gates HTTP-path interpolation. `serde(into)` keeps wire
/// serialization byte-identical to the prior `transparent` shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct GroupId(String);

impl From<GroupId> for String {
    fn from(g: GroupId) -> Self {
        g.0
    }
}

impl TryFrom<String> for GroupId {
    type Error = ChatError;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl GroupId {
    /// Parse and validate a group ID. Only non-empty strings of
    /// `[a-zA-Z0-9_-]` are accepted. Rejecting `/`, `..`, and other
    /// characters prevents path traversal against the x0xd daemon
    /// when the ID is interpolated into HTTP path segments.
    ///
    /// # Errors
    /// Returns [`ChatError::Invalid`] when `s` is empty or contains
    /// any character outside `[a-zA-Z0-9_-]`.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(ChatError::Invalid("GroupId is empty".into()));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ChatError::Invalid(
                "GroupId contains characters outside [a-zA-Z0-9_-]".into(),
            ));
        }
        Ok(GroupId(s.to_string()))
    }

    /// String view of the group id, safe to interpolate into URL path
    /// segments because `parse` enforces `[a-zA-Z0-9_-]`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Wire-level confidentiality of a group, mirroring x0xd's
/// `policy.confidentiality`. `Private` is the PQ MLS/TreeKEM path
/// (`send_private_group`); `Public` is the `SignedPublic` plaintext path
/// (`groups().send`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum GroupKind {
    /// PQ-encrypted MLS group (`preset=private_secure`, confidentiality
    /// `MlsEncrypted`).
    Private,
    /// Plaintext `SignedPublic` room (`preset=public_open`).
    Public,
}

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
    /// Confidentiality kind. Known locally at create time
    /// (`create` -> `Public`, `create_private` -> `Private`); `None`
    /// when deserialized from x0xd's list/join responses, which omit it.
    /// `messages().send_to_group` resolves a `None` kind on demand via
    /// `GET /groups/<id>`.
    #[serde(default)]
    pub kind: Option<GroupKind>,
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

#[derive(Serialize)]
struct CreatePrivateRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    /// Hard-coded `private_secure` — x0xd v0.20.1+ activates PQ
    /// `TreeKEM` on `private_secure` + `discoverability=Hidden`.
    preset: &'static str,
    /// Hard-coded `Hidden` — required alongside `private_secure` for
    /// `MlsEncrypted` activation per x0xd v0.20.1 release notes.
    discoverability: &'static str,
}

#[derive(Deserialize)]
struct InviteResponse {
    // x0xd 0.19+ calls the field `invite_link` (the full x0x:// URI),
    // not bare `invite`. Earlier shape would have failed decode
    // silently with "transport: error decoding response body".
    invite_link: String,
}

/// `POST /groups/join` response. The `Group` fields are flattened in;
/// `member_joined` is the patched x0xd's synchronous hand-off of the
/// joiner's own freshly-minted, signed `member_joined` event so the
/// cross-NAT bridge does not have to capture it off the (unreliable)
/// gossip SSE. Absent/null when the daemon failed to sign the event.
#[derive(Deserialize)]
struct JoinResponse {
    #[serde(flatten)]
    group: Group,
    #[serde(default)]
    member_joined: Option<SelfJoinEvent>,
}

/// The joiner's own minted `member_joined`, carried inline in the join
/// response. `event_b64` is base64 of the exact gossip-payload bytes
/// (`serde_json::to_vec(event)`), so it decodes byte-identical to what a
/// gossip capture would have yielded.
#[derive(Deserialize)]
struct SelfJoinEvent {
    topic: String,
    event_b64: String,
}

#[derive(Serialize)]
struct JoinRequest<'a> {
    invite: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
}

#[derive(Serialize)]
struct AddMemberRequest<'a> {
    agent_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
}

/// Body for `PATCH /groups/<id>` (group metadata update). Only the
/// fields we set are serialized; an omitted field leaves x0xd's value
/// untouched. We only ever set `name` (rename).
#[derive(Serialize)]
struct UpdateGroupRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Deserialize)]
struct GroupsResponse {
    #[serde(default)]
    groups: Vec<Group>,
}

/// One entry in the response from `GET /groups/<id>/members`. Mirrors
/// the x0xd shape: `agent_id` is the 64-char hex id, `state` is one of
/// `active` | `pending` | `removed`, `role` is `owner` | `admin` |
/// `member`. We surface only what private-group fanout needs (the
/// agent id) and ignore the rest so wire-shape drift is silent for
/// fields we don't consume.
#[derive(Debug, Clone, Deserialize)]
struct GroupMemberEntry {
    agent_id: AgentId,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

/// A group member as surfaced for the roster ("who is in this group")
/// view: their agent id, the display name they joined with (when x0xd
/// has one), their role, and their membership state. Distinct from the
/// bare [`AgentId`] list [`Endpoint::members`] returns for send fanout.
#[derive(Debug, Clone)]
pub struct GroupMemberInfo {
    /// The member's agent id.
    pub agent_id: AgentId,
    /// Display name the member joined or was added with, if x0xd has one.
    pub display_name: Option<String>,
    /// Role as reported by x0xd (`"owner"` / `"admin"` / `"member"`).
    /// Drives owner-gated moderation controls in the UI.
    pub role: Option<String>,
    /// Membership state as reported by x0xd (e.g. `"active"`).
    pub state: Option<String>,
}

#[derive(Deserialize)]
struct GroupMembersResponse {
    #[serde(default)]
    members: Vec<GroupMemberEntry>,
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
        let path = format!("/groups/{}", group.as_str());
        self.http.delete(&path).await
    }

    /// Create a new "public room" — a group whose messages flow
    /// plaintext-over-gossip on x0xd's side (wire-level preset is
    /// `public_open`, surfaced to users as "public room"). The
    /// `/groups/<id>/send` endpoint accepts plaintext directly. This is
    /// the UNENCRYPTED variant; the PQ-encrypted path (MLS `TreeKEM` +
    /// ML-KEM-768 via x0xd `/secure/encrypt`) shipped at M2 and lives in
    /// [`Self::create_private`] + the private-group methods in
    /// [`crate::messages`]. Use `create_private` for private groups.
    pub async fn create(&self, name: &str, display_name: Option<&str>) -> Result<Group> {
        let mut group: Group = self
            .http
            .post_json(
                "/groups",
                &CreateRequest {
                    name,
                    display_name,
                    preset: "public_open",
                },
            )
            .await?;
        // x0xd's create response omits `policy`, so the deserialized
        // kind is None. The preset is `public_open` here, so the kind is
        // known locally -- stamp it so callers (and the send-router's
        // warm cache) skip the GET /groups/<id> round-trip.
        group.kind = Some(GroupKind::Public);
        Ok(group)
    }

    /// Create a private MLS group with PQ `TreeKEM` activation. Backed
    /// by x0xd's `preset=private_secure` + `discoverability=Hidden`,
    /// which the daemon backs with `saorsa-mls v0.3.x` (ML-KEM-768 +
    /// ML-DSA-65). Distinct from [`Self::create`] which makes a
    /// plaintext-on-gossip public room.
    ///
    /// # Errors
    /// Returns whatever the underlying HTTP layer surfaces.
    pub async fn create_private(&self, name: &str, display_name: Option<&str>) -> Result<Group> {
        let mut group: Group = self
            .http
            .post_json(
                "/groups",
                &CreatePrivateRequest {
                    name,
                    display_name,
                    preset: "private_secure",
                    discoverability: "Hidden",
                },
            )
            .await?;
        // The preset is `private_secure` here, so the kind is known
        // locally even though x0xd's create response omits `policy`.
        // Stamp it so the send-router routes through send_private_group
        // without a cold GET /groups/<id> lookup.
        group.kind = Some(GroupKind::Private);
        Ok(group)
    }

    /// Generate a fresh invite link for a group.
    pub async fn invite(&self, group: &GroupId) -> Result<GroupInvite> {
        let path = format!("/groups/{}/invite", group.as_str());
        let resp: InviteResponse = self.http.post_json(&path, &serde_json::json!({})).await?;
        Ok(GroupInvite(resp.invite_link))
    }

    /// Accept a `x0x://invite/…` link into the local roster and block
    /// until x0xd has applied `MemberAdded` locally.
    ///
    /// Two-stage: `POST /groups/join` on x0xd (which David's v0.21.3
    /// `63b5c63` patches with a Welcome-fetch retry), then
    /// [`membership::wait_for_active_membership`] poll-loop against
    /// `GET /groups/<id>/members` so a follow-up `/secure/decrypt` on
    /// an owner-gossiped envelope can't race the convergence and 403
    /// "not a member". The implicit `GET /agent` lookup resolves the
    /// joiner's own id once per call; callers that already hold an
    /// [`AgentId`] should reach for [`Self::join_with_membership_wait`]
    /// to skip it.
    ///
    /// # Errors
    /// - Whatever the underlying HTTP layer surfaces for `/groups/join`
    ///   or `/agent`.
    /// - [`ChatError::JoinerNotConverged`] when x0xd never applies
    ///   `MemberAdded` to the joiner within
    ///   [`membership::membership_wait_timeout`] (the 60s
    ///   [`membership::MEMBERSHIP_WAIT_TIMEOUT`] default, or the
    ///   `FETCHIT_MEMBERSHIP_WAIT_SECS` override).
    pub async fn join(&self, invite: &GroupInvite, display_name: Option<&str>) -> Result<Group> {
        let me: AgentIdentity = self.http.get_json("/agent").await?;
        self.join_with_membership_wait(
            invite,
            display_name,
            &me.agent_id,
            membership::membership_wait_timeout(),
            membership::MEMBERSHIP_POLL_INTERVAL,
        )
        .await
    }

    /// Variant of [`Self::join`] that lets the caller supply the
    /// joiner's [`AgentId`] (skipping the implicit `/agent` round-trip)
    /// and tune the membership-convergence poll window. Used by tests
    /// and by callers that already cached self's id during Client
    /// construction.
    ///
    /// # Errors
    /// Same as [`Self::join`] minus the `/agent` lookup.
    pub async fn join_with_membership_wait(
        &self,
        invite: &GroupInvite,
        display_name: Option<&str>,
        self_id: &AgentId,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Group> {
        let (group, _) = self.join_post(invite, display_name).await?;
        self.wait_membership(&group.group_id, self_id, timeout, poll_interval)
            .await?;
        Ok(group)
    }

    /// Bare `POST /groups/join` with no membership wait, returning the
    /// joined [`Group`] plus the joiner's own freshly-minted, signed
    /// `member_joined` event when the patched daemon hands it back inline
    /// ([`SelfJoinEvent`]). The cross-NAT join
    /// ([`crate::Client::join_group_bridged`]) bridges that event to the
    /// owner instead of capturing it off the gossip SSE — which is
    /// unreliable when the joiner's gossip mesh has not formed. The
    /// `member_joined` is `None` against an unpatched daemon or when the
    /// daemon failed to sign the event.
    ///
    /// # Errors
    /// - Whatever the underlying HTTP layer surfaces for `/groups/join`.
    /// - [`ChatError::Invalid`] when the inline `event_b64` is not valid
    ///   base64.
    pub async fn join_post(
        &self,
        invite: &GroupInvite,
        display_name: Option<&str>,
    ) -> Result<(Group, Option<crate::groups::join_bridge::CapturedSelfJoin>)> {
        let resp: JoinResponse = self
            .http
            .post_json(
                "/groups/join",
                &JoinRequest {
                    invite: &invite.0,
                    display_name,
                },
            )
            .await?;
        let self_join = resp
            .member_joined
            .map(|m| {
                B64.decode(m.event_b64.as_bytes())
                    .map(|payload| crate::groups::join_bridge::CapturedSelfJoin {
                        topic: m.topic,
                        payload,
                    })
                    .map_err(|e| {
                        ChatError::Invalid(format!(
                            "join_post: member_joined event_b64 decode: {e}"
                        ))
                    })
            })
            .transpose()?;
        Ok((resp.group, self_join))
    }

    /// Poll `GET /groups/<id>/members` until `self_id` is `active`. The
    /// wait half of [`Self::join_with_membership_wait`], exposed so the
    /// bridged-join flow can run it *after* emitting its join bridge.
    ///
    /// # Errors
    /// [`ChatError::JoinerNotConverged`] when `self_id` never becomes
    /// active within `timeout`; otherwise whatever `GET /members`
    /// surfaces.
    pub async fn wait_membership(
        &self,
        group_id: &GroupId,
        self_id: &AgentId,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        membership::wait_for_active_membership(
            group_id,
            self_id,
            timeout,
            poll_interval,
            || async { self.members(group_id).await },
        )
        .await
    }

    /// Register an agent as a member of a group from the creator's
    /// side. **The creator must call this for every invitee.**
    ///
    /// `/groups/join` on the invitee establishes their local group
    /// state and subscribes them to the group's metadata gossip topic,
    /// but does NOT add them to /members on either side. Per x0xd's
    /// named-groups model (see `docs/primers/groups.md` upstream),
    /// creator-authored membership changes are what propagate across
    /// subscribed peers — the creator posts a member-add event on the
    /// group's metadata topic and every already-subscribed daemon
    /// (including the invitee's, after their /groups/join) picks up
    /// the converged roster.
    ///
    /// Without this call, the creator's `groups::members()` returns
    /// only the owner and `send_private_group`'s fanout has nothing
    /// to address; symmetrically, the invitee's own /members never
    /// shows them in their own roster.
    ///
    /// # Errors
    /// Whatever the underlying HTTP layer surfaces. 4xx from x0xd
    /// (unknown group, malformed `agent_id`, already-a-member) lands as
    /// [`ChatError::Daemon`].
    pub async fn add_member(
        &self,
        group: &GroupId,
        agent_id: &AgentId,
        display_name: Option<&str>,
    ) -> Result<()> {
        let path = format!("/groups/{}/members", group.as_str());
        let _: serde_json::Value = self
            .http
            .post_json(
                &path,
                &AddMemberRequest {
                    agent_id: &agent_id.0,
                    display_name,
                },
            )
            .await?;
        Ok(())
    }

    /// Send a message into a group.
    pub async fn send(&self, group: &GroupId, body: &str) -> Result<Option<String>> {
        let path = format!("/groups/{}/send", group.as_str());
        let resp: serde_json::Value = self
            .http
            .post_json(&path, &SendGroupRequest { body, kind: "chat" })
            .await?;
        Ok(resp
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(String::from))
    }

    /// Fetch the agent ids of every currently-active member of `group`.
    /// Drives private-group fanout in
    /// [`crate::messages::Endpoint::send_private_group`] — one envelope
    /// per recipient, addressed at the routing layer to each member's
    /// agent id. The local agent is included in the response and the
    /// caller is responsible for filtering itself out.
    ///
    /// Hits `GET /groups/<id>/members`, which returns members along with
    /// `role` and `state`. We surface only `state == "active"` entries
    /// — pending / removed members must not receive new envelopes.
    ///
    /// # Errors
    /// Returns whatever the underlying HTTP layer surfaces. A 404 from
    /// x0xd (unknown group) lands as [`ChatError::Daemon`].
    pub async fn members(&self, group: &GroupId) -> Result<Vec<AgentId>> {
        let path = format!("/groups/{}/members", group.as_str());
        let resp: GroupMembersResponse = self.http.get_json(&path).await?;
        Ok(resp
            .members
            .into_iter()
            .filter(|m| m.state.as_deref().is_none_or(|s| s == "active"))
            .map(|m| m.agent_id)
            .collect())
    }

    /// Fetch the active group roster with display names, for the
    /// "who is in this group" view. Same `/members` call as
    /// [`Self::members`] but keeps the per-member display name x0xd
    /// returns (members join/are-added with one) instead of dropping it,
    /// so the UI can show real names rather than bare agent ids.
    ///
    /// # Errors
    /// Whatever the underlying HTTP layer surfaces; a 404 (unknown
    /// group) lands as [`ChatError::Daemon`].
    pub async fn member_roster(&self, group: &GroupId) -> Result<Vec<GroupMemberInfo>> {
        let path = format!("/groups/{}/members", group.as_str());
        let resp: GroupMembersResponse = self.http.get_json(&path).await?;
        Ok(resp
            .members
            .into_iter()
            .filter(|m| m.state.as_deref().is_none_or(|s| s == "active"))
            .map(|m| GroupMemberInfo {
                agent_id: m.agent_id,
                display_name: m.display_name,
                role: m.role,
                state: m.state,
            })
            .collect())
    }

    /// Remove (kick) a member from a group. Hits
    /// `DELETE /groups/<id>/members/<agent_id>`, which x0xd authorizes
    /// (admin+ only, and the target must not be the owner) and, for a
    /// private group, drives the `TreeKEM` commit that re-keys the room
    /// without the removed member. The UI gates this on the viewer's
    /// role, but x0xd is the real authority — a non-admin caller gets a
    /// 4xx surfaced as [`ChatError::Daemon`].
    ///
    /// # Errors
    /// Whatever the underlying HTTP layer surfaces.
    pub async fn remove_member(&self, group: &GroupId, agent_id: &AgentId) -> Result<()> {
        let path = format!("/groups/{}/members/{}", group.as_str(), agent_id.0);
        self.http.delete(&path).await
    }

    /// Rename a group. `PATCH /groups/<id>` with the new name; x0xd
    /// gates it to admin+ and propagates a `GroupMetadataUpdated` event
    /// so other members see the new name.
    ///
    /// # Errors
    /// Whatever the underlying HTTP layer surfaces (a non-admin caller
    /// 4xxs as [`ChatError::Daemon`]).
    pub async fn rename(&self, group: &GroupId, name: &str) -> Result<()> {
        let path = format!("/groups/{}", group.as_str());
        let _: serde_json::Value = self
            .http
            .patch_json(&path, &UpdateGroupRequest { name: Some(name) })
            .await?;
        Ok(())
    }

    /// Ban a member. `POST /groups/<id>/ban/<agent_id>`; x0xd gates to
    /// admin+, refuses to ban the owner, removes the member (driving the
    /// `TreeKEM` re-key for a private group), and blocks their rejoin.
    /// Stronger than [`Self::remove_member`], which a banned-then-removed
    /// member could undo with a fresh invite.
    ///
    /// # Errors
    /// Whatever the underlying HTTP layer surfaces.
    pub async fn ban_member(&self, group: &GroupId, agent_id: &AgentId) -> Result<()> {
        let path = format!("/groups/{}/ban/{}", group.as_str(), agent_id.0);
        let _: serde_json::Value = self.http.post_json(&path, &serde_json::json!({})).await?;
        Ok(())
    }

    /// Fetch the recent message history for a group. Daemon-side
    /// messages don't carry a stable `message_id` on public groups, so
    /// we synthesise one from the cryptographic signature (which is
    /// per-message-unique) when the daemon omits it.
    pub async fn history(&self, group: &GroupId) -> Result<Vec<GroupMessage>> {
        let path = format!("/groups/{}/messages", group.as_str());
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
    fn group_id_parse_accepts_valid_chars() {
        assert!(GroupId::parse("valid-group_123").is_ok());
        assert!(GroupId::parse("a").is_ok());
        assert!(GroupId::parse("ABC-123_def").is_ok());
        // Lock the accessor round-trip so future refactors can't drift.
        assert_eq!(
            GroupId::parse("valid-group_123").unwrap().as_str(),
            "valid-group_123"
        );
    }

    #[test]
    fn group_id_parse_rejects_invalid() {
        for bad in [
            "",
            "/",
            "..",
            "with space",
            "a/b",
            "with.dot",
            "with:colon",
            "with%encoded",
            "unicode-é",
        ] {
            assert!(GroupId::parse(bad).is_err(), "expected reject for {bad:?}");
        }
        // Pin the error variant so a future refactor surfacing a
        // different variant (e.g. ChatError::Io) doesn't pass this test.
        let err = GroupId::parse("/").unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    #[test]
    fn group_id_deserialize_rejects_traversal() {
        // serde must route through parse — a JSON string containing
        // `/` must fail decode rather than landing in the private field.
        let bad = "\"with/slash\"";
        let parsed: Result<GroupId> =
            serde_json::from_str::<GroupId>(bad).map_err(|e| ChatError::Invalid(e.to_string()));
        assert!(parsed.is_err());
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

    #[test]
    fn create_private_request_includes_private_secure_and_hidden() {
        let req = CreatePrivateRequest {
            name: "alpha",
            display_name: None,
            preset: "private_secure",
            discoverability: "Hidden",
        };
        let json = serde_json::to_string(&req).expect("encode");
        assert!(
            json.contains("\"preset\":\"private_secure\""),
            "preset: {json}"
        );
        assert!(
            json.contains("\"discoverability\":\"Hidden\""),
            "discoverability: {json}"
        );
        assert!(json.contains("\"name\":\"alpha\""), "name: {json}");
        // display_name omitted entirely when None (skip_serializing_if)
        assert!(!json.contains("display_name"), "should be skipped: {json}");
    }

    #[test]
    fn create_private_request_includes_display_name_when_supplied() {
        let req = CreatePrivateRequest {
            name: "alpha",
            display_name: Some("Alice"),
            preset: "private_secure",
            discoverability: "Hidden",
        };
        let json = serde_json::to_string(&req).expect("encode");
        assert!(
            json.contains("\"display_name\":\"Alice\""),
            "display_name: {json}"
        );
    }

    #[test]
    fn group_member_entry_decodes_real_x0xd_shape() {
        // Real shape from `GET /groups/<id>/members` on a 1-member
        // private_secure group — captured live during the Task 12
        // roster probe. Confirms the decode survives the extra fields
        // (added_by, display_name, joined_at, role) we ignore.
        let json = r#"{
            "added_by": null,
            "agent_id": "a48e8af11d8f76a73e59acda012caa4977ecfad91a232aa7e4eebd9537fcc947",
            "display_name": "a48e8af1…",
            "joined_at": 1780455374550,
            "role": "owner",
            "state": "active"
        }"#;
        let m: GroupMemberEntry = serde_json::from_str(json).expect("decode");
        assert_eq!(m.state.as_deref(), Some("active"));
        assert!(m.agent_id.0.starts_with("a48e8af1"));
    }

    #[tokio::test]
    async fn add_member_posts_agent_id_and_display_name() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        let bob = "b".repeat(64);
        Mock::given(method("POST"))
            .and(path(format!("/groups/{gid}/members")))
            .and(body_json(serde_json::json!({
                "agent_id": &bob,
                "display_name": "Bob",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": gid,
                "agent_id": &bob,
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        endpoint
            .add_member(
                &GroupId::parse(gid).unwrap(),
                &AgentId(bob.clone()),
                Some("Bob"),
            )
            .await
            .expect("add_member");
    }

    #[tokio::test]
    async fn add_member_omits_display_name_when_none() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        let bob = "b".repeat(64);
        Mock::given(method("POST"))
            .and(path(format!("/groups/{gid}/members")))
            .and(body_json(serde_json::json!({ "agent_id": &bob })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        endpoint
            .add_member(&GroupId::parse(gid).unwrap(), &AgentId(bob), None)
            .await
            .expect("add_member");
    }

    #[tokio::test]
    async fn members_returns_active_agent_ids() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("GET"))
            .and(path(format!("/groups/{gid}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": gid,
                "member_count": 3,
                "members": [
                    {"agent_id": "a".repeat(64), "role": "owner",  "state": "active"},
                    {"agent_id": "b".repeat(64), "role": "member", "state": "active"},
                    {"agent_id": "c".repeat(64), "role": "member", "state": "active"},
                ]
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        let ids = endpoint
            .members(&GroupId::parse(gid).unwrap())
            .await
            .expect("members");
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0].0, "a".repeat(64));
        assert_eq!(ids[2].0, "c".repeat(64));
    }

    #[tokio::test]
    async fn member_roster_keeps_display_names_and_filters_non_active() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("GET"))
            .and(path(format!("/groups/{gid}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": "a".repeat(64), "display_name": "Alice", "role": "owner", "state": "active"},
                    {"agent_id": "b".repeat(64), "state": "active"},
                    {"agent_id": "c".repeat(64), "display_name": "Carol", "state": "removed"},
                ]
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        let roster = endpoint
            .member_roster(&GroupId::parse(gid).unwrap())
            .await
            .expect("roster");
        // Non-active (Carol) filtered out; display names + role preserved, absent -> None.
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].agent_id.0, "a".repeat(64));
        assert_eq!(roster[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(roster[0].role.as_deref(), Some("owner"));
        assert_eq!(roster[1].agent_id.0, "b".repeat(64));
        assert_eq!(roster[1].display_name, None);
        assert_eq!(roster[1].role, None);
    }

    #[tokio::test]
    async fn remove_member_deletes_the_member_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        let target = "b".repeat(64);
        Mock::given(method("DELETE"))
            .and(path(format!("/groups/{gid}/members/{target}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        endpoint
            .remove_member(&GroupId::parse(gid).unwrap(), &AgentId(target.clone()))
            .await
            .expect("remove_member");
        // Unmatched (wrong) route would 404 -> the mount asserts the DELETE path.
    }

    #[tokio::test]
    async fn rename_patches_the_group_with_the_new_name() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("PATCH"))
            .and(path(format!("/groups/{gid}")))
            .and(body_partial_json(serde_json::json!({ "name": "New Name" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        Endpoint::new(&http)
            .rename(&GroupId::parse(gid).unwrap(), "New Name")
            .await
            .expect("rename");
    }

    #[tokio::test]
    async fn ban_member_posts_to_the_ban_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        let target = "b".repeat(64);
        Mock::given(method("POST"))
            .and(path(format!("/groups/{gid}/ban/{target}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        Endpoint::new(&http)
            .ban_member(&GroupId::parse(gid).unwrap(), &AgentId(target.clone()))
            .await
            .expect("ban");
    }

    #[tokio::test]
    async fn members_filters_out_non_active_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("GET"))
            .and(path(format!("/groups/{gid}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": gid,
                "member_count": 3,
                "members": [
                    {"agent_id": "a".repeat(64), "state": "active"},
                    {"agent_id": "b".repeat(64), "state": "pending"},
                    {"agent_id": "c".repeat(64), "state": "removed"},
                ]
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        let ids = endpoint
            .members(&GroupId::parse(gid).unwrap())
            .await
            .expect("members");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].0, "a".repeat(64));
    }

    #[tokio::test]
    async fn members_treats_missing_state_field_as_active() {
        // Backward-compat: older x0xd revisions may have omitted `state`
        // on the single-member self entry. Treat absent state as active
        // so the fanout doesn't suddenly start dropping the owner.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("GET"))
            .and(path(format!("/groups/{gid}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [{"agent_id": "a".repeat(64)}]
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        let ids = endpoint
            .members(&GroupId::parse(gid).unwrap())
            .await
            .expect("members");
        assert_eq!(ids.len(), 1);
    }

    #[tokio::test]
    async fn members_returns_empty_for_empty_roster() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("GET"))
            .and(path(format!("/groups/{gid}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [],
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        let ids = endpoint
            .members(&GroupId::parse(gid).unwrap())
            .await
            .expect("members");
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn members_surfaces_4xx_as_daemon_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let gid = "abc";
        Mock::given(method("GET"))
            .and(path(format!("/groups/{gid}/members")))
            .respond_with(ResponseTemplate::new(404).set_body_string("group not found"))
            .mount(&server)
            .await;
        let http = crate::http::Http::new(server.uri(), "tok".to_owned()).expect("http");
        let endpoint = Endpoint::new(&http);
        let err = endpoint
            .members(&GroupId::parse(gid).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Daemon { status: 404, .. }),
            "expected Daemon(404), got {err:?}",
        );
    }
}

#[cfg(test)]
mod kind_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn group_defaults_kind_none_and_serdes() {
        let g = Group {
            group_id: GroupId::parse(&"a".repeat(64)).unwrap(),
            name: None,
            member_count: 0,
            is_owner: false,
            kind: Some(GroupKind::Private),
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: Group = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, Some(GroupKind::Private));
        // x0xd /groups list omits kind -> deserializes to None.
        let gid = "a".repeat(64);
        let listed_json = format!(r#"{{"group_id":"{gid}","member_count":0,"is_owner":false}}"#);
        let listed: Group = serde_json::from_str(&listed_json).unwrap();
        assert_eq!(listed.kind, None);
    }
}
