//! Presence + FOAF discovery — who's online, find-a-peer-by-id.
//!
//! The daemon emits presence over two surfaces: a snapshot list at
//! `GET /presence/online` (everyone the local view considers online)
//! and an SSE stream at `GET /presence/events` (each `online`/`offline`
//! transition). Use the snapshot for initial render and the event
//! stream for live updates.

use crate::error::Result;
use crate::http::Http;
use crate::identity::AgentId;
use serde::{Deserialize, Serialize};

/// Coarse-grained presence status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceStatus {
    /// Recently saw a beacon.
    Online,
    /// Beacon window expired.
    Offline,
    /// Never seen, or status not yet computed.
    Unknown,
}

/// A peer entry from the online snapshot.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OnlineAgent {
    /// Peer's agent id.
    pub agent_id: AgentId,
    /// Their machine fingerprint id.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Optional user-id binding.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Reachable network addresses at last announce.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Unix epoch seconds the daemon last saw their beacon.
    #[serde(default)]
    pub last_seen: Option<u64>,
    /// Unix epoch seconds they were first announced this session.
    #[serde(default)]
    pub announced_at: Option<u64>,
}

/// A single online/offline transition from the SSE stream.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PresenceTransition {
    /// Peer whose status changed.
    pub agent_id: AgentId,
    /// `online` / `offline`.
    pub event: String,
    /// Whether the daemon can currently reach them.
    #[serde(default)]
    pub reachable: Option<bool>,
}

/// Endpoint wrapper. Build via [`Client::presence`](crate::Client::presence).
#[derive(Debug)]
pub struct Endpoint<'a> {
    http: &'a Http,
}

#[derive(Deserialize)]
struct OnlineResponse {
    #[serde(default)]
    agents: Vec<OnlineAgent>,
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(http: &'a Http) -> Self {
        Self { http }
    }

    /// Every agent currently seen as online by the local daemon.
    pub async fn online(&self) -> Result<Vec<OnlineAgent>> {
        let resp: OnlineResponse = self.http.get_json("/presence/online").await?;
        Ok(resp.agents)
    }

    /// Discover agents via friend-of-a-friend random walks, up to
    /// `ttl` hops.
    pub async fn foaf(&self, ttl: u8) -> Result<Vec<OnlineAgent>> {
        let path = format!("/presence/foaf?ttl={ttl}");
        let resp: OnlineResponse = self.http.get_json(&path).await?;
        Ok(resp.agents)
    }

    /// Look up the current status of a specific agent.
    pub async fn status(&self, agent_id: &AgentId) -> Result<OnlineAgent> {
        let path = format!("/presence/status/{}", agent_id.0);
        self.http.get_json(&path).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn online_agent_decodes_full_shape() {
        let json = r#"{
            "agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "machine_id": "m1",
            "user_id": null,
            "addresses": ["1.2.3.4:5483"],
            "last_seen": 1779740232,
            "announced_at": 1779722357
        }"#;
        let a: OnlineAgent = serde_json::from_str(json).unwrap();
        assert_eq!(a.addresses, vec!["1.2.3.4:5483"]);
        assert_eq!(a.last_seen, Some(1_779_740_232));
    }

    #[test]
    fn transition_decodes() {
        let json = r#"{"agent_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","event":"online","reachable":true}"#;
        let t: PresenceTransition = serde_json::from_str(json).unwrap();
        assert_eq!(t.event, "online");
        assert_eq!(t.reachable, Some(true));
    }
}
