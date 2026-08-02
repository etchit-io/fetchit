//! Device-side follow-state sync: heal what a single lost delivery
//! would otherwise wedge forever.
//!
//! Two passes, both driven from the ensure path (so a hub-open or the
//! shell's ensure retry loop keeps the follow graph converging without
//! any user ritual):
//!
//! 1. **Drain inbound follow requests.** The bridge queues verified
//!    `Follow` activities (`GET /actors/:h/follow-requests`); the device
//!    signs the `Accept` (the bridge holds no keys), delivers it to the
//!    follower's inbox, then confirms the follower at the bridge (which
//!    consumes the queue entry). Open-follows policy: every verified
//!    request is accepted, matching an unlocked Mastodon account.
//! 2. **Re-assert stuck pending follows.** An `Accept` lost in transit
//!    (server outage, a verify bug window, an expired retry queue) left
//!    the row `pending` forever — the 2026-07/08 `@josh` follow was this
//!    exact class. Re-delivering the SAME `Follow` id is idempotent on
//!    Mastodon-family servers: they answer with a fresh `Accept`.
//!
//! Re-assert damping is process-wide (one device = one process): a
//! pending row is only re-delivered once it is [`REASSERT_MIN_AGE_MS`]
//! old, and attempts per follow id are spaced [`REASSERT_COOLDOWN_MS`]
//! apart regardless of how often the ensure path runs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_fedi::activity::{build_accept_follow, FollowActivity};
use fetchit_fedi::bridge_auth::{canonical_request, HEADER_AGENT, HEADER_SIG, HEADER_TS};
use fetchit_fedi::signature::HttpSignatureKey;
use serde::Deserialize;

use crate::client::Client;
use crate::error::{ChatError, Result};

/// A pending follow younger than this is presumed in-flight — the normal
/// `Accept` round-trip takes seconds, so nothing this fresh is stuck.
pub const REASSERT_MIN_AGE_MS: u64 = 10 * 60 * 1000;
/// Minimum spacing between re-assert attempts for one follow id. The
/// ensure path can run every few seconds while the hub is open; without
/// this the remote inbox would be hammered.
pub const REASSERT_COOLDOWN_MS: u64 = 30 * 60 * 1000;

/// Last re-assert attempt per follow activity id. Process-wide by
/// design: a device runs one client, and damping must survive client
/// rebuilds (the shell tears the gateway down on network changes).
fn reassert_marks() -> &'static Mutex<HashMap<String, u64>> {
    static MARKS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    MARKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Pure damping decision for one pending follow row.
fn should_reassert(now_ms: u64, created_ms: u64, last_attempt_ms: Option<u64>) -> bool {
    if now_ms.saturating_sub(created_ms) < REASSERT_MIN_AGE_MS {
        return false;
    }
    match last_attempt_ms {
        Some(last) => now_ms.saturating_sub(last) >= REASSERT_COOLDOWN_MS,
        None => true,
    }
}

/// What one sync pass actually did.
#[derive(Clone, Copy, Debug, Default)]
pub struct FollowSyncReport {
    /// Inbound follow requests answered with a delivered `Accept` +
    /// bridge confirm.
    pub accepted: u32,
    /// Stuck pending follows whose `Follow` was re-delivered.
    pub reasserted: u32,
}

#[derive(Deserialize)]
struct FollowRequestsBody {
    items: Vec<FollowRequestEntry>,
}

/// One queued inbound follow request from the bridge.
#[derive(Clone, Debug, Deserialize)]
pub struct FollowRequestEntry {
    /// The remote actor asking to follow us.
    pub follower_actor_url: String,
    /// Their inbox — where our signed `Accept` goes.
    pub follower_inbox_url: String,
    /// Their `Follow` activity id — the `Accept` must echo it.
    pub follow_activity_id: String,
}

impl Client {
    /// Run one follow-state sync pass for our actor `handle`: accept
    /// queued inbound follows, re-assert stuck outbound ones. Best-effort
    /// per item — one dead remote server must not block the rest.
    ///
    /// A no-op (zero report) for REST-only clients and unminted handles,
    /// so callers can invoke it unconditionally.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] only on identity-load failure; per-item
    /// transport and bridge failures are logged and skipped.
    pub async fn sync_fedi_follow_state(
        &self,
        handle: &str,
        now_ms: u64,
    ) -> Result<FollowSyncReport> {
        let mut report = FollowSyncReport::default();
        let Some(transport) = self.fediverse_transport() else {
            return Ok(report);
        };
        let transport = Arc::clone(transport);
        let Some(identity) = self.load_actor_identity(handle).await? else {
            return Ok(report);
        };
        let key = HttpSignatureKey {
            key_id: format!("{}#main-key", identity.actor_url),
            rsa_private_pem: identity.rsa_priv_pem.clone(),
        };
        report.accepted = self
            .accept_queued_follows(handle, &identity, &key, &transport, now_ms)
            .await;
        report.reasserted = self
            .reassert_pending_follows(handle, &identity, &key, &transport, now_ms)
            .await;
        Ok(report)
    }

    /// Pass 1: answer every queued inbound follow request with a signed,
    /// delivered `Accept` + bridge confirm. Returns how many succeeded.
    async fn accept_queued_follows(
        &self,
        handle: &str,
        identity: &fetchit_fedi::actor::ActorIdentity,
        key: &HttpSignatureKey,
        transport: &fetchit_fedi::transport::FediverseTransport,
        now_ms: u64,
    ) -> u32 {
        let requests = match self
            .fetch_fedi_follow_requests(handle, identity, now_ms)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[fedi] follow-requests fetch failed: {e}");
                return 0;
            }
        };
        let mut accepted = 0u32;
        for (i, req) in requests.iter().enumerate() {
            let Ok(inbox) = req.follower_inbox_url.parse::<url::Url>() else {
                log::warn!("[fedi] bad follower inbox url {}", req.follower_inbox_url);
                continue;
            };
            // Rebuild THEIR Follow so the Accept echoes it in full.
            let follow = FollowActivity {
                context: "https://www.w3.org/ns/activitystreams".to_owned(),
                id: req.follow_activity_id.clone(),
                kind: "Follow".to_owned(),
                actor: req.follower_actor_url.clone(),
                object: identity.actor_url.to_string(),
            };
            let accept = build_accept_follow(
                identity.actor_url.as_str(),
                &follow,
                now_ms.saturating_add(i as u64),
            );
            let Ok(body) = serde_json::to_vec(&accept) else {
                continue;
            };
            match transport
                .deliver(key, &body, &inbox, &identity.actor_url)
                .await
            {
                Ok(_) => {
                    let confirmed = self
                        .confirm_follower_at_bridge(
                            handle,
                            identity,
                            &req.follower_actor_url,
                            &req.follower_inbox_url,
                            now_ms,
                        )
                        .await
                        .unwrap_or(false);
                    log::info!(
                        "[fedi] accepted inbound follow from {} (confirmed={confirmed})",
                        req.follower_actor_url
                    );
                    accepted = accepted.saturating_add(1);
                }
                Err(e) => log::warn!(
                    "[fedi] accept delivery to {} failed ({e}); request stays queued",
                    req.follower_actor_url
                ),
            }
        }
        accepted
    }

    /// Pass 2: re-deliver the `Follow` for rows stuck `pending` past the
    /// damping thresholds. Returns how many were re-delivered.
    async fn reassert_pending_follows(
        &self,
        handle: &str,
        identity: &fetchit_fedi::actor::ActorIdentity,
        key: &HttpSignatureKey,
        transport: &fetchit_fedi::transport::FediverseTransport,
        now_ms: u64,
    ) -> u32 {
        let rows = match self.list_fedi_following(handle, now_ms).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[fedi] following list fetch failed: {e}");
                return 0;
            }
        };
        let mut reasserted = 0u32;
        for row in rows.iter().filter(|r| r.state == "pending") {
            let last = reassert_marks()
                .lock()
                .ok()
                .and_then(|m| m.get(&row.follow_activity_id).copied());
            if !should_reassert(now_ms, row.created_ms, last) {
                continue;
            }
            let Some(inbox_str) = row.target_inbox_url.as_deref() else {
                continue; // pre-sync bridge: no delivery target recorded
            };
            let Ok(inbox) = inbox_str.parse::<url::Url>() else {
                continue;
            };
            // Mark the attempt BEFORE delivering: a failing remote must be
            // spaced out exactly like a succeeding one.
            if let Ok(mut m) = reassert_marks().lock() {
                m.insert(row.follow_activity_id.clone(), now_ms);
            }
            let follow = FollowActivity {
                context: "https://www.w3.org/ns/activitystreams".to_owned(),
                id: row.follow_activity_id.clone(),
                kind: "Follow".to_owned(),
                actor: identity.actor_url.to_string(),
                object: row.target_actor_url.clone(),
            };
            let Ok(body) = serde_json::to_vec(&follow) else {
                continue;
            };
            match transport
                .deliver(key, &body, &inbox, &identity.actor_url)
                .await
            {
                Ok(_) => {
                    log::info!(
                        "[fedi] re-asserted stuck pending follow of {} ({})",
                        row.target_actor_url,
                        row.follow_activity_id
                    );
                    reasserted = reasserted.saturating_add(1);
                }
                Err(e) => log::warn!(
                    "[fedi] follow re-assert to {} failed: {e}",
                    row.target_actor_url
                ),
            }
        }
        reasserted
    }

    /// `GET {bridge}/actors/{handle}/follow-requests` under
    /// `bridge-auth-v1`.
    async fn fetch_fedi_follow_requests(
        &self,
        handle: &str,
        identity: &fetchit_fedi::actor::ActorIdentity,
        now_ms: u64,
    ) -> Result<Vec<FollowRequestEntry>> {
        let origin = crate::fedi_follow::actor_origin(identity)?;
        let path = format!("/actors/{handle}/follow-requests");
        let canonical = canonical_request("GET", &path, now_ms, b"");
        let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;

        let http = crate::relay_http::guarded_client();
        let resp = http
            .get(format!("{origin}{path}"))
            .header(HEADER_AGENT, agent_id_hex)
            .header(HEADER_TS, now_ms.to_string())
            .header(HEADER_SIG, B64.encode(&sig))
            .send()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge follow-requests GET: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChatError::Invalid(format!(
                "bridge follow-requests: HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body: FollowRequestsBody = resp
            .json()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge follow-requests decode: {e}")))?;
        Ok(body.items)
    }

    /// `POST {bridge}/actors/{handle}/followers/confirm` under
    /// `bridge-auth-v1` — records the follower and consumes the queued
    /// request. Returns `Ok(true)` on 2xx.
    async fn confirm_follower_at_bridge(
        &self,
        handle: &str,
        identity: &fetchit_fedi::actor::ActorIdentity,
        follower_actor_url: &str,
        follower_inbox_url: &str,
        now_ms: u64,
    ) -> Result<bool> {
        let origin = crate::fedi_follow::actor_origin(identity)?;
        let path = format!("/actors/{handle}/followers/confirm");
        let body = serde_json::to_vec(&serde_json::json!({
            "follower_actor_url": follower_actor_url,
            "follower_inbox_url": follower_inbox_url,
        }))
        .map_err(|e| ChatError::Invalid(format!("serialize confirm: {e}")))?;
        let canonical = canonical_request("POST", &path, now_ms, &body);
        let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;

        let http = crate::relay_http::guarded_client();
        let resp = http
            .post(format!("{origin}{path}"))
            .header(HEADER_AGENT, agent_id_hex)
            .header(HEADER_TS, now_ms.to_string())
            .header(HEADER_SIG, B64.encode(&sig))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge confirm POST: {e}")))?;
        Ok(resp.status().is_success())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fresh_pending_rows_are_left_alone() {
        // Younger than REASSERT_MIN_AGE_MS: the normal Accept round-trip
        // is still plausibly in flight.
        assert!(!should_reassert(1_000_000, 1_000_000, None));
        assert!(!should_reassert(
            1_000_000 + REASSERT_MIN_AGE_MS - 1,
            1_000_000,
            None
        ));
    }

    #[test]
    fn old_pending_rows_reassert_once_then_cool_down() {
        let created = 1_000_000;
        let now = created + REASSERT_MIN_AGE_MS;
        assert!(should_reassert(now, created, None), "first attempt fires");
        assert!(
            !should_reassert(now + 1, created, Some(now)),
            "immediate re-run is damped"
        );
        assert!(
            should_reassert(now + REASSERT_COOLDOWN_MS, created, Some(now)),
            "attempt after the cooldown fires again"
        );
    }

    #[test]
    fn accept_echoes_the_followers_own_follow() {
        // The Accept we mint for an inbound request must wrap THEIR
        // Follow verbatim — id, actor, and object — or Mastodon cannot
        // correlate the answer.
        let follow = FollowActivity {
            context: "https://www.w3.org/ns/activitystreams".to_owned(),
            id: "https://mas.to/users/x#follows/9".to_owned(),
            kind: "Follow".to_owned(),
            actor: "https://mas.to/users/x".to_owned(),
            object: "https://etchit.io/actors/josh".to_owned(),
        };
        let accept = build_accept_follow("https://etchit.io/actors/josh", &follow, 77);
        assert_eq!(accept.kind, "Accept");
        assert_eq!(accept.actor, "https://etchit.io/actors/josh");
        assert_eq!(accept.id, "https://etchit.io/actors/josh/accepts/77");
        assert_eq!(accept.object, follow);
    }

    #[test]
    fn follow_requests_body_decodes_bridge_shape() {
        let body = r#"{"items":[{
            "follower_actor_url":"https://mas.to/users/x",
            "follower_inbox_url":"https://mas.to/users/x/inbox",
            "follow_activity_id":"https://mas.to/users/x#follows/9",
            "received_ms":1754000000000
        }]}"#;
        let decoded: FollowRequestsBody = serde_json::from_str(body).unwrap();
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(
            decoded.items[0].follower_actor_url,
            "https://mas.to/users/x"
        );
    }
}
