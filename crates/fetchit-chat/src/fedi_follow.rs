//! Device-side fediverse follow driver (M7 P1).
//!
//! The bridge holds no keys, so following someone is a device operation:
//! resolve the target, sign a `Follow` with our actor's RSA key, deliver
//! it to their inbox via [`FediverseTransport`](fetchit_fedi::transport::FediverseTransport), then record the pending
//! follow at the bridge under `bridge-auth-v1` (an ML-DSA agent-key
//! signature over the request). Everything crypto-bearing happens here,
//! on the device; the bridge only verifies + stores.
//!
//! The bridge base URL is derived from our own actor URL
//! (`https://<domain>/actors/<handle>` → `https://<domain>`), so no
//! extra configuration is threaded through.

use fetchit_fedi::activity::{build_follow, build_undo_follow, FollowActivity};
use fetchit_fedi::bridge_auth::{canonical_request, HEADER_AGENT, HEADER_SIG, HEADER_TS};
use fetchit_fedi::signature::HttpSignatureKey;

use crate::client::Client;
use crate::error::{ChatError, Result};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;

/// Outcome of a follow attempt: the `Follow` activity was signed +
/// delivered, and the bridge recorded the pending follow.
#[derive(Clone, Debug)]
pub struct FollowReport {
    /// Canonical actor URL we followed.
    pub target_actor_url: String,
    /// The `Follow` activity id (the remote `Accept` will echo it).
    pub follow_activity_id: String,
    /// True when the target inbox accepted the delivery. A `false` here
    /// with `recorded == true` means the follow is pending locally but
    /// the remote never saw it — the client can retry delivery.
    pub delivered: bool,
    /// True when the bridge recorded the pending follow.
    pub recorded: bool,
}

impl Client {
    /// Follow a remote fediverse account from our actor `handle`.
    ///
    /// `target` is a `@user@instance` handle. Resolves it (`WebFinger` →
    /// actor doc, SSRF-guarded, denylist-gated), signs + delivers a
    /// `Follow`, then records the pending follow at the bridge. The
    /// remote `Accept` arrives later on the bridge inbox and flips the
    /// state; this call returns as soon as the `Follow` is out and
    /// recorded.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] for REST-only clients (no fedi transport /
    /// no minted actor), a blocked target, an unresolvable handle, or a
    /// signing failure. Delivery + bridge-record failures are reported
    /// in [`FollowReport`] rather than erroring — the follow is a
    /// best-effort two-party handshake and a transient inbox outage
    /// should not lose the local intent.
    pub async fn follow_fedi(
        &self,
        handle: &str,
        target: &str,
        now_ms: u64,
    ) -> Result<FollowReport> {
        let transport = self.fediverse_transport().ok_or_else(|| {
            ChatError::Invalid("fediverse transport not configured (REST-only client)".into())
        })?;
        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;

        // Resolve + denylist-gate the target before anything leaves the
        // device (reuses the publish path's mention resolve+gate).
        let target_url = self.resolve_and_gate_mention(target).await?;
        // Lenient decode: the target is any fediverse actor (Mastodon et al),
        // not necessarily a fetchit actor, so it need not carry a PQ
        // attestation. We only need its inbox to deliver the Follow.
        let target_actor = fetchit_fedi::lookup::fetch_remote_actor(&target_url)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't fetch that account: {e}")))?;
        let target_actor_url = target_actor.id.to_string();
        self.note_fedi_avatar_source(
            &crate::fedi_feed::author_label(&target_actor_url),
            target_actor.icon_url.as_deref(),
        );

        // Build + sign + deliver the Follow.
        let follow = build_follow(identity.actor_url.as_str(), &target_actor_url, now_ms);
        let body = serde_json::to_vec(&follow)
            .map_err(|e| ChatError::Invalid(format!("serialize Follow: {e}")))?;
        let key = HttpSignatureKey {
            key_id: format!("{}#main-key", identity.actor_url),
            rsa_private_pem: identity.rsa_priv_pem.clone(),
        };
        let delivered = transport
            .deliver(&key, &body, &target_actor.inbox, &identity.actor_url)
            .await
            .is_ok();

        // Record the pending follow at the bridge (bridge-auth-v1).
        let recorded = self
            .record_follow_at_bridge(
                handle,
                &identity,
                &target_actor_url,
                target_actor.inbox.as_str(),
                &follow.id,
                now_ms,
            )
            .await
            .unwrap_or(false);

        Ok(FollowReport {
            target_actor_url,
            follow_activity_id: follow.id,
            delivered,
            recorded,
        })
    }

    /// POST the pending follow to `{bridge}/actors/{handle}/following`
    /// under `bridge-auth-v1`. The bridge base is the origin of our own
    /// actor URL. Returns `Ok(true)` on 2xx.
    async fn record_follow_at_bridge(
        &self,
        handle: &str,
        identity: &fetchit_fedi::actor::ActorIdentity,
        target_actor_url: &str,
        target_inbox_url: &str,
        follow_activity_id: &str,
        now_ms: u64,
    ) -> Result<bool> {
        let origin = actor_origin(identity)?;
        let path = format!("/actors/{handle}/following");
        let url = format!("{origin}{path}");

        let body = serde_json::to_vec(&serde_json::json!({
            "target_actor_url": target_actor_url,
            "target_inbox_url": target_inbox_url,
            "follow_activity_id": follow_activity_id,
        }))
        .map_err(|e| ChatError::Invalid(format!("serialize follow record: {e}")))?;

        // Sign the canonical request via the chat agent key (bridge-auth-v1).
        let canonical = canonical_request("POST", &path, now_ms, &body);
        let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;

        let http = crate::relay_http::guarded_client();
        let resp = http
            .post(&url)
            .header(HEADER_AGENT, agent_id_hex)
            .header(HEADER_TS, now_ms.to_string())
            .header(HEADER_SIG, B64.encode(&sig))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge follow POST: {e}")))?;
        Ok(resp.status().is_success())
    }

    /// The accounts our actor `handle` follows, as recorded at the
    /// bridge (owner-only view; the public AP collection serves counts
    /// alone). Fetched under `bridge-auth-v1`.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] on a missing minted identity, transport
    /// failure, a non-2xx bridge answer, or a malformed response body.
    pub async fn list_fedi_following(
        &self,
        handle: &str,
        now_ms: u64,
    ) -> Result<Vec<FollowingEntry>> {
        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;
        let origin = actor_origin(&identity)?;
        let path = format!("/actors/{handle}/following");
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
            .map_err(|e| ChatError::Invalid(format!("bridge following GET: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChatError::Invalid(format!(
                "bridge following list: HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body: FollowingListBody = resp
            .json()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge following decode: {e}")))?;
        Ok(body.items)
    }

    /// The accounts following our actor `handle`, as recorded at the
    /// bridge (owner-only view; the public AP collection serves counts
    /// alone). Fetched under `bridge-auth-v1`. Returns follower actor
    /// URLs, newest first.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] on a missing minted identity, transport
    /// failure, a non-2xx bridge answer, or a malformed response body.
    pub async fn fetch_fedi_followers(&self, handle: &str, now_ms: u64) -> Result<Vec<String>> {
        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;
        let origin = actor_origin(&identity)?;
        let path = format!("/actors/{handle}/followers/list");
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
            .map_err(|e| ChatError::Invalid(format!("bridge followers GET: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChatError::Invalid(format!(
                "bridge followers list: HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body: FollowersListBody = resp
            .json()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge followers decode: {e}")))?;
        Ok(body
            .items
            .into_iter()
            .map(|e| e.follower_actor_url)
            .collect())
    }

    /// Unfollow `target_actor_url` from our actor `handle`: sign +
    /// deliver the `Undo(Follow)` retracting the original activity, then
    /// drop the bridge record. Mirrors [`Self::follow_fedi`]'s
    /// best-effort split — the report carries what actually happened
    /// rather than failing the whole intent on a transient outage.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] for REST-only clients, a missing minted
    /// identity, or when we are not following the target (nothing to
    /// undo).
    pub async fn unfollow_fedi(
        &self,
        handle: &str,
        target_actor_url: &str,
        now_ms: u64,
    ) -> Result<UnfollowReport> {
        let transport = self.fediverse_transport().ok_or_else(|| {
            ChatError::Invalid("fediverse transport not configured (REST-only client)".into())
        })?;
        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;
        // The bridge record carries the original Follow's activity id —
        // the remote side matches the Undo against it.
        let entry = self
            .list_fedi_following(handle, now_ms)
            .await?
            .into_iter()
            .find(|e| e.target_actor_url == target_actor_url)
            .ok_or_else(|| ChatError::Invalid("not following that account".into()))?;

        let follow = FollowActivity {
            context: "https://www.w3.org/ns/activitystreams".to_owned(),
            id: entry.follow_activity_id,
            kind: "Follow".to_owned(),
            actor: identity.actor_url.to_string(),
            object: target_actor_url.to_owned(),
        };
        let undo = build_undo_follow(identity.actor_url.as_str(), &follow);

        // Deliver best-effort: the target's server may be gone, and a
        // dead server must not pin us to a follow forever.
        let delivered = match fetchit_fedi::lookup::fetch_remote_actor(
            &target_actor_url
                .parse()
                .map_err(|e| ChatError::Invalid(format!("target url: {e}")))?,
        )
        .await
        {
            Ok(actor) => {
                let body = serde_json::to_vec(&undo)
                    .map_err(|e| ChatError::Invalid(format!("serialize Undo: {e}")))?;
                let key = HttpSignatureKey {
                    key_id: format!("{}#main-key", identity.actor_url),
                    rsa_private_pem: identity.rsa_priv_pem.clone(),
                };
                transport
                    .deliver(&key, &body, &actor.inbox, &identity.actor_url)
                    .await
                    .is_ok()
            }
            Err(_) => false,
        };

        let removed = self
            .unrecord_follow_at_bridge(handle, &identity, target_actor_url, now_ms)
            .await
            .unwrap_or(false);

        Ok(UnfollowReport { delivered, removed })
    }

    /// POST the unfollow to `{bridge}/actors/{handle}/unfollow` under
    /// `bridge-auth-v1`. Returns `Ok(true)` on 2xx.
    async fn unrecord_follow_at_bridge(
        &self,
        handle: &str,
        identity: &fetchit_fedi::actor::ActorIdentity,
        target_actor_url: &str,
        now_ms: u64,
    ) -> Result<bool> {
        let origin = actor_origin(identity)?;
        let path = format!("/actors/{handle}/unfollow");
        let body = serde_json::to_vec(&serde_json::json!({
            "target_actor_url": target_actor_url,
        }))
        .map_err(|e| ChatError::Invalid(format!("serialize unfollow: {e}")))?;
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
            .map_err(|e| ChatError::Invalid(format!("bridge unfollow POST: {e}")))?;
        Ok(resp.status().is_success())
    }
}

/// One row of the bridge's owner-only following list.
#[derive(Clone, Debug, Deserialize)]
pub struct FollowingEntry {
    /// Remote actor URL the follow targets.
    pub target_actor_url: String,
    /// The target's inbox URL (re-assert delivery target). `None` from a
    /// bridge predating the follow-sync deploy.
    #[serde(default)]
    pub target_inbox_url: Option<String>,
    /// `"pending"` (Follow sent) or `"accepted"` (their Accept arrived).
    pub state: String,
    /// The original Follow's activity id (needed to build the Undo).
    pub follow_activity_id: String,
    /// Bridge-side record time (epoch ms).
    pub created_ms: u64,
}

#[derive(Deserialize)]
struct FollowingListBody {
    items: Vec<FollowingEntry>,
}

/// Body of the bridge `GET /actors/:handle/followers/list` response.
#[derive(Deserialize)]
struct FollowersListBody {
    items: Vec<FollowerEntry>,
}

/// One row of the bridge's owner-only followers list.
#[derive(Deserialize)]
struct FollowerEntry {
    follower_actor_url: String,
}

/// Outcome of an unfollow attempt.
#[derive(Clone, Debug)]
pub struct UnfollowReport {
    /// The `Undo(Follow)` reached the target's inbox.
    pub delivered: bool,
    /// The bridge dropped its follow record.
    pub removed: bool,
}

/// `https://<host>` origin of our own actor URL — the bridge base.
pub(crate) fn actor_origin(identity: &fetchit_fedi::actor::ActorIdentity) -> Result<String> {
    Ok(format!(
        "{}://{}",
        identity.actor_url.scheme(),
        identity
            .actor_url
            .host_str()
            .ok_or_else(|| ChatError::Invalid("actor url has no host".into()))?
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use fetchit_fedi::activity::build_follow;

    // The bridge base is the ORIGIN of the actor URL, and the record path
    // is /actors/<handle>/following — the exact path bridge-auth-v1 signs.
    #[test]
    fn bridge_url_and_path_derivation() {
        let actor = url::Url::parse("https://etchit.io/actors/josh").unwrap();
        let origin = format!("{}://{}", actor.scheme(), actor.host_str().unwrap());
        assert_eq!(origin, "https://etchit.io");
        let handle = "josh";
        let path = format!("/actors/{handle}/following");
        assert_eq!(path, "/actors/josh/following");
        assert_eq!(
            format!("{origin}{path}"),
            "https://etchit.io/actors/josh/following"
        );
    }

    // The follow activity id we mint is what the remote Accept must echo;
    // it must be stable + unique per (actor, counter).
    #[test]
    fn follow_activity_id_is_addressed_to_our_actor() {
        let f = build_follow(
            "https://etchit.io/actors/josh",
            "https://fosstodon.org/users/happyborg",
            42,
        );
        assert_eq!(f.id, "https://etchit.io/actors/josh/follows/42");
        assert_eq!(f.object, "https://fosstodon.org/users/happyborg");
    }

    // Unfollow rebuilds the original Follow from the bridge record; the
    // Undo's id and echoed object must match what the remote side saw,
    // or Mastodon cannot correlate the retraction.
    #[test]
    fn undo_reconstructs_the_original_follow() {
        let follow = fetchit_fedi::activity::FollowActivity {
            context: "https://www.w3.org/ns/activitystreams".to_owned(),
            id: "https://etchit.io/actors/josh/follows/42".to_owned(),
            kind: "Follow".to_owned(),
            actor: "https://etchit.io/actors/josh".to_owned(),
            object: "https://fosstodon.org/users/happyborg".to_owned(),
        };
        let undo =
            fetchit_fedi::activity::build_undo_follow("https://etchit.io/actors/josh", &follow);
        assert_eq!(undo.id, "https://etchit.io/actors/josh/follows/42/undo");
        assert_eq!(undo.object, follow);
        assert_eq!(undo.kind, "Undo");
    }

    // Decode contract for the bridge's owner-only following list — the
    // exact JSON `following_list` emits.
    #[test]
    fn following_list_body_decodes_bridge_shape() {
        let body = r#"{"items":[{
            "target_actor_url":"https://fosstodon.org/users/happyborg",
            "state":"pending",
            "follow_activity_id":"https://etchit.io/actors/josh/follows/42",
            "created_ms":1752000000000
        }]}"#;
        let decoded: super::FollowingListBody = serde_json::from_str(body).unwrap();
        assert_eq!(decoded.items.len(), 1);
        let e = &decoded.items[0];
        assert_eq!(e.target_actor_url, "https://fosstodon.org/users/happyborg");
        assert_eq!(e.state, "pending");
        assert_eq!(e.created_ms, 1_752_000_000_000);
    }
}
