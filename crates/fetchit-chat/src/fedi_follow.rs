//! Device-side fediverse follow driver (M7 P1).
//!
//! The bridge holds no keys, so following someone is a device operation:
//! resolve the target, sign a `Follow` with our actor's RSA key, deliver
//! it to their inbox via [`FediverseTransport`], then record the pending
//! follow at the bridge under `bridge-auth-v1` (an ML-DSA agent-key
//! signature over the request). Everything crypto-bearing happens here,
//! on the device; the bridge only verifies + stores.
//!
//! The bridge base URL is derived from our own actor URL
//! (`https://<domain>/actors/<handle>` → `https://<domain>`), so no
//! extra configuration is threaded through.

use fetchit_fedi::activity::build_follow;
use fetchit_fedi::bridge_auth::{canonical_request, HEADER_AGENT, HEADER_SIG, HEADER_TS};
use fetchit_fedi::signature::HttpSignatureKey;

use crate::client::Client;
use crate::error::{ChatError, Result};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

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
        let origin = format!(
            "{}://{}",
            identity.actor_url.scheme(),
            identity
                .actor_url
                .host_str()
                .ok_or_else(|| ChatError::Invalid("actor url has no host".into()))?
        );
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
}
