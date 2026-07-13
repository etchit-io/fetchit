//! Device-side fediverse direct-message driver (M7 P3).
//!
//! A fedi DM is an ordinary `ActivityPub` `Create(Note)` with
//! visibility=direct, signed with our actor's RSA key on the device and
//! delivered straight to the recipient's inbox over the same
//! [`FediverseTransport`] a public post or a `Follow` uses. The bridge
//! holds no keys and is not in this path at all — this is a direct
//! device-to-inbox delivery.
//!
//! This message is **not** end-to-end encrypted: the recipient's server
//! (and any relay it federates through) can read it. The UI renders these
//! DMs under a persistent unencrypted-thread banner and never interleaves
//! them with PQ chat (the M7 P3 hard rule). Escalating a fedi DM to a PQ
//! conversation is a separate, user-consented action (P4).

use fetchit_fedi::activity::build_direct_note;
use fetchit_fedi::signature::HttpSignatureKey;

use crate::client::Client;
use crate::error::{ChatError, Result};

/// Outcome of a fedi DM: the `Create(Note)` was signed and an attempt was
/// made to deliver it to the recipient's inbox.
#[derive(Clone, Debug)]
pub struct FediDmReport {
    /// Canonical actor URL the DM was addressed to.
    pub recipient_actor_url: String,
    /// The note object id (`<actor_url>/statuses/<created_at_ms>`).
    pub note_id: String,
    /// True when the recipient inbox accepted the delivery. A `false`
    /// means the DM was signed but the remote inbox was unreachable — the
    /// caller can surface a retry rather than losing the message intent.
    pub delivered: bool,
}

impl Client {
    /// Send a plaintext fediverse DM from our actor `handle` to `target`.
    ///
    /// `target` is a `@user@instance` handle. Resolves it (`WebFinger` →
    /// actor doc, SSRF-guarded, denylist-gated), builds a direct-visibility
    /// `Create(Note)`, signs it with our actor's RSA key, and delivers it
    /// to the recipient's inbox. Returns as soon as the delivery attempt
    /// completes.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] for REST-only clients (no fedi transport / no
    /// minted actor), a blocked target, an unresolvable handle, or a
    /// signing/serialization failure. A transient inbox outage is reported
    /// as `delivered == false` in [`FediDmReport`], not an error.
    pub async fn send_fedi_dm(
        &self,
        handle: &str,
        target: &str,
        body: &str,
        now_ms: u64,
    ) -> Result<FediDmReport> {
        let transport = self.fediverse_transport().ok_or_else(|| {
            ChatError::Invalid("fediverse transport not configured (REST-only client)".into())
        })?;
        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;

        // Resolve + denylist-gate the target before anything leaves the
        // device (reuses the publish/follow path's mention resolve+gate).
        let target_url = self.resolve_and_gate_mention(target).await?;
        // Lenient decode: the recipient is any fediverse actor, not
        // necessarily a fetchit actor, so it carries no PQ attestation. We
        // only need its inbox to deliver the DM.
        let target_actor = fetchit_fedi::lookup::fetch_remote_actor(&target_url)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't fetch that account: {e}")))?;
        let recipient_actor_url = target_actor.id.to_string();

        // Build + sign + deliver the direct Note.
        let activity = build_direct_note(
            identity.actor_url.as_str(),
            &recipient_actor_url,
            target,
            body,
            now_ms,
        );
        let note_id = activity.object.id.clone();
        let wire = serde_json::to_vec(&activity)
            .map_err(|e| ChatError::Invalid(format!("serialize DM: {e}")))?;
        let key = HttpSignatureKey {
            key_id: format!("{}#main-key", identity.actor_url),
            rsa_private_pem: identity.rsa_priv_pem.clone(),
        };
        let delivered = transport
            .deliver(&key, &wire, &target_actor.inbox, &identity.actor_url)
            .await
            .is_ok();

        Ok(FediDmReport {
            recipient_actor_url,
            note_id,
            delivered,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use fetchit_fedi::activity::{build_direct_note, PUBLIC_AUDIENCE};

    // The note id the driver returns is the direct note's own id, addressed
    // to the recipient and never to the public audience — this is what the
    // UI keys a DM thread on.
    #[test]
    fn direct_dm_note_id_is_addressed_to_recipient_only() {
        let activity = build_direct_note(
            "https://etchit.io/actors/josh",
            "https://fosstodon.org/users/happyborg",
            "@happyborg@fosstodon.org",
            "hi over the fediverse",
            42,
        );
        assert_eq!(
            activity.object.id,
            "https://etchit.io/actors/josh/statuses/42"
        );
        assert_eq!(activity.to, vec!["https://fosstodon.org/users/happyborg"]);
        assert!(!activity.to.iter().any(|t| t == PUBLIC_AUDIENCE));
        assert!(activity.cc.is_empty());
    }
}
