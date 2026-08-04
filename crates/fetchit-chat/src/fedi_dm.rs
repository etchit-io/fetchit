//! Device-side fediverse direct-message driver (M7 P3).
//!
//! A fedi DM is an ordinary `ActivityPub` `Create(Note)` with
//! visibility=direct, signed with our actor's RSA key on the device and
//! delivered straight to the recipient's inbox over the same
//! [`FediverseTransport`](fetchit_fedi::transport::FediverseTransport) a public post or a `Follow` uses. The bridge
//! holds no keys and is not in this path at all — this is a direct
//! device-to-inbox delivery.
//!
//! This message is **not** end-to-end encrypted: the recipient's server
//! (and any relay it federates through) can read it. The UI renders these
//! DMs under a persistent unencrypted-thread banner and never interleaves
//! them with PQ chat (the M7 P3 hard rule). Escalating a fedi DM to a PQ
//! conversation is a separate, user-consented action (P4).

use fetchit_fedi::activity::build_direct_note;
use fetchit_fedi::bridge_auth::{canonical_request, HEADER_AGENT, HEADER_SIG, HEADER_TS};
use fetchit_fedi::signature::HttpSignatureKey;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;

use crate::client::Client;
use crate::error::{ChatError, Result};
use crate::fedi_thread::{load_fedi_threads, save_fedi_threads, FediThreadMsg, FediThreadSummary};

/// One inbound fediverse message pulled from the bridge inbox, ready to
/// render in the fedi thread.
#[derive(Clone, Debug, Deserialize)]
pub struct FediInboxMessage {
    /// Sender's canonical actor URL.
    pub sender_actor_url: String,
    /// The Note's id (thread-dedup key on the client too).
    pub note_id: String,
    /// Plain-text body (the bridge already reduced the HTML).
    pub text: String,
    /// ISO-8601 publish stamp as served (may be empty).
    pub published: String,
    /// Bridge receive time (epoch ms) — the cursor axis.
    pub created_ms: i64,
}

#[derive(Deserialize)]
struct InboxListBody {
    items: Vec<FediInboxMessage>,
}

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

        // Thread the reply under the correspondent's most recent inbound
        // note so the recipient's client nests it into the ongoing
        // conversation (Mastodon threads on `inReplyTo`). First contact
        // -- no inbound message yet -- sends a standalone note.
        let reply_to = self.latest_inbound_note_id(handle, target).unwrap_or(None);

        // Build + sign + deliver the direct Note.
        let activity = build_direct_note(
            identity.actor_url.as_str(),
            &recipient_actor_url,
            target,
            body,
            now_ms,
            reply_to.as_deref(),
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

        // Persist the sent DM into the durable thread store BEFORE
        // returning: without this the bubble exists only in shell
        // memory and vanishes on process death. A store failure is
        // logged, not returned — the DM already left for the
        // recipient's inbox, and reporting failure now would be the
        // bigger lie.
        let record = FediThreadMsg {
            outbound: true,
            text: body.to_owned(),
            note_id: note_id.clone(),
            at_ms: i64::try_from(now_ms).unwrap_or(i64::MAX),
            peer_actor_url: recipient_actor_url.clone(),
            delivered,
        };
        if let Err(e) = self.record_fedi_thread_msg(handle, target, record) {
            log::warn!("[chat] fedi DM sent but not persisted locally: {e}");
        }

        Ok(FediDmReport {
            recipient_actor_url,
            note_id,
            delivered,
        })
    }

    /// Pull inbound fediverse messages for our actor `handle` from the
    /// bridge inbox, strictly newer than `since_ms` (0 = from the start).
    /// Owner-only: authed with `bridge-auth-v1` over our agent key.
    /// Returns oldest-first (the render order); the caller advances a
    /// `since_ms` cursor from the last row's `created_ms`.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] on a missing minted identity, transport
    /// failure, non-2xx bridge answer, or malformed body.
    pub async fn fetch_fedi_inbox(
        &self,
        handle: &str,
        since_ms: i64,
        now_ms: u64,
    ) -> Result<Vec<FediInboxMessage>> {
        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;
        let origin = format!(
            "{}://{}",
            identity.actor_url.scheme(),
            identity
                .actor_url
                .host_str()
                .ok_or_else(|| ChatError::Invalid("actor url has no host".into()))?
        );
        // The signed path is the bare route; the cursor rides the query
        // string (not part of the bridge-auth canonical request).
        let path = format!("/actors/{handle}/messages");
        let canonical = canonical_request("GET", &path, now_ms, b"");
        let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;

        let http = crate::relay_http::guarded_client();
        let resp = http
            .get(format!("{origin}{path}?since_ms={since_ms}"))
            .header(HEADER_AGENT, agent_id_hex)
            .header(HEADER_TS, now_ms.to_string())
            .header(HEADER_SIG, B64.encode(&sig))
            .send()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge inbox GET: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChatError::Invalid(format!(
                "bridge inbox list: HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body: InboxListBody = resp
            .json()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge inbox decode: {e}")))?;
        Ok(body.items)
    }

    /// Append one message to `handle`'s durable fedi thread store under
    /// the thread for `label` (canonicalised inside the store),
    /// persisting atomically.
    ///
    /// # Errors
    /// [`ChatError`] on store load/save failures.
    fn record_fedi_thread_msg(&self, handle: &str, label: &str, msg: FediThreadMsg) -> Result<()> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut threads = load_fedi_threads(handle, &master, &layout)?;
        threads.insert(label, msg);
        save_fedi_threads(handle, &threads, &master, &layout)
    }

    /// The note id of the most recent INBOUND message in `handle`'s
    /// thread with `label`, or `None` when the thread has no inbound
    /// message yet (first contact). Used to thread an outbound reply
    /// under what the correspondent last sent.
    ///
    /// # Errors
    /// [`ChatError`] on store load failures.
    fn latest_inbound_note_id(&self, handle: &str, label: &str) -> Result<Option<String>> {
        let (master, layout) = self.fedi_at_rest()?;
        let threads = load_fedi_threads(handle, &master, &layout)?;
        Ok(threads
            .history(label)
            .into_iter()
            .rev()
            .find(|m| !m.outbound)
            .map(|m| m.note_id))
    }

    /// Sync the bridge inbox into the durable thread store: pull
    /// everything newer than the stored cursor, land every message in
    /// its sender's own thread, then advance the cursor. Messages and
    /// cursor persist in one atomic save, so no message can be
    /// cursor-skipped — the loss class behind replies vanishing
    /// on-device. Returns how many messages were new.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] on a missing minted identity, transport
    /// failure, non-2xx bridge answer, malformed body, or store IO.
    pub async fn sync_fedi_inbox(&self, handle: &str, now_ms: u64) -> Result<u32> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut threads = load_fedi_threads(handle, &master, &layout)?;
        let items = self
            .fetch_fedi_inbox(handle, threads.cursor_ms, now_ms)
            .await?;
        if items.is_empty() {
            return Ok(0);
        }
        let inserted = threads.fold_inbox(&items);
        save_fedi_threads(handle, &threads, &master, &layout)?;
        Ok(inserted)
    }

    /// The durable fedi DM thread with `label` (canonicalised), oldest
    /// first — the render source for an `f:<label>` conversation.
    ///
    /// # Errors
    /// [`ChatError`] on store load failures.
    pub fn fedi_thread_history(&self, handle: &str, label: &str) -> Result<Vec<FediThreadMsg>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_threads(handle, &master, &layout)?.history(label))
    }

    /// Every fediverse DM thread as a one-line summary, newest first —
    /// the render source for fediverse rows in the unified conversation
    /// list. A device with no minted handle has no threads.
    ///
    /// # Errors
    /// [`ChatError`] on store load failures.
    pub fn fedi_threads_overview(&self, handle: &str) -> Result<Vec<FediThreadSummary>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_threads(handle, &master, &layout)?.overview())
    }

    /// Mark the fediverse DM thread with `label` read up to its newest
    /// message — the unread count in the conversation list clears and
    /// stays clear across restarts, because the mark is sealed into the
    /// same store as the messages. Returns `true` when the mark moved;
    /// a re-open that changes nothing skips the write.
    ///
    /// # Errors
    /// [`ChatError`] on store load/save failures.
    pub fn mark_fedi_thread_read(&self, handle: &str, label: &str) -> Result<bool> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut threads = load_fedi_threads(handle, &master, &layout)?;
        if !threads.mark_read(label) {
            return Ok(false);
        }
        save_fedi_threads(handle, &threads, &master, &layout)?;
        Ok(true)
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
            None,
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
