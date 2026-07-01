//! Production [`PendingDeliverySink`] — the inbox → public-feed bridge.
//!
//! Stage 3.3 / M4 #200. A gate-passed inbound `ActivityPub` activity
//! is turned into a broadcast `EnvelopeKind::PublicPost` envelope and
//! fanned out to every connected chat session, so the chat-layer drains
//! it like any other envelope. There is no single recipient — a
//! `#Public` post is delivered to whoever is currently online.
//!
//! Two security riders from the #200 sign-off are enforced here:
//!
//! - **RIDER-2 (attribution canonicalisation).** The verified actor URL
//!   is canonicalised through the SAME
//!   [`TargetIdentity::try_new(EntryKind::ActorUrl, ..)`](TargetIdentity::try_new)
//!   path the denylist uses, so a client's
//!   `is_blocked(ActorUrl, ..)` check compares the same canonical form
//!   the denylist publisher stores. The sink fails closed if the actor
//!   URL does not canonicalise — an unverifiable attribution is never
//!   broadcast.
//! - **RIDER-1 (sentinel never a target)** is enforced one layer down
//!   in [`crate::session::SessionRegistry::send`]: the bridge sentinel
//!   id stamped by [`TransitEnvelope::public_post`] is a source marker
//!   only. The broadcast path here never performs a sender lookup, so
//!   it is structurally immune regardless.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use fetchit_relay_proto::{Deliver, ServerFrame, TransitEnvelope};
use fetchit_trust_types::{EntryKind, TargetIdentity};

use super::{PendingDelivery, PendingDeliverySink};
use crate::session::SessionRegistry;

/// [`PendingDeliverySink`] that broadcasts a gate-passed activity to
/// every connected session as an [`EnvelopeKind::PublicPost`] envelope.
///
/// [`EnvelopeKind::PublicPost`]: fetchit_relay_proto::EnvelopeKind::PublicPost
pub struct SessionBroadcastSink {
    sessions: Arc<SessionRegistry>,
}

impl SessionBroadcastSink {
    /// Build a sink fanning out over `sessions` — share the same
    /// `Arc<SessionRegistry>` the WebSocket handler registers into
    /// (see [`crate::server::Server::sessions`]) so broadcasts reach
    /// live connections.
    #[must_use]
    pub fn new(sessions: Arc<SessionRegistry>) -> Self {
        Self { sessions }
    }
}

#[async_trait]
impl PendingDeliverySink for SessionBroadcastSink {
    async fn enqueue(&self, delivery: PendingDelivery) -> Result<(), ()> {
        // RIDER-2: canonicalise the HTTP-Signature-verified actor URL
        // through the SAME path the denylist uses, so the client's
        // actor-denylist check compares canonical-vs-canonical on the
        // same `/v1/denylist?kind=actor_url` form. Fail closed if it
        // does not canonicalise — never broadcast an attribution we
        // can't line up with the denylist (maps to `SinkRejected`
        // upstream; near-impossible after a successful HTTP-Sig verify,
        // whose keyId actor is already an `https://` URL).
        let canonical = TargetIdentity::try_new(EntryKind::ActorUrl, delivery.actor_url)
            .map_err(|_| ())?
            .value;

        let received_ms = system_time_to_ms(delivery.received_at);

        let envelope =
            TransitEnvelope::public_post(canonical, delivery.body, received_ms).map_err(|_| ())?;

        // A broadcast PublicPost is NOT part of any per-connection
        // ordered transit stream, so `transit_seq` is 0 and the client
        // MUST dispatch on `envelope.kind` before any sequence/gap
        // logic (the kind-drives-everything contract from the #200
        // sign-off). `delivered_at_ms` mirrors the inbox receipt time.
        let frame = ServerFrame::Deliver(Deliver {
            envelope,
            transit_seq: 0,
            delivered_at_ms: received_ms,
        });

        // Broadcast-only: no single recipient, and zero online sessions
        // is a valid outcome (public posts are live-only — no transit
        // fallback, history-pull is post-launch). A full session queue
        // is skipped, not an error. So enqueue always succeeds once the
        // envelope is built.
        self.sessions.broadcast(&frame);
        Ok(())
    }
}

/// Milliseconds since the Unix epoch for `t`, saturating to 0 on a
/// pre-epoch clock and to `u64::MAX` on overflow. No casts — the
/// `u128` millis are range-checked into `u64`.
fn system_time_to_ms(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::inbox::SignatureScheme;
    use fetchit_relay_proto::{AgentId, EnvelopeKind, PublicPostPayload, FEDIVERSE_BRIDGE_SENDER};
    use std::time::Duration;
    use tokio::sync::mpsc;

    const RECEIVED_MS: u64 = 1_700_000_000_000;

    fn delivery(actor_url: &str, body: &[u8]) -> PendingDelivery {
        PendingDelivery {
            actor_url: actor_url.to_owned(),
            scheme: SignatureScheme::Rfc9421,
            body: body.to_vec(),
            received_at: SystemTime::UNIX_EPOCH + Duration::from_millis(RECEIVED_MS),
        }
    }

    #[tokio::test]
    async fn enqueue_broadcasts_canonical_public_post_to_connected_session() {
        let sessions = Arc::new(SessionRegistry::new());
        let (tx, mut rx) = mpsc::channel(8);
        let _id = sessions.register(AgentId::from_bytes([7u8; 32]), tx);
        let sink = SessionBroadcastSink::new(sessions.clone());

        let body = br#"{"type":"Create","object":{"type":"Note"}}"#;
        // Non-canonical input: mixed case + trailing slash. RIDER-2
        // must fold it to the denylist's canonical form.
        sink.enqueue(delivery("https://Mastodon.Example/users/Alice/", body))
            .await
            .expect("enqueue succeeds");

        let frame = rx.try_recv().expect("a frame was broadcast");
        let ServerFrame::Deliver(d) = frame else {
            panic!("expected Deliver, got {frame:?}");
        };
        assert_eq!(d.envelope.kind, EnvelopeKind::PublicPost);
        assert_eq!(d.envelope.sender_agent_id, FEDIVERSE_BRIDGE_SENDER);
        assert_eq!(d.envelope.timestamp_ms, RECEIVED_MS);
        assert_eq!(d.transit_seq, 0);
        assert_eq!(d.delivered_at_ms, RECEIVED_MS);

        let payload =
            PublicPostPayload::from_ciphertext(&d.envelope.ciphertext).expect("decode wrapper");
        assert_eq!(
            payload.verified_actor_url, "https://mastodon.example/users/alice",
            "actor URL must be folded to the denylist-canonical form"
        );
        assert_eq!(payload.activity_json, body);
    }

    #[tokio::test]
    async fn enqueue_fails_closed_on_non_canonical_actor() {
        let sessions = Arc::new(SessionRegistry::new());
        let (tx, mut rx) = mpsc::channel(8);
        let _id = sessions.register(AgentId::from_bytes([8u8; 32]), tx);
        let sink = SessionBroadcastSink::new(sessions);

        // `http://` (not `https://`) is rejected by the ActorUrl
        // canonicaliser → fail closed, nothing broadcast.
        let res = sink
            .enqueue(delivery("http://mastodon.example/users/eve", b"{}"))
            .await;
        assert!(res.is_err(), "non-canonical actor must fail closed");
        assert!(
            rx.try_recv().is_err(),
            "a fail-closed delivery must not broadcast anything"
        );
    }

    #[tokio::test]
    async fn enqueue_with_no_connected_sessions_is_ok() {
        // Public posts are live-only: zero online recipients is a valid
        // outcome, not a sink rejection.
        let sink = SessionBroadcastSink::new(Arc::new(SessionRegistry::new()));
        sink.enqueue(delivery("https://mastodon.example/users/alice", b"{}"))
            .await
            .expect("zero-recipient broadcast still succeeds");
    }
}
