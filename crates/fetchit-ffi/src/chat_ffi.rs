//! [`ChatClient`] — daemonless chat surface exposed to the Android shell.
//!
//! Wraps [`fetchit_chat::Client`] (built with the `daemonless` profile) and
//! exposes connect, agent identity, pointer-URI pairing, DM send, and an
//! inbound event pump that surfaces DMs, delivery receipts, and bridged
//! fediverse public posts through a single [`ChatEventFfi`] stream.

use crate::chat_error::ChatFfiError;
use fetchit_chat::conversation::{dispatch_inbound, InboundDispatch};
use fetchit_chat::messages::is_private_group_envelope;
use fetchit_chat::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use url::Url;

/// An inbound chat event delivered by [`ChatClient::next_event`].
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ChatEventFfi {
    /// An inbound direct message.
    Dm {
        /// Hex-encoded sender agent id (64 lowercase hex chars).
        from_agent_id_hex: String,
        /// Message body.
        body: String,
        /// Optional dedupe id for the message; used to correlate receipts.
        message_id: Option<String>,
    },
    /// A delivery receipt for a previously sent message.
    Receipt {
        /// The message id that was received and confirmed decoded.
        message_id: String,
    },
    /// A bridged fediverse public post. `activity_json` is raw
    /// `application/activity+json` bytes delivered verbatim from the relay.
    /// Attribution comes from `verified_actor_url` — the relay-verified,
    /// denylist-canonical signing actor. The `activity_json` body is
    /// UNTRUSTED fediverse content; the render surface MUST sanitize it
    /// before display.
    PublicPost {
        /// Relay-verified actor URL.
        verified_actor_url: String,
        /// Raw Activity Streams JSON bytes. UNTRUSTED — sanitize before
        /// rendering.
        activity_json: Vec<u8>,
    },
}

/// Routing verdict for one inbound transit envelope, in evaluation
/// order: self-originated envelopes are dropped before dispatch, and
/// the all-zeros bridge sentinel can never match a real agent id, so
/// public posts always route.
#[derive(Debug, PartialEq, Eq)]
enum EnvelopeRoute {
    /// Bridge-originated fediverse post: feed the public-post dispatcher.
    PublicPost,
    /// Own send echoed back by the relay: drop silently.
    SelfSource,
    /// Everything else: conversation dispatch.
    Dispatch,
}

fn route_envelope(
    kind: &fetchit_relay_proto::EnvelopeKind,
    sender_hex: &str,
    self_agent_id_hex: &str,
) -> EnvelopeRoute {
    // Keep the SAME order the pump uses today (self-source first, then
    // PublicPost).
    if sender_hex == self_agent_id_hex {
        return EnvelopeRoute::SelfSource;
    }
    if matches!(kind, fetchit_relay_proto::EnvelopeKind::PublicPost) {
        return EnvelopeRoute::PublicPost;
    }
    EnvelopeRoute::Dispatch
}

/// Daemonless chat client for the Android shell.
///
/// Connect with [`ChatClient::connect`], which builds a
/// [`fetchit_chat::Client`] using the daemonless profile (local ML-DSA-65
/// signer; relay WebSocket transport in-process). Inbound events — DMs,
/// receipts, and bridged fediverse public posts — are drained via
/// [`ChatClient::next_event`].
///
/// Call [`ChatClient::disconnect`] when the app no longer needs live chat
/// (background, account switch). [`Drop`] aborts both background tasks as a
/// GC backstop, but `disconnect` is the deterministic path.
#[derive(uniffi::Object)]
pub struct ChatClient {
    inner: Client,
    relay_url: String,
    events: Mutex<mpsc::UnboundedReceiver<ChatEventFfi>>,
    pump_abort: tokio::task::AbortHandle,
    drain_abort: tokio::task::AbortHandle,
}

/// GC backstop: abort both background tasks if the Kotlin side releases
/// the object without calling `disconnect` first. `disconnect` is the
/// deterministic path; `Drop` is the safety net.
///
/// Cycle break trace: after abort, each task drops its captured `Client`
/// clone; once the Kotlin side releases the `Arc<ChatClient>` the struct's
/// `inner` drops too; `Router` and `RelayTransport` refcounts hit zero; the
/// transport's own `Drop` closes the WebSocket (see `impl Drop for RelayTransport` in relay_transport.rs).
impl Drop for ChatClient {
    fn drop(&mut self) {
        self.pump_abort.abort();
        self.drain_abort.abort();
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatClient {
    /// Connect to the relay and build a daemonless chat client.
    ///
    /// `relay_url` must be an HTTP or WebSocket URL of a running fetch>it
    /// relay (e.g. `http://67.207.94.66:8088`). `data_dir` is the
    /// on-device path for the identity vault and conversation store.
    /// `passphrase` derives the at-rest master key.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `relay_url` is malformed.
    /// [`ChatFfiError::Network`] on relay connect or vault bootstrap failure.
    #[uniffi::constructor]
    pub async fn connect(
        relay_url: String,
        data_dir: String,
        passphrase: String,
    ) -> Result<Arc<Self>, ChatFfiError> {
        let parsed_url = Url::parse(&relay_url).map_err(|e| ChatFfiError::Invalid {
            reason: format!("relay_url: {e}"),
        })?;

        let inner = Client::builder()
            .daemonless(true)
            .relay_url(parsed_url)
            .data_dir(PathBuf::from(&data_dir))
            .passphrase(passphrase)
            .build()
            .await
            .map_err(ChatFfiError::from)?;

        let (tx, rx) = mpsc::unbounded_channel::<ChatEventFfi>();

        // Subscribe to bridged fediverse public posts before spawning the
        // inbound pump so no posts are missed between build and subscribe.
        let drain_abort = if let Some(mut post_rx) = inner.subscribe_to_public_posts() {
            let post_tx = tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    match post_rx.recv().await {
                        Ok(delivery) => {
                            let _ = post_tx.send(ChatEventFfi::PublicPost {
                                verified_actor_url: delivery.verified_actor_url,
                                activity_json: delivery.activity_json,
                            });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            // Live-only feed; drop oldest and continue.
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            });
            handle.abort_handle()
        } else {
            // No public-post broadcast; park a no-op task so drain_abort
            // is always a valid handle.
            tokio::spawn(async {}).abort_handle()
        };

        let pump_abort = spawn_inbound_pump(inner.clone(), tx);

        Ok(Arc::new(Self {
            inner,
            relay_url,
            events: Mutex::new(rx),
            pump_abort,
            drain_abort,
        }))
    }

    /// Stop the inbound pump and feed drains, releasing the relay
    /// connection. Idempotent; safe to call more than once. Android
    /// calls this when the app no longer needs live chat (background,
    /// account switch) instead of waiting for garbage collection to
    /// drop the object. After disconnect, `next_event` drains any
    /// already-queued events and then returns `None` forever.
    pub fn disconnect(&self) {
        self.pump_abort.abort();
        self.drain_abort.abort();
    }

    /// The local agent id as lowercase 64-character hex.
    ///
    /// Returns an empty string when the client was built without chat state
    /// (should not happen on the daemonless path).
    pub fn agent_id_hex(&self) -> String {
        self.inner.local_agent_id_hex().unwrap_or_default()
    }

    /// Publish this agent's pair record to the relay, then return a
    /// `x0x://pair/<agent_id>?r=<relay>` URI the user can share.
    ///
    /// Pair record is published first so a peer resolving the URI never
    /// 404s on the relay.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Network`] on relay publish failure.
    /// [`ChatFfiError::Invalid`] when pair URI construction fails.
    pub async fn pair_share_uri(&self) -> Result<String, ChatFfiError> {
        self.inner
            .publish_pair_record()
            .await
            .map_err(ChatFfiError::from)?;

        fetchit_chat::pair_uri::emit_pair_uri(
            &self.agent_id_hex(),
            std::slice::from_ref(&self.relay_url),
        )
        .map_err(|e| ChatFfiError::Invalid {
            reason: e.to_string(),
        })
    }

    /// Import a contact from a `x0x://pair/<agent_id_hex>?r=<relay>...` URI.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] for a malformed URI or self-import.
    /// [`ChatFfiError::Network`] on relay fetch failure.
    pub async fn import_pair_uri(&self, uri: String) -> Result<(), ChatFfiError> {
        self.inner
            .import_pair_uri(uri.trim())
            .await
            .map_err(ChatFfiError::from)
    }

    /// Send a direct message to `to_agent_id_hex`.
    ///
    /// Returns the message id on success (suitable for receipt correlation),
    /// or `None` when the transport succeeded but no id was minted.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `to_agent_id_hex` is not valid 64-hex.
    /// [`ChatFfiError::Network`] on transport or relay failure.
    pub async fn send_dm(
        &self,
        to_agent_id_hex: String,
        body: String,
        sender_name: String,
    ) -> Result<Option<String>, ChatFfiError> {
        let id = fetchit_chat::identity::AgentId::parse(to_agent_id_hex).map_err(|e| {
            ChatFfiError::Invalid {
                reason: e.to_string(),
            }
        })?;
        self.inner
            .messages()
            .send(&id, &body, &sender_name, None, None)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Drain the next inbound event. Returns `None` when the pump has
    /// shut down (relay disconnected and all buffered events consumed).
    ///
    /// Callers should loop on this in a background coroutine:
    /// ```kotlin
    /// while (true) {
    ///     val event = client.nextEvent() ?: break
    ///     // dispatch event ...
    /// }
    /// ```
    pub async fn next_event(&self) -> Option<ChatEventFfi> {
        self.events.lock().await.recv().await
    }
}

/// Spawn the relay inbound pump. Takes the relay transport's inbound
/// channel, classifies each [`fetchit_chat::transport::InboundEnvelope`],
/// and forwards decoded events to `tx`.
///
/// - `PublicPost` envelopes are dispatched via
///   [`Client::dispatch_inbound_public_post`], which feeds the broadcast
///   the public-post subscriber task drains.
/// - `X0xdGroupMetadataEvent` (bridge) envelopes are dispatched via the
///   client's bridge helper and then dropped from the FFI stream.
/// - All other envelopes go through
///   [`fetchit_chat::conversation::dispatch_inbound`]:
///   - `Message` outcomes trigger a best-effort receipt send and produce a
///     [`ChatEventFfi::Dm`].
///   - `Receipt` outcomes produce a [`ChatEventFfi::Receipt`].
///   - Other outcomes (Welcomed, Rekeyed, stale epoch, etc.) are silently
///     ignored — the conversation store is updated as a side-effect.
///
/// A malformed or unrecognised envelope never panics the pump; errors are
/// logged at `warn` level.
///
/// Returns the [`tokio::task::AbortHandle`] for the spawned task so the
/// caller can abort it on disconnect or drop.
fn spawn_inbound_pump(
    client: Client,
    tx: mpsc::UnboundedSender<ChatEventFfi>,
) -> tokio::task::AbortHandle {
    let rx = match client.take_transport_inbound("relay") {
        Some(r) => r,
        None => {
            log::warn!("[chat_ffi] no relay inbound channel; inbound pump not started");
            // Return a handle to a no-op task so the caller always holds a
            // valid AbortHandle.
            return tokio::spawn(async {}).abort_handle();
        }
    };

    tokio::spawn(async move {
        run_inbound_pump(client, rx, tx).await;
    })
    .abort_handle()
}

async fn run_inbound_pump(
    client: Client,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fetchit_chat::transport::InboundEnvelope>,
    tx: mpsc::UnboundedSender<ChatEventFfi>,
) {
    while let Some(mut env) = rx.recv().await {
        let transit = match env.transit.take() {
            Some(t) => t,
            None => continue,
        };

        let sender_hex = hex::encode(transit.sender_agent_id.as_bytes());
        let self_hex = client
            .identity_arc()
            .map(|id| id.agent_id_hex().to_owned())
            .unwrap_or_default();

        match route_envelope(&transit.kind, &sender_hex, &self_hex) {
            EnvelopeRoute::SelfSource => continue,

            EnvelopeRoute::PublicPost => {
                // M4 Stage 5.3: bridged fediverse public post. Dispatch feeds
                // the broadcast that the public-post subscriber task drains
                // into `tx`.
                if let Err(e) = client.dispatch_inbound_public_post(&transit) {
                    log::warn!("[chat_ffi] public-post dispatch dropped envelope: {e}");
                }
                continue;
            }

            EnvelopeRoute::Dispatch => {}
        }

        // M2.5 bridge: X0xdGroupMetadataEvent tunnels MLS state through
        // the relay when gossip can't reach a peer. No FFI event emitted.
        if matches!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent
        ) {
            if let Err(e) = client.dispatch_inbound_bridge(&transit).await {
                log::warn!("[chat_ffi] bridge dispatch dropped envelope: {e}");
            }
            continue;
        }

        // M2 private-group path (PQ-TreeKEM frames from x0xd /secure/encrypt).
        // The daemonless profile has no x0xd, so these frames can't be decrypted
        // here. Log and skip.
        if is_private_group_envelope(&transit) {
            log::warn!("[chat_ffi] private-group envelope received on daemonless client; skipping");
            continue;
        }

        // Chat-v2 conversation path.
        let identity = match client.identity_arc() {
            Some(id) => id,
            None => {
                log::warn!("[chat_ffi] no identity; dropping inbound envelope");
                continue;
            }
        };
        let registry = match client.registry_arc() {
            Some(r) => r,
            None => {
                log::warn!("[chat_ffi] no registry; dropping inbound envelope");
                continue;
            }
        };

        match dispatch_inbound(transit, identity.as_ref(), registry.as_ref()).await {
            Ok(InboundDispatch::Message {
                group_id_hex,
                sender_agent_id_hex,
                payload,
            }) => {
                // Best-effort receipt send (mirrors peer.rs lines 770-786).
                if let Some(message_id) = payload.message_id.as_deref() {
                    let received_at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    if let Err(e) = client
                        .messages()
                        .send_receipt(
                            &group_id_hex,
                            message_id,
                            &sender_agent_id_hex,
                            received_at_ms,
                        )
                        .await
                    {
                        log::warn!("[chat_ffi] receipt send error: {e}");
                    }
                }
                let _ = tx.send(ChatEventFfi::Dm {
                    from_agent_id_hex: sender_agent_id_hex,
                    body: payload.body,
                    message_id: payload.message_id,
                });
            }
            Ok(InboundDispatch::Receipt { message_id, .. }) => {
                let _ = tx.send(ChatEventFfi::Receipt { message_id });
            }
            Ok(_other) => {
                // Welcomed, Rekeyed, WelcomeIgnored, stale epoch, KEM/AEAD
                // failures — conversation state may be updated as a side-
                // effect; no FFI event needed.
            }
            Err(e) => {
                log::warn!("[chat_ffi] dispatch_inbound error: {e}");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // All-zeros hex is the bridge sentinel: 32 zero bytes = 64 '0' chars.
    // A real agent id is SHA-256(AGENT_ID_DOMAIN || public_key), which cannot
    // collide with the all-zeros value in practice.
    const ZEROS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const REAL_HEX: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    #[test]
    fn route_self_source_drops_any_kind() {
        // A GroupChat from self is dropped regardless of kind.
        assert_eq!(
            route_envelope(
                &fetchit_relay_proto::EnvelopeKind::GroupChat,
                REAL_HEX,
                REAL_HEX,
            ),
            EnvelopeRoute::SelfSource,
        );
    }

    #[test]
    fn route_public_post_from_sentinel_routes_public_post() {
        // The all-zeros bridge sentinel is never equal to a real agent id,
        // so a PublicPost from it cannot be self-sourced and must route
        // PublicPost.
        assert_eq!(
            route_envelope(
                &fetchit_relay_proto::EnvelopeKind::PublicPost,
                ZEROS_HEX,
                REAL_HEX,
            ),
            EnvelopeRoute::PublicPost,
        );
    }

    #[test]
    fn route_ordinary_kind_from_other_agent_dispatches() {
        assert_eq!(
            route_envelope(&fetchit_relay_proto::EnvelopeKind::Dm, REAL_HEX, ZEROS_HEX,),
            EnvelopeRoute::Dispatch,
        );
    }

    #[test]
    fn route_public_post_from_real_self_is_self_source() {
        // Self-source check runs first: even a PublicPost whose sender_hex
        // equals self_agent_id_hex (unusual but valid to test order) is
        // dropped as SelfSource. This exercises the evaluation-order comment
        // in route_envelope.
        assert_eq!(
            route_envelope(
                &fetchit_relay_proto::EnvelopeKind::PublicPost,
                REAL_HEX,
                REAL_HEX,
            ),
            EnvelopeRoute::SelfSource,
        );
    }

    /// Verify that the daemonless client connects to the production NYC relay
    /// and returns a well-formed local agent id. This is the first-ever
    /// daemonless connect against prod; it exercises vault bootstrap + relay
    /// WebSocket handshake.
    ///
    /// Requires network access; excluded from CI by default.
    #[tokio::test]
    #[ignore = "requires network + live relay"]
    async fn connect_against_prod_relay_round_trips_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let client = ChatClient::connect(
            "http://67.207.94.66:8088".into(),
            dir.path().to_str().unwrap().to_owned(),
            "test-passphrase-ffi-smoke".into(),
        )
        .await
        .expect("connect should succeed");

        let id = client.agent_id_hex();
        assert_eq!(
            id.len(),
            64,
            "agent_id_hex must be 64 hex chars, got: {id:?}"
        );
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "agent_id_hex must be lowercase hex, got: {id:?}"
        );
    }

    /// Verify that pair_share_uri publishes the pair record and returns a
    /// well-formed x0x://pair/ URI. Gated separately from identity smoke
    /// because it requires the relay to have the T8b /v1/pair-record route
    /// deployed (returns 404 on older relay builds).
    ///
    /// Requires network access and a relay with T8b deployed; excluded from
    /// CI by default.
    #[tokio::test]
    #[ignore = "requires network + live relay with T8b pair-record route"]
    async fn pair_share_uri_publishes_and_returns_x0x_uri() {
        let dir = tempfile::TempDir::new().unwrap();
        let client = ChatClient::connect(
            "http://67.207.94.66:8088".into(),
            dir.path().to_str().unwrap().to_owned(),
            "test-passphrase-ffi-pair-smoke".into(),
        )
        .await
        .expect("connect should succeed");

        let uri = client
            .pair_share_uri()
            .await
            .expect("pair_share_uri should succeed");
        assert!(
            uri.starts_with("x0x://pair/"),
            "pair URI must start with x0x://pair/, got: {uri:?}"
        );
    }
}
