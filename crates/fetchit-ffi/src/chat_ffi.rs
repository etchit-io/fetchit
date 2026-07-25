//! [`ChatClient`] -- daemonless chat surface exposed to the Android shell.
//!
//! Wraps [`fetchit_chat::Client`] (built with the `daemonless` profile) and
//! exposes connect, agent identity, pointer-URI pairing, DM send, and an
//! inbound event pump that surfaces DMs, delivery receipts, and bridged
//! fediverse public posts through a single [`ChatEventFfi`] stream.

use crate::chat_error::ChatFfiError;
use crate::group_ffi::{GroupFfi, JoinOutcomeFfi};
use crate::member_ffi::GroupMemberFfi;
use fetchit_chat::conversation::{dispatch_inbound_with_outbox, InboundDispatch};
use fetchit_chat::messages::is_private_group_envelope;
use fetchit_chat::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use url::Url;
use x0x::exec::ExecPolicy;
use x0x::server::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};

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
    /// Attribution comes from `verified_actor_url` -- the relay-verified,
    /// denylist-canonical signing actor. The `activity_json` body is
    /// UNTRUSTED fediverse content; the render surface MUST sanitize it
    /// before display.
    PublicPost {
        /// Relay-verified actor URL.
        verified_actor_url: String,
        /// Raw Activity Streams JSON bytes. UNTRUSTED -- sanitize before
        /// rendering.
        activity_json: Vec<u8>,
    },
    /// An outbox change for an outbound DM: optimistic echo, delivery, or
    /// failure. Upsert keyed by `bubble.id`; drives the send-status UI.
    Outbox {
        /// The bubble's current state.
        bubble: OutboxBubbleFfi,
    },
    /// An inbound private-group message, decrypted via the in-process x0xd
    /// `/secure/decrypt` surface. Surfaced only for fresh
    /// [`fetchit_chat::messages::PrivateGroupReceive::Persisted`] frames;
    /// replays are dropped. Carries no delivery receipt -- the engine's
    /// group path sends none (mirrors `peer.rs` + the desktop seam).
    GroupMessage {
        /// 64-hex group id the message belongs to.
        group_id: String,
        /// 64-hex sender agent id (ML-DSA verified by the decrypt path).
        from_agent_id_hex: String,
        /// Sender display name at send time, if any.
        sender_name: Option<String>,
        /// Plaintext body.
        body: String,
        /// Dedupe / message id for receipt correlation.
        message_id: Option<String>,
    },
}

/// Delivery state of an outbound DM bubble, mirrored from
/// [`fetchit_chat::outbox::OutboxStatus`] for the uniffi surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OutboxStatusFfi {
    /// Send attempted, not yet confirmed delivered.
    Sending,
    /// Recipient acknowledged delivery.
    Delivered,
    /// The attempt errored or timed out; eligible for retry.
    Failed,
}

impl From<fetchit_chat::outbox::OutboxStatus> for OutboxStatusFfi {
    fn from(status: fetchit_chat::outbox::OutboxStatus) -> Self {
        match status {
            fetchit_chat::outbox::OutboxStatus::Sending => Self::Sending,
            fetchit_chat::outbox::OutboxStatus::Delivered => Self::Delivered,
            fetchit_chat::outbox::OutboxStatus::Failed => Self::Failed,
        }
    }
}

/// One outbound DM bubble surfaced to the shell, mirrored from
/// [`fetchit_chat::outbox::OutboxBubble`]. `peer` is rendered as lowercase
/// 64-char hex so Kotlin never handles the raw `AgentId` newtype.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutboxBubbleFfi {
    /// Client-assigned bubble id, stable across retries.
    pub id: String,
    /// Recipient agent id as lowercase 64-char hex.
    pub peer_agent_id_hex: String,
    /// Plaintext body.
    pub body: String,
    /// Delivery state.
    pub status: OutboxStatusFfi,
    /// Relay dedupe-key hex, set once the first send is acked.
    pub message_id: Option<String>,
    /// Unix epoch ms when first enqueued.
    pub enqueued_at_ms: u64,
    /// Last send error, populated when `status` is `Failed`.
    pub last_error: Option<String>,
    /// For a private-group fan-out bubble, the UI message anchor
    /// (`GroupOutbound.client_message_id`) so the shell can correlate this
    /// bubble reaching `Delivered` back to the one UI message and flip its
    /// pending tick to sent. `None` for a DM bubble.
    pub group_client_message_id: Option<String>,
}

impl From<fetchit_chat::outbox::OutboxBubble> for OutboxBubbleFfi {
    fn from(bubble: fetchit_chat::outbox::OutboxBubble) -> Self {
        Self {
            id: bubble.id,
            peer_agent_id_hex: bubble.peer.0,
            body: bubble.body,
            status: bubble.status.into(),
            message_id: bubble.message_id,
            enqueued_at_ms: bubble.enqueued_at_ms,
            last_error: bubble.last_error,
            group_client_message_id: bubble.group.map(|g| g.client_message_id),
        }
    }
}

/// One persisted message in a conversation transcript, surfaced to the shell
/// for reload-on-open from the encrypted at-rest vault.
///
/// Mapped from [`fetchit_chat::conversation::HistoryEntry`] into the SAME
/// fields the live [`ChatEventFfi::Dm`] / [`ChatEventFfi::GroupMessage`] /
/// [`OutboxBubbleFfi`] projections already carry, so a hydrated transcript
/// renders identically to live traffic. `outbound` is derived by the getter
/// (`HistoryEntry` is sender-stamped, not self-stamped): an entry whose
/// `sender_agent_id_hex` equals the local agent id is one this device sent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatHistoryMessageFfi {
    /// `true` when this device sent the message (sender == local agent id).
    pub outbound: bool,
    /// Hex sender agent id (64 lowercase hex chars). Carried for the group
    /// sender label; the shell leaves the DM label null.
    pub from_agent_id_hex: String,
    /// Sender display name at send time, if any.
    pub sender_name: Option<String>,
    /// Plaintext body.
    pub body: String,
    /// Sender-asserted Unix-ms timestamp (preserves ordering across a reload).
    pub sent_at_ms: u64,
    /// Logical message id (hex). The de-dup key against an already-present
    /// live message of the same id. Empty for legacy pre-id entries.
    pub message_id: String,
    /// `true` once the recipient's delivery receipt arrived. Only meaningful
    /// for entries this device sent (`outbound`).
    pub delivered: bool,
}

/// Map one persisted [`HistoryEntry`](fetchit_chat::conversation::HistoryEntry)
/// to its FFI shape, deriving `outbound` from `local_agent_id_hex`.
///
/// Pure so the projection is unit-tested without a live client; the getter
/// calls it on the same path it ships.
fn history_entry_to_ffi(
    entry: fetchit_chat::conversation::HistoryEntry,
    local_agent_id_hex: &str,
) -> ChatHistoryMessageFfi {
    ChatHistoryMessageFfi {
        outbound: entry.sender_agent_id_hex == local_agent_id_hex,
        from_agent_id_hex: entry.sender_agent_id_hex,
        sender_name: entry.sender_name,
        body: entry.body,
        sent_at_ms: entry.ts_ms,
        message_id: entry.message_id,
        delivered: entry.delivered_at_ms.is_some(),
    }
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

/// Project a private-group decrypt outcome into the FFI event stream.
///
/// A fresh [`PrivateGroupReceive::Persisted`] entry becomes a
/// [`ChatEventFfi::GroupMessage`] with the [`fetchit_chat::conversation::HistoryEntry`]
/// fields mapped straight through (`sender_agent_id_hex` -> `from_agent_id_hex`,
/// the `String` `message_id` wrapped in `Some`); a
/// [`PrivateGroupReceive::Replay`] surfaces nothing, matching the engine's
/// "caller MUST NOT surface anything" replay contract. The engine-detected
/// `gap` is dropped here: the FFI event enum has no gap variant yet, so the
/// Android shell does not surface missed-message detection. Pure so the
/// projection is unit-tested without a live x0xd; the inbound pump calls it
/// on the same path it ships.
fn project_group_receive(
    group_id: String,
    outcome: fetchit_chat::messages::PrivateGroupReceive,
) -> Option<ChatEventFfi> {
    match outcome {
        fetchit_chat::messages::PrivateGroupReceive::Persisted { entry, .. } => {
            Some(ChatEventFfi::GroupMessage {
                group_id,
                from_agent_id_hex: entry.sender_agent_id_hex,
                sender_name: entry.sender_name,
                body: entry.body,
                message_id: Some(entry.message_id),
            })
        }
        fetchit_chat::messages::PrivateGroupReceive::Replay => None,
    }
}

/// Daemonless chat client for the Android shell.
///
/// Connect with [`ChatClient::connect`], which builds a
/// [`fetchit_chat::Client`] using the daemonless profile (local ML-DSA-65
/// signer; relay WebSocket transport in-process) and embeds an x0xd on a
/// loopback port for the group `/secure` TreeKEM surface. Inbound events --
/// DMs, receipts, and bridged fediverse public posts -- are drained via
/// [`ChatClient::next_event`].
///
/// Call [`ChatClient::disconnect`] when the app no longer needs live chat
/// (background, account switch): it aborts the background tasks and shuts the
/// embedded x0xd down. [`Drop`] does the same as a GC backstop, but
/// `disconnect` is the deterministic path.
#[derive(uniffi::Object)]
pub struct ChatClient {
    inner: Client,
    relay_url: String,
    /// uniffi's tokio runtime handle, captured in connect (which runs on that
    /// runtime). Sync methods that spawn engine tasks (start_outbox /
    /// retry_outbox) enter() it first: they run on the Kotlin caller thread,
    /// which has no ambient tokio runtime, so the engine's internal spawn would
    /// otherwise panic with "no reactor running".
    rt_handle: tokio::runtime::Handle,
    /// The in-process x0xd serving the group `/secure` TreeKEM surface.
    /// `connect` points the daemonless engine's `base_url`/`token` at this
    /// handle's loopback address. `disconnect`/`Drop` call its sync
    /// `shutdown()`. Held (not underscore-prefixed) because the teardown
    /// paths read it.
    x0xd: ServerHandle,
    events: Mutex<mpsc::UnboundedReceiver<ChatEventFfi>>,
    pump_abort: tokio::task::AbortHandle,
    drain_abort: tokio::task::AbortHandle,
    /// Drains the outbox broadcast into the unified event stream; started in
    /// `connect`.
    outbox_event_abort: tokio::task::AbortHandle,
    /// The background outbox retry driver, started lazily by `start_outbox`
    /// (so `Drop`/`disconnect` can abort it even though it begins after
    /// construction). `None` until `start_outbox` runs.
    outbox_driver_abort: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    /// Outcome of the connect-time pair-record publish, captured so the shell
    /// can surface relay reachability (and the exact failure) instead of a
    /// silent error. `None` until the publish resolves, then `"ok"`,
    /// `"error: <reason>"`, or `"panic: <reason>"`. Read via
    /// [`ChatClient::pair_publish_outcome`].
    last_publish_outcome: Arc<std::sync::Mutex<Option<String>>>,
}

/// GC backstop: abort all background tasks if the Kotlin side releases
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
        self.outbox_event_abort.abort();
        if let Ok(slot) = self.outbox_driver_abort.lock() {
            if let Some(handle) = slot.as_ref() {
                handle.abort();
            }
        }
        // Trigger the embedded x0xd's graceful shutdown. Sync + non-consuming;
        // the spawned serve future ends on the next poll.
        self.x0xd.shutdown();
    }
}

/// Compiled-in default M3 denylist endpoint (the NY-Trust service).
/// Mirrors the desktop default; `FETCHIT_DENYLIST_URL` overrides it.
const DEFAULT_DENYLIST_URL: &str = "https://trust.etchit.io/v1";

/// Resolve the M3 denylist endpoint: a non-empty `FETCHIT_DENYLIST_URL`
/// wins, else the compiled-in default. Mirrors the desktop resolver so
/// Android chat gates against the same signed list.
fn resolve_denylist_url() -> Option<String> {
    std::env::var("FETCHIT_DENYLIST_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| Some(DEFAULT_DENYLIST_URL.to_string()))
}

/// Bring x0xd up in-process for the group `/secure` TreeKEM surface and
/// return its [`ServerHandle`].
///
/// `connect` points the daemonless engine's `base_url`/`token` at the
/// returned handle's loopback address so private-group encrypt/decrypt has a
/// local x0xd without a separate daemon process. The DM path is unchanged --
/// `daemonless(true)` keeps the local ML-DSA-65 vault signer; only the x0xd
/// HTTP surface is redirected (the engine's P2 in-process-router shape).
///
/// Hardening, all load-bearing on a phone:
/// - Both sockets bind ephemeral (API on loopback, gossip on the unspecified
///   address) so the embed never clashes with a fixed port already in use on
///   the device.
/// - Self-update is fully disabled. `update.enabled = false` is the master
///   gate -- every update task in `serve()` (gossip manifest listener, GitHub
///   fallback poll, startup check, manifest re-broadcast) is spawned only when
///   it is true, so the dominated sub-flags (`gossip_updates`,
///   `fallback_check_interval_minutes`, `stop_on_upgrade`) need no separate
///   handling. No self-modifying binary, as Play policy requires.
/// - Remote `x0x-exec`-over-gossip is disabled via [`ExecPolicy::Disabled`].
/// - The agent identity keys (`machine.key`/`agent.key`/`agent.cert`) are
///   rooted under `<data_dir>/identity` via the fork's opt-in
///   `DaemonConfig.identity_dir`. Without it `serve()` writes them to `~/.x0x`,
///   which is unwritable on Android.
///
/// `disable_peer_cache` is forced `true` at the `serve()` call below -- the
/// peer cache (not the bootstrap list) is what rejoins the public gossip net.
///
/// # Errors
///
/// [`ChatFfiError::Network`] when `serve()` fails to bind or start.
async fn serve_inprocess(x0xd_data: &std::path::Path) -> Result<ServerHandle, ChatFfiError> {
    // #115 DaemonConfig has private fields, so the struct-literal +
    // `..Default::default()` form is rejected from this crate (E0451). Build from
    // Default and set the public fields -- the same idiom #115's own bin uses
    // (src/bin/x0xd.rs). Private fields (update, port_mapping_enabled, ...) keep
    // their defaults; self-update is gated off via `ServeOptions` below.
    #[allow(clippy::field_reassign_with_default)]
    let cfg = {
        let mut cfg = DaemonConfig::default();
        // HTTP control surface: loopback, OS-assigned port (read via local_addr()).
        cfg.api_address = (std::net::Ipv4Addr::LOCALHOST, 0).into();
        // QUIC gossip socket: ephemeral, NOT the fixed default -- avoid a
        // fixed-port clash with any other x0xd on the device.
        cfg.bind_address = (std::net::Ipv4Addr::UNSPECIFIED, 0).into();
        cfg.data_dir = x0xd_data.to_path_buf();
        // Android has no writable home -- root the identity keys under app
        // storage via the opt-in identity_dir override.
        cfg.identity_dir = Some(x0xd_data.join("identity"));
        // gossip-OFF (1 of 2): clear the hardcoded bootstrap seeds (== all the
        // --no-hard-coded-bootstrap flag does). NECESSARY but NOT sufficient --
        // the peer cache also rejoins the public net; it is disabled via
        // `ServeOptions.cli_disable_peer_cache` below (2 of 2). With both, the
        // gossip runtime still starts (relay / DM-inbox) but holds 0 public peers.
        // The field is three-valued since x0x 0.34: `None` resolves to the
        // HARDCODED global bootstrap; `Some([])` is "no seed peers at all" --
        // only the latter matches this path's intent.
        cfg.bootstrap_peers = Some(Vec::new());
        cfg
    };
    // ExecPolicy::Disabled is a 3-field struct variant (no disabled() ctor),
    // under x0x::exec. Gates remote x0x-exec-over-gossip only.
    let exec_policy = ExecPolicy::Disabled {
        path: PathBuf::new(),
        reason: "embedded_mobile".to_owned(),
        loaded_at_unix_ms: 0,
    };
    // ServeOptions.cli_disable_peer_cache MUST be true for gossip-off. Empty
    // bootstrap alone is not enough -- with the cache on, the embedded x0xd
    // reconnects to cached public coordinators from a prior run (seen on-device:
    // "Connected to cached peer ... :5483"). Cache off + empty bootstrap = gossip
    // runtime up (relay / DM-inbox) at 0 public peers. self_update_enabled = false
    // keeps the embedded daemon from ever replacing/restarting the host app.
    serve_with_options(
        cfg,
        ServeOptions {
            skip_update_check: true,
            // gossip-off embed has no inbound peers; skip UPnP router probing.
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            instance_name: None,
            exec_policy,
            // x0x >= 0.29 requires a connect ACL policy on the embed. This
            // gossip-off embed has no inbound peers to gate, so the documented
            // embedder default (`ConnectPolicy::Disabled` = default-deny
            // inbound; outbound to the relay is unaffected) is correct.
            connect_policy: x0x::connect::ConnectPolicy::default(),
            self_update_enabled: false,
        },
    )
    .await
    .map_err(|e| ChatFfiError::Network {
        reason: format!("x0xd serve: {e}"),
    })
}

/// Receipt for a group send: the message id plus whether it reached the
/// relay. `delivered` is the honest tick signal -- `true` = relay-accepted,
/// `false` = durably queued (relay down), which flips to delivered when the
/// outbox flushes on reconnect. Correlate the flip by matching a group
/// outbox event's client message id back to `message_id`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupSendReceiptFfi {
    /// Client message id (the UI bubble anchor); `None` for a public group.
    pub message_id: Option<String>,
    /// `true` = relay-accepted; `false` = durably queued (relay down).
    pub delivered: bool,
}

/// Fediverse host whose directory serves minted actors. Mirrors the desktop
/// `DEFAULT_FEDI_DOMAIN`; the registry base is `https://{FEDI_DOMAIN}/`.
const FEDI_DOMAIN: &str = "etchit.io";

/// Result of [`ChatClient::fedi_mint`]: the identity is always created +
/// persisted locally on success; directory registration is best-effort and
/// reported honestly (mirrors the desktop mint-outcome DTO).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MintOutcomeFfi {
    /// Canonical actor URL of the minted identity.
    pub actor_url: String,
    /// True when the directory accepted the registration.
    pub registered: bool,
    /// Why registration is pending, when it is (bridge unreachable, etc.).
    pub registration_error: Option<String>,
}

/// One inbox that rejected a published post. uniffi has no tuples, so the
/// engine's `(target, error)` pair is surfaced as a struct.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FailedDeliveryFfi {
    /// The inbox URL, or the actor URL when the actor fetch itself failed.
    pub target: String,
    /// The failure reason.
    pub error: String,
}

/// Result of [`ChatClient::fedi_publish`]: which inboxes accepted the post
/// and which failed. Delivery is best-effort, so a non-empty `failed` is not
/// itself an error -- the post still reached every inbox in `delivered`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishReportFfi {
    /// Inbox URLs that accepted the activity.
    pub delivered: Vec<String>,
    /// Per-recipient failures.
    pub failed: Vec<FailedDeliveryFfi>,
}

/// Result of [`ChatClient::fedi_follow`]: the `Follow` was signed +
/// delivered from the device and recorded at the bridge as pending. The
/// remote `Accept` arrives later and flips the state.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FollowReportFfi {
    /// Canonical actor URL we followed.
    pub target_actor_url: String,
    /// `Follow` activity id the remote `Accept` will echo.
    pub follow_activity_id: String,
    /// True when the target inbox accepted the delivery.
    pub delivered: bool,
    /// True when the bridge recorded the pending follow.
    pub recorded: bool,
}

/// Result of [`ChatClient::fedi_dm`]: a plaintext fediverse DM signed on
/// the device and delivered to the recipient's inbox. This message is not
/// end-to-end encrypted -- the UI must show the unencrypted-thread banner.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FediDmReportFfi {
    /// Canonical actor URL the DM was addressed to.
    pub recipient_actor_url: String,
    /// The note object id (the DM thread key).
    pub note_id: String,
    /// True when the recipient inbox accepted the delivery.
    pub delivered: bool,
}

/// One account we follow, from the bridge's owner-only list.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FediFollowingFfi {
    /// Remote actor URL the follow targets.
    pub target_actor_url: String,
    /// Short display label -- `user@host` derived from the actor URL.
    pub label: String,
    /// `"pending"` (Follow sent) or `"accepted"` (their Accept arrived).
    pub state: String,
}

/// One fediverse DM thread summarised for the unified conversation
/// list -- mirrors [`fetchit_chat::fedi_thread::FediThreadSummary`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FediThreadSummaryFfi {
    /// Canonical `user@host` label (the `f:<label>` conversation key body).
    pub label: String,
    /// Newest message body -- the list preview.
    pub last_body: String,
    /// Newest message stamp (epoch ms) -- the list sort key.
    pub last_at_ms: i64,
    /// `true` when the newest message was outbound.
    pub last_outbound: bool,
}

/// One fediverse↔LIT person link -- mirrors
/// [`fetchit_chat::fedi_link::PersonLink`] plus its canonical label.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FediPersonLinkFfi {
    /// Canonical `user@host` fediverse label.
    pub label: String,
    /// The PQ agent id this handle is linked to, if linked.
    pub agent_id_hex: Option<String>,
    /// A go-private invite has been delivered to this person.
    pub invited: bool,
    /// When the invite was delivered (epoch ms), if invited -- drives the
    /// resend cooldown so the shell doesn't spam the recipient's inbox.
    pub invited_at_ms: Option<i64>,
    /// This person is linked to a PQ contact (chat privately in Chats).
    pub linked: bool,
}

/// Result of [`ChatClient::fedi_go_private_invite`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct GoPrivateReportFfi {
    /// The invite fedi DM reached the recipient's inbox. `false` means it
    /// was signed but the inbox was unreachable -- the pending state is NOT
    /// recorded, so the caller can offer a retry.
    pub delivered: bool,
}

/// Result of [`ChatClient::fedi_unfollow`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct UnfollowReportFfi {
    /// The `Undo(Follow)` reached the target's inbox.
    pub delivered: bool,
    /// The bridge dropped its follow record.
    pub removed: bool,
}

/// One post in the pulled read feed (text only; wire HTML is reduced
/// engine-side, so shells render this as plain text).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FediPostFfi {
    /// Author actor URL.
    pub author_url: String,
    /// Short author label -- `user@host`.
    pub author_label: String,
    /// Post body as plain text.
    pub text: String,
    /// ISO-8601 publish stamp as served (may be empty).
    pub published: String,
    /// Link to the post on its home server.
    pub object_url: String,
}

/// Result of [`ChatClient::fedi_ensure_v2`]: the hub-open upgrade pass. Never
/// errors for blockers -- those land in `pending`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnsureV2Ffi {
    /// True when a fresh v2 attestation was signed + stored this pass.
    pub upgraded: bool,
    /// True when the directory holds the current record.
    pub registered: bool,
    /// Why the pass could not complete (profile unpublished, bridge down).
    pub pending: Option<String>,
}

/// Verified-vs-public classification of a [`ChatClient::fedi_lookup`] result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LookupKindFfi {
    /// The v2 attestation verified: the actor is bound to `agentIdHex`.
    Verified,
    /// No attestation / verification failed: display but do not trust.
    PublicOnly,
    /// The handle does not resolve to any account.
    NotFound,
}

/// One resolved fediverse account card from [`ChatClient::fedi_lookup`]. The
/// rich display fields (name/bio/avatar) are fetched separately from the
/// Autonomi manifest at `profile_addr`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LookupFfi {
    /// Verified, public-only, or not-found.
    pub kind: LookupKindFfi,
    /// Canonical `@local@instance` handle.
    pub handle: String,
    /// Actor URL the handle resolved to (empty for not-found).
    pub actor_url: String,
    /// Verified chat agent id (verified only).
    pub agent_id_hex: Option<String>,
    /// Autonomi profile-manifest address (verified only); load name/bio/avatar
    /// from it via the reader.
    pub profile_addr: Option<String>,
    /// Synthesized v3 share URI for "message privately" (verified only).
    pub share_uri: Option<String>,
    /// Set when this handle previously resolved to a DIFFERENT agent id on
    /// this device (a possible handle takeover) -- render a warning.
    pub previous_agent_id_hex: Option<String>,
    /// Set when an attestation was present but failed verification.
    pub verify_failure: Option<String>,
}

/// M6.4 new-device link offer: the QR pointer to encode plus the confirm
/// code to show beside it plus the absolute expiry. Returned by
/// [`ChatClient::create_link_offer`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct CreatedLinkOfferFfi {
    /// `fetchit://link/v1/…` pointer to render as the QR the new device shows.
    pub uri: String,
    /// Human-comparable confirm code (`XXXX-XXXX-XXXX`) shown beside the QR.
    pub short_code: String,
    /// Absolute expiry, milliseconds since Unix epoch.
    pub exp_ms: u64,
}

/// M6.4 confirm-screen preview the existing device shows after scanning a
/// link QR: the new device's agent id, the code to compare against the new
/// device's screen, and whether the offer already expired. Returned by
/// [`ChatClient::preview_link_offer`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct LinkOfferPreviewFfi {
    /// The new device's agent id (hex).
    pub agent_id_hex: String,
    /// Human-comparable confirm code (`XXXX-XXXX-XXXX`) to compare against the
    /// new device's screen before confirming.
    pub short_code: String,
    /// True when the offer is past its expiry at the caller's clock.
    pub expired: bool,
}

/// M6.4 outcome of a completed enrollment (existing-device side), returned by
/// [`enroll_confirmed_device`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnrollOutcomeFfi {
    /// The newly linked device's agent id (hex).
    pub agent_id_hex: String,
    /// The account roster revision published for this enrollment (N+1).
    pub record_revision: u64,
    /// True once the devices-group admission is live (M6.6); false while it is
    /// the M6.4 stub -- lets the shell show "linked, syncing" vs "linked".
    pub devices_group_admitted: bool,
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatClient {
    /// Connect to the relay and build a daemonless chat client.
    ///
    /// `relay_url` must be an HTTP or WebSocket URL of a running fetch>it
    /// relay (e.g. `https://nyc-relay.etchit.io`). `data_dir` is the
    /// on-device path for the identity vault and conversation store.
    /// `passphrase` derives the at-rest master key.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `relay_url` is malformed.
    /// [`ChatFfiError::Network`] when the in-process x0xd fails to start, or
    /// on relay connect or vault bootstrap failure.
    #[uniffi::constructor]
    pub async fn connect(
        relay_url: String,
        data_dir: String,
        passphrase: String,
    ) -> Result<Arc<Self>, ChatFfiError> {
        // rustls 0.23 cannot auto-determine its process CryptoProvider when both
        // aws-lc-rs and ring are in the dependency graph (the in-process x0x
        // embed pulls both), so the first TLS use panics. Install aws-lc-rs
        // explicitly -- it backs ant-quic's PQC and the relay TLS. Idempotent: a
        // later call (reconnect) returns Err once a provider is set; we ignore it.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Capture uniffi's tokio runtime handle here (connect runs on it) so the
        // sync start_outbox / retry_outbox methods can enter() it before the
        // engine spawns the driver off the Kotlin caller thread.
        let rt_handle = tokio::runtime::Handle::current();

        let parsed_url = Url::parse(&relay_url).map_err(|e| ChatFfiError::Invalid {
            reason: format!("relay_url: {e}"),
        })?;

        // Embed x0xd in-process for group TreeKEM (/secure) BEFORE building
        // the engine: `build()` runs a version probe against `base_url`, so
        // x0xd must already be listening. `daemonless(true)` keeps the local
        // ML-DSA-65 vault signer -- base_url/token only redirect the x0xd HTTP
        // surface (the engine's P2 in-process-router shape), so the DM path is
        // unchanged.
        let x0xd_data = PathBuf::from(&data_dir).join("x0xd");

        // Identity unification (daemonless): seed the embedded x0xd's agent key
        // with the chat vault's ML-DSA-65 keypair BEFORE serve() loads or mints
        // its own, so the x0xd (TreeKEM group owner) and the chat client
        // (pair-record + DM id) are ONE agent V. Otherwise the x0xd uses a
        // SEPARATE id, the group it owns is keyed under that id, but the owner
        // pair-record publishes under V -- so engine-A joiners resolve the owner
        // KEM by the x0xd id and 404. The vault key round-trips into x0x's
        // AgentKeypair to the SAME id (tests/identity_unification.rs).
        // UNCONDITIONAL overwrite: an existing install already wrote agent.key
        // for the OLD self-minted id, so skip-if-absent would silently keep the
        // split. x0x persists agent.key in its own bincode (perms 0600, not
        // app-sealed) -- within x0x's model + Android FBE; a fork-side seal is a
        // logged hardening follow-up.
        {
            let provisioned = fetchit_chat::provision_local_signer_keypair(
                std::path::Path::new(&data_dir),
                Some(&passphrase),
            )
            .map_err(ChatFfiError::from)?;
            let agent_kp = x0x::identity::AgentKeypair::from_bytes(
                provisioned.public_key.as_slice(),
                provisioned.secret_key.as_slice(),
            )
            .map_err(|e| ChatFfiError::Network {
                reason: format!("seed x0xd identity (from_bytes): {e}"),
            })?;
            let identity_dir = x0xd_data.join("identity");
            std::fs::create_dir_all(&identity_dir).map_err(|e| ChatFfiError::Network {
                reason: format!("create x0xd identity dir: {e}"),
            })?;
            x0x::storage::save_agent_keypair_to(&agent_kp, identity_dir.join("agent.key"))
                .await
                .map_err(|e| ChatFfiError::Network {
                    reason: format!("seed x0xd agent.key: {e}"),
                })?;
        }

        let x0xd = serve_inprocess(&x0xd_data).await?;
        let x0xd_base = format!("http://{}", x0xd.local_addr());
        // #115 ServerHandle does not expose the API token; the daemon wrote it
        // to <data_dir>/api-token via load_or_generate_api_token during serve(),
        // so it exists by the time the handle returns.
        let x0xd_token = std::fs::read_to_string(x0xd_data.join("api-token"))
            .map_err(|e| ChatFfiError::Network {
                reason: format!("read x0xd api-token: {e}"),
            })?
            .trim()
            .to_owned();

        let mut inner = Client::builder()
            .daemonless(true)
            .relay_url(parsed_url)
            .data_dir(PathBuf::from(&data_dir))
            .passphrase(passphrase.clone())
            .base_url(x0xd_base)
            .token(x0xd_token)
            .build()
            .await
            .map_err(ChatFfiError::from)?;

        // Unified-identity confirm: V is the chat / pair-record id AND (via the
        // seed above) the embedded x0xd group-owner id. Logged so the device
        // test can verify GET /v1/pair-record/<V> = 200 before any transfer.
        log::info!(
            "[chat_ffi] connected as unified agent {}",
            inner.local_agent_id_hex().unwrap_or_default()
        );

        // M3: install the community denylist consumer so Android chat gates
        // RelayUrl / AgentId like desktop. `install_m3_denylist` also routes
        // BlockEvents into MultiHomeTransport when one is wired. Endpoint
        // resolves from FETCHIT_DENYLIST_URL, else the NY-Trust default.
        // Non-fatal: chat still runs if the install fails.
        if let Some(denylist_url) = resolve_denylist_url() {
            match fetchit_trust_client::ReqwestClient::new() {
                Ok(http) => {
                    let cache = PathBuf::from(&data_dir).join("denylist");
                    let _ = std::fs::create_dir_all(&cache);
                    let http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static> =
                        Arc::new(http);
                    if let Err(e) = inner.install_m3_denylist(denylist_url, Some(cache), http) {
                        log::warn!("denylist install failed (non-fatal): {e}");
                    }
                }
                Err(e) => log::warn!("denylist http client init failed (non-fatal): {e}"),
            }
        }

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

        // Subscribe to outbox change events before returning so optimistic
        // echoes + delivery/failure transitions surface through the SAME
        // ChatEventFfi pump. Mirrors the public-post drain above.
        let outbox_event_abort = if let Some(mut outbox_rx) = inner.subscribe_outbox() {
            let outbox_tx = tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    match outbox_rx.recv().await {
                        Ok(event) => {
                            let _ = outbox_tx.send(ChatEventFfi::Outbox {
                                bubble: event.bubble.into(),
                            });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            handle.abort_handle()
        } else {
            // No outbox broadcast (REST-only mode); park a no-op task.
            tokio::spawn(async {}).abort_handle()
        };

        let pump_abort = spawn_inbound_pump(inner.clone(), tx);

        // Capture the connect-time pair-record publish outcome for the FFI
        // surface. The shared from_parts publish (client.rs:687) already runs on
        // this build (the daemonless builder sets a primary relay, so its chat +
        // primary gate passes), so this does NOT add discoverability -- it makes
        // the outcome OBSERVABLE: fetchit_chat log records do not reach android
        // logcat, and a rustls CryptoProvider panic would unwind the publish
        // future before its `Err` ever logs. Run it under a JoinHandle and record
        // Ok / Err / panic into a slot the shell reads via pair_publish_outcome().
        // Non-fatal; never blocks connect.
        let last_publish_outcome: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));
        {
            let publish_client = inner.clone();
            let outcome_slot = Arc::clone(&last_publish_outcome);
            tokio::spawn(async move {
                let handle =
                    tokio::spawn(async move { publish_client.publish_pair_record().await });
                let outcome = match handle.await {
                    Ok(Ok(())) => "ok".to_owned(),
                    Ok(Err(e)) => format!("error: {e}"),
                    Err(join_err) if join_err.is_panic() => {
                        let payload = join_err.into_panic();
                        let msg = payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_owned())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "non-string panic payload".to_owned());
                        format!("panic: {msg}")
                    }
                    Err(join_err) => format!("join-error: {join_err}"),
                };
                log::warn!("[chat_ffi] pair-record publish outcome: {outcome}");
                if let Ok(mut slot) = outcome_slot.lock() {
                    *slot = Some(outcome);
                }
            });
        }

        Ok(Arc::new(Self {
            inner,
            relay_url,
            rt_handle,
            x0xd,
            events: Mutex::new(rx),
            pump_abort,
            drain_abort,
            outbox_event_abort,
            outbox_driver_abort: std::sync::Mutex::new(None),
            last_publish_outcome,
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
        self.outbox_event_abort.abort();
        if let Ok(slot) = self.outbox_driver_abort.lock() {
            if let Some(handle) = slot.as_ref() {
                handle.abort();
            }
        }
        // Stop the embedded x0xd alongside the background-task teardown.
        // Sync + non-consuming, so it is safe from this `&self` method
        // (the consuming async `join()` would not be).
        self.x0xd.shutdown();
    }

    /// The local agent id as lowercase 64-character hex.
    ///
    /// Returns an empty string when the client was built without chat state
    /// (should not happen on the daemonless path).
    pub fn agent_id_hex(&self) -> String {
        self.inner.local_agent_id_hex().unwrap_or_default()
    }

    /// Outcome of the connect-time pair-record publish, for surfacing relay
    /// reachability to the shell (and diagnosing on-device publish failures
    /// that never reach logcat). `None` while the publish is still in flight;
    /// then `"ok"`, `"error: <reason>"`, or `"panic: <reason>"`.
    pub fn pair_publish_outcome(&self) -> Option<String> {
        self.last_publish_outcome
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
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

    /// M6.4 new-device side: mint a link-device offer for THIS device and
    /// publish it to the relay blob store, returning the QR pointer to encode
    /// plus the short-code to show beside it. `ttl_secs` bounds the enrollment
    /// window -- the offer self-expires and the existing device rejects a stale
    /// one on confirm.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] in REST-only mode (no chat state) or on a seal
    /// failure; [`ChatFfiError::Network`] when no relay accepts the offer.
    pub async fn create_link_offer(
        &self,
        ttl_secs: u64,
    ) -> Result<CreatedLinkOfferFfi, ChatFfiError> {
        let offer = self.inner.create_link_offer(ttl_secs).await?;
        Ok(CreatedLinkOfferFfi {
            uri: offer.uri,
            short_code: offer.short_code,
            exp_ms: offer.exp_ms,
        })
    }

    /// M6.4 existing-device side: fetch the offer a scanned `uri` points at and
    /// return the confirm-screen preview (the new device's agent id, the
    /// short-code to compare, and freshness). The full offer is validated
    /// during the fetch; mint the certificate only after the human confirms the
    /// short-code matches the new device's screen.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] on a malformed URI or offer;
    /// [`ChatFfiError::Network`] when no relay serves the blob.
    pub async fn preview_link_offer(
        &self,
        uri: String,
    ) -> Result<LinkOfferPreviewFfi, ChatFfiError> {
        let preview = self.inner.preview_link_offer(uri.trim()).await?;
        Ok(LinkOfferPreviewFfi {
            agent_id_hex: preview.agent_id_hex,
            short_code: preview.short_code,
            expired: preview.expired,
        })
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

    /// Create a group. `private=true` is the PQ MLS/`TreeKEM` path
    /// (the default the UI offers); `false` is a plaintext public room.
    ///
    /// Returns the created [`GroupFfi`] with `is_private` already stamped
    /// from the chosen preset (the engine's create paths warm the kind
    /// locally, so the first send skips the cold `GET /groups/<id>`).
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    pub async fn create_group(
        &self,
        name: String,
        display_name: Option<String>,
        private: bool,
    ) -> Result<GroupFfi, ChatFfiError> {
        let group = if private {
            self.inner
                .groups()
                .create_private(&name, display_name.as_deref())
                .await
        } else {
            self.inner
                .groups()
                .create(&name, display_name.as_deref())
                .await
        }
        .map_err(ChatFfiError::from)?;
        Ok(GroupFfi::from(group))
    }

    /// Join a private group from an `x0x://invite/...` link through the v1
    /// shared join policy ([`fetchit_chat::Client::join_group_auto`]) -- the
    /// same path the desktop shell takes, so both shells join identically.
    ///
    /// Native-first, then ALWAYS bridge. The best-effort native
    /// warm-gossip membership wait runs first (outcome non-gating) so the
    /// *existing* members converge over the group's gossip topic; the
    /// engine-A relay bridge then always runs, which is what guarantees the
    /// joiner's `TreeKEM` Welcome/keys regardless of gossip reachability.
    /// The single-use invite is spent exactly once: the inline
    /// `member_joined` captured by the one `join_post` is reused on the
    /// bridge. `run_inbound_pump` (live since `connect`) applies the bridged
    /// result via `dispatch_inbound_bridge`.
    ///
    /// After the join converges, best-effort warms every other member's
    /// ML-DSA card so the first inbound private-group frame decrypts
    /// without a lazy mid-receive fetch. A prefetch failure is swallowed:
    /// the join itself already succeeded, and the receive path re-resolves
    /// any still-missing card on demand.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    /// [`ChatFfiError::Invalid`] for a malformed invite or self-join.
    pub async fn join_group(
        &self,
        invite: String,
        display_name: Option<String>,
    ) -> Result<GroupFfi, ChatFfiError> {
        // GroupInvite is a transparent newtype over the raw URI String.
        let inv = fetchit_chat::groups::GroupInvite(invite);
        // v1 shared policy: native warm-gossip convergence first (so existing
        // members converge natively), then ALWAYS the engine-A bridge, which
        // is what guarantees the joiner's keys. Desktop already routes here;
        // this keeps Android on the same path rather than bridge-only.
        let group = self
            .inner
            .join_group_auto(&inv, display_name.as_deref())
            .await
            .map_err(ChatFfiError::from)?;

        // Best-effort: warm member cards so the first inbound private-group
        // frame decrypts without a lazy fetch. Non-fatal -- the join already
        // landed; the receive path re-resolves a missing card on demand.
        // FetchitIdentity exposes the self id as hex only, so parse it back
        // into the AgentId prefetch expects.
        if let Ok(members) = self.inner.groups().members(&group.group_id).await {
            if let Some(identity) = self.inner.identity_arc() {
                if let Ok(me) = fetchit_chat::identity::AgentId::parse(identity.agent_id_hex()) {
                    let _ = self
                        .inner
                        .messages()
                        .prefetch_group_member_cards(&members, &me)
                        .await;
                }
            }
        }
        Ok(GroupFfi::from(group))
    }

    /// Durable join: like [`Self::join_group`], but a join that cannot
    /// converge now (owner offline) is a resumable [`JoinOutcomeFfi::Pending`]
    /// the resume pump completes when the owner is next reachable -- never a
    /// hard error, never a re-spent single-use invite. The shell draws
    /// "joining…" on `Pending`, calls [`Self::drive_pending_joins_once`] on a
    /// timer to advance it, and lists in-flight joins via
    /// [`Self::pending_joins`]. `Converged` warms member cards exactly like
    /// [`Self::join_group`] so the first inbound frame decrypts without a lazy
    /// fetch.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    /// [`ChatFfiError::Invalid`] for a malformed invite or self-join.
    pub async fn join_group_durable(
        &self,
        invite: String,
        display_name: Option<String>,
    ) -> Result<JoinOutcomeFfi, ChatFfiError> {
        let inv = fetchit_chat::groups::GroupInvite(invite);
        match self
            .inner
            .join_group_durable(&inv, display_name.as_deref())
            .await
            .map_err(ChatFfiError::from)?
        {
            fetchit_chat::groups::JoinOutcome::Converged(group) => {
                // Warm member cards so the first inbound private-group frame
                // decrypts without a lazy fetch (mirrors join_group). Non-fatal.
                if let Ok(members) = self.inner.groups().members(&group.group_id).await {
                    if let Some(identity) = self.inner.identity_arc() {
                        if let Ok(me) =
                            fetchit_chat::identity::AgentId::parse(identity.agent_id_hex())
                        {
                            let _ = self
                                .inner
                                .messages()
                                .prefetch_group_member_cards(&members, &me)
                                .await;
                        }
                    }
                }
                Ok(JoinOutcomeFfi::Converged {
                    group: GroupFfi::from(group),
                })
            }
            fetchit_chat::groups::JoinOutcome::Pending { group_id } => {
                Ok(JoinOutcomeFfi::Pending { group_id })
            }
        }
    }

    /// Group ids with a durable join still in progress -- the shell draws
    /// these as "joining…" rather than a failure.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError`] on a pending-join store read error.
    pub fn pending_joins(&self) -> Result<Vec<String>, ChatFfiError> {
        self.inner.pending_joins().map_err(ChatFfiError::from)
    }

    /// Advance every due durable join one step (re-bridge the saved event or
    /// re-request the Welcome; a fully-keyed one is retired). Returns the
    /// group ids STILL pending after this pass, so a shell timer can refresh
    /// "joining…" badges and detect convergence (a group leaving the set).
    /// Idempotent, cheap, and a no-op when nothing is pending; spends no
    /// second invite (a resume never calls `join_post`).
    ///
    /// # Errors
    ///
    /// [`ChatFfiError`] on a pending-join store error.
    pub async fn drive_pending_joins_once(&self) -> Result<Vec<String>, ChatFfiError> {
        self.inner
            .drive_pending_joins_once()
            .await
            .map_err(ChatFfiError::from)?;
        self.inner.pending_joins().map_err(ChatFfiError::from)
    }

    /// Send a message to a group, routing private/public via the engine's
    /// kind-aware `send_to_group` (private fans out over `TreeKEM`; public
    /// posts plaintext). Returns the message id on success, or `None` when
    /// the transport succeeded but no id was minted.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id.
    /// [`ChatFfiError::Network`] on transport, x0xd, or relay failure.
    pub async fn send_group_message(
        &self,
        group_id: String,
        body: String,
        sender_name: String,
    ) -> Result<GroupSendReceiptFfi, ChatFfiError> {
        let receipt = self
            .inner
            .messages()
            .send_to_group(&group_id, &body, &sender_name)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(GroupSendReceiptFfi {
            message_id: receipt.message_id,
            delivered: receipt.delivered,
        })
    }

    /// The active minted fediverse handle, or `None` when the user has not
    /// opted in to public posting. Reads the local vault only (no network),
    /// so the onboarding gate can query it before anything connects.
    #[must_use]
    pub fn fedi_actor_status(&self) -> Option<String> {
        self.inner
            .layout()
            .map(fetchit_chat::fedi_vault::list_actor_handles)
            .and_then(|handles| handles.into_iter().next())
    }

    /// Opt in to public posting: mint the actor identity for `handle` (with
    /// its v2 attestation binding the published profile + active relay) and
    /// register it with the directory. One-tap on a fresh identity: when no
    /// profile is published yet the engine publishes a minimal handle-only
    /// profile-index record first, then mints against it. Directory-
    /// registration failure is NOT an error -- it lands in the returned
    /// [`MintOutcomeFfi`].
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] on a bad relay/registry URL, a transient
    /// relay failure (so a network blip is not mistaken for no-profile), or
    /// the mint failing.
    pub async fn fedi_mint(&self, handle: String) -> Result<MintOutcomeFfi, ChatFfiError> {
        let handle = handle.trim().to_lowercase();
        let relay = url::Url::parse(&self.relay_url).map_err(|e| ChatFfiError::Invalid {
            reason: format!("relay url: {e}"),
        })?;
        let registry_base = url::Url::parse(&format!("https://{FEDI_DOMAIN}/")).map_err(|e| {
            ChatFfiError::Invalid {
                reason: format!("registry url: {e}"),
            }
        })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let outcome = self
            .inner
            .mint_and_register_actor(&handle, FEDI_DOMAIN, &relay, &registry_base, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(MintOutcomeFfi {
            actor_url: outcome.actor_url,
            registered: outcome.registered,
            registration_error: outcome.registration_error,
        })
    }

    /// Publish a public post as the active minted handle. `@user@host`
    /// mentions are extracted from `body_md`; the engine resolves them via
    /// WebFinger and runs denylist gating before any delivery. Delivery is
    /// best-effort: the report lists accepted + failed inboxes.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted, or the publish
    /// fails before any delivery was attempted.
    pub async fn fedi_publish(
        &self,
        body_md: String,
        reply_to_actor_url: Option<String>,
    ) -> Result<PublishReportFfi, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let created_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let post = fetchit_fedi::PublicPost {
            author_handle: format!("@{handle}@{FEDI_DOMAIN}"),
            body_md: body_md.clone(),
            created_at_ms,
            reply_to_actor_url,
            mentions: fetchit_fedi::extract_mentions(&body_md),
        };
        let report = self
            .inner
            .publish_public_post(&handle, &post)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(PublishReportFfi {
            delivered: report.delivered,
            failed: report
                .failed
                .into_iter()
                .map(|(target, error)| FailedDeliveryFfi { target, error })
                .collect(),
        })
    }

    /// Follow a remote fediverse account (`@user@instance`) from our
    /// minted handle: sign + deliver a `Follow` from the device, then
    /// record it pending at the bridge. The remote `Accept` flips the
    /// state later. Requires a minted handle.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted, the target is
    /// blocked/unresolvable, or signing fails. Delivery/record failures
    /// are reported in the returned [`FollowReportFfi`], not errored.
    pub async fn fedi_follow(&self, target: String) -> Result<FollowReportFfi, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let report = self
            .inner
            .follow_fedi(&handle, &target, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(FollowReportFfi {
            target_actor_url: report.target_actor_url,
            follow_activity_id: report.follow_activity_id,
            delivered: report.delivered,
            recorded: report.recorded,
        })
    }

    /// Send a plaintext fediverse DM (`@user@instance`) from our minted
    /// handle: sign a direct `Create(Note)` on the device and deliver it to
    /// the recipient's inbox. Requires a minted handle. This message is
    /// **not** end-to-end encrypted -- the UI shows the unencrypted-thread
    /// banner and offers escalation to PQ chat (P4).
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted, the target is
    /// blocked/unresolvable, or signing fails. A transient inbox outage is
    /// reported as `delivered == false` in [`FediDmReportFfi`], not errored.
    pub async fn fedi_dm(
        &self,
        target: String,
        body: String,
    ) -> Result<FediDmReportFfi, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let report = self
            .inner
            .send_fedi_dm(&handle, &target, &body, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(FediDmReportFfi {
            recipient_actor_url: report.recipient_actor_url,
            note_id: report.note_id,
            delivered: report.delivered,
        })
    }

    /// The accounts our minted handle follows, from the bridge's
    /// owner-only list (newest first as the bridge returns them).
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted or the bridge
    /// is unreachable.
    pub async fn fedi_following(&self) -> Result<Vec<FediFollowingFfi>, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let entries = self
            .inner
            .list_fedi_following(&handle, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(entries
            .into_iter()
            .map(|e| FediFollowingFfi {
                label: fetchit_chat::fedi_feed::author_label(&e.target_actor_url),
                target_actor_url: e.target_actor_url,
                state: e.state,
            })
            .collect())
    }

    /// Every fediverse DM thread as a one-line summary, newest first, for
    /// the unified conversation list. A device with no minted handle has
    /// no threads and returns an empty list (quiet-hydrate contract --
    /// never an error).
    ///
    /// # Errors
    /// [`ChatFfiError`] on a thread-store load failure.
    pub async fn fedi_threads_overview(&self) -> Result<Vec<FediThreadSummaryFfi>, ChatFfiError> {
        let Some(handle) = self.fedi_actor_status() else {
            return Ok(Vec::new());
        };
        let rows = self
            .inner
            .fedi_threads_overview(&handle)
            .map_err(ChatFfiError::from)?;
        Ok(rows
            .into_iter()
            .map(|s| FediThreadSummaryFfi {
                label: s.label,
                last_body: s.last_body,
                last_at_ms: s.last_at_ms,
                last_outbound: s.last_outbound,
            })
            .collect())
    }

    /// The accounts following the minted handle, as `@user@host` labels,
    /// from the directory's owner-only list. Throws when no handle is
    /// minted or the directory is unreachable (mirrors [`Self::fedi_following`]).
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted or the fetch fails.
    pub async fn fedi_followers(&self) -> Result<Vec<String>, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let urls = self
            .inner
            .fetch_fedi_followers(&handle, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(urls
            .iter()
            .map(|u| fetchit_chat::fedi_feed::author_label(u))
            .collect())
    }

    /// Send a "go private" invite to `target` over the fediverse: publish
    /// our pair record, compose the invite (pair link + install nudge +
    /// history note), and deliver it as a fediverse DM. Records the
    /// pending invite ONLY on delivery, so the pending state can never
    /// claim an invite the recipient never received.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted; [`ChatFfiError`]
    /// on a pair-publish / signing / store failure. A transient inbox
    /// outage is `delivered == false`, not an error.
    pub async fn fedi_go_private_invite(
        &self,
        target: String,
        display_name: String,
    ) -> Result<GoPrivateReportFfi, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        self.inner
            .publish_pair_record()
            .await
            .map_err(ChatFfiError::from)?;
        let pair_uri = fetchit_chat::pair_uri::emit_pair_uri(
            &self.agent_id_hex(),
            std::slice::from_ref(&self.relay_url),
        )
        .map_err(|e| ChatFfiError::Invalid {
            reason: e.to_string(),
        })?;
        let body = format!(
            "{display_name} invited you to a private, post-quantum encrypted chat \
             on fetch>it. Open this link in the fetch>it app to accept: {pair_uri}\
             . New here? Get the app: https://etchit.io/fetch (your fediverse \
             messages stay here; the private chat starts fresh)"
        );
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let report = self
            .inner
            .send_fedi_dm(&handle, &target, &body, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        if report.delivered {
            self.inner
                .record_fedi_invite(&handle, &target, i64::try_from(now_ms).unwrap_or(i64::MAX))
                .map_err(ChatFfiError::from)?;
        }
        Ok(GoPrivateReportFfi {
            delivered: report.delivered,
        })
    }

    /// Fediverse handles invited to private chat but not yet linked.
    /// Empty when no handle is minted (quiet).
    ///
    /// # Errors
    /// [`ChatFfiError`] on store load.
    pub fn fedi_pending_invites(&self) -> Result<Vec<String>, ChatFfiError> {
        let Some(handle) = self.fedi_actor_status() else {
            return Ok(Vec::new());
        };
        self.inner
            .pending_go_private(&handle)
            .map_err(ChatFfiError::from)
    }

    /// Link a fediverse `target` to a PQ `agent_id_hex` -- the manual
    /// "Same person?" confirm. Local only; never published.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted; [`ChatFfiError`]
    /// on store IO.
    pub fn fedi_link_person(
        &self,
        target: String,
        agent_id_hex: String,
    ) -> Result<(), ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        self.inner
            .link_fedi_person(&handle, &target, &agent_id_hex)
            .map_err(ChatFfiError::from)
    }

    /// Drop the link for a fediverse `target`.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted; [`ChatFfiError`]
    /// on store IO.
    pub fn fedi_unlink_person(&self, target: String) -> Result<(), ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        self.inner
            .unlink_fedi_person(&handle, &target)
            .map_err(ChatFfiError::from)
    }

    /// Every fediverse↔LIT person link. Empty when no handle is minted.
    ///
    /// # Errors
    /// [`ChatFfiError`] on store load.
    pub fn fedi_person_links(&self) -> Result<Vec<FediPersonLinkFfi>, ChatFfiError> {
        let Some(handle) = self.fedi_actor_status() else {
            return Ok(Vec::new());
        };
        Ok(self
            .inner
            .fedi_person_links(&handle)
            .map_err(ChatFfiError::from)?
            .into_iter()
            .map(|(label, p)| FediPersonLinkFfi {
                invited: p.invited_at_ms.is_some(),
                invited_at_ms: p.invited_at_ms,
                linked: p.agent_id_hex.is_some(),
                agent_id_hex: p.agent_id_hex,
                label,
            })
            .collect())
    }

    /// The fediverse label linked to `agent_id_hex`, if any (reverse
    /// lookup used to collapse a linked thread into its PQ contact row).
    ///
    /// # Errors
    /// [`ChatFfiError`] on store load.
    pub fn fedi_linked_label_for_agent(
        &self,
        agent_id_hex: String,
    ) -> Result<Option<String>, ChatFfiError> {
        let Some(handle) = self.fedi_actor_status() else {
            return Ok(None);
        };
        self.inner
            .linked_label_for_agent(&handle, &agent_id_hex)
            .map_err(ChatFfiError::from)
    }

    /// Unfollow a fediverse account: sign + deliver the `Undo(Follow)`
    /// and drop the bridge record.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted or we are not
    /// following the target. Delivery/record outages are reported in the
    /// returned [`UnfollowReportFfi`], not errored.
    pub async fn fedi_unfollow(
        &self,
        target_actor_url: String,
    ) -> Result<UnfollowReportFfi, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let report = self
            .inner
            .unfollow_fedi(&handle, &target_actor_url, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(UnfollowReportFfi {
            delivered: report.delivered,
            removed: report.removed,
        })
    }

    /// Sync inbound fediverse messages (replies on the plaintext rails)
    /// from the bridge inbox into the engine's durable thread store.
    /// The engine owns the cursor: every pulled message is persisted
    /// into its sender's own thread and the cursor advances in the same
    /// atomic save, so nothing can be skipped or lost to a process
    /// death. Returns how many messages were new; render threads via
    /// [`Self::conversation_history`] with an `f:<handle>` key.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted or the bridge
    /// is unreachable.
    pub async fn fedi_sync_inbox(&self) -> Result<u32, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.inner
            .sync_fedi_inbox(&handle, now_ms)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Pull the read feed: newest text posts from followed accounts,
    /// merged newest-first (engine caps apply). Per-account failures are
    /// skipped engine-side; an empty vec is a valid feed.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when no handle is minted or the bridge
    /// following list is unreachable.
    pub async fn fedi_feed(&self) -> Result<Vec<FediPostFfi>, ChatFfiError> {
        let handle = self
            .fedi_actor_status()
            .ok_or_else(|| ChatFfiError::Invalid {
                reason: "no public handle minted".to_owned(),
            })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let posts = self
            .inner
            .fetch_fedi_feed(&handle, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(posts
            .into_iter()
            .map(|p| FediPostFfi {
                author_url: p.author_url,
                author_label: p.author_label,
                text: p.text,
                published: p.published,
                object_url: p.object_url,
            })
            .collect())
    }

    /// Run the v2 upgrade + re-register pass, called when the fedi hub opens
    /// for an already-minted handle. Never errors for blockers -- they land
    /// in [`EnsureV2Ffi::pending`]. A no-op (all false) when no handle is
    /// minted yet.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] on a bad relay/registry URL or a vault
    /// access failure.
    pub async fn fedi_ensure_v2(&self) -> Result<EnsureV2Ffi, ChatFfiError> {
        let Some(handle) = self.fedi_actor_status() else {
            return Ok(EnsureV2Ffi {
                upgraded: false,
                registered: false,
                pending: None,
            });
        };
        let relay = url::Url::parse(&self.relay_url).map_err(|e| ChatFfiError::Invalid {
            reason: format!("relay url: {e}"),
        })?;
        let registry_base = url::Url::parse(&format!("https://{FEDI_DOMAIN}/")).map_err(|e| {
            ChatFfiError::Invalid {
                reason: format!("registry url: {e}"),
            }
        })?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let outcome = self
            .inner
            .ensure_actor_v2_and_register(&handle, &relay, &registry_base, now_ms)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(EnsureV2Ffi {
            upgraded: outcome.upgraded,
            registered: outcome.registered,
            pending: outcome.pending,
        })
    }

    /// Resolve a `@user@host` fediverse handle to an account card: verified
    /// (attestation-bound to a chat agent id, with a share URI for "message
    /// privately") or public-only. Load the rich profile (name/bio/avatar)
    /// from `profileAddr` via the reader.
    ///
    /// # Errors
    /// [`ChatFfiError`] on a transport failure (WebFinger/actor fetch,
    /// unreachable sender relay). A handle that simply does NOT resolve is
    /// returned as a `NotFound` card, not an error.
    pub async fn fedi_lookup(&self, handle: String) -> Result<LookupFfi, ChatFfiError> {
        match self.inner.lookup_fedi_handle(&handle).await {
            Ok(l) => Ok(LookupFfi {
                kind: match l.kind {
                    fetchit_chat::FediLookupKind::Verified => LookupKindFfi::Verified,
                    fetchit_chat::FediLookupKind::PublicOnly => LookupKindFfi::PublicOnly,
                },
                handle: l.handle,
                actor_url: l.actor_url,
                agent_id_hex: l.agent_id_hex,
                profile_addr: l.profile_addr,
                share_uri: l.share_uri,
                previous_agent_id_hex: l.previous_agent_id_hex,
                verify_failure: l.verify_failure,
            }),
            Err(e) => {
                // Contract: a genuine "no such handle" (a resolve miss) is a
                // NotFound card, not an FFI error; every other transport
                // failure surfaces as an error.
                if e.to_string().contains("couldn't resolve") {
                    Ok(LookupFfi {
                        kind: LookupKindFfi::NotFound,
                        handle,
                        actor_url: String::new(),
                        agent_id_hex: None,
                        profile_addr: None,
                        share_uri: None,
                        previous_agent_id_hex: None,
                        verify_failure: None,
                    })
                } else {
                    Err(ChatFfiError::from(e))
                }
            }
        }
    }

    /// List the groups this agent belongs to.
    ///
    /// Groups from x0xd's list omit their confidentiality, so the returned
    /// `is_private` is `None` until a send resolves the kind; the create
    /// paths above return it stamped.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    pub async fn list_groups(&self) -> Result<Vec<GroupFfi>, ChatFfiError> {
        let groups = self
            .inner
            .groups()
            .list()
            .await
            .map_err(ChatFfiError::from)?;
        Ok(groups.into_iter().map(GroupFfi::from).collect())
    }

    /// Mint a fresh `x0x://invite/...` link for a group, suitable for the
    /// QR / share path.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id.
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    pub async fn group_invite(&self, group_id: String) -> Result<String, ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        let invite = self
            .inner
            .groups()
            .invite(&gid)
            .await
            .map_err(ChatFfiError::from)?;
        // GroupInvite is a transparent newtype; `.0` is the raw x0x:// URI.
        Ok(invite.0)
    }

    /// Remove a contact, dropping the conversation from the local store.
    ///
    /// Mirrors the desktop `chat_remove_contact` command: the engine forgets
    /// the peer; the shell is responsible for clearing any cached UI state.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `agent_id_hex` is not valid 64-hex.
    /// [`ChatFfiError::Network`] on store failure.
    pub async fn remove_contact(&self, agent_id_hex: String) -> Result<(), ChatFfiError> {
        let id = fetchit_chat::identity::AgentId::parse(agent_id_hex).map_err(|e| {
            ChatFfiError::Invalid {
                reason: e.to_string(),
            }
        })?;
        self.inner
            .contacts()
            .remove(&id)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Leave a group, dropping it from the local list.
    ///
    /// Mirrors the desktop `chat_group_leave` command. Rejoining requires a
    /// fresh invite, so the shell should confirm before calling.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id.
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    pub async fn leave_group(&self, group_id: String) -> Result<(), ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        self.inner
            .groups()
            .leave(&gid)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Delete a group for everyone (terminal withdrawal commit).
    ///
    /// The ADR-0016 exit valve, and the only way to end a group you are the
    /// sole member of -- a last admin cannot `leave_group` (the daemon 409s).
    /// Admin-or-above only; the daemon authorizes. No key material survives.
    /// Irreversible.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id;
    /// [`ChatFfiError`] on a daemon rejection (`403` when not an admin).
    pub async fn delete_group(&self, group_id: String) -> Result<(), ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        self.inner
            .groups()
            .delete(&gid)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Roster of active members for a group ("who is in this group").
    ///
    /// Mirrors the desktop `chat_group_members` command. The engine roster is
    /// already filtered to active members; each is mapped into a
    /// [`GroupMemberFfi`] with `is_owner` / `is_admin` pre-derived from the
    /// x0xd role so the UI can hide controls that would 4xx. Those booleans are
    /// cosmetic -- x0xd is the real authorization gate.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id.
    /// [`ChatFfiError::Network`] on relay or x0xd failure.
    pub async fn group_members(
        &self,
        group_id: String,
    ) -> Result<Vec<GroupMemberFfi>, ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        let roster = self
            .inner
            .groups()
            .member_roster(&gid)
            .await
            .map_err(ChatFfiError::from)?;
        Ok(roster.into_iter().map(GroupMemberFfi::from).collect())
    }

    /// Remove a member from a group. `DELETE /groups/<id>/members/<agent_id>`.
    ///
    /// Mirrors the desktop `chat_group_remove_member` command. x0xd authorizes
    /// the call (admin+, refuses an owner-target) and drives the TreeKEM re-key
    /// on private groups -- a client-side role check is cosmetic, so the shell
    /// must surface the error a non-admin caller gets back.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id or
    /// `agent_id_hex` is not valid 64-hex.
    /// [`ChatFfiError::Network`] on relay or x0xd failure (incl. authorization
    /// rejection).
    pub async fn remove_member(
        &self,
        group_id: String,
        agent_id_hex: String,
    ) -> Result<(), ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        let id = fetchit_chat::identity::AgentId::parse(agent_id_hex).map_err(|e| {
            ChatFfiError::Invalid {
                reason: e.to_string(),
            }
        })?;
        self.inner
            .groups()
            .remove_member(&gid, &id)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Ban a member from a group. `POST /groups/<id>/ban/<agent_id>`.
    ///
    /// Mirrors the desktop `chat_group_ban_member` command. Like
    /// [`remove_member`](Self::remove_member) but the ban prevents rejoin;
    /// x0xd is the authorization gate and drives the re-key, so surface its
    /// error on failure rather than gating on a client role check.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id or
    /// `agent_id_hex` is not valid 64-hex.
    /// [`ChatFfiError::Network`] on relay or x0xd failure (incl. authorization
    /// rejection).
    pub async fn ban_member(
        &self,
        group_id: String,
        agent_id_hex: String,
    ) -> Result<(), ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        let id = fetchit_chat::identity::AgentId::parse(agent_id_hex).map_err(|e| {
            ChatFfiError::Invalid {
                reason: e.to_string(),
            }
        })?;
        self.inner
            .groups()
            .ban_member(&gid, &id)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Rename a group. `PATCH /groups/<id>` with the new name.
    ///
    /// Mirrors the desktop `chat_group_rename` command. x0xd gates the rename
    /// to admin+, so a non-admin caller gets an error the shell must surface --
    /// the client cannot authorize it locally.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `group_id` is not a valid group id.
    /// [`ChatFfiError::Network`] on relay or x0xd failure (incl. authorization
    /// rejection).
    pub async fn rename_group(
        &self,
        group_id: String,
        new_name: String,
    ) -> Result<(), ChatFfiError> {
        let gid =
            fetchit_chat::groups::GroupId::parse(&group_id).map_err(|e| ChatFfiError::Invalid {
                reason: e.to_string(),
            })?;
        self.inner
            .groups()
            .rename(&gid, &new_name)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Persisted message transcript for a conversation, for reload-on-open.
    ///
    /// The engine already persists every DM and private-group message to the
    /// encrypted at-rest vault ([`fetchit_chat::conversation::HistoryEntry`]);
    /// this surfaces that transcript so the shell's message store survives a
    /// process kill instead of starting empty.
    ///
    /// `conv_key` is the SHELL's conversation key, mirroring how the engine
    /// keys conversations: a `g:`-prefixed 64-hex group id resolves the group
    /// conversation directly ([`ConversationRegistry::get`]); a bare 64-hex
    /// peer agent id resolves that peer's current DM
    /// ([`ConversationRegistry::find_dm_with`], which scans for the two-member
    /// conversation containing the peer -- the engine has no stable
    /// peer-keyed DM id, so the DM is resolved, not constructed). An unknown
    /// or not-yet-persisted conversation returns an empty list (not an error).
    ///
    /// Each entry is mapped to the SAME shape the live event projections
    /// carry; `outbound` is derived against the local agent id so a hydrated
    /// transcript renders identically to live traffic and de-dups by
    /// `message_id`.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `conv_key` is not a valid group id /
    /// 64-hex agent id, or when the client has no chat state (no registry).
    /// [`ChatFfiError::Network`] on a vault open / AEAD / parse failure while
    /// hydrating from disk.
    pub async fn conversation_history(
        &self,
        conv_key: String,
    ) -> Result<Vec<ChatHistoryMessageFfi>, ChatFfiError> {
        // Mirror the shell key scheme: "f:<handle>" is a fediverse
        // (plaintext-rails) thread served from the engine's durable
        // fedi thread store; "g:<hex>" is a group; bare hex is a DM
        // peer. A fedi thread with no minted handle hydrates empty --
        // the quiet-hydrate contract, never an error.
        if let Some(label) = conv_key.strip_prefix("f:") {
            let Some(handle) = self.fedi_actor_status() else {
                return Ok(Vec::new());
            };
            let msgs = self
                .inner
                .fedi_thread_history(&handle, label)
                .map_err(ChatFfiError::from)?;
            return Ok(msgs
                .into_iter()
                .map(|m| ChatHistoryMessageFfi {
                    outbound: m.outbound,
                    from_agent_id_hex: String::new(),
                    sender_name: None,
                    body: m.text,
                    sent_at_ms: u64::try_from(m.at_ms).unwrap_or(0),
                    message_id: m.note_id,
                    delivered: m.delivered,
                })
                .collect());
        }
        let registry = self.inner.registry_arc().ok_or(ChatFfiError::Invalid {
            reason: "no chat state".to_owned(),
        })?;
        // The engine keys every conversation by group_id_hex, so a group
        // is a direct get; a DM has no peer-keyed id and must be resolved.
        let conv = if let Some(group_id) = conv_key.strip_prefix("g:") {
            let gid = fetchit_chat::groups::GroupId::parse(group_id).map_err(|e| {
                ChatFfiError::Invalid {
                    reason: e.to_string(),
                }
            })?;
            registry
                .get(gid.as_str())
                .await
                .map_err(ChatFfiError::from)?
        } else {
            let peer = fetchit_chat::identity::AgentId::parse(conv_key).map_err(|e| {
                ChatFfiError::Invalid {
                    reason: e.to_string(),
                }
            })?;
            registry
                .find_dm_with(&peer.0)
                .await
                .map_err(ChatFfiError::from)?
        };
        let Some(conv) = conv else {
            return Ok(Vec::new());
        };
        let local = self.inner.local_agent_id_hex().unwrap_or_default();
        Ok(conv
            .history
            .into_iter()
            .map(|entry| history_entry_to_ffi(entry, &local))
            .collect())
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

    /// Enqueue an outbound DM through the durable outbox: persist a
    /// `Sending` bubble, surface it immediately as a [`ChatEventFfi::Outbox`]
    /// optimistic echo, then send. The terminal state (Delivered/Failed)
    /// arrives as a later `Outbox` event keyed by the returned bubble id.
    ///
    /// Prefer this over [`ChatClient::send_dm`] for user-visible sends: the
    /// outbox survives restarts and (once [`ChatClient::start_outbox`] runs)
    /// auto-resends on reconnect. `send_dm` stays for fire-and-forget sends
    /// with no durability.
    ///
    /// Attachments + reply-to are not yet carried over the FFI outbox; the
    /// bubble is body-only. The engine supports both -- wiring them through
    /// uniffi is a follow-up.
    ///
    /// # Errors
    ///
    /// [`ChatFfiError::Invalid`] when `to_agent_id_hex` is not valid 64-hex
    /// or the client has no chat state.
    /// [`ChatFfiError::Network`] on transport or relay failure.
    pub async fn enqueue_dm(
        &self,
        to_agent_id_hex: String,
        body: String,
        sender_name: String,
    ) -> Result<String, ChatFfiError> {
        let id = fetchit_chat::identity::AgentId::parse(to_agent_id_hex).map_err(|e| {
            ChatFfiError::Invalid {
                reason: e.to_string(),
            }
        })?;
        self.inner
            .enqueue_dm(&id, &body, &sender_name, None, None)
            .await
            .map_err(ChatFfiError::from)
    }

    /// Snapshot of all tracked outbox bubbles, for hydrating the send-status
    /// UI on startup before subscribing to live [`ChatEventFfi::Outbox`]
    /// events. Empty when the client has no chat state.
    pub async fn outbox_snapshot(&self) -> Vec<OutboxBubbleFfi> {
        self.inner
            .outbox_snapshot()
            .await
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Start the background outbox retry driver: re-sends failed/unacked
    /// bubbles on relay reconnect, runs the 24h + boot timeout sweeps, and
    /// services [`ChatClient::retry_outbox`]. Call once after `connect`,
    /// passing the user's display name (used for body-only resends, so it
    /// should match the `sender_name` given to [`ChatClient::enqueue_dm`]).
    /// Calling again aborts the previous driver before starting a new one.
    pub fn start_outbox(&self, display_name: String) {
        // Sync FFI method called off the Kotlin thread; enter uniffi's runtime
        // so start_outbox_driver's internal tokio::spawn has a reactor.
        let _rt = self.rt_handle.enter();
        if let Some(handle) = self
            .inner
            .start_outbox_driver(Arc::new(move || display_name.clone()))
        {
            if let Ok(mut slot) = self.outbox_driver_abort.lock() {
                if let Some(previous) = slot.take() {
                    previous.abort();
                }
                *slot = Some(handle.abort_handle());
            }
        }
    }

    /// Kick the outbox driver to re-send every retryable bubble now -- the
    /// shell's "Retry" button. Fire-and-forget + coalescing; a no-op when
    /// the driver has not been started ([`ChatClient::start_outbox`]).
    pub fn retry_outbox(&self) {
        // Defensive: same runtime-context guard as start_outbox.
        let _rt = self.rt_handle.enter();
        self.inner.retry_outbox();
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
///     ignored -- the conversation store is updated as a side-effect.
///
/// A malformed or unrecognised envelope never panics the pump; errors are
/// logged at `warn` level.
///
/// Delivery acks (`InboundEnvelope::ack`) are confirmed only at terminal
/// outcomes (vault-persisted, provable duplicate, deterministic reject of
/// immutable bytes); transient failures leave the token unconfirmed so
/// the relay redelivers within its TTL.
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
    // Live handles into the durable outbox so an inbound DeliveryReceipt
    // marks the matching bubble Delivered engine-side (not just the
    // conversation UI). Android drives its own pump, so the engine SSE
    // dispatcher never runs here; without this a delivered bubble stays
    // is_retryable and the driver would re-send it. `None` in REST-only
    // mode -- dispatch_inbound_with_outbox then behaves like the 3-arg form.
    let outbox = client.outbox_arc();
    let events = client.outbox_events();
    while let Some(mut env) = rx.recv().await {
        // Ack-after-persist: confirm ONLY at terminal outcomes so the
        // relay reclaims its stored copy; every transient path drops the
        // token unconfirmed and redelivery retries. Decision table
        // mirrors `Client::default_dispatch_one`.
        let ack = env.ack.take();
        let transit = match env.transit.take() {
            Some(t) => t,
            // No wire envelope: nothing any consumer could ever apply.
            None => {
                if let Some(a) = &ack {
                    a.confirm();
                }
                continue;
            }
        };

        let sender_hex = hex::encode(transit.sender_agent_id.as_bytes());
        let self_hex = client
            .identity_arc()
            .map(|id| id.agent_id_hex().to_owned())
            .unwrap_or_default();

        match route_envelope(&transit.kind, &sender_hex, &self_hex) {
            // Own echo: permanently uninteresting, reclaim.
            EnvelopeRoute::SelfSource => {
                if let Some(a) = &ack {
                    a.confirm();
                }
                continue;
            }

            EnvelopeRoute::PublicPost => {
                // M4 Stage 5.3: bridged fediverse public post. Dispatch feeds
                // the broadcast that the public-post subscriber task drains
                // into `tx`.
                if let Err(e) = client.dispatch_inbound_public_post(&transit) {
                    log::warn!("[chat_ffi] public-post dispatch dropped envelope: {e}");
                }
                // Terminal either way: the broadcast is ephemeral and a
                // decode failure is a deterministic verdict on immutable
                // bytes.
                if let Some(a) = &ack {
                    a.confirm();
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
            match client.dispatch_inbound_bridge(&transit).await {
                Ok(()) => {
                    if let Some(a) = &ack {
                        a.confirm();
                    }
                }
                // x0xd may be down/restarting: hold, redelivery retries.
                Err(e) => log::warn!("[chat_ffi] bridge dispatch dropped envelope: {e}"),
            }
            continue;
        }

        // M2 private-group receive: decrypt via the in-process x0xd
        // /secure/decrypt and surface a GroupMessage. Mirrors the desktop
        // handle_inbound seam and peer.rs decode_private_group: empty-group_id
        // guard, then receive_private_group_envelope -> Persisted = surface /
        // Replay = drop / Err = warn-never-crash. No DeliveryReceipt for group
        // messages -- the engine's group path sends none. Self-source is
        // already dropped above by route_envelope (EnvelopeRoute::SelfSource),
        // so no re-filter is needed here.
        if is_private_group_envelope(&transit) {
            let group_id_hex = transit
                .group_id
                .as_ref()
                .map(|g| hex::encode(g.as_bytes()))
                .unwrap_or_default();
            if group_id_hex.is_empty() {
                log::warn!("[chat_ffi] private-group envelope without group_id; dropping");
                // Malformed: no group id can ever appear on redelivery.
                if let Some(a) = &ack {
                    a.confirm();
                }
                continue;
            }
            match client
                .messages()
                .receive_private_group_envelope(&transit, &group_id_hex)
                .await
            {
                // Persisted and Replay are both terminal: history
                // extended + vault flushed, or provably already held.
                Ok(outcome) => {
                    if let Some(event) = project_group_receive(group_id_hex, outcome) {
                        let _ = tx.send(event);
                    }
                    if let Some(a) = &ack {
                        a.confirm();
                    }
                }
                // StaleEpoch-class decrypt failures: hold the ack so the
                // relay redelivers after re-key / epoch catch-up.
                Err(e) => log::warn!("[chat_ffi] private_group_decrypt_failed: {e}"),
            }
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

        let dispatch = match dispatch_inbound_with_outbox(
            transit,
            identity.as_ref(),
            registry.as_ref(),
            outbox.as_ref(),
            events.as_ref(),
        )
        .await
        {
            Ok(dispatch) => dispatch,
            // Transient (vault/registry I/O): hold for redelivery.
            Err(e) => {
                log::warn!("[chat_ffi] dispatch_inbound error: {e}");
                continue;
            }
        };
        // Variant-aware: StaleEpoch / KemDecapFailed / missing-card drops
        // are Ok-shaped but NOT terminal -- the classifier holds exactly
        // those for redelivery.
        if fetchit_chat::conversation::confirms_delivery(&dispatch) {
            if let Some(a) = &ack {
                a.confirm();
            }
        }
        match dispatch {
            InboundDispatch::Message {
                group_id_hex,
                sender_agent_id_hex,
                payload,
            } => {
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
            InboundDispatch::Receipt { message_id, .. } => {
                let _ = tx.send(ChatEventFfi::Receipt { message_id });
            }
            _other => {
                // Welcomed, Rekeyed, WelcomeIgnored, stale epoch, KEM/AEAD
                // failures -- conversation state may be updated as a side-
                // effect; no FFI event needed.
            }
        }
    }
}

/// Reveal the identity's 24-word BIP39 recovery phrase for backup, reading the
/// on-device vault under `data_dir` and re-deriving its key from `passphrase`.
/// `None` for legacy identities minted before seed backup existed (they have no
/// recoverable seed and must rotate to gain one). A pure vault read, usable
/// without a live connection. Gate behind a device re-auth prompt before
/// display; the returned string is the raw backup secret.
///
/// # Errors
/// `ChatFfiError` if no vault exists under `data_dir`, the passphrase is wrong,
/// or the stored material is malformed.
#[uniffi::export]
pub fn reveal_recovery_phrase(
    data_dir: String,
    passphrase: String,
) -> Result<Option<String>, ChatFfiError> {
    let phrase = fetchit_chat::reveal_local_signer_recovery_phrase(
        std::path::Path::new(&data_dir),
        Some(&passphrase),
    )?;
    Ok(phrase.map(|p| p.to_string()))
}

/// Restore the identity from its 24-word BIP39 recovery phrase, sealing a fresh
/// vault under `data_dir` keyed by `passphrase`. Reproduces the exact signing
/// agent id (returned hex); the ML-KEM key and prior message history do NOT come
/// back. Refuses if an identity already exists -- call only on a fresh install,
/// before the first `connect`.
///
/// # Errors
/// `ChatFfiError` if the phrase is not valid BIP39, an identity already exists
/// under `data_dir`, or vault setup fails.
#[uniffi::export]
pub fn restore_recovery_phrase(
    data_dir: String,
    passphrase: String,
    phrase: String,
) -> Result<String, ChatFfiError> {
    Ok(fetchit_chat::restore_identity_from_recovery_phrase(
        std::path::Path::new(&data_dir),
        Some(&passphrase),
        &phrase,
    )?)
}

/// M6.4 existing-device side: complete a scanned link enrollment. Fetches +
/// validates the offer at `uri`, mints the new device's account certificate
/// under a single vault unlock (`passphrase`, or the OS keychain when `None`),
/// republishes the account roster to `post_relay` at the next revision with the
/// new device (its own advertised relays read from the URI), and returns the
/// outcome. A free function, not a `ChatClient` method, because the account
/// vault lives under `data_dir` -- no live connection is required. The
/// devices-group admission is deferred to M6.6 (`devices_group_admitted` is
/// currently always false).
///
/// # Errors
/// `ChatFfiError` on an expired / malformed offer, a wrong passphrase, no
/// cached account record, or a relay rejection.
#[uniffi::export(async_runtime = "tokio")]
pub async fn enroll_confirmed_device(
    data_dir: String,
    passphrase: Option<String>,
    uri: String,
    post_relay: String,
) -> Result<EnrollOutcomeFfi, ChatFfiError> {
    let relay = url::Url::parse(post_relay.trim()).map_err(|e| ChatFfiError::Invalid {
        reason: format!("relay url: {e}"),
    })?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let outcome = fetchit_chat::enroll_confirmed_device(
        std::path::Path::new(&data_dir),
        passphrase.as_deref(),
        uri.trim(),
        &relay,
        now_ms,
        &fetchit_chat::PendingDevicesGroupSink,
    )
    .await?;
    Ok(EnrollOutcomeFfi {
        agent_id_hex: outcome.agent_id_hex,
        record_revision: outcome.record_revision,
        devices_group_admitted: outcome.devices_group_admitted,
    })
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

    // The moderation methods parse their ids up front; an invalid id never
    // reaches the engine. These exercise that same parse the FFI methods call
    // first -- the rejection path that yields `ChatFfiError::Invalid` -- without
    // standing up a live client.

    #[test]
    fn group_members_rejects_invalid_group_id() {
        // `/` is outside [a-zA-Z0-9_-] (the path-traversal guard), so it is
        // rejected; the FFI maps this to ChatFfiError::Invalid before the
        // engine is ever hit.
        let err = fetchit_chat::groups::GroupId::parse("bad/id").unwrap_err();
        let mapped = ChatFfiError::Invalid {
            reason: err.to_string(),
        };
        assert!(matches!(mapped, ChatFfiError::Invalid { .. }));
    }

    #[test]
    fn remove_member_rejects_invalid_agent_id() {
        // Valid group id, but the agent id is short -> the AgentId parse rejects.
        assert!(fetchit_chat::groups::GroupId::parse(&"a".repeat(64)).is_ok());
        let err = fetchit_chat::identity::AgentId::parse("xyz").unwrap_err();
        let mapped = ChatFfiError::Invalid {
            reason: err.to_string(),
        };
        assert!(matches!(mapped, ChatFfiError::Invalid { .. }));
    }

    #[test]
    fn ban_member_rejects_invalid_group_id() {
        let err = fetchit_chat::groups::GroupId::parse("").unwrap_err();
        let mapped = ChatFfiError::Invalid {
            reason: err.to_string(),
        };
        assert!(matches!(mapped, ChatFfiError::Invalid { .. }));
    }

    #[test]
    fn rename_group_rejects_invalid_group_id() {
        let err = fetchit_chat::groups::GroupId::parse("has space").unwrap_err();
        let mapped = ChatFfiError::Invalid {
            reason: err.to_string(),
        };
        assert!(matches!(mapped, ChatFfiError::Invalid { .. }));
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
            "https://nyc-relay.etchit.io".into(),
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
            "https://nyc-relay.etchit.io".into(),
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

    /// The in-process x0xd embed comes up on loopback with a non-empty API
    /// token, and -- the load-bearing Android invariant -- roots its identity
    /// keys (machine.key/agent.key) under the configured `identity_dir`, NOT
    /// `~/.x0x`. The stock `serve()` wrote those keys to the home dir, which
    /// is unwritable on Android; the fork's opt-in `DaemonConfig.identity_dir`
    /// (set by `serve_inprocess`) fixes that. Proving the keys land under
    /// app storage is what makes the embed device-viable.
    #[tokio::test]
    async fn inprocess_serve_binds_loopback_and_roots_identity_under_data_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let x0xd_data = dir.path().join("x0xd");
        let handle = serve_inprocess(&x0xd_data)
            .await
            .expect("in-process serve should come up");

        let addr = handle.local_addr();
        assert!(
            addr.ip().is_loopback(),
            "API must bind loopback, got: {addr}"
        );
        assert!(
            addr.port() != 0,
            "OS-assigned port must be concrete, got: {addr}"
        );
        // #115 ServerHandle does not expose the token; it is written to
        // <data_dir>/api-token during serve. Verify it is present + non-empty.
        let api_token = std::fs::read_to_string(x0xd_data.join("api-token"))
            .expect("api-token file must be written by serve");
        assert!(
            !api_token.trim().is_empty(),
            "api-token must be non-empty for the engine bearer auth"
        );

        // The identity keys must be under our configured dir, never ~/.x0x.
        let identity_dir = x0xd_data.join("identity");
        assert!(
            identity_dir.join("machine.key").exists(),
            "machine.key must be rooted under the configured identity_dir, \
             not the home dir (Android has no writable home)"
        );
        assert!(
            identity_dir.join("agent.key").exists(),
            "agent.key must be rooted under the configured identity_dir"
        );

        handle.shutdown();
    }

    #[test]
    fn project_group_receive_persisted_maps_to_group_message() {
        use fetchit_chat::conversation::HistoryEntry;
        use fetchit_chat::messages::PrivateGroupReceive;
        let group_id = "f".repeat(64);
        let entry = HistoryEntry {
            sender_agent_id_hex: REAL_HEX.to_owned(),
            sender_name: Some("alice".to_owned()),
            body: "hello group".to_owned(),
            ts_ms: 1_700_000_000_000,
            message_id: "mid-7".to_owned(),
            attachment: None,
            delivered_at_ms: None,
        };
        let projected = project_group_receive(
            group_id.clone(),
            PrivateGroupReceive::Persisted { entry, gap: None },
        );
        match projected {
            Some(ChatEventFfi::GroupMessage {
                group_id: gid,
                from_agent_id_hex,
                sender_name,
                body,
                message_id,
            }) => {
                assert_eq!(gid, group_id);
                assert_eq!(from_agent_id_hex, REAL_HEX);
                assert_eq!(sender_name.as_deref(), Some("alice"));
                assert_eq!(body, "hello group");
                assert_eq!(message_id.as_deref(), Some("mid-7"));
            }
            other => panic!("expected GroupMessage, got {other:?}"),
        }
    }

    #[test]
    fn project_group_receive_replay_maps_to_none() {
        use fetchit_chat::messages::PrivateGroupReceive;
        let projected = project_group_receive("f".repeat(64), PrivateGroupReceive::Replay);
        assert!(
            projected.is_none(),
            "a Replay must surface nothing, got: {projected:?}"
        );
    }

    #[test]
    fn outbox_status_ffi_maps_all_variants() {
        use fetchit_chat::outbox::OutboxStatus;
        assert_eq!(
            OutboxStatusFfi::from(OutboxStatus::Sending),
            OutboxStatusFfi::Sending
        );
        assert_eq!(
            OutboxStatusFfi::from(OutboxStatus::Delivered),
            OutboxStatusFfi::Delivered
        );
        assert_eq!(
            OutboxStatusFfi::from(OutboxStatus::Failed),
            OutboxStatusFfi::Failed
        );
    }

    #[test]
    fn outbox_bubble_ffi_maps_fields_and_peer_hex() {
        use fetchit_chat::identity::AgentId;
        use fetchit_chat::outbox::{OutboxBubble, OutboxStatus};
        let peer_hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let bubble = OutboxBubble {
            id: "bid-1".into(),
            peer: AgentId(peer_hex.into()),
            body: "hello".into(),
            status: OutboxStatus::Failed,
            message_id: Some("mid-9".into()),
            enqueued_at_ms: 1_700_000_000_000,
            last_error: Some("boom".into()),
            group: None,
        };
        let ffi = OutboxBubbleFfi::from(bubble);
        assert_eq!(ffi.id, "bid-1");
        assert_eq!(ffi.peer_agent_id_hex, peer_hex);
        assert_eq!(ffi.body, "hello");
        assert_eq!(ffi.status, OutboxStatusFfi::Failed);
        assert_eq!(ffi.message_id.as_deref(), Some("mid-9"));
        assert_eq!(ffi.enqueued_at_ms, 1_700_000_000_000);
        assert_eq!(ffi.last_error.as_deref(), Some("boom"));
        // A DM bubble carries no group correlation id.
        assert_eq!(ffi.group_client_message_id, None);
    }

    #[test]
    fn outbox_bubble_ffi_surfaces_group_client_message_id() {
        use fetchit_chat::identity::AgentId;
        use fetchit_chat::outbox::{GroupOutbound, OutboxBubble, OutboxStatus};
        let peer_hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let bubble = OutboxBubble {
            id: "bid-2".into(),
            peer: AgentId(peer_hex.into()),
            body: "group hello".into(),
            status: OutboxStatus::Sending,
            message_id: None,
            enqueued_at_ms: 1_700_000_000_001,
            last_error: None,
            group: Some(GroupOutbound {
                group_id: "cafe".into(),
                envelope: vec![1, 2, 3],
                client_message_id: "ui-anchor-7".into(),
            }),
        };
        let ffi = OutboxBubbleFfi::from(bubble);
        // The fan-out bubble carries the UI anchor so the shell can flip the tick.
        assert_eq!(ffi.group_client_message_id.as_deref(), Some("ui-anchor-7"));
    }

    #[test]
    fn history_entry_from_other_sender_is_inbound() {
        use fetchit_chat::conversation::HistoryEntry;
        let entry = HistoryEntry {
            sender_agent_id_hex: REAL_HEX.to_owned(),
            sender_name: Some("alice".to_owned()),
            body: "hi from alice".to_owned(),
            ts_ms: 1_700_000_000_000,
            message_id: "mid-1".to_owned(),
            attachment: None,
            delivered_at_ms: None,
        };
        // Local agent id differs from the sender -> inbound.
        let ffi = history_entry_to_ffi(entry, ZEROS_HEX);
        assert!(!ffi.outbound, "a message from another agent is inbound");
        assert_eq!(ffi.from_agent_id_hex, REAL_HEX);
        assert_eq!(ffi.sender_name.as_deref(), Some("alice"));
        assert_eq!(ffi.body, "hi from alice");
        assert_eq!(ffi.sent_at_ms, 1_700_000_000_000);
        assert_eq!(ffi.message_id, "mid-1");
        assert!(!ffi.delivered, "no receipt -> not delivered");
    }

    #[test]
    fn history_entry_from_self_is_outbound_and_delivered_tracks_receipt() {
        use fetchit_chat::conversation::HistoryEntry;
        let entry = HistoryEntry {
            sender_agent_id_hex: REAL_HEX.to_owned(),
            sender_name: None,
            body: "my own message".to_owned(),
            ts_ms: 1_700_000_000_001,
            message_id: "mid-2".to_owned(),
            attachment: None,
            delivered_at_ms: Some(1_700_000_000_500),
        };
        // Local agent id EQUALS the sender -> outbound; receipt present -> delivered.
        let ffi = history_entry_to_ffi(entry, REAL_HEX);
        assert!(ffi.outbound, "a message from self is outbound");
        assert!(ffi.delivered, "a present delivered_at_ms maps to delivered");
        assert_eq!(ffi.message_id, "mid-2");
    }
}
