//! High-level client API.
//!
//! [`Client::connect`] runs the auth handshake, opens the WebSocket,
//! sends `Hello`, waits for `Ready`, and spawns a supervisor task that
//! owns the connection lifecycle: reading inbound frames, emitting
//! `Ping` on a keepalive timer, tracking `Pong` receipts, and
//! reconnecting with exponential backoff when the underlying socket
//! dies or stops responding.
//!
//! The returned [`Client`] is reconnect-transparent: [`Client::send`]
//! and [`Client::next_delivery`] talk to channels owned across
//! reconnect cycles. Application code observes connection health via
//! [`Client::connection_state`].

use crate::error::ClientError;
use crate::outbox::{Outbox, Receipt, SendResolution};
use crate::signer::Signer;
use fetchit_relay_proto::{
    auth_signing_bytes, from_bytes, to_bytes, Ack, AgentId, AuthChallenge, AuthVerifyRequest,
    AuthVerifyResponse, CapabilityToken, ClientFrame, DedupeKey, Deliver, EffectiveCapabilities,
    Hello, Moved, Ping, Pong, PresenceUpdate, Ready, SendFrame, ServerFrame, TenantId, Throttle,
    TransitEnvelope, WatchPresence,
};
use futures_util::{stream::SplitSink, stream::SplitStream, SinkExt, StreamExt};
use rand::RngCore;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSender = SplitSink<WsStream, Message>;
type WsReceiver = SplitStream<WsStream>;

/// Default keepalive Ping interval.
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(30);
/// Default Pong-arrival deadline (2× the default keepalive interval).
const DEFAULT_PONG_TIMEOUT: Duration = Duration::from_secs(60);
/// Initial reconnect backoff after a disconnect.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Upper cap on reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long a WS write may block before the supervisor declares the
/// connection wedged and surfaces a [`ClientError::SendTimeout`].
///
/// Catches the specific TCP-wedge failure mode where bytes accumulate
/// in the socket's send buffer because the peer never ACKs them: the
/// `sender.send()` call cannot complete, so without a timeout the
/// outbox future hangs forever and the bubble stays in `sending`
/// state with no indication of the underlying failure.
///
/// 5 s is generous: a healthy WS write of a ~1 KB frame completes in
/// milliseconds; if the underlying socket is taking longer than that,
/// the link is wedged and waiting longer just delays the user-visible
/// "Retry" affordance.
const SEND_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for the relay's `Ack` frame after the WS write
/// completed. Distinct from [`SEND_WRITE_TIMEOUT`]: this catches the
/// case where the bytes left the socket but the relay never echoed
/// back (server bug, dropped packet, route flap mid-send).
///
/// 10 s is twice the round-trip budget we'd see in normal traffic,
/// chosen so a slow but functioning link still resolves successfully
/// while an actually-lost ack surfaces well before the user gives up.
const SEND_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection parameters for one relay session.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// HTTPS base URL of the relay to dial.
    pub base: Url,
    /// Client build identifier sent in `Hello`.
    pub client_version: String,
    /// Tenant binding to negotiate on `Hello`.
    pub tenant_id: Option<TenantId>,
    /// Optional capability token presented for tier widening.
    pub capabilities: Option<CapabilityToken>,
    /// Auth handshake timeout.
    pub auth_timeout: Duration,
    /// Interval between client-emitted `Ping` keepalive frames.
    ///
    /// Set to `None` to disable client-side keepalive. Defaults to 30s.
    pub keepalive: Option<Duration>,
    /// Maximum time without a `Pong` before the supervisor treats the
    /// connection as dead and triggers reconnect.
    ///
    /// Set to `None` to disable Pong-deadline enforcement. Defaults to
    /// 60s (2× the default keepalive).
    pub pong_timeout: Option<Duration>,
    /// Maximum time a WS write may block before the supervisor
    /// surfaces a [`ClientError::SendTimeout`]. Catches the TCP-wedge
    /// failure mode from issue #156.
    ///
    /// Defaults to 5 s. Lower in tests that exercise wedge handling.
    pub send_write_timeout: Duration,
    /// Maximum time to wait for the relay's `Ack` after a successful
    /// WS write. Catches relay-side stalls / lost acks; without this,
    /// the outbox future hangs forever.
    ///
    /// Defaults to 10 s. Lower in tests.
    pub send_ack_timeout: Duration,
    /// Cap on consecutive reconnect attempts before the supervisor
    /// gives up and surfaces a terminal [`ConnState::PermanentlyDisconnected`].
    /// `Some(n)` stops after `n` failed `open_session` calls; `None`
    /// retries forever (legacy behaviour).
    ///
    /// Defaults to `Some(20)` — at `MAX_BACKOFF=60s` that's roughly
    /// 20 minutes of wall-clock churn, plenty for transient outages
    /// without ringing the user's CPU forever on a hard relay outage.
    pub max_reconnect_attempts: Option<u32>,
    /// Cap on total elapsed wall-clock time spent in the reconnect
    /// loop before the supervisor gives up. `None` means no time
    /// limit (only `max_reconnect_attempts` applies).
    ///
    /// Defaults to `None`. Set if a fixed wall-clock budget makes
    /// more sense than an attempt count for the deployment.
    pub max_reconnect_elapsed: Option<Duration>,
}

impl ClientConfig {
    /// Bare-minimum config dialing `base` with default values for everything else.
    #[must_use]
    pub fn new(base: Url) -> Self {
        Self {
            base,
            client_version: format!("fetchit-relay-client/{}", env!("CARGO_PKG_VERSION")),
            tenant_id: None,
            capabilities: None,
            auth_timeout: Duration::from_secs(10),
            keepalive: Some(DEFAULT_KEEPALIVE),
            pong_timeout: Some(DEFAULT_PONG_TIMEOUT),
            send_write_timeout: SEND_WRITE_TIMEOUT,
            send_ack_timeout: SEND_ACK_TIMEOUT,
            max_reconnect_attempts: Some(20),
            max_reconnect_elapsed: None,
        }
    }

    /// Reconnect FOREVER: never surface [`ConnState::PermanentlyDisconnected`].
    ///
    /// The always-on chat message pump uses this so a relay outage longer
    /// than the default attempt cap can never leave the pump permanently
    /// dead. It keeps retrying at the `MAX_BACKOFF` floor (one attempt/min)
    /// until connectivity returns, so the client self-heals without the app
    /// having to rebuild it.
    #[must_use]
    pub fn with_unbounded_reconnect(mut self) -> Self {
        self.max_reconnect_attempts = None;
        self
    }
}

/// Coarse-grained state of the supervisor's live WebSocket.
#[derive(Clone, Debug)]
pub enum ConnState {
    /// No socket yet; an auth + handshake attempt is in flight.
    Connecting,
    /// A WebSocket is open and `Ready` has been received.
    Connected {
        /// The relay's resolved session limits for the current connection.
        effective_capabilities: EffectiveCapabilities,
    },
    /// The previous socket has dropped; the supervisor will retry at
    /// `retry_at` (when present).
    Disconnected {
        /// Human-readable reason the connection ended.
        reason: String,
        /// Wall-clock instant of the next reconnect attempt, if any.
        retry_at: Option<Instant>,
    },
    /// The supervisor exhausted [`ClientConfig::max_reconnect_attempts`]
    /// or [`ClientConfig::max_reconnect_elapsed`] without a successful
    /// reconnect and has stopped trying. The application must rebuild
    /// the [`Client`] to attempt a fresh connection — the UI typically
    /// surfaces a "lost connection" notice with a manual retry.
    PermanentlyDisconnected {
        /// Last failure reason recorded before giving up.
        reason: String,
        /// Number of failed reconnect attempts before bailing.
        attempts: u32,
    },
}

/// Monotonic identifier for one supervisor-owned connection.
///
/// Reader / keepalive tasks tag the `Disconnected` cmd with the
/// generation of the connection they belong to so a stale signal
/// from an already-torn-down connection doesn't kick a fresh one.
type ConnGen = u64;

/// Commands the [`Client`] handle issues to the supervisor task.
enum SupervisorCmd {
    Send {
        to: AgentId,
        envelope: Box<TransitEnvelope>,
        dedupe_key: DedupeKey,
        reply: oneshot::Sender<Result<Receipt, ClientError>>,
    },
    /// Mutate the local watch set and forward the delta to the relay.
    ///
    /// The supervisor owns the *authoritative* watch set so it can
    /// resend it on reconnect — the relay clears its per-connection
    /// watchers when the WS closes.
    WatchPresence {
        add: Vec<AgentId>,
        remove: Vec<AgentId>,
    },
    /// Internal signal raised by the reader / keepalive tasks when the
    /// WS for `gen` died. Carries the reason for diagnostics.
    Disconnected {
        gen: ConnGen,
        reason: String,
    },
    Shutdown,
    /// Re-arm the reconnect loop. If the supervisor is in backoff, reset the
    /// backoff to the floor and retry immediately instead of waiting out the
    /// exponential delay. The in-process hook a foreground / network-change
    /// trigger (or the wedge-watchdog) pulls so a returning connection
    /// recovers fast. A no-op when already connected.
    ReconnectNow,
}

/// Per-connection state owned by the supervisor.
///
/// Replaced on every reconnect; dropping it tears down the WS sink,
/// the reader task, and the keepalive task in lockstep.
struct Inner {
    gen: ConnGen,
    sender: Arc<Mutex<WsSender>>,
    outbox: Arc<Outbox>,
    reader: JoinHandle<()>,
    keepalive: Option<JoinHandle<()>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.reader.abort();
        if let Some(h) = self.keepalive.take() {
            h.abort();
        }
    }
}

/// A live relay session.
///
/// Internally a thin handle around a supervisor task that owns the WS
/// lifecycle. Cloning the receiver via [`Client::connection_state`]
/// exposes the live connection health to UI code.
pub struct Client {
    /// The relay's resolved session limits from the first successful
    /// handshake.
    ///
    /// This reflects the *initial* connection; later reconnects may
    /// renegotiate — read [`Client::connection_state`] for the
    /// up-to-date value.
    pub effective_capabilities: EffectiveCapabilities,
    cmd_tx: mpsc::UnboundedSender<SupervisorCmd>,
    inbox: Mutex<mpsc::UnboundedReceiver<Deliver>>,
    presence: Mutex<mpsc::UnboundedReceiver<PresenceUpdate>>,
    state_rx: watch::Receiver<ConnState>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl Client {
    /// Run the full handshake against `config.base` and open the WS.
    ///
    /// Spawns a supervisor task that owns the connection lifecycle: it
    /// reads inbound frames, emits keepalive `Ping` frames on the
    /// configured cadence, watches for `Pong` deadline misses, and
    /// reconnects with exponential backoff when the socket dies.
    ///
    /// `signer` is held by the supervisor across reconnect cycles so
    /// it must be wrapped in an `Arc<dyn Signer + Send + Sync>`.
    ///
    /// A failed *initial* handshake no longer aborts the build: when
    /// `open_session` fails (connect refused, timeout, auth glitch),
    /// the client is constructed in a connecting state with the
    /// supervisor started in reconnect mode, so the existing backoff
    /// loop establishes the session in the background. This lets a cold
    /// app on a flaky network start and self-heal instead of refusing
    /// to launch. A permanent failure still surfaces as
    /// [`ConnState::PermanentlyDisconnected`] after the bounded
    /// reconnect budget.
    ///
    /// # Errors
    /// Returns `Err` only for non-transient setup failures (e.g. a URL
    /// that cannot be turned into a WS request). Once this function
    /// returns `Ok`, all disconnects — including a never-established
    /// first session — are handled by the supervisor and surfaced via
    /// [`Self::connection_state`].
    pub async fn connect(
        config: ClientConfig,
        signer: Arc<dyn Signer + Send + Sync>,
    ) -> Result<Self, ClientError> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        let (presence_tx, presence_rx) = mpsc::unbounded_channel();

        let (initial_state, initial_session, effective_capabilities) = match open_session(
            &config,
            signer.as_ref(),
        )
        .await
        {
            Ok(s) => {
                let caps = s.effective_capabilities.clone();
                (
                    ConnState::Connected {
                        effective_capabilities: caps.clone(),
                    },
                    Some(s),
                    caps,
                )
            }
            Err(e) => {
                tracing::warn!(
                        "[relay] initial connect failed ({e}); starting in reconnect mode and self-healing"
                    );
                // The stored `effective_capabilities` snapshot is
                // informational only (UI affordances); the send path
                // reads the live session's caps via the supervisor,
                // never this field. Until the first session lands we
                // have no negotiated limits, so seed the conservative
                // anonymous/no-token profile (the smallest documented
                // limits). `connection_state` carries the live value
                // once the background reconnect completes.
                (
                    ConnState::Connecting,
                    None,
                    EffectiveCapabilities::default_profile(),
                )
            }
        };

        let (state_tx, state_rx) = watch::channel(initial_state);

        let supervisor = Supervisor {
            config,
            signer,
            inbox_tx,
            presence_tx,
            state_tx,
            cmd_tx: cmd_tx.clone(),
        };
        let join = tokio::spawn(supervisor.run(initial_session, cmd_rx));

        Ok(Self {
            effective_capabilities,
            cmd_tx,
            inbox: Mutex::new(inbox_rx),
            presence: Mutex::new(presence_rx),
            state_rx,
            supervisor: Mutex::new(Some(join)),
        })
    }

    /// Submit `envelope` for delivery to `to`, awaiting the relay's ack.
    ///
    /// If the supervisor is mid-reconnect, the send fails fast with
    /// [`ClientError::Disconnected`] — callers decide whether to wait
    /// for [`Self::connection_state`] to report `Connected` before
    /// retrying.
    ///
    /// # Errors
    /// Returns [`ClientError::Disconnected`] when the supervisor has
    /// no live connection, or [`ClientError::InboxClosed`] if the
    /// supervisor has shut down. Returns the underlying WS / proto
    /// error on a write failure.
    /// In-flight sends whose `Ack` was lost to a reconnect resolve as
    /// [`ClientError::InboxClosed`] — callers decide whether to retry
    /// with a fresh `dedupe_key`.
    pub async fn send(
        &self,
        to: AgentId,
        envelope: TransitEnvelope,
        dedupe_key: DedupeKey,
    ) -> Result<Receipt, ClientError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SupervisorCmd::Send {
                to,
                envelope: Box::new(envelope),
                dedupe_key,
                reply: reply_tx,
            })
            .map_err(|_| ClientError::InboxClosed)?;
        reply_rx.await.map_err(|_| ClientError::InboxClosed)?
    }

    /// Receive the next delivered envelope, if any.
    ///
    /// The inbox channel is owned by the [`Client`] handle and survives
    /// reconnects, so this stream pauses while the WS is down and
    /// resumes once the supervisor has re-established the session.
    ///
    /// Returns `None` once the supervisor has shut down for good.
    pub async fn next_delivery(&self) -> Option<Deliver> {
        self.inbox.lock().await.recv().await
    }

    /// Subscribe to presence transitions for `agents`.
    ///
    /// The relay immediately echoes each agent's current online state
    /// over the presence channel; subsequent transitions stream through
    /// the same channel as long as the watch is active.
    ///
    /// The watch set is owned by the client supervisor and re-sent on
    /// every reconnect, so callers don't have to re-watch after the WS
    /// drops.
    ///
    /// # Errors
    /// Returns [`ClientError::InboxClosed`] when the supervisor has
    /// shut down.
    pub fn watch_presence(&self, agents: &[AgentId]) -> Result<(), ClientError> {
        if agents.is_empty() {
            return Ok(());
        }
        self.cmd_tx
            .send(SupervisorCmd::WatchPresence {
                add: agents.to_vec(),
                remove: Vec::new(),
            })
            .map_err(|_| ClientError::InboxClosed)
    }

    /// Drop the supervisor's interest in `agents`. Returns `Ok` even
    /// when `agents` are not currently in the watch set (the relay
    /// silently ignores stale removes).
    ///
    /// # Errors
    /// Returns [`ClientError::InboxClosed`] when the supervisor has
    /// shut down.
    pub fn unwatch_presence(&self, agents: &[AgentId]) -> Result<(), ClientError> {
        if agents.is_empty() {
            return Ok(());
        }
        self.cmd_tx
            .send(SupervisorCmd::WatchPresence {
                add: Vec::new(),
                remove: agents.to_vec(),
            })
            .map_err(|_| ClientError::InboxClosed)
    }

    /// Re-arm the reconnect loop: if the client is currently reconnecting,
    /// reset the backoff to the floor and retry immediately instead of waiting
    /// out the exponential delay. Call this on app-foreground or a
    /// network-regain event (or from a wedge-watchdog) so a returning
    /// connection recovers in ~1 s rather than up to `MAX_BACKOFF`. A no-op
    /// when already connected or after the supervisor has stopped; pairs with
    /// [`ClientConfig::with_unbounded_reconnect`] (retry forever) to give
    /// "retry forever, and retry NOW when connectivity returns".
    pub fn reconnect_now(&self) {
        let _ = self.cmd_tx.send(SupervisorCmd::ReconnectNow);
    }

    /// Receive the next presence transition pushed by the relay, if any.
    ///
    /// Mirrors [`Self::next_delivery`]: the channel is owned by the
    /// client handle and survives reconnects.
    pub async fn next_presence(&self) -> Option<PresenceUpdate> {
        self.presence.lock().await.recv().await
    }

    /// Borrow a [`watch::Receiver`] reporting the supervisor's current
    /// [`ConnState`].
    #[must_use]
    pub fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.state_rx.clone()
    }

    /// Signal the supervisor to close the session and stop reconnecting.
    ///
    /// Subsequent calls are no-ops. Existing pending sends resolve with
    /// [`ClientError::InboxClosed`].
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(SupervisorCmd::Shutdown);
        let handle = self.supervisor.lock().await.take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(SupervisorCmd::Shutdown);
        if let Ok(mut guard) = self.supervisor.try_lock() {
            if let Some(h) = guard.take() {
                h.abort();
            }
        }
    }
}

/// Result of a successful handshake handed to the supervisor.
struct OpenSession {
    sender: WsSender,
    receiver: WsReceiver,
    effective_capabilities: EffectiveCapabilities,
}

struct Supervisor {
    config: ClientConfig,
    signer: Arc<dyn Signer + Send + Sync>,
    inbox_tx: mpsc::UnboundedSender<Deliver>,
    presence_tx: mpsc::UnboundedSender<PresenceUpdate>,
    state_tx: watch::Sender<ConnState>,
    cmd_tx: mpsc::UnboundedSender<SupervisorCmd>,
}

impl Supervisor {
    /// Establish the first `Inner` before the command loop.
    ///
    /// `Some(session)` installs it exactly as the legacy path did.
    /// `None` (a failed initial connect) drives the reconnect loop once
    /// to self-heal, mirroring the drop-then-reconnect outcome handling.
    ///
    /// Returns `Some(inner)` to proceed into the command loop — `inner`
    /// is `None` only when the None-start path exhausted the reconnect
    /// budget, in which case the loop still runs so `Send` reports
    /// `Disconnected`. Returns `None` to signal `run` should return
    /// (a `Shutdown` arrived before any session landed).
    async fn bootstrap(
        &self,
        initial: Option<OpenSession>,
        next_gen: &mut ConnGen,
        backoff: &mut Duration,
        watch_set: &mut HashSet<AgentId>,
        cmd_rx: &mut mpsc::UnboundedReceiver<SupervisorCmd>,
    ) -> Option<Option<Inner>> {
        if let Some(session) = initial {
            let inner = self.install(session, *next_gen, watch_set).await;
            *next_gen += 1;
            return Some(Some(inner));
        }
        // No session on the first connect (the cold app booted on a
        // flaky network). Drive the existing reconnect loop once to
        // establish the first session in the background.
        let _ = self.state_tx.send(ConnState::Disconnected {
            reason: "initial connect pending".into(),
            retry_at: Some(Instant::now() + *backoff),
        });
        match self.reconnect(cmd_rx, backoff, watch_set).await {
            ReconnectOutcome::Connected(session) => {
                let inner = self.install(session, *next_gen, watch_set).await;
                *next_gen += 1;
                *backoff = INITIAL_BACKOFF;
                Some(Some(inner))
            }
            ReconnectOutcome::Shutdown => None,
            ReconnectOutcome::PermanentlyDisconnected { reason, attempts } => {
                let _ = self
                    .state_tx
                    .send(ConnState::PermanentlyDisconnected { reason, attempts });
                // inner stays None; fall through to the command loop
                // where Send returns Disconnected, matching the existing
                // post-permanent behavior.
                Some(None)
            }
        }
    }

    async fn run(
        self,
        initial: Option<OpenSession>,
        mut cmd_rx: mpsc::UnboundedReceiver<SupervisorCmd>,
    ) {
        let mut next_gen: ConnGen = 1;
        let mut watch_set: HashSet<AgentId> = HashSet::new();
        let mut backoff = INITIAL_BACKOFF;
        let Some(mut inner) = self
            .bootstrap(
                initial,
                &mut next_gen,
                &mut backoff,
                &mut watch_set,
                &mut cmd_rx,
            )
            .await
        else {
            // Bootstrap saw a Shutdown before any session landed.
            return;
        };

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                SupervisorCmd::Shutdown => {
                    drop(inner.take());
                    break;
                }
                // Already connected — a re-arm is a no-op here; it only
                // matters while reconnecting (see `reconnect`).
                SupervisorCmd::ReconnectNow => {}
                SupervisorCmd::Send {
                    to,
                    envelope,
                    dedupe_key,
                    reply,
                } => {
                    let result = if let Some(i) = inner.as_ref() {
                        do_send(
                            i,
                            to,
                            *envelope,
                            dedupe_key,
                            self.config.send_write_timeout,
                            self.config.send_ack_timeout,
                        )
                        .await
                    } else {
                        Err(ClientError::Disconnected("client is reconnecting".into()))
                    };
                    let _ = reply.send(result);
                }
                SupervisorCmd::WatchPresence { add, remove } => {
                    for a in &add {
                        watch_set.insert(*a);
                    }
                    for a in &remove {
                        watch_set.remove(a);
                    }
                    if let Some(i) = inner.as_ref() {
                        let _ = send_watch_frame(i, add, remove).await;
                    }
                }
                SupervisorCmd::Disconnected { gen, reason } => {
                    // Ignore signals from already-torn-down connections.
                    let Some(current) = inner.as_ref() else {
                        continue;
                    };
                    if current.gen != gen {
                        continue;
                    }
                    drop(inner.take());
                    let _ = self.state_tx.send(ConnState::Disconnected {
                        reason: reason.clone(),
                        retry_at: Some(Instant::now() + backoff),
                    });
                    match self
                        .reconnect(&mut cmd_rx, &mut backoff, &mut watch_set)
                        .await
                    {
                        ReconnectOutcome::Connected(session) => {
                            inner = Some(self.install(session, next_gen, &watch_set).await);
                            next_gen += 1;
                            backoff = INITIAL_BACKOFF;
                        }
                        ReconnectOutcome::Shutdown => break,
                        ReconnectOutcome::PermanentlyDisconnected { reason, attempts } => {
                            let _ = self
                                .state_tx
                                .send(ConnState::PermanentlyDisconnected { reason, attempts });
                            // Stop the supervisor; the application
                            // must rebuild Client to reconnect.
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn install(
        &self,
        session: OpenSession,
        gen: ConnGen,
        watch_set: &HashSet<AgentId>,
    ) -> Inner {
        let OpenSession {
            sender,
            receiver,
            effective_capabilities,
        } = session;
        let sender = Arc::new(Mutex::new(sender));
        let outbox = Arc::new(Outbox::new());
        let reader = spawn_reader(
            gen,
            receiver,
            outbox.clone(),
            self.inbox_tx.clone(),
            self.presence_tx.clone(),
            self.cmd_tx.clone(),
        );
        let keepalive = self.config.keepalive.map(|i| {
            spawn_keepalive(
                gen,
                i,
                self.config.pong_timeout,
                sender.clone(),
                outbox.clone(),
                self.cmd_tx.clone(),
            )
        });
        let _ = self.state_tx.send(ConnState::Connected {
            effective_capabilities,
        });
        let inner = Inner {
            gen,
            sender,
            outbox,
            reader,
            keepalive,
        };
        if !watch_set.is_empty() {
            let _ = send_watch_frame(&inner, watch_set.iter().copied().collect(), Vec::new()).await;
        }
        inner
    }

    async fn reconnect(
        &self,
        cmd_rx: &mut mpsc::UnboundedReceiver<SupervisorCmd>,
        backoff: &mut Duration,
        watch_set: &mut HashSet<AgentId>,
    ) -> ReconnectOutcome {
        let max_attempts = self.config.max_reconnect_attempts;
        let max_elapsed = self.config.max_reconnect_elapsed;
        let start = Instant::now();
        let mut attempts: u32 = 0;
        let mut last_reason: String;
        loop {
            // Wait for the backoff, but also drain commands so that
            // Send calls during the disconnect fail fast rather than
            // pile up in the mpsc queue.
            let deadline = sleep(*backoff);
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    () = &mut deadline => break,
                    maybe = cmd_rx.recv() => match maybe {
                        None | Some(SupervisorCmd::Shutdown) => return ReconnectOutcome::Shutdown,
                        Some(SupervisorCmd::Send { reply, .. }) => {
                            let _ = reply.send(Err(ClientError::Disconnected(
                                "client is reconnecting".into(),
                            )));
                        }
                        Some(SupervisorCmd::WatchPresence { add, remove }) => {
                            // No live connection to forward to, but the
                            // watch_set is the supervisor's source of truth
                            // — install() will rehydrate from it once the
                            // reconnect completes.
                            for a in &add { watch_set.insert(*a); }
                            for a in &remove { watch_set.remove(a); }
                        }
                        // Spurious Disconnected from a previous WS;
                        // already handled — ignore.
                        Some(SupervisorCmd::Disconnected { .. }) => {}
                        // Re-arm: skip the rest of the backoff and retry
                        // now, resetting to the floor so a later failure
                        // backs off from scratch.
                        Some(SupervisorCmd::ReconnectNow) => {
                            *backoff = INITIAL_BACKOFF;
                            break;
                        }
                    }
                }
            }

            let _ = self.state_tx.send(ConnState::Connecting);
            match open_session(&self.config, self.signer.as_ref()).await {
                Ok(s) => return ReconnectOutcome::Connected(s),
                Err(e) => {
                    attempts = attempts.saturating_add(1);
                    last_reason = format!("reconnect failed: {e}");
                    *backoff = (backoff.saturating_mul(2)).min(MAX_BACKOFF);
                    // Check caps BEFORE pushing the next "still
                    // retrying" Disconnected so the terminal state
                    // is the user's final signal.
                    let hit_attempts = max_attempts.is_some_and(|m| attempts >= m);
                    let hit_elapsed = max_elapsed.is_some_and(|d| start.elapsed() >= d);
                    if hit_attempts || hit_elapsed {
                        return ReconnectOutcome::PermanentlyDisconnected {
                            reason: last_reason,
                            attempts,
                        };
                    }
                    let _ = self.state_tx.send(ConnState::Disconnected {
                        reason: last_reason.clone(),
                        retry_at: Some(Instant::now() + *backoff),
                    });
                }
            }
        }
    }
}

enum ReconnectOutcome {
    Connected(OpenSession),
    Shutdown,
    PermanentlyDisconnected { reason: String, attempts: u32 },
}

async fn do_send(
    inner: &Inner,
    to: AgentId,
    envelope: TransitEnvelope,
    dedupe_key: DedupeKey,
    write_timeout: Duration,
    ack_timeout: Duration,
) -> Result<Receipt, ClientError> {
    let rx = inner.outbox.track(dedupe_key);
    let frame = ClientFrame::Send(SendFrame {
        to,
        envelope,
        dedupe_key,
    });
    let bytes = to_bytes(&frame)?;
    // Cap the WS write: if the TCP send buffer is wedged (the
    // failure mode from issue #156), `sender.send()` blocks forever.
    // Time it out so the caller's bubble flips to a clear `failed`
    // state instead of hanging in `sending` until the heat-death of
    // the universe.
    {
        let mut sender = inner.sender.lock().await;
        match tokio::time::timeout(write_timeout, sender.send(Message::Binary(bytes))).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(ClientError::SendTimeout(write_timeout)),
        }
    }
    // Cap the Ack wait: bytes left our socket but the relay either
    // never accepted them into its routing path or never emitted an
    // Ack. Either way, treat it as definitively un-sent so the user
    // can retry rather than wait indefinitely.
    match tokio::time::timeout(ack_timeout, rx).await {
        Ok(Ok(SendResolution::Acked(receipt))) => Ok(receipt),
        Ok(Ok(SendResolution::RecipientMoved)) => Err(ClientError::RecipientMoved),
        Ok(Err(_)) => Err(ClientError::InboxClosed),
        Err(_) => Err(ClientError::SendTimeout(ack_timeout)),
    }
}

async fn open_session(
    config: &ClientConfig,
    signer: &(dyn Signer + Send + Sync),
) -> Result<OpenSession, ClientError> {
    let bearer = obtain_bearer(&config.base, signer, config.auth_timeout).await?;
    let ws_url = build_ws_url(&config.base, &bearer)?;
    let mut req = ws_url.as_str().into_client_request()?;
    // #113: also present the bearer as an `Authorization` header so the
    // token can leave the URL once relays read the header. The `?token=`
    // query stays during the transition (the server still reads it); a
    // follow-up drops the query once relays prefer the header.
    let auth_value = HeaderValue::from_str(&format!("Bearer {bearer}"))
        .map_err(|e| ClientError::AuthRejected(format!("bearer header: {e}")))?;
    req.headers_mut().insert(AUTHORIZATION, auth_value);
    let (mut stream, _resp) = connect_async(req).await?;

    let hello = ClientFrame::Hello(Hello {
        client_version: config.client_version.clone(),
        tenant_id: config.tenant_id.clone(),
        preferred_region: None,
        capabilities: config.capabilities.clone(),
    });
    stream.send(Message::Binary(to_bytes(&hello)?)).await?;

    let ready = await_ready(&mut stream).await?;
    let (sender, receiver) = stream.split();
    Ok(OpenSession {
        sender,
        receiver,
        effective_capabilities: ready.effective_capabilities,
    })
}

async fn obtain_bearer(
    base: &Url,
    signer: &(dyn Signer + Send + Sync),
    timeout: Duration,
) -> Result<String, ClientError> {
    let http = reqwest::Client::builder().timeout(timeout).build()?;
    let challenge: AuthChallenge = http
        .post(base.join("v1/auth/challenge")?)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let signing_bytes = auth_signing_bytes(&challenge.challenge);
    let signature = signer
        .sign(&signing_bytes)
        .await
        .map_err(ClientError::AuthRejected)?;

    let req = AuthVerifyRequest {
        agent_id: AgentId::from_bytes(signer.agent_id()),
        agent_public_key: signer.public_key(),
        challenge: challenge.challenge,
        signature,
    };
    let resp: AuthVerifyResponse = http
        .post(base.join("v1/auth/verify")?)
        .json(&req)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp.token)
}

fn build_ws_url(base: &Url, bearer: &str) -> Result<Url, ClientError> {
    let mut ws_base = base.clone();
    let scheme = match ws_base.scheme() {
        "https" => "wss",
        _ => "ws",
    };
    ws_base
        .set_scheme(scheme)
        .map_err(|()| ClientError::Url(url::ParseError::SetHostOnCannotBeABaseUrl))?;
    let url = ws_base.join(&format!("v1/ws?token={bearer}"))?;
    Ok(url)
}

async fn await_ready(stream: &mut WsStream) -> Result<Ready, ClientError> {
    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let Message::Binary(b) = msg else {
            continue;
        };
        match from_bytes::<ServerFrame>(&b)? {
            ServerFrame::Ready(r) => return Ok(r),
            ServerFrame::Bye(b) => {
                return Err(ClientError::RelayClosed(format!(
                    "bye before ready: {:?}",
                    b.reason
                )));
            }
            _ => {}
        }
    }
    Err(ClientError::RelayClosed("ws closed before ready".into()))
}

fn spawn_reader(
    gen: ConnGen,
    mut receiver: WsReceiver,
    outbox: Arc<Outbox>,
    inbox: mpsc::UnboundedSender<Deliver>,
    presence: mpsc::UnboundedSender<PresenceUpdate>,
    cmd_tx: mpsc::UnboundedSender<SupervisorCmd>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let reason = loop {
            match receiver.next().await {
                None => break "ws stream ended".to_string(),
                Some(Err(e)) => break format!("ws read error: {e}"),
                Some(Ok(msg)) => {
                    let Message::Binary(b) = msg else { continue };
                    let Ok(frame) = from_bytes::<ServerFrame>(&b) else {
                        continue;
                    };
                    match frame {
                        ServerFrame::Ack(Ack {
                            dedupe_key,
                            accepted_at_ms,
                        }) => {
                            let _ = outbox.ack(&dedupe_key, accepted_at_ms);
                        }
                        ServerFrame::Deliver(d) => {
                            if inbox.send(d).is_err() {
                                break "inbox dropped".to_string();
                            }
                        }
                        ServerFrame::PresenceUpdate(p) => {
                            if presence.send(p).is_err() {
                                break "presence channel dropped".to_string();
                            }
                        }
                        ServerFrame::Pong(Pong { nonce }) => {
                            outbox.record_pong(nonce);
                            // Steady heartbeat line: external liveness probes
                            // (journal-recency watchdogs) key on this, since
                            // inbound traffic alone can't distinguish a quiet
                            // peer from a hung process.
                            tracing::debug!("relay keepalive pong");
                        }
                        ServerFrame::Throttle(Throttle { .. }) | ServerFrame::Ready(_) => {
                            // Throttle observable via metrics in a future pass.
                            // Stray Ready outside the handshake is a no-op.
                        }
                        ServerFrame::Moved(Moved { dedupe_key }) => {
                            // The recipient migrated away from this relay;
                            // resolve the pending send so the caller's
                            // deposit path can re-resolve via the signed
                            // forwarding record and retry at the new relay.
                            let _ = outbox.moved(&dedupe_key);
                        }
                        ServerFrame::Bye(b) => break format!("relay sent Bye: {:?}", b.reason),
                    }
                }
            }
        };
        let _ = cmd_tx.send(SupervisorCmd::Disconnected { gen, reason });
    })
}

async fn send_watch_frame(
    inner: &Inner,
    add: Vec<AgentId>,
    remove: Vec<AgentId>,
) -> Result<(), ClientError> {
    if add.is_empty() && remove.is_empty() {
        return Ok(());
    }
    let frame = ClientFrame::WatchPresence(WatchPresence { add, remove });
    let bytes = to_bytes(&frame)?;
    let mut sender = inner.sender.lock().await;
    sender.send(Message::Binary(bytes)).await?;
    Ok(())
}

fn spawn_keepalive(
    gen: ConnGen,
    keepalive_interval: Duration,
    pong_timeout: Option<Duration>,
    sender: Arc<Mutex<WsSender>>,
    outbox: Arc<Outbox>,
    cmd_tx: mpsc::UnboundedSender<SupervisorCmd>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Reset the Pong clock so a fresh connection isn't immediately
        // judged unresponsive.
        outbox.touch_pong();
        let mut tick = interval(keepalive_interval);
        // The first tick fires immediately by default; skip it so we
        // don't ping before the relay has finished installing the
        // session in the writer task.
        tick.tick().await;
        loop {
            tick.tick().await;
            let nonce = random_nonce();
            let frame = ClientFrame::Ping(Ping { nonce });
            let bytes = match to_bytes(&frame) {
                Ok(b) => b,
                Err(e) => {
                    let _ = cmd_tx.send(SupervisorCmd::Disconnected {
                        gen,
                        reason: format!("encode ping: {e}"),
                    });
                    return;
                }
            };
            {
                let mut s = sender.lock().await;
                if let Err(e) = s.send(Message::Binary(bytes)).await {
                    let _ = cmd_tx.send(SupervisorCmd::Disconnected {
                        gen,
                        reason: format!("send ping: {e}"),
                    });
                    return;
                }
            }
            if let Some(deadline) = pong_timeout {
                let last = outbox.last_pong();
                if last.elapsed() > deadline {
                    let _ = cmd_tx.send(SupervisorCmd::Disconnected {
                        gen,
                        reason: format!("no Pong for {:?}", last.elapsed()),
                    });
                    return;
                }
            }
        }
    })
}

fn random_nonce() -> u64 {
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signer::StaticKeySigner;
    use fetchit_relay_proto::Region;
    use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Bind an ephemeral port, then release it. The returned address is
    /// free *right now* but nothing is listening — a connect against it
    /// is refused fast, which is exactly the cold-flaky-network case.
    async fn reserve_then_release() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    /// Tight reconnect budget so a permanent failure resolves quickly
    /// and the test never waits on the production-default 20 attempts.
    fn fast_config(base: Url) -> ClientConfig {
        let mut cfg = ClientConfig::new(base);
        cfg.auth_timeout = Duration::from_millis(200);
        cfg.max_reconnect_attempts = Some(3);
        cfg
    }

    #[tokio::test]
    async fn reconnect_now_short_circuits_the_backoff() {
        // Against a refusing relay the supervisor backs off exponentially
        // (1s, 2s, 4s, ...). `reconnect_now` must reset to the floor and retry
        // immediately, so a re-armed Connecting appears well before the grown
        // backoff would have fired.
        let addr = reserve_then_release().await;
        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        let signer = Arc::new(StaticKeySigner::from_public_key(b"rearm-key".to_vec()));
        let mut cfg = ClientConfig::new(base);
        cfg.auth_timeout = Duration::from_millis(100);
        cfg.max_reconnect_attempts = None; // retry forever so the backoff keeps growing
        let client = Client::connect(cfg, signer).await.unwrap();
        let mut state = client.connection_state();

        // Wait until the next natural retry is >= 3s out (backoff has grown to
        // ~4s after a few failed attempts).
        loop {
            state.changed().await.unwrap();
            let deep_backoff = matches!(
                &*state.borrow(),
                ConnState::Disconnected { retry_at: Some(at), .. }
                    if at.saturating_duration_since(Instant::now()) >= Duration::from_secs(3)
            );
            if deep_backoff {
                break;
            }
        }

        // Re-arm: a Connecting must appear well inside that 3s+ window.
        client.reconnect_now();
        let reconnected = tokio::time::timeout(Duration::from_millis(1200), async {
            loop {
                state.changed().await.unwrap();
                if matches!(&*state.borrow(), ConnState::Connecting) {
                    return;
                }
            }
        })
        .await;
        assert!(
            reconnected.is_ok(),
            "reconnect_now must trigger a reconnect well before the grown backoff elapses"
        );
    }

    #[tokio::test]
    async fn connect_tolerates_unreachable_relay_and_starts_reconnecting() {
        // A connect against an address that refuses must NOT fail the
        // build: the client is constructed in a connecting state and the
        // supervisor self-heals in the background.
        let addr = reserve_then_release().await;
        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        let signer = Arc::new(StaticKeySigner::from_public_key(
            b"unreachable-key".to_vec(),
        ));

        let client = Client::connect(fast_config(base), signer)
            .await
            .expect("connect must tolerate an unreachable relay, not Err");

        // Immediately after construct the supervisor has not yet
        // established a session, so the state is Connecting (initial) or
        // Disconnected (the None-start path's first emission) — never
        // Connected.
        let state = client.connection_state().borrow().clone();
        assert!(
            matches!(
                state,
                ConnState::Connecting | ConnState::Disconnected { .. }
            ),
            "expected Connecting/Disconnected before any session lands, got {state:?}"
        );

        // The conservative default-profile caps are seeded until the
        // first session negotiates real limits.
        assert_eq!(
            client.effective_capabilities,
            EffectiveCapabilities::default_profile()
        );
    }

    #[tokio::test]
    async fn connect_self_heals_when_relay_becomes_reachable() {
        // Start with the relay down: connect resolves Ok and the client
        // is reconnecting. Then bring the relay up on the same address
        // and assert the supervisor reaches Connected on its own.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Hold the bound port so the client's first connect is refused,
        // then hand it to the server once the client is reconnecting.
        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        let signer = Arc::new(StaticKeySigner::from_public_key(b"self-heal-key".to_vec()));

        // Generous reconnect budget; backoff starts at 1s so the heal
        // lands on the second attempt well within the timeout below.
        let client = Client::connect(ClientConfig::new(base), signer)
            .await
            .expect("connect must resolve Ok while the relay is down");
        assert!(
            !matches!(
                *client.connection_state().borrow(),
                ConnState::Connected { .. }
            ),
            "must not be Connected before the relay comes up"
        );

        // Bring the production server up on the held listener.
        let cfg = ServerConfig::defaults(addr, Region::Nyc);
        let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
        let (router, _state) = server.router();
        let _server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Wait for the supervisor's reconnect loop to land a session.
        let mut state_rx = client.connection_state();
        let healed = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if matches!(*state_rx.borrow_and_update(), ConnState::Connected { .. }) {
                    return true;
                }
                if state_rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .expect("timed out waiting for the client to self-heal to Connected");
        assert!(healed, "state channel closed before reaching Connected");
    }
}
