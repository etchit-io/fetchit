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
use crate::outbox::{Outbox, Receipt};
use crate::signer::Signer;
use fetchit_relay_proto::{
    auth_signing_bytes, from_bytes, to_bytes, Ack, AgentId, AuthChallenge, AuthVerifyRequest,
    AuthVerifyResponse, CapabilityToken, ClientFrame, DedupeKey, Deliver, EffectiveCapabilities,
    Hello, Ping, Pong, Ready, SendFrame, ServerFrame, TenantId, Throttle, TransitEnvelope,
};
use futures_util::{stream::SplitSink, stream::SplitStream, SinkExt, StreamExt};
use rand::RngCore;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
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
        }
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
    /// Internal signal raised by the reader / keepalive tasks when the
    /// WS for `gen` died. Carries the reason for diagnostics.
    Disconnected {
        gen: ConnGen,
        reason: String,
    },
    Shutdown,
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
    /// # Errors
    /// Bubbles up any HTTP, WebSocket, auth, or proto failure from the
    /// *first* connection attempt. Once this function returns `Ok`,
    /// subsequent disconnects are handled transparently by the
    /// supervisor and surfaced via [`Self::connection_state`].
    pub async fn connect(
        config: ClientConfig,
        signer: Arc<dyn Signer + Send + Sync>,
    ) -> Result<Self, ClientError> {
        let initial = open_session(&config, signer.as_ref()).await?;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        let effective_capabilities = initial.effective_capabilities.clone();
        let (state_tx, state_rx) = watch::channel(ConnState::Connected {
            effective_capabilities: effective_capabilities.clone(),
        });

        let supervisor = Supervisor {
            config,
            signer,
            inbox_tx,
            state_tx,
            cmd_tx: cmd_tx.clone(),
        };
        let join = tokio::spawn(supervisor.run(initial, cmd_rx));

        Ok(Self {
            effective_capabilities,
            cmd_tx,
            inbox: Mutex::new(inbox_rx),
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
    state_tx: watch::Sender<ConnState>,
    cmd_tx: mpsc::UnboundedSender<SupervisorCmd>,
}

impl Supervisor {
    async fn run(self, initial: OpenSession, mut cmd_rx: mpsc::UnboundedReceiver<SupervisorCmd>) {
        let mut next_gen: ConnGen = 1;
        let mut inner = Some(self.install(initial, next_gen));
        next_gen += 1;
        let mut backoff = INITIAL_BACKOFF;

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                SupervisorCmd::Shutdown => {
                    drop(inner.take());
                    break;
                }
                SupervisorCmd::Send {
                    to,
                    envelope,
                    dedupe_key,
                    reply,
                } => {
                    let result = if let Some(i) = inner.as_ref() {
                        do_send(i, to, *envelope, dedupe_key).await
                    } else {
                        Err(ClientError::Disconnected("client is reconnecting".into()))
                    };
                    let _ = reply.send(result);
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
                    match self.reconnect(&mut cmd_rx, &mut backoff).await {
                        ReconnectOutcome::Connected(session) => {
                            inner = Some(self.install(session, next_gen));
                            next_gen += 1;
                            backoff = INITIAL_BACKOFF;
                        }
                        ReconnectOutcome::Shutdown => break,
                    }
                }
            }
        }
    }

    fn install(&self, session: OpenSession, gen: ConnGen) -> Inner {
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
        Inner {
            gen,
            sender,
            outbox,
            reader,
            keepalive,
        }
    }

    async fn reconnect(
        &self,
        cmd_rx: &mut mpsc::UnboundedReceiver<SupervisorCmd>,
        backoff: &mut Duration,
    ) -> ReconnectOutcome {
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
                        // Spurious Disconnected from a previous WS;
                        // already handled — ignore.
                        Some(SupervisorCmd::Disconnected { .. }) => {}
                    }
                }
            }

            let _ = self.state_tx.send(ConnState::Connecting);
            match open_session(&self.config, self.signer.as_ref()).await {
                Ok(s) => return ReconnectOutcome::Connected(s),
                Err(e) => {
                    *backoff = (backoff.saturating_mul(2)).min(MAX_BACKOFF);
                    let _ = self.state_tx.send(ConnState::Disconnected {
                        reason: format!("reconnect failed: {e}"),
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
}

async fn do_send(
    inner: &Inner,
    to: AgentId,
    envelope: TransitEnvelope,
    dedupe_key: DedupeKey,
) -> Result<Receipt, ClientError> {
    let rx = inner.outbox.track(dedupe_key);
    let frame = ClientFrame::Send(SendFrame {
        to,
        envelope,
        dedupe_key,
    });
    let bytes = to_bytes(&frame)?;
    {
        let mut sender = inner.sender.lock().await;
        sender.send(Message::Binary(bytes)).await?;
    }
    rx.await.map_err(|_| ClientError::InboxClosed)
}

async fn open_session(
    config: &ClientConfig,
    signer: &(dyn Signer + Send + Sync),
) -> Result<OpenSession, ClientError> {
    let bearer = obtain_bearer(&config.base, signer, config.auth_timeout).await?;
    let ws_url = build_ws_url(&config.base, &bearer)?;
    let req = ws_url.as_str().into_client_request()?;
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
            ServerFrame::Bye(_) => {
                return Err(ClientError::RelayClosed("bye before ready".into()));
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
                        ServerFrame::Pong(Pong { nonce }) => {
                            outbox.record_pong(nonce);
                        }
                        ServerFrame::Throttle(Throttle { .. }) | ServerFrame::Ready(_) => {
                            // Throttle observable via metrics in a future pass.
                            // Stray Ready outside the handshake is a no-op.
                        }
                        ServerFrame::Bye(_) => break "relay sent Bye".to_string(),
                    }
                }
            }
        };
        let _ = cmd_tx.send(SupervisorCmd::Disconnected { gen, reason });
    })
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
