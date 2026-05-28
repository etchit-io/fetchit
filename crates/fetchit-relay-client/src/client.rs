//! High-level client API.
//!
//! [`Client::connect`] runs the auth handshake, opens the WebSocket,
//! sends `Hello`, waits for `Ready`, and spawns a background task that
//! pumps inbound frames into a channel and correlates acks with the
//! outbox. [`Client::send`] returns once the relay acks.

use crate::error::ClientError;
use crate::outbox::{Outbox, Receipt};
use crate::signer::Signer;
use fetchit_relay_proto::{
    auth_signing_bytes, from_bytes, to_bytes, Ack, AgentId, AuthChallenge, AuthVerifyRequest,
    AuthVerifyResponse, CapabilityToken, ClientFrame, DedupeKey, Deliver, EffectiveCapabilities,
    Hello, Pong, Ready, SendFrame, ServerFrame, TenantId, Throttle, TransitEnvelope,
};
use futures_util::{stream::SplitSink, stream::SplitStream, SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

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
        }
    }
}

/// A live relay session.
pub struct Client {
    /// The relay's resolved session limits.
    pub effective_capabilities: EffectiveCapabilities,
    sender: Arc<Mutex<SplitSink<WsStream, Message>>>,
    outbox: Arc<Outbox>,
    inbox: Mutex<mpsc::UnboundedReceiver<Deliver>>,
}

impl Client {
    /// Run the full handshake against `config.base` and open the WS.
    ///
    /// # Errors
    /// Bubbles up any HTTP, WebSocket, auth, or proto failure.
    pub async fn connect<S: Signer + ?Sized>(
        config: ClientConfig,
        signer: &S,
    ) -> Result<Self, ClientError> {
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
        let sender = Arc::new(Mutex::new(sender));
        let outbox = Arc::new(Outbox::new());
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        spawn_reader(receiver, sender.clone(), outbox.clone(), inbox_tx);

        Ok(Self {
            effective_capabilities: ready.effective_capabilities,
            sender,
            outbox,
            inbox: Mutex::new(inbox_rx),
        })
    }

    /// Submit `envelope` for delivery to `to`, awaiting the relay's ack.
    ///
    /// # Errors
    /// Returns if the WS write fails or the relay closes the session
    /// before sending an `Ack` for this dedupe key.
    pub async fn send(
        &self,
        to: AgentId,
        envelope: TransitEnvelope,
        dedupe_key: DedupeKey,
    ) -> Result<Receipt, ClientError> {
        let rx = self.outbox.track(dedupe_key);
        let frame = ClientFrame::Send(SendFrame {
            to,
            envelope,
            dedupe_key,
        });
        let bytes = to_bytes(&frame)?;
        self.sender
            .lock()
            .await
            .send(Message::Binary(bytes))
            .await?;
        rx.await.map_err(|_| ClientError::InboxClosed)
    }

    /// Receive the next delivered envelope, if any.
    ///
    /// Returns `None` once the inbound channel is closed (i.e. the
    /// session ended).
    pub async fn next_delivery(&self) -> Option<Deliver> {
        self.inbox.lock().await.recv().await
    }
}

async fn obtain_bearer<S: Signer + ?Sized>(
    base: &Url,
    signer: &S,
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
    mut receiver: SplitStream<WsStream>,
    sender: Arc<Mutex<SplitSink<WsStream, Message>>>,
    outbox: Arc<Outbox>,
    inbox: mpsc::UnboundedSender<Deliver>,
) {
    tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            let Message::Binary(b) = msg else {
                continue;
            };
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
                        break;
                    }
                }
                ServerFrame::Throttle(Throttle { .. })
                | ServerFrame::Pong(Pong { .. })
                | ServerFrame::Ready(_) => {
                    // Throttle is observable via metrics in a future pass.
                    // Stray Ready / Pong outside the handshake are no-ops.
                    let _ = &sender;
                }
                ServerFrame::Bye(_) => break,
            }
        }
    });
}
