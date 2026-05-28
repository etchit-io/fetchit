//! WebSocket upgrade + per-connection event loop.

use crate::auth::AuthTokenState;
use crate::server::ServerState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use fetchit_relay_proto::{
    from_bytes, to_bytes, Ack, ClientFrame, Deliver, EffectiveCapabilities, Hello, Ping, Pong,
    Ready, SendFrame, ServerFrame, Throttle, ThrottleReason,
};
use futures_util::{stream::SplitStream, SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Query string carrying the bearer token for the WS upgrade.
#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// Bearer token previously issued by `/v1/auth/verify`.
    pub token: String,
}

/// Axum handler: validate bearer, upgrade, hand off to [`handle_socket`].
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
    Query(query): Query<WsQuery>,
) -> impl IntoResponse {
    let Some(auth) = state.auth.validate_bearer(&query.token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    ws.on_upgrade(move |socket| handle_socket(socket, auth, state))
}

async fn handle_socket(socket: WebSocket, auth: AuthTokenState, state: Arc<ServerState>) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerFrame>();

    let Some(hello) = await_hello(&mut receiver).await else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };

    let region = state.config.region.clone();
    let Ok(effective_caps) = state.capability_resolver.resolve(
        hello.capabilities.as_ref(),
        state.verifier.as_ref(),
        &auth.agent_id,
        &region,
    ) else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };

    let ready = ServerFrame::Ready(Ready {
        server_version: state.config.server_version.clone(),
        region: region.clone(),
        effective_capabilities: effective_caps.clone(),
    });
    let Ok(ready_bytes) = to_bytes(&ready) else {
        return;
    };
    if sender.send(Message::Binary(ready_bytes)).await.is_err() {
        return;
    }

    state.sessions.register(auth.agent_id, tx.clone());
    state.metrics.connection_opened();

    for (seq, entry) in state.transit.drain(&auth.agent_id).into_iter().enumerate() {
        let frame = ServerFrame::Deliver(Deliver {
            envelope: entry.envelope,
            transit_seq: seq as u64,
            delivered_at_ms: now_ms(),
        });
        if tx.send(frame).is_err() {
            break;
        }
        state.metrics.envelope_delivered();
    }

    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            let Ok(bytes) = to_bytes(&f) else { break };
            if sender.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = receiver.next().await {
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(frame) = from_bytes::<ClientFrame>(&bytes) else {
            continue;
        };
        if !handle_client_frame(&state, &auth, &effective_caps, &tx, frame) {
            break;
        }
    }

    state.sessions.unregister(&auth.agent_id);
    state.metrics.connection_closed();
    writer.abort();
}

async fn await_hello(receiver: &mut SplitStream<WebSocket>) -> Option<Hello> {
    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Binary(b) = msg {
            if let Ok(ClientFrame::Hello(h)) = from_bytes::<ClientFrame>(&b) {
                return Some(h);
            }
            return None;
        }
    }
    None
}

fn handle_client_frame(
    state: &Arc<ServerState>,
    auth: &AuthTokenState,
    caps: &EffectiveCapabilities,
    self_tx: &mpsc::UnboundedSender<ServerFrame>,
    frame: ClientFrame,
) -> bool {
    match frame {
        ClientFrame::Hello(_) | ClientFrame::Subscribe(_) => true,
        ClientFrame::Ping(Ping { nonce }) => {
            self_tx.send(ServerFrame::Pong(Pong { nonce })).is_ok()
        }
        ClientFrame::Bye(_) => false,
        ClientFrame::Send(SendFrame {
            to,
            envelope,
            dedupe_key,
        }) => {
            let encoded = envelope.encoded_len().unwrap_or(usize::MAX);
            if encoded > caps.max_envelope_bytes as usize {
                state.metrics.throttle_envelope_too_large();
                let _ = self_tx.send(ServerFrame::Throttle(Throttle {
                    retry_after_ms: 0,
                    reason: ThrottleReason::EnvelopeTooLarge,
                }));
                return true;
            }
            if !state
                .ratelimit
                .allow(&auth.agent_id, caps.max_envelopes_per_min)
            {
                state.metrics.throttle_per_sender();
                let _ = self_tx.send(ServerFrame::Throttle(Throttle {
                    retry_after_ms: 1_000,
                    reason: ThrottleReason::PerSenderRate,
                }));
                return true;
            }
            if envelope.sender_agent_id != auth.agent_id {
                return true;
            }

            let direct_pushed = state.sessions.send(
                &to,
                ServerFrame::Deliver(Deliver {
                    envelope: envelope.clone(),
                    transit_seq: 0,
                    delivered_at_ms: now_ms(),
                }),
            );
            if direct_pushed {
                state.metrics.envelope_delivered();
            } else if state.transit.enqueue(to, envelope).is_err() {
                state.metrics.throttle_per_recipient();
                let _ = self_tx.send(ServerFrame::Throttle(Throttle {
                    retry_after_ms: 5_000,
                    reason: ThrottleReason::PerRecipientCapacity,
                }));
                return true;
            } else {
                state.metrics.envelope_buffered();
            }
            state.metrics.envelope_sent();
            let _ = self_tx.send(ServerFrame::Ack(Ack {
                dedupe_key,
                accepted_at_ms: now_ms(),
            }));
            true
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}
