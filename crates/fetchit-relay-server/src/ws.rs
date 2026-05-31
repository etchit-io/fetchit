//! WebSocket upgrade + per-connection event loop.

use crate::auth::AuthTokenState;
use crate::server::ServerState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use fetchit_relay_proto::{
    from_bytes, to_bytes, Ack, ClientFrame, Deliver, EffectiveCapabilities, Hello, Ping, Pong,
    Ready, SendFrame, ServerFrame, Throttle, ThrottleReason, WatchPresence,
};
use futures_util::{stream::SplitStream, SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

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

    let session_id = state.sessions.register(auth.agent_id, tx.clone());
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

    let mut writer: JoinHandle<()> = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            let Ok(bytes) = to_bytes(&f) else { break };
            if sender.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    info!(session = session_id, "ws: session opened");
    let exit = run_io_loop(
        &mut receiver,
        &mut writer,
        &state,
        &auth,
        &effective_caps,
        &tx,
        session_id,
    )
    .await;

    // Cleanup-trail tracing — operators (Bob's metrics dashboard)
    // need to distinguish clean client closes from writer-task death
    // so a flapping-relay outage is visible without grep'ing for
    // session ids. Per private/metrics-policy.md: NO agent_id or
    // peer-IP fields land in the log — only the session id (opaque
    // monotonic) and the LoopExit reason.
    match exit {
        LoopExit::ClientClosed => {
            debug!(session = session_id, reason = "client_closed", "ws: session closing");
        }
        LoopExit::ProtocolEnd => {
            // Voluntary Bye from the client — normal app-close /
            // navigation lifecycle, fires multiple times per active
            // user. Stays at DEBUG to keep steady-state logs quiet.
            debug!(session = session_id, reason = "protocol_end", "ws: session closing");
        }
        LoopExit::WriterDied => {
            warn!(
                session = session_id,
                reason = "writer_died",
                "ws: session closing — writer task exited mid-flight (WS write or encode error)",
            );
        }
    }
    state.sessions.drop_all_watches(session_id);
    state.sessions.unregister(&auth.agent_id, session_id);
    state.metrics.connection_closed();
    writer.abort();
}

/// Why the per-connection receiver loop exited.
///
/// Cleanup is the same in every case; the variant is informational so callers
/// (and tests) can distinguish a clean client-side close from writer death.
#[derive(Debug, PartialEq, Eq)]
enum LoopExit {
    /// Client sent a Close frame, the read half closed, or a stream error
    /// surfaced.
    ClientClosed,
    /// `handle_client_frame` returned false (e.g. client sent Bye).
    ProtocolEnd,
    /// The writer task exited — typically a WS write error or postcard encode
    /// failure. The per-connection mpsc receiver is now dropped, so any further
    /// `SessionRegistry::send` to this agent will silently fail. The caller
    /// must unregister immediately so the session stops appearing live.
    WriterDied,
}

/// Drive the receiver loop until either the client closes or the writer exits.
///
/// The writer task owns the outbound mpsc receiver; if it dies (WS write error,
/// postcard encode error) the per-connection channel is silently broken. Watching
/// the writer's `JoinHandle` here ensures the caller's cleanup runs promptly
/// instead of waiting for the client-side keepalive timeout to force a reconnect.
async fn run_io_loop(
    receiver: &mut SplitStream<WebSocket>,
    writer: &mut JoinHandle<()>,
    state: &Arc<ServerState>,
    auth: &AuthTokenState,
    effective_caps: &EffectiveCapabilities,
    tx: &mpsc::UnboundedSender<ServerFrame>,
    session_id: crate::session::SessionId,
) -> LoopExit {
    loop {
        tokio::select! {
            msg = receiver.next() => {
                let Some(Ok(msg)) = msg else { return LoopExit::ClientClosed };
                let bytes = match msg {
                    Message::Binary(b) => b,
                    Message::Close(_) => return LoopExit::ClientClosed,
                    _ => continue,
                };
                let Ok(frame) = from_bytes::<ClientFrame>(&bytes) else {
                    continue;
                };
                if !handle_client_frame(state, auth, effective_caps, tx, session_id, frame) {
                    return LoopExit::ProtocolEnd;
                }
            }
            _ = &mut *writer => {
                return LoopExit::WriterDied;
            }
        }
    }
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
    session_id: crate::session::SessionId,
    frame: ClientFrame,
) -> bool {
    match frame {
        ClientFrame::Hello(_) | ClientFrame::Subscribe(_) => true,
        ClientFrame::Ping(Ping { nonce }) => {
            self_tx.send(ServerFrame::Pong(Pong { nonce })).is_ok()
        }
        ClientFrame::Bye(_) => false,
        ClientFrame::WatchPresence(WatchPresence { add, remove }) => {
            if !add.is_empty() {
                state.sessions.add_watches(session_id, self_tx, &add);
            }
            if !remove.is_empty() {
                state.sessions.remove_watches(session_id, &remove);
            }
            true
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Loop-exit semantics for the per-connection select!.
    //!
    //! The production [`run_io_loop`] selects between client-frame reads and the
    //! writer `JoinHandle`. These tests mirror that pattern with a synthetic
    //! receiver + writer to prove the writer-exit arm fires promptly — a
    //! regression here would re-introduce ghosted sessions that linger until
    //! the client-side keepalive eventually triggers a reconnect.
    use super::LoopExit;
    use futures_util::stream::{self, StreamExt};
    use std::time::Duration;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    /// Same `tokio::select!` shape as `run_io_loop`, kept generic so we can
    /// drive it with a synthetic receiver + writer.
    async fn select_until_exit<S>(mut receiver: S, mut writer: JoinHandle<()>) -> LoopExit
    where
        S: futures_util::Stream<Item = ()> + Unpin,
    {
        loop {
            tokio::select! {
                msg = receiver.next() => {
                    if msg.is_none() { return LoopExit::ClientClosed }
                }
                _ = &mut writer => { return LoopExit::WriterDied }
            }
        }
    }

    #[tokio::test]
    async fn loop_reports_writer_died_when_writer_returns() {
        // Receiver never yields — the only way out is the writer arm.
        let pending = stream::pending::<()>();
        let writer: JoinHandle<()> = tokio::spawn(async {});

        let exit = timeout(
            Duration::from_millis(500),
            select_until_exit(pending, writer),
        )
        .await
        .expect("loop must exit promptly when the writer task completes");
        assert_eq!(exit, LoopExit::WriterDied);
    }

    #[tokio::test]
    async fn loop_reports_writer_died_when_writer_is_aborted() {
        // The realistic failure mode: writer task is alive but its inner
        // `sender.send().await` would never resolve. Aborting it externally
        // mimics the production case where the WS sink errors and the writer
        // returns — the receiver loop must exit immediately so the caller can
        // unregister the now-ghosted session.
        let pending = stream::pending::<()>();
        let writer: JoinHandle<()> = tokio::spawn(async {
            futures_util::future::pending::<()>().await;
        });
        let abort = writer.abort_handle();
        let loop_fut = tokio::spawn(select_until_exit(pending, writer));
        abort.abort();

        let exit = timeout(Duration::from_millis(500), loop_fut)
            .await
            .expect("loop must exit promptly when the writer task is aborted")
            .unwrap();
        assert_eq!(exit, LoopExit::WriterDied);
    }

    #[tokio::test]
    async fn loop_reports_client_closed_when_receiver_ends() {
        // Sanity: the other select! arm still triggers normal close.
        let closed = stream::iter(std::iter::empty::<()>());
        let writer: JoinHandle<()> = tokio::spawn(async {
            futures_util::future::pending::<()>().await;
        });

        let exit = timeout(
            Duration::from_millis(500),
            select_until_exit(closed, writer),
        )
        .await
        .expect("loop must exit when the receiver yields None");
        assert_eq!(exit, LoopExit::ClientClosed);
    }
}
