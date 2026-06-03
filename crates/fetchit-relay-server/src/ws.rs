//! WebSocket upgrade + per-connection event loop.

use crate::auth::AuthTokenState;
use crate::server::ServerState;
use crate::transit::StoredEntry;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use fetchit_relay_proto::{
    from_bytes, to_bytes, Ack, ClientFrame, Deliver, EffectiveCapabilities, GroupId, Hello,
    LogAppend, LogFetch, LogRecordWire, LogRecords, Moved, Ping, Pong, Ready, SendFrame,
    ServerFrame, Throttle, ThrottleReason, TransitAck, WatchPresence,
};
use futures_util::{stream::SplitStream, SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Per-connection outbound queue depth. Bounded to cap RAM under a
/// slow or unresponsive WebSocket sink — a flooded queue surfaces as
/// `try_send` failures upstream rather than unbounded allocation.
const WS_OUTBOUND_CAPACITY: usize = 512;

/// Maximum wait for the client's opening Hello frame before the
/// connection is dropped. A client sending only non-Binary frames (or
/// nothing at all) must not be able to pin a connection handler open
/// indefinitely.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum records per `LogRecords` reply frame. Keeps any single
/// frame bounded while a long backlog streams as multiple chunks.
const LOG_RECORDS_CHUNK: usize = 64;

/// Query string optionally carrying the bearer token for the WS upgrade.
/// Legacy transport: newer clients send the token in the `Authorization:
/// Bearer` header instead (#113), so the query field is optional.
#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// Bearer token previously issued by `/v1/auth/verify`. `None` when the
    /// client supplies it via the `Authorization` header instead.
    #[serde(default)]
    pub token: Option<String>,
}

/// Axum handler: validate bearer, upgrade, hand off to `handle_socket`.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
) -> impl IntoResponse {
    // #113: prefer the bearer token from the `Authorization` header so it
    // stays out of the URL (and out of any fronting proxy / CF access log);
    // fall back to the legacy `?token=` query for backward-compat with
    // older clients during the rollout. The header wins when both are sent.
    let Some(token) = bearer_from_headers(&headers).or(query.token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(auth) = state.auth.validate_bearer(&token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    ws.on_upgrade(move |socket| handle_socket(socket, auth, state))
}

/// Extract the bearer token from an `Authorization: Bearer <token>` header.
/// Case-insensitive on the scheme; `None` when the header is absent,
/// non-UTF-8, not a `Bearer` scheme, or carries an empty token.
fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    // Scheme is case-insensitive per RFC 7235 (auth-scheme). Split off the
    // first token as the scheme, the remainder is the credential.
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

async fn handle_socket(socket: WebSocket, auth: AuthTokenState, state: Arc<ServerState>) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ServerFrame>(WS_OUTBOUND_CAPACITY);

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

    // Replay buffered transit non-destructively: every entry stays in
    // the store until the client confirms it with a TransitAck echoing
    // the durable id carried in `Deliver::transit_seq`. A mid-replay
    // disconnect (or a writer that dies with frames still in the
    // socket) therefore redelivers on the next connect instead of
    // silently losing what was drained but never read. Entries that
    // don't fit the outbound channel (a contended watcher set can
    // consume capacity between register and replay) also just remain
    // stored for the next connect.
    let ReplayOutcome { delivered } =
        replay_transit(state.transit.read_all(&auth.agent_id), &tx, now_ms());
    for _ in 0..delivered {
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

    // Cleanup-trail tracing — operators need to distinguish clean
    // client closes from writer-task death so a flapping-relay
    // outage is visible without grep'ing for session ids. Per
    // `docs/metrics-policy.md`: NO agent_id or peer-IP fields land
    // in the log — only the session id (opaque monotonic) and the
    // LoopExit reason.
    match exit {
        LoopExit::ClientClosed => {
            debug!(
                session = session_id,
                reason = "client_closed",
                "ws: session closing"
            );
        }
        LoopExit::ProtocolEnd => {
            // Voluntary Bye from the client — normal app-close /
            // navigation lifecycle, fires multiple times per active
            // user. Stays at DEBUG to keep steady-state logs quiet.
            debug!(
                session = session_id,
                reason = "protocol_end",
                "ws: session closing"
            );
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
    tx: &mpsc::Sender<ServerFrame>,
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

async fn await_hello<S, E>(receiver: &mut S) -> Option<Hello>
where
    S: futures_util::Stream<Item = Result<Message, E>> + Unpin,
{
    tokio::time::timeout(HELLO_TIMEOUT, await_hello_inner(receiver))
        .await
        .ok()
        .flatten()
}

async fn await_hello_inner<S, E>(receiver: &mut S) -> Option<Hello>
where
    S: futures_util::Stream<Item = Result<Message, E>> + Unpin,
{
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
    self_tx: &mpsc::Sender<ServerFrame>,
    session_id: crate::session::SessionId,
    frame: ClientFrame,
) -> bool {
    match frame {
        ClientFrame::Hello(_) | ClientFrame::Subscribe(_) => true,
        ClientFrame::LogAppend(append) => {
            handle_log_append(state, auth, caps, self_tx, append);
            true
        }
        ClientFrame::LogFetch(fetch) => {
            handle_log_fetch(state, auth, self_tx, &fetch);
            true
        }
        ClientFrame::Ping(Ping { nonce }) => {
            self_tx.try_send(ServerFrame::Pong(Pong { nonce })).is_ok()
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
        ClientFrame::TransitAck(TransitAck { acked_ids }) => {
            // Scoped to the authenticated agent: a client can only
            // reclaim durable entries addressed to itself, so a
            // malicious ack cannot evict another recipient's backlog.
            state.transit.delete(&auth.agent_id, &acked_ids);
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
                let _ = self_tx.try_send(ServerFrame::Throttle(Throttle {
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
                let _ = self_tx.try_send(ServerFrame::Throttle(Throttle {
                    retry_after_ms: 1_000,
                    reason: ThrottleReason::PerSenderRate,
                }));
                return true;
            }
            if envelope.sender_agent_id != auth.agent_id {
                return true;
            }
            // Accept v2 (pre-M2 sealed wire) and v3 (M2 post-cut wire)
            // during the transition window. v3 is the only version
            // emitted on send paths after M2; v2 stays accepted until
            // all live peers upgrade. Anything else is silently dropped
            // — the relay never decrypts, but it gates schema drift.
            //
            // Sunset date: `fetchit_relay_proto::WIRE_VERSION_V2_SUNSET`.
            // CI fails (via the trip-wire test on that constant) once
            // the date is past — forcing a deliberate revisit instead
            // of letting the v2-accept window drift indefinitely.
            if !matches!(envelope.version, 2 | 3) {
                state.metrics.envelope_dropped_version_gate();
                return true;
            }
            // Burn-down counter for the v2-accept window: bumped on
            // every accepted legacy envelope so operators can see when
            // the active-peer set has fully migrated and the gate can
            // be narrowed to v3-only.
            if envelope.version == 2 {
                state.metrics.envelope_accepted_legacy_v2();
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
            } else {
                // T7b: a recipient that migrated away leaves a signed
                // forwarding record behind. Buffering here would be a
                // silent black hole — the recipient no longer reads this
                // relay, yet the deposit would Ack — so answer `Moved`
                // and let the SENDER re-resolve the signed record and
                // retry at the new relay. Offline WITHOUT a forwarding
                // record keeps today's buffer+Ack: `Moved` fires only on
                // the unambiguous departed signal, only while the record
                // is live (the TB2 TTL sweep bounds it), and only while
                // the agent's own pair-record hasn't superseded it (an
                // agent that returned home publishes a newer pair-record,
                // which retires the stale pointer without any removal).
                let to_hex = hex::encode(to.as_bytes());
                if crate::forwarding::get_live_unsuperseded(state, &to_hex, now_ms()).is_some() {
                    state.metrics.envelope_moved();
                    let _ = self_tx.try_send(ServerFrame::Moved(Moved { dedupe_key }));
                    return true;
                }
                if state.transit.enqueue(to, envelope).is_err() {
                    state.metrics.throttle_per_recipient();
                    let _ = self_tx.try_send(ServerFrame::Throttle(Throttle {
                        retry_after_ms: 5_000,
                        reason: ThrottleReason::PerRecipientCapacity,
                    }));
                    return true;
                }
                state.metrics.envelope_buffered();
            }
            state.metrics.envelope_sent();
            let _ = self_tx.try_send(ServerFrame::Ack(Ack {
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

/// Deposit one record onto the group log. Deposits ride the same
/// per-envelope size cap and per-sender rate limiter as `Send`
/// deposits. Fire-and-forget: success sends no reply; a cap rejection
/// answers `Throttle` so the depositor can back off and retry.
fn handle_log_append(
    state: &Arc<ServerState>,
    auth: &AuthTokenState,
    caps: &EffectiveCapabilities,
    self_tx: &mpsc::Sender<ServerFrame>,
    append: LogAppend,
) {
    let LogAppend {
        group_id,
        kind,
        recipient,
        payload,
    } = append;
    if payload.len() > caps.max_envelope_bytes as usize {
        state.metrics.throttle_envelope_too_large();
        let _ = self_tx.try_send(ServerFrame::Throttle(Throttle {
            retry_after_ms: 0,
            reason: ThrottleReason::EnvelopeTooLarge,
        }));
        return;
    }
    if !state
        .ratelimit
        .allow(&auth.agent_id, caps.max_envelopes_per_min)
    {
        state.metrics.throttle_per_sender();
        let _ = self_tx.try_send(ServerFrame::Throttle(Throttle {
            retry_after_ms: 1_000,
            reason: ThrottleReason::PerSenderRate,
        }));
        return;
    }
    if state
        .group_log
        .append(group_id, kind, recipient, payload, now_ms())
        .is_err()
    {
        state.metrics.throttle_per_recipient();
        let _ = self_tx.try_send(ServerFrame::Throttle(Throttle {
            retry_after_ms: 5_000,
            reason: ThrottleReason::PerRecipientCapacity,
        }));
    }
}

/// Serve a `LogFetch`. Possession of the group id is the fetch
/// capability for Commit records — the relay is blind and runs no
/// membership check. `JoinResult` records are additionally gated to
/// the authenticated agent they are addressed to, so one joiner can
/// never read another's staged result.
fn handle_log_fetch(
    state: &Arc<ServerState>,
    auth: &AuthTokenState,
    self_tx: &mpsc::Sender<ServerFrame>,
    fetch: &LogFetch,
) {
    let records: Vec<LogRecordWire> = state
        .group_log
        .fetch_since(&fetch.group_id, fetch.since_seq)
        .into_iter()
        .filter(|r| r.recipient.is_none() || r.recipient == Some(auth.agent_id))
        .map(|r| LogRecordWire {
            seq: r.seq,
            kind: r.kind,
            recipient: r.recipient,
            payload: r.payload,
            inserted_at_ms: r.inserted_at_ms,
        })
        .collect();
    send_log_records(self_tx, fetch.group_id, records);
}

/// Answer a `LogFetch`: push `records` onto the outbound channel as
/// `LogRecords` frames of at most [`LOG_RECORDS_CHUNK`] records, the
/// final frame carrying `done = true`. An empty result still sends one
/// `done` frame so the client observes completion. If the channel
/// fills mid-reply the remainder is dropped — the log is
/// non-destructive, so the client simply refetches with a higher
/// `since_seq`.
fn send_log_records(
    tx: &mpsc::Sender<ServerFrame>,
    group_id: GroupId,
    records: Vec<LogRecordWire>,
) {
    let mut remaining = records;
    loop {
        let tail = if remaining.len() > LOG_RECORDS_CHUNK {
            remaining.split_off(LOG_RECORDS_CHUNK)
        } else {
            Vec::new()
        };
        let done = tail.is_empty();
        if tx
            .try_send(ServerFrame::LogRecords(LogRecords {
                group_id,
                records: remaining,
                done,
            }))
            .is_err()
            || done
        {
            return;
        }
        remaining = tail;
    }
}

/// Outcome of replaying stored transit entries onto a fresh
/// per-connection outbound channel.
struct ReplayOutcome {
    /// Number of envelopes that landed on the channel successfully.
    delivered: usize,
}

/// Push every stored entry onto `tx` as a `Deliver` carrying its
/// durable store id in `transit_seq` — the id the client echoes back
/// in a `TransitAck` to reclaim the entry. Non-destructive: the store
/// still holds every entry, so this stops at the first `try_send`
/// error (`Full` and `Closed` alike mean no further send can succeed)
/// and the unsent remainder is simply replayed on the next connect.
fn replay_transit(
    stored: Vec<StoredEntry>,
    tx: &mpsc::Sender<ServerFrame>,
    delivered_at_ms: u64,
) -> ReplayOutcome {
    let mut delivered = 0usize;
    for entry in stored {
        let frame = ServerFrame::Deliver(Deliver {
            envelope: entry.envelope,
            transit_seq: entry.id,
            delivered_at_ms,
        });
        if tx.try_send(frame).is_err() {
            break;
        }
        delivered += 1;
    }
    ReplayOutcome { delivered }
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
    use super::{
        await_hello_inner, bearer_from_headers, replay_transit, send_log_records, LoopExit,
        HELLO_TIMEOUT, LOG_RECORDS_CHUNK, WS_OUTBOUND_CAPACITY,
    };
    use crate::transit::StoredEntry;
    use axum::extract::ws::Message;
    use fetchit_relay_proto::{
        to_bytes, AgentId, ClientFrame, EnvelopeKind, Hello, MachineId, Pong, ServerFrame,
        TransitEnvelope, WIRE_VERSION,
    };

    fn auth_headers(value: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[test]
    fn bearer_from_authorization_header() {
        assert_eq!(
            bearer_from_headers(&auth_headers("Bearer abc123")).as_deref(),
            Some("abc123"),
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        for scheme in ["bearer", "BEARER", "BeArEr"] {
            assert_eq!(
                bearer_from_headers(&auth_headers(&format!("{scheme} abc123"))).as_deref(),
                Some("abc123"),
                "scheme {scheme:?} should be accepted case-insensitively",
            );
        }
    }

    #[test]
    fn non_bearer_empty_or_absent_is_none() {
        assert!(bearer_from_headers(&auth_headers("Basic abc123")).is_none());
        assert!(bearer_from_headers(&auth_headers("Bearer ")).is_none());
        assert!(bearer_from_headers(&auth_headers("Bearer   ")).is_none());
        assert!(bearer_from_headers(&axum::http::HeaderMap::new()).is_none());
    }
    use futures_util::stream::{self, StreamExt};
    use std::convert::Infallible;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    fn marked_envelope(tag: u8) -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([tag; 32]),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![tag],
            nonce: vec![0u8; 12],
            kem_ciphertext: vec![0u8; 32],
            sender_signature: vec![0u8; 32],
        }
    }

    fn stored_with_tags(tags: &[u8]) -> Vec<StoredEntry> {
        tags.iter()
            .map(|&t| StoredEntry {
                id: u64::from(t) * 10,
                envelope: marked_envelope(t),
                enqueued_at_ms: 1,
            })
            .collect()
    }

    #[tokio::test]
    async fn replay_transit_delivers_everything_when_channel_has_room() {
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(WS_OUTBOUND_CAPACITY);
        let outcome = replay_transit(stored_with_tags(&[1, 2, 3]), &tx, 0);
        assert_eq!(outcome.delivered, 3);
        // Receiver gets all three Deliver frames in order, each
        // carrying its durable store id (the ack handle) in
        // transit_seq.
        for tag in [1u8, 2, 3] {
            match rx.try_recv().expect("frame available") {
                ServerFrame::Deliver(d) => {
                    assert_eq!(d.envelope.ciphertext, vec![tag]);
                    assert_eq!(d.transit_seq, u64::from(tag) * 10);
                }
                other => panic!("expected Deliver, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn replay_transit_stops_counting_when_channel_fills_mid_replay() {
        // Channel sized to exactly two frames. Replay three. The third
        // try_send surfaces as Full; the replay is non-destructive so
        // the unsent entry simply stays in the store for the next
        // connect — only the delivered count matters here.
        let (tx, _rx) = mpsc::channel::<ServerFrame>(2);
        let outcome = replay_transit(stored_with_tags(&[1, 2, 3]), &tx, 0);
        assert_eq!(outcome.delivered, 2);
    }

    #[tokio::test]
    async fn replay_transit_delivers_none_when_first_send_full() {
        // Watcher set saturated the channel BEFORE the replay loop
        // starts — nothing lands, everything stays stored.
        let (tx, _rx) = mpsc::channel::<ServerFrame>(1);
        tx.try_send(ServerFrame::Pong(fetchit_relay_proto::Pong { nonce: 0 }))
            .unwrap();
        let outcome = replay_transit(stored_with_tags(&[1, 2, 3]), &tx, 0);
        assert_eq!(outcome.delivered, 0);
    }

    #[tokio::test]
    async fn replay_transit_delivers_none_when_channel_closed() {
        // Writer task died before replay — receiver dropped, every
        // try_send fails Closed. Everything stays stored for the next
        // connect.
        let (tx, rx) = mpsc::channel::<ServerFrame>(8);
        drop(rx);
        let outcome = replay_transit(stored_with_tags(&[7, 8, 9]), &tx, 0);
        assert_eq!(outcome.delivered, 0);
    }

    fn wire_records(n: usize) -> Vec<fetchit_relay_proto::LogRecordWire> {
        (1..=n)
            .map(|i| fetchit_relay_proto::LogRecordWire {
                seq: i as u64,
                kind: fetchit_relay_proto::LogRecordKind::Commit,
                recipient: None,
                payload: vec![0xcd; 4],
                inserted_at_ms: 1,
            })
            .collect()
    }

    fn recv_log_records(
        rx: &mut mpsc::Receiver<ServerFrame>,
    ) -> Option<fetchit_relay_proto::LogRecords> {
        match rx.try_recv() {
            Ok(ServerFrame::LogRecords(lr)) => Some(lr),
            Ok(other) => panic!("expected LogRecords, got {other:?}"),
            Err(_) => None,
        }
    }

    #[tokio::test]
    async fn send_log_records_chunks_and_marks_final_frame_done() {
        let group = fetchit_relay_proto::GroupId::from_bytes([7u8; 32]);
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(WS_OUTBOUND_CAPACITY);
        send_log_records(&tx, group, wire_records(LOG_RECORDS_CHUNK * 2 + 10));

        let first = recv_log_records(&mut rx).expect("first chunk");
        assert_eq!(first.records.len(), LOG_RECORDS_CHUNK);
        assert!(!first.done);
        assert_eq!(first.records[0].seq, 1);
        let second = recv_log_records(&mut rx).expect("second chunk");
        assert_eq!(second.records.len(), LOG_RECORDS_CHUNK);
        assert!(!second.done);
        let last = recv_log_records(&mut rx).expect("final chunk");
        assert_eq!(last.records.len(), 10);
        assert!(last.done, "final chunk carries done=true");
        assert_eq!(
            last.records.last().unwrap().seq,
            (LOG_RECORDS_CHUNK * 2 + 10) as u64,
            "seqs stream in order across chunks"
        );
        assert!(recv_log_records(&mut rx).is_none(), "no extra frames");
    }

    #[tokio::test]
    async fn send_log_records_empty_result_sends_single_done_frame() {
        let group = fetchit_relay_proto::GroupId::from_bytes([8u8; 32]);
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(8);
        send_log_records(&tx, group, Vec::new());
        let only = recv_log_records(&mut rx).expect("completion frame");
        assert!(only.records.is_empty());
        assert!(only.done);
        assert!(recv_log_records(&mut rx).is_none());
    }

    #[tokio::test]
    async fn send_log_records_stops_when_channel_fills() {
        // Channel holds exactly one frame: the first chunk lands, the
        // rest is dropped. The log is non-destructive, so the client
        // refetches with a higher since_seq.
        let group = fetchit_relay_proto::GroupId::from_bytes([9u8; 32]);
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(1);
        send_log_records(&tx, group, wire_records(LOG_RECORDS_CHUNK * 3));
        let first = recv_log_records(&mut rx).expect("first chunk landed");
        assert_eq!(first.records.len(), LOG_RECORDS_CHUNK);
        assert!(!first.done);
        assert!(
            recv_log_records(&mut rx).is_none(),
            "reply stops at the full channel"
        );
    }

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

    #[tokio::test(start_paused = true)]
    async fn await_hello_times_out_when_no_hello_arrives() {
        // Pending stream models a client that connects and then sends
        // nothing (or only non-Binary keepalives that the loop skips).
        // The timeout wrapper must reclaim the connection within
        // HELLO_TIMEOUT — without it, the handler pins memory forever.
        let mut stream = stream::pending::<Result<Message, Infallible>>();
        let result = tokio::time::timeout(
            HELLO_TIMEOUT + Duration::from_secs(1),
            super::await_hello(&mut stream),
        )
        .await
        .expect("await_hello wrapper must complete within its own timeout + slack");
        assert!(
            result.is_none(),
            "no Hello arrived; await_hello must surface None",
        );
    }

    #[tokio::test]
    async fn await_hello_inner_returns_hello_from_first_binary_frame() {
        let hello = Hello {
            client_version: "test".into(),
            tenant_id: None,
            preferred_region: None,
            capabilities: None,
        };
        let bytes = to_bytes(&ClientFrame::Hello(hello.clone())).unwrap();
        let mut stream = stream::iter([Ok::<Message, Infallible>(Message::Binary(bytes))]);
        let got = await_hello_inner(&mut stream).await.expect("hello arrives");
        assert_eq!(got.client_version, hello.client_version);
    }

    #[tokio::test]
    async fn await_hello_inner_skips_leading_text_frames() {
        let hello = Hello {
            client_version: "skip-text".into(),
            tenant_id: None,
            preferred_region: None,
            capabilities: None,
        };
        let bytes = to_bytes(&ClientFrame::Hello(hello.clone())).unwrap();
        let mut stream = stream::iter([
            Ok::<Message, Infallible>(Message::Text("not hello".into())),
            Ok::<Message, Infallible>(Message::Text("still not".into())),
            Ok::<Message, Infallible>(Message::Binary(bytes)),
        ]);
        let got = await_hello_inner(&mut stream)
            .await
            .expect("text frames are skipped; hello eventually arrives");
        assert_eq!(got.client_version, hello.client_version);
    }

    #[tokio::test]
    async fn bounded_channel_backpressure_slow_receiver() {
        // Slow receiver: never reads. Bounded channel must reject the
        // (WS_OUTBOUND_CAPACITY + 1)-th send instead of growing without
        // bound. This is the load-bearing invariant the bounded
        // outbound channel was added for.
        let (tx, _rx) = mpsc::channel::<ServerFrame>(WS_OUTBOUND_CAPACITY);
        for i in 0..WS_OUTBOUND_CAPACITY {
            tx.try_send(ServerFrame::Pong(Pong { nonce: i as u64 }))
                .expect("first WS_OUTBOUND_CAPACITY sends must succeed");
        }
        let err = tx
            .try_send(ServerFrame::Pong(Pong { nonce: u64::MAX }))
            .expect_err("send beyond capacity must error rather than grow heap");
        assert!(
            matches!(err, mpsc::error::TrySendError::Full(_)),
            "expected Full when receiver hasn't drained, got {err:?}",
        );
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
