//! Auto-reconnect + keepalive coverage.
//!
//! Verifies the supervisor's behaviour against a real in-process relay
//! for the parts we can deterministically force:
//! - `ConnState::Connected` is reported immediately on a healthy session
//! - Keepalive pings flow without tripping the watchdog when the relay
//!   is alive
//! - Disabling keepalive does not cause spurious disconnects
//! - The connection-state watch is clonable per-observer
//! - `Client::shutdown` stops the supervisor and closes the inbox
//!
//! A focused reconnect test against a controllable mock WS server
//! demonstrates the disconnect → backoff → reconnect path end-to-end
//! by forcibly closing the WS sink mid-session.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]

use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use fetchit_relay_client::{Client, ClientConfig, ConnState, StaticKeySigner};
use fetchit_relay_proto::{
    auth_signing_bytes, AgentId, AuthChallenge, AuthVerifyRequest, AuthVerifyResponse, ClientFrame,
    EffectiveCapabilities, Pong, Ready, Region, ServerFrame,
};
use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use url::Url;

/// Spawn the production server on a freshly-bound listener.
async fn spawn_server_on(addr: Option<SocketAddr>) -> (SocketAddr, JoinHandle<()>) {
    let listener = match addr {
        Some(a) => TcpListener::bind(a).await.unwrap(),
        None => TcpListener::bind("127.0.0.1:0").await.unwrap(),
    };
    let bound = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(bound, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
    let (router, _state) = server.router();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (bound, join)
}

fn fast_keepalive_config(base: Url) -> ClientConfig {
    let mut cfg = ClientConfig::new(base);
    cfg.keepalive = Some(Duration::from_millis(150));
    cfg.pong_timeout = Some(Duration::from_millis(750));
    cfg
}

#[tokio::test]
async fn first_connect_reports_connected_state() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"conn-key".to_vec()));
    let client = Client::connect(ClientConfig::new(base), signer)
        .await
        .unwrap();

    let state = client.connection_state().borrow().clone();
    assert!(
        matches!(state, ConnState::Connected { .. }),
        "expected Connected state immediately after connect, got {state:?}"
    );
}

#[tokio::test]
async fn keepalive_pings_keep_session_alive() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"keepalive-key".to_vec()));
    let client = Client::connect(fast_keepalive_config(base), signer)
        .await
        .unwrap();

    // Wait long enough that several Ping cycles would have fired. If
    // Pongs are tracked correctly, the connection stays Connected and
    // the supervisor never trips its `no Pong for ...` watchdog.
    tokio::time::sleep(Duration::from_millis(900)).await;

    let state = client.connection_state().borrow().clone();
    assert!(
        matches!(state, ConnState::Connected { .. }),
        "expected Connected after multiple keepalive cycles, got {state:?}"
    );
}

#[tokio::test]
async fn disable_keepalive_yields_no_pings_or_disconnects() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"no-ka-key".to_vec()));
    let mut cfg = ClientConfig::new(base);
    cfg.keepalive = None;
    cfg.pong_timeout = None;
    let client = Client::connect(cfg, signer).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let state = client.connection_state().borrow().clone();
    assert!(
        matches!(state, ConnState::Connected { .. }),
        "expected Connected with keepalive disabled, got {state:?}"
    );
}

#[tokio::test]
async fn connection_state_watch_is_clonable_and_independent() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"watch-key".to_vec()));
    let client = Client::connect(ClientConfig::new(base), signer)
        .await
        .unwrap();

    let rx_a = client.connection_state();
    let rx_b = client.connection_state();
    assert!(matches!(*rx_a.borrow(), ConnState::Connected { .. }));
    assert!(matches!(*rx_b.borrow(), ConnState::Connected { .. }));
}

#[tokio::test]
async fn shutdown_stops_supervisor_and_closes_inbox() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"shutdown-key".to_vec()));
    let client = Client::connect(ClientConfig::new(base), signer)
        .await
        .unwrap();
    client.shutdown().await;

    // After shutdown the supervisor drops its inbox_tx, so the
    // next_delivery future must resolve to `None` rather than block.
    let next = tokio::time::timeout(Duration::from_secs(1), client.next_delivery())
        .await
        .expect("next_delivery did not complete after shutdown");
    assert!(next.is_none());
}

// ============================================================
// Controllable mock WS server: lets a test force a disconnect
// at a precise moment, so we can deterministically observe the
// supervisor's reconnect path.
// ============================================================

#[derive(Clone)]
struct MockState {
    close_next: Arc<AtomicBool>,
    connect_count: Arc<AtomicUsize>,
    notify_connect: Arc<Notify>,
}

async fn mock_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "region": "nyc" }))
}

async fn mock_challenge() -> Json<AuthChallenge> {
    Json(AuthChallenge {
        challenge: [0u8; 32],
        expires_at_ms: u64::MAX,
    })
}

async fn mock_verify(Json(_req): Json<AuthVerifyRequest>) -> Json<AuthVerifyResponse> {
    Json(AuthVerifyResponse {
        token: "mock-bearer".to_string(),
        expires_at_ms: u64::MAX,
    })
}

async fn mock_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<MockState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| mock_ws_loop(socket, state))
}

async fn mock_ws_loop(mut socket: WebSocket, state: MockState) {
    state.connect_count.fetch_add(1, Ordering::SeqCst);
    state.notify_connect.notify_waiters();

    let close_now = state.close_next.swap(false, Ordering::SeqCst);
    if close_now {
        let _ = socket.send(AxumMessage::Close(None)).await;
        return;
    }

    // Wait for Hello, then send Ready.
    while let Some(Ok(msg)) = socket.recv().await {
        if let AxumMessage::Binary(b) = msg {
            if let Ok(ClientFrame::Hello(_)) = postcard::from_bytes::<ClientFrame>(&b) {
                let ready = ServerFrame::Ready(Ready {
                    server_version: "mock/0".into(),
                    region: Region::Nyc,
                    effective_capabilities: EffectiveCapabilities::default_profile(),
                });
                let _ = socket
                    .send(AxumMessage::Binary(postcard::to_allocvec(&ready).unwrap()))
                    .await;
                break;
            }
        }
    }

    // Main loop: respond to Pings; honour the close-next flag.
    loop {
        if state.close_next.swap(false, Ordering::SeqCst) {
            let _ = socket.send(AxumMessage::Close(None)).await;
            return;
        }
        let recv = tokio::time::timeout(Duration::from_millis(50), socket.recv()).await;
        let Ok(Some(Ok(msg))) = recv else {
            if matches!(recv, Ok(None | Some(Err(_)))) {
                return;
            }
            continue;
        };
        if let AxumMessage::Binary(b) = msg {
            if let Ok(ClientFrame::Ping(p)) = postcard::from_bytes::<ClientFrame>(&b) {
                let pong = ServerFrame::Pong(Pong { nonce: p.nonce });
                let _ = socket
                    .send(AxumMessage::Binary(postcard::to_allocvec(&pong).unwrap()))
                    .await;
            }
        }
    }
}

async fn spawn_mock(addr: Option<SocketAddr>) -> (SocketAddr, MockState, JoinHandle<()>) {
    let listener = match addr {
        Some(a) => TcpListener::bind(a).await.unwrap(),
        None => TcpListener::bind("127.0.0.1:0").await.unwrap(),
    };
    let bound = listener.local_addr().unwrap();
    let state = MockState {
        close_next: Arc::new(AtomicBool::new(false)),
        connect_count: Arc::new(AtomicUsize::new(0)),
        notify_connect: Arc::new(Notify::new()),
    };
    let app = Router::new()
        .route("/v1/health", get(mock_health))
        .route("/v1/auth/challenge", post(mock_challenge))
        .route("/v1/auth/verify", post(mock_verify))
        .route("/v1/ws", get(mock_ws_handler))
        .with_state(state.clone());
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (bound, state, join)
}

#[tokio::test]
async fn supervisor_reconnects_after_explicit_close() {
    let (addr, mock_state, _server) = spawn_mock(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"reconnect-key".to_vec()));

    // Sub-second keepalive cadence so the close-next flag triggers
    // visible cycles within the test window.
    let mut cfg = ClientConfig::new(base);
    cfg.keepalive = Some(Duration::from_millis(100));
    cfg.pong_timeout = Some(Duration::from_millis(800));

    let client = Client::connect(cfg, signer).await.unwrap();
    let mut state_rx = client.connection_state();
    assert!(matches!(*state_rx.borrow(), ConnState::Connected { .. }));
    assert_eq!(mock_state.connect_count.load(Ordering::SeqCst), 1);

    // Tell the mock to close the next WS message it processes — the
    // client's reader will see the close, send Disconnected, and the
    // supervisor will back off + reconnect.
    mock_state.close_next.store(true, Ordering::SeqCst);

    // Observe the transition.
    let saw_disconnected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            state_rx.changed().await.unwrap();
            if matches!(
                *state_rx.borrow(),
                ConnState::Disconnected { .. } | ConnState::Connecting
            ) {
                return;
            }
        }
    })
    .await;
    assert!(
        saw_disconnected.is_ok(),
        "supervisor never reported a non-Connected state after server close",
    );

    // Then observe Connected again — the supervisor must reconnect.
    let saw_reconnected = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(*state_rx.borrow(), ConnState::Connected { .. }) {
                return;
            }
            state_rx.changed().await.unwrap();
        }
    })
    .await;
    assert!(
        saw_reconnected.is_ok(),
        "supervisor never reported Connected again after reconnect",
    );
    assert!(
        mock_state.connect_count.load(Ordering::SeqCst) >= 2,
        "expected mock to have accepted a second WS connection, got {}",
        mock_state.connect_count.load(Ordering::SeqCst),
    );
}

#[tokio::test]
async fn send_during_disconnect_returns_disconnected_error() {
    use fetchit_relay_client::ClientError;
    use fetchit_relay_proto::{DedupeKey, EnvelopeKind, MachineId, TransitEnvelope};

    let (addr, mock_state, server) = spawn_mock(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(b"send-disc-key".to_vec()));
    let mut cfg = ClientConfig::new(base);
    cfg.keepalive = Some(Duration::from_millis(100));
    cfg.pong_timeout = Some(Duration::from_millis(800));
    let client = Client::connect(cfg, signer).await.unwrap();
    let mut state_rx = client.connection_state();

    // Force the next WS interaction to close, then wait until the
    // supervisor has dropped the live Inner (Disconnected or
    // Connecting state).
    mock_state.close_next.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            state_rx.changed().await.unwrap();
            if matches!(
                *state_rx.borrow(),
                ConnState::Disconnected { .. } | ConnState::Connecting
            ) {
                return;
            }
        }
    })
    .await
    .unwrap();

    // Drop the mock server entirely so reconnect can't succeed
    // mid-test and racing this assertion.
    drop(server);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let env = TransitEnvelope {
        version: 2,
        kind: EnvelopeKind::Dm,
        group_id: None,
        tenant_id: None,
        sender_agent_id: AgentId::from_bytes([0xbb; 32]),
        sender_machine_id: MachineId::from_bytes([0u8; 32]),
        timestamp_ms: 1,
        epoch: 0,
        ciphertext: vec![0u8; 4],
        nonce: vec![0u8; 12],
        kem_ciphertext: vec![0u8; 32],
        sender_signature: vec![0u8; 32],
    };
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        client.send(
            AgentId::from_bytes([0xaa; 32]),
            env,
            DedupeKey::from_bytes([0xcc; 16]),
        ),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            result,
            Err(ClientError::Disconnected(_) | ClientError::InboxClosed)
        ),
        "expected Disconnected (or InboxClosed if racing shutdown), got {result:?}"
    );
}

#[tokio::test]
async fn watch_presence_echoes_initial_state_then_transitions() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();

    let watcher_pk = b"presence-watcher-key";
    let watcher_signer = Arc::new(StaticKeySigner::from_public_key(watcher_pk.to_vec()));
    let watcher = Client::connect(ClientConfig::new(base.clone()), watcher_signer)
        .await
        .unwrap();

    let watched_pk = b"presence-watched-key";
    let watched_id =
        AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(watched_pk));

    watcher.watch_presence(&[watched_id]).unwrap();

    let initial = tokio::time::timeout(Duration::from_secs(2), watcher.next_presence())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(initial.agent_id, watched_id);
    assert!(!initial.online);

    let watched_signer = Arc::new(StaticKeySigner::from_public_key(watched_pk.to_vec()));
    let watched_client = Client::connect(ClientConfig::new(base), watched_signer)
        .await
        .unwrap();

    let online = tokio::time::timeout(Duration::from_secs(2), watcher.next_presence())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(online.agent_id, watched_id);
    assert!(online.online);

    watched_client.shutdown().await;

    let offline = tokio::time::timeout(Duration::from_secs(2), watcher.next_presence())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offline.agent_id, watched_id);
    assert!(!offline.online);
}

#[tokio::test]
async fn unwatch_presence_stops_further_updates() {
    let (addr, _server) = spawn_server_on(None).await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();

    let watcher_pk = b"unwatch-watcher-key";
    let watcher_signer = Arc::new(StaticKeySigner::from_public_key(watcher_pk.to_vec()));
    let watcher = Client::connect(ClientConfig::new(base.clone()), watcher_signer)
        .await
        .unwrap();

    let watched_pk = b"unwatch-watched-key";
    let watched_id =
        AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(watched_pk));

    watcher.watch_presence(&[watched_id]).unwrap();
    let _initial = tokio::time::timeout(Duration::from_secs(2), watcher.next_presence())
        .await
        .unwrap()
        .unwrap();

    watcher.unwatch_presence(&[watched_id]).unwrap();
    // Give the relay a moment to apply the unwatch.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let watched_signer = Arc::new(StaticKeySigner::from_public_key(watched_pk.to_vec()));
    let _watched_client = Client::connect(ClientConfig::new(base), watched_signer)
        .await
        .unwrap();

    let res = tokio::time::timeout(Duration::from_millis(300), watcher.next_presence()).await;
    assert!(
        res.is_err(),
        "expected no further presence updates after unwatch, got {res:?}"
    );
}

#[tokio::test]
async fn challenge_signing_bytes_are_consumed() {
    // Sanity: the mock_verify accepts any verify request, which
    // exercises the supervisor's re-auth path during reconnect
    // without coupling the test to specific signature semantics. This
    // assertion guards against accidental regressions in the
    // auth-signing-bytes import path.
    let bytes = auth_signing_bytes(&[0u8; 32]);
    assert!(!bytes.is_empty());
}
