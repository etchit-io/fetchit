//! End-to-end: spin up a server, run two clients through challenge / verify /
//! WebSocket, send a message between them, and assert the recipient gets it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_proto::pair_record::{
    forwarding_signing_input, pair_signing_input, ForwardingRecordV1, PairRecordV1,
};
use fetchit_relay_proto::{
    from_bytes, to_bytes, Ack, AgentId, AuthChallenge, AuthVerifyRequest, AuthVerifyResponse, Bye,
    ByeReason, ClientFrame, DedupeKey, Deliver, EnvelopeKind, Hello, MachineId, PresenceUpdate,
    Ready, Region, SendFrame, ServerFrame, TenantId, TransitEnvelope, WatchPresence, WIRE_VERSION,
};
use fetchit_relay_server::server::ServerState;
use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
use futures_util::{SinkExt, StreamExt};
use saorsa_pqc::api::sig::{MlDsa, MlDsaSecretKey, MlDsaVariant};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};

async fn start_test_server() -> SocketAddr {
    start_test_server_with_state().await.0
}

async fn start_test_server_with_state() -> (SocketAddr, Arc<ServerState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(addr, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
    let (router, state) = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    // tiny yield so the server is accepting before clients dial
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, state)
}

async fn obtain_bearer(addr: SocketAddr, agent_pk: &[u8]) -> String {
    let http = reqwest::Client::new();
    let challenge: AuthChallenge = http
        .post(format!("http://{addr}/v1/auth/challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let agent_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(agent_pk));
    let req = AuthVerifyRequest {
        agent_id,
        agent_public_key: agent_pk.to_vec(),
        challenge: challenge.challenge,
        signature: vec![0u8; 16],
    };
    let resp: AuthVerifyResponse = http
        .post(format!("http://{addr}/v1/auth/verify"))
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp.token
}

async fn connect_ws(
    addr: SocketAddr,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}/v1/ws?token={token}");
    let req = url.into_client_request().unwrap();
    let (ws, _resp) = connect_async(req).await.unwrap();
    ws
}

/// #113: connect supplying the bearer via the `Authorization` header
/// instead of the `?token=` query, so the token never appears in the URL.
async fn connect_ws_with_bearer_header(
    addr: SocketAddr,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut req = format!("ws://{addr}/v1/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let (ws, _resp) = connect_async(req).await.unwrap();
    ws
}

fn envelope_from(sender: AgentId, body: &[u8]) -> TransitEnvelope {
    TransitEnvelope {
        version: WIRE_VERSION,
        kind: EnvelopeKind::Dm,
        group_id: None,
        tenant_id: None,
        sender_agent_id: sender,
        sender_machine_id: MachineId::from_bytes([0u8; 32]),
        timestamp_ms: 1,
        epoch: 0,
        ciphertext: body.to_vec(),
        nonce: vec![0u8; 12],
        kem_ciphertext: vec![0u8; 32],
        sender_signature: vec![0u8; 32],
    }
}

async fn expect_ready(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Ready {
    let msg = ws.next().await.unwrap().unwrap();
    let Message::Binary(b) = msg else {
        panic!("expected binary, got {msg:?}");
    };
    match from_bytes::<ServerFrame>(&b).unwrap() {
        ServerFrame::Ready(r) => r,
        other => panic!("expected Ready, got {other:?}"),
    }
}

async fn send_hello(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    let frame = ClientFrame::Hello(Hello {
        client_version: "test/0.0.1".into(),
        tenant_id: Some(TenantId::new("public")),
        preferred_region: Some(Region::Nyc),
        capabilities: None,
    });
    ws.send(Message::Binary(to_bytes(&frame).unwrap()))
        .await
        .unwrap();
}

#[tokio::test]
async fn health_endpoint_responds() {
    let addr = start_test_server().await;
    let resp = reqwest::get(format!("http://{addr}/v1/health"))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["region"], "nyc");
}

#[tokio::test]
async fn auth_handshake_yields_bearer_token() {
    let addr = start_test_server().await;
    let token = obtain_bearer(addr, b"alice-pubkey").await;
    assert!(!token.is_empty());
}

#[tokio::test]
async fn ws_upgrade_authenticates_via_authorization_header() {
    // #113: a bearer presented in the Authorization header (no ?token= in
    // the URL) is accepted; the upgrade succeeds and the session reaches
    // Ready. This is the real win -- the token leaves the URL.
    let addr = start_test_server().await;
    let token = obtain_bearer(addr, b"alice-pubkey").await;
    let mut ws = connect_ws_with_bearer_header(addr, &token).await;
    send_hello(&mut ws).await;
    let _ready = expect_ready(&mut ws).await;
}

#[tokio::test]
async fn auth_verify_failure_returns_generic_body_without_leaking_variant_detail() {
    // SEC-001: drive auth_verify into the AgentMismatch rejection
    // path (agent_id does not derive from the supplied public key)
    // and assert the response body is exactly "authentication
    // failed" — not the variant-specific reason string.
    let addr = start_test_server().await;
    let http = reqwest::Client::new();
    let challenge: AuthChallenge = http
        .post(format!("http://{addr}/v1/auth/challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let bogus_agent_id = AgentId::from_bytes([0xffu8; 32]);
    let req = AuthVerifyRequest {
        agent_id: bogus_agent_id,
        agent_public_key: b"alice-pubkey-bytes".to_vec(),
        challenge: challenge.challenge,
        signature: vec![0u8; 16],
    };
    let resp = http
        .post(format!("http://{addr}/v1/auth/verify"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body = resp.text().await.unwrap();
    assert_eq!(
        body, "authentication failed",
        "response body must be the canned generic message — got: {body:?}",
    );
    let lower = body.to_ascii_lowercase();
    for needle in ["pubkey", "public_key", "agent", "challenge", "signature"] {
        assert!(
            !lower.contains(needle),
            "leak: response body contains {needle:?} ({body:?})",
        );
    }
}

#[tokio::test]
async fn send_between_two_connected_clients_delivers() {
    let addr = start_test_server().await;

    let alice_pk = b"alice-pubkey-bytes";
    let bob_pk = b"bob-pubkey-bytes-here";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let bob_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(bob_pk));

    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let bob_tok = obtain_bearer(addr, bob_pk).await;

    let mut alice = connect_ws(addr, &alice_tok).await;
    let mut bob = connect_ws(addr, &bob_tok).await;

    send_hello(&mut alice).await;
    send_hello(&mut bob).await;
    let _ready_a = expect_ready(&mut alice).await;
    let _ready_b = expect_ready(&mut bob).await;

    let payload = b"hello bob";
    let send_frame = ClientFrame::Send(SendFrame {
        to: bob_id,
        envelope: envelope_from(alice_id, payload),
        dedupe_key: DedupeKey::from_bytes([0xaa; 16]),
    });
    alice
        .send(Message::Binary(to_bytes(&send_frame).unwrap()))
        .await
        .unwrap();

    // Bob should receive Deliver
    let bob_frame = loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), bob.next())
            .await
            .expect("bob receive timed out")
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            break from_bytes::<ServerFrame>(&b).unwrap();
        }
    };
    let delivered = match bob_frame {
        ServerFrame::Deliver(d) => d,
        other => panic!("expected Deliver, got {other:?}"),
    };
    assert_eq!(delivered.envelope.ciphertext, payload);
    assert_eq!(delivered.envelope.sender_agent_id, alice_id);

    // Alice should receive Ack
    let alice_frame = loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), alice.next())
            .await
            .expect("alice ack timed out")
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            break from_bytes::<ServerFrame>(&b).unwrap();
        }
    };
    let ack = match alice_frame {
        ServerFrame::Ack(a) => a,
        other => panic!("expected Ack, got {other:?}"),
    };
    assert_eq!(ack.dedupe_key, DedupeKey::from_bytes([0xaa; 16]));
}

#[tokio::test]
async fn offline_recipient_gets_buffered_message_on_connect() {
    let addr = start_test_server().await;

    let alice_pk = b"alice-pubkey-bytes";
    let carol_pk = b"carol-pubkey-bytes-here";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let carol_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(carol_pk));

    let alice_tok = obtain_bearer(addr, alice_pk).await;

    let mut alice = connect_ws(addr, &alice_tok).await;
    send_hello(&mut alice).await;
    let _ = expect_ready(&mut alice).await;

    let payload = b"see you tomorrow";
    let send_frame = ClientFrame::Send(SendFrame {
        to: carol_id,
        envelope: envelope_from(alice_id, payload),
        dedupe_key: DedupeKey::from_bytes([0xbb; 16]),
    });
    alice
        .send(Message::Binary(to_bytes(&send_frame).unwrap()))
        .await
        .unwrap();

    // Drain alice's ack so the channel is clean
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), alice.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            if matches!(
                from_bytes::<ServerFrame>(&b).unwrap(),
                ServerFrame::Ack(Ack { .. })
            ) {
                break;
            }
        }
    }

    // Now carol comes online and should receive the buffered envelope.
    let carol_tok = obtain_bearer(addr, carol_pk).await;
    let mut carol = connect_ws(addr, &carol_tok).await;
    send_hello(&mut carol).await;
    let _ = expect_ready(&mut carol).await;

    let frame = loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), carol.next())
            .await
            .expect("carol deliver timed out")
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            break from_bytes::<ServerFrame>(&b).unwrap();
        }
    };
    let d: Deliver = match frame {
        ServerFrame::Deliver(d) => d,
        other => panic!("expected Deliver, got {other:?}"),
    };
    assert_eq!(d.envelope.ciphertext, payload);
}

#[tokio::test]
async fn duplicate_agent_connect_displaces_with_bye() {
    let addr = start_test_server().await;

    let pk = b"dave-pubkey-bytes-here";
    let dave_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(pk));

    // First connection takes the registration.
    let tok_a = obtain_bearer(addr, pk).await;
    let mut conn_a = connect_ws(addr, &tok_a).await;
    send_hello(&mut conn_a).await;
    let _ = expect_ready(&mut conn_a).await;

    // Second connection for the same agent_id displaces it.
    let tok_b = obtain_bearer(addr, pk).await;
    let mut conn_b = connect_ws(addr, &tok_b).await;
    send_hello(&mut conn_b).await;
    let _ = expect_ready(&mut conn_b).await;

    // conn_a must observe Bye(DisplacedByNewSession).
    let bye = loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), conn_a.next())
            .await
            .expect("displaced connection did not receive Bye")
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            break from_bytes::<ServerFrame>(&b).unwrap();
        }
    };
    match bye {
        ServerFrame::Bye(Bye { reason }) => {
            assert_eq!(reason, ByeReason::DisplacedByNewSession);
        }
        other => panic!("expected Bye(DisplacedByNewSession), got {other:?}"),
    }

    // conn_b's session must still be active: a Send from a third agent
    // routes to conn_b, not conn_a, even after conn_a's reader exits.
    drop(conn_a);

    let eve_pk = b"eve-pubkey-bytes-here";
    let eve_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(eve_pk));
    let eve_tok = obtain_bearer(addr, eve_pk).await;
    let mut eve = connect_ws(addr, &eve_tok).await;
    send_hello(&mut eve).await;
    let _ = expect_ready(&mut eve).await;

    let payload = b"after displacement";
    let send_frame = ClientFrame::Send(SendFrame {
        to: dave_id,
        envelope: envelope_from(eve_id, payload),
        dedupe_key: DedupeKey::from_bytes([0xcc; 16]),
    });
    eve.send(Message::Binary(to_bytes(&send_frame).unwrap()))
        .await
        .unwrap();

    let delivered = loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), conn_b.next())
            .await
            .expect("active connection did not receive Deliver after displacement")
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            break from_bytes::<ServerFrame>(&b).unwrap();
        }
    };
    let d = match delivered {
        ServerFrame::Deliver(d) => d,
        other => panic!("expected Deliver, got {other:?}"),
    };
    assert_eq!(d.envelope.ciphertext, payload);
}

#[tokio::test]
async fn client_disconnect_promptly_decrements_connection_count() {
    // Observable invariant: after a connected client drops its WS, the session
    // must clear from the registry within a short window. The receiver loop now
    // watches the writer's `JoinHandle` so a writer crash (WS write error)
    // triggers the same cleanup path — without that, a ghosted session would
    // sit in `by_agent` until the client-side keepalive eventually forced a
    // reconnect.
    let addr = start_test_server().await;
    let pk = b"frank-pubkey-bytes-here";

    // Sanity: no live sessions yet.
    assert_eq!(connection_count(addr).await, 0);

    let tok = obtain_bearer(addr, pk).await;
    let mut ws = connect_ws(addr, &tok).await;
    send_hello(&mut ws).await;
    let _ = expect_ready(&mut ws).await;

    // Session is registered.
    assert_eq!(connection_count(addr).await, 1);

    // Drop the client connection — the underlying TCP closes, the server
    // receiver yields None, the loop exits via the ClientClosed arm, and
    // `unregister` runs. Equivalently, if the writer ever crashes the
    // WriterDied arm would fire here.
    drop(ws);

    // Cleanup must run promptly: poll up to a second.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        if connection_count(addr).await == 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "session not unregistered within 1s of client disconnect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn connection_count(addr: SocketAddr) -> u64 {
    let body: serde_json::Value = reqwest::get(format!("http://{addr}/v1/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["connections"].as_u64().unwrap()
}

#[tokio::test]
async fn ws_upgrade_without_a_valid_bearer_is_rejected() {
    // Reachability V1 / TB3 — pooled-deposit auth parity. A pooled
    // deposit connection is a real WS upgrade and must present a valid
    // bearer; there is no unauthenticated path onto the relay. An
    // invalid/forged token fails the upgrade (`ws.rs`: `validate_bearer`
    // returns `None` → the upgrade is refused before `handle_socket`).
    let addr = start_test_server().await;
    let url = format!("ws://{addr}/v1/ws?token=not-a-real-bearer-token");
    let req = url.into_client_request().unwrap();
    assert!(
        connect_async(req).await.is_err(),
        "WS upgrade with an invalid bearer must be rejected"
    );
}

#[tokio::test]
async fn deposit_with_spoofed_sender_agent_id_is_not_delivered() {
    // Reachability V1 / TB3 — over any (pooled or primary) connection you
    // can only deposit AS your authenticated agent. An envelope whose
    // `sender_agent_id` differs from the connection's authed agent is
    // dropped at the relay (`ws.rs`: `envelope.sender_agent_id !=
    // auth.agent_id`), so it never reaches the recipient.
    let addr = start_test_server().await;

    let alice_pk = b"alice-pubkey-bytes";
    let bob_pk = b"bob-pubkey-bytes-here";
    let bob_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(bob_pk));
    // A sender id that is NOT alice's authenticated agent.
    let spoofed = AgentId::from_bytes([0x77; 32]);

    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let bob_tok = obtain_bearer(addr, bob_pk).await;
    let mut alice = connect_ws(addr, &alice_tok).await;
    let mut bob = connect_ws(addr, &bob_tok).await;
    send_hello(&mut alice).await;
    send_hello(&mut bob).await;
    let _ = expect_ready(&mut alice).await;
    let _ = expect_ready(&mut bob).await;

    let send_frame = ClientFrame::Send(SendFrame {
        to: bob_id,
        envelope: envelope_from(spoofed, b"forged sender"),
        dedupe_key: DedupeKey::from_bytes([0xde; 16]),
    });
    alice
        .send(Message::Binary(to_bytes(&send_frame).unwrap()))
        .await
        .unwrap();

    // Bob must receive nothing — the spoofed-sender deposit was dropped.
    let got = tokio::time::timeout(Duration::from_millis(500), bob.next()).await;
    assert!(
        got.is_err(),
        "recipient must receive no Deliver for a spoofed-sender deposit, got {got:?}"
    );
}

#[tokio::test]
async fn watch_presence_echoes_offline_then_online_then_offline() {
    let addr = start_test_server().await;

    let watcher_pk = b"watcher-pubkey-bytes";
    let watched_pk = b"watched-pubkey-bytes";
    let watched_id =
        AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(watched_pk));

    let watcher_tok = obtain_bearer(addr, watcher_pk).await;
    let mut watcher = connect_ws(addr, &watcher_tok).await;
    send_hello(&mut watcher).await;
    let _ = expect_ready(&mut watcher).await;

    let watch = ClientFrame::WatchPresence(WatchPresence {
        add: vec![watched_id],
        remove: vec![],
    });
    watcher
        .send(Message::Binary(to_bytes(&watch).unwrap()))
        .await
        .unwrap();

    let initial = next_presence(&mut watcher).await;
    assert_eq!(initial.agent_id, watched_id);
    assert!(!initial.online, "watched agent starts offline");

    let watched_tok = obtain_bearer(addr, watched_pk).await;
    let mut watched = connect_ws(addr, &watched_tok).await;
    send_hello(&mut watched).await;
    let _ = expect_ready(&mut watched).await;

    let online = next_presence(&mut watcher).await;
    assert_eq!(online.agent_id, watched_id);
    assert!(online.online, "watched agent transitions online");

    drop(watched);

    let offline = next_presence(&mut watcher).await;
    assert_eq!(offline.agent_id, watched_id);
    assert!(!offline.online, "watched agent transitions offline");
}

async fn next_presence(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> PresenceUpdate {
    let deadline = Duration::from_secs(2);
    loop {
        let msg = tokio::time::timeout(deadline, ws.next())
            .await
            .expect("presence update timed out")
            .unwrap()
            .unwrap();
        if let Message::Binary(b) = msg {
            if let ServerFrame::PresenceUpdate(p) = from_bytes::<ServerFrame>(&b).unwrap() {
                return p;
            }
        }
    }
}

/// Build an envelope at an explicit wire version (bypasses
/// `envelope_from`'s `WIRE_VERSION` default) so the version-gate tests
/// can pin v2/v3/other independently of which version is current.
fn envelope_at(sender: AgentId, body: &[u8], version: u16) -> TransitEnvelope {
    let mut e = envelope_from(sender, body);
    e.version = version;
    e
}

async fn send_envelope_to(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    to: AgentId,
    envelope: TransitEnvelope,
    dedupe_key: [u8; 16],
) {
    let frame = ClientFrame::Send(SendFrame {
        to,
        envelope,
        dedupe_key: DedupeKey::from_bytes(dedupe_key),
    });
    ws.send(Message::Binary(to_bytes(&frame).unwrap()))
        .await
        .unwrap();
}

async fn next_server_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    timeout: Duration,
) -> Option<ServerFrame> {
    let msg = tokio::time::timeout(timeout, ws.next()).await.ok()??;
    let msg = msg.ok()?;
    if let Message::Binary(b) = msg {
        return Some(from_bytes::<ServerFrame>(&b).unwrap());
    }
    None
}

#[tokio::test]
async fn relay_accepts_wire_versions_2_and_3() {
    // Both v2 (pre-M2) and v3 (post-M2) envelopes must traverse the
    // relay during the transition window — old peers stay reachable
    // while new sends emit v3.
    let addr = start_test_server().await;

    let alice_pk = b"alice-v2v3-key";
    let bob_pk = b"bob-v2v3-keybob";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let bob_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(bob_pk));

    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let bob_tok = obtain_bearer(addr, bob_pk).await;

    let mut alice = connect_ws(addr, &alice_tok).await;
    let mut bob = connect_ws(addr, &bob_tok).await;
    send_hello(&mut alice).await;
    send_hello(&mut bob).await;
    let _ = expect_ready(&mut alice).await;
    let _ = expect_ready(&mut bob).await;

    for (version, dedupe) in [(2u16, [0xa2u8; 16]), (3u16, [0xa3u8; 16])] {
        send_envelope_to(
            &mut alice,
            bob_id,
            envelope_at(alice_id, b"hi", version),
            dedupe,
        )
        .await;

        let mut got_deliver = false;
        let mut got_ack = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while (!got_deliver || !got_ack) && std::time::Instant::now() < deadline {
            tokio::select! {
                frame = next_server_frame(&mut bob, Duration::from_millis(200)) => {
                    if let Some(ServerFrame::Deliver(d)) = frame {
                        assert_eq!(d.envelope.version, version);
                        got_deliver = true;
                    }
                }
                frame = next_server_frame(&mut alice, Duration::from_millis(200)) => {
                    if let Some(ServerFrame::Ack(a)) = frame {
                        assert_eq!(a.dedupe_key, DedupeKey::from_bytes(dedupe));
                        got_ack = true;
                    }
                }
            }
        }
        assert!(got_deliver, "v{version} envelope was not delivered to Bob");
        assert!(got_ack, "v{version} envelope was not acked to Alice");
    }
}

#[tokio::test]
async fn relay_rejects_unknown_wire_version() {
    // Any envelope.version outside {2, 3} is dropped at the gate —
    // Bob sees no Deliver and Alice sees no Ack. Future versions go
    // through the same cutover dance (widen the match, ship, then
    // narrow).
    let addr = start_test_server().await;

    let alice_pk = b"alice-unknown-v";
    let bob_pk = b"bob-unknown-vvv";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let bob_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(bob_pk));

    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let bob_tok = obtain_bearer(addr, bob_pk).await;

    let mut alice = connect_ws(addr, &alice_tok).await;
    let mut bob = connect_ws(addr, &bob_tok).await;
    send_hello(&mut alice).await;
    send_hello(&mut bob).await;
    let _ = expect_ready(&mut alice).await;
    let _ = expect_ready(&mut bob).await;

    send_envelope_to(
        &mut alice,
        bob_id,
        envelope_at(alice_id, b"v99", 99),
        [0x99; 16],
    )
    .await;

    // Drain a brief window — Bob must NOT receive a Deliver, and
    // Alice must NOT receive an Ack for this dedupe key.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        tokio::select! {
            frame = next_server_frame(&mut bob, Duration::from_millis(100)) => {
                if let Some(ServerFrame::Deliver(d)) = frame {
                    panic!("relay forwarded an unknown-version envelope: {d:?}");
                }
            }
            frame = next_server_frame(&mut alice, Duration::from_millis(100)) => {
                if let Some(ServerFrame::Ack(a)) = frame {
                    panic!("relay acked an unknown-version send: {a:?}");
                }
            }
        }
    }
}

// ---- T7b: deposit-path Moved emit (departed-recipient signal) ----
//
// Signing helpers mirror tests/forwarding_index.rs — a forwarding
// record only verifies against the pubkey in the agent's stored
// pair-record, so the happy path posts the pair-record first.

fn agent_id_hex(pk_bytes: &[u8]) -> String {
    hex::encode(fetchit_relay_server::signature::derive_agent_id(pk_bytes))
}

fn mk_signed_pair(dsa: &MlDsa, sk: &MlDsaSecretKey, pk_bytes: &[u8], issued: u64) -> PairRecordV1 {
    let id = agent_id_hex(pk_bytes);
    let kem = [0u8; 1184];
    let relays = vec!["https://old.relay.example".to_string()];
    let input = pair_signing_input(&id, pk_bytes, &kem, &relays, issued).unwrap();
    let sig = dsa.sign(sk, &input).unwrap().to_bytes();
    PairRecordV1 {
        agent_id_hex: id,
        ml_dsa_pubkey_b64: B64.encode(pk_bytes),
        kem_pubkey_b64: B64.encode(kem),
        advertised_relays: relays,
        issued_at_ms: issued,
        sig_b64: B64.encode(sig),
    }
}

fn mk_signed_forwarding(
    dsa: &MlDsa,
    sk: &MlDsaSecretKey,
    pk_bytes: &[u8],
    issued: u64,
) -> ForwardingRecordV1 {
    let id = agent_id_hex(pk_bytes);
    let moved = vec!["https://new.relay.example".to_string()];
    let input = forwarding_signing_input(&id, &moved, issued).unwrap();
    let sig = dsa.sign(sk, &input).unwrap().to_bytes();
    ForwardingRecordV1 {
        agent_id_hex: id,
        moved_to_relays: moved,
        issued_at_ms: issued,
        sig_b64: B64.encode(sig),
    }
}

async fn post_pair(client: &reqwest::Client, addr: SocketAddr, rec: &PairRecordV1) {
    let r = client
        .post(format!("http://{addr}/v1/pair-record"))
        .json(rec)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "pair-record precondition POST must succeed"
    );
}

async fn post_forwarding(client: &reqwest::Client, addr: SocketAddr, rec: &ForwardingRecordV1) {
    let r = client
        .post(format!("http://{addr}/v1/forwarding"))
        .json(rec)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "forwarding precondition POST must succeed");
}

#[tokio::test]
async fn moved_emitted_for_departed_recipient_with_live_forwarding() {
    let addr = start_test_server().await;

    // Ruth migrated away: pair-record + live forwarding record, no session.
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let http = reqwest::Client::new();
    post_pair(&http, addr, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;
    post_forwarding(
        &http,
        addr,
        &mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000),
    )
    .await;
    let ruth_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(&pk_bytes));

    let alice_pk = b"alice-pubkey-bytes";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let mut alice = connect_ws(addr, &alice_tok).await;
    send_hello(&mut alice).await;
    let _ = expect_ready(&mut alice).await;

    send_envelope_to(
        &mut alice,
        ruth_id,
        envelope_from(alice_id, b"where did you go"),
        [0xcc; 16],
    )
    .await;

    // The deposit must answer Moved — not Ack — so the sender's
    // forwarding re-resolve fires instead of trusting a black-hole
    // buffer the departed recipient will never read.
    let frame = next_server_frame(&mut alice, Duration::from_secs(2))
        .await
        .expect("expected a server frame after deposit");
    let m = match frame {
        ServerFrame::Moved(m) => m,
        other => panic!("expected Moved, got {other:?}"),
    };
    assert_eq!(m.dedupe_key, DedupeKey::from_bytes([0xcc; 16]));

    // Moved replaces the Ack; both for one deposit would double-signal.
    if let Some(f) = next_server_frame(&mut alice, Duration::from_millis(400)).await {
        assert!(
            !matches!(f, ServerFrame::Ack(_)),
            "Moved deposit must not also Ack: {f:?}"
        );
    }

    // And nothing was buffered: Ruth reconnecting here drains nothing.
    let ruth_tok = obtain_bearer(addr, &pk_bytes).await;
    let mut ruth = connect_ws(addr, &ruth_tok).await;
    send_hello(&mut ruth).await;
    let _ = expect_ready(&mut ruth).await;
    if let Some(f) = next_server_frame(&mut ruth, Duration::from_millis(400)).await {
        assert!(
            !matches!(f, ServerFrame::Deliver(_)),
            "Moved deposit must not also buffer: {f:?}"
        );
    }
}

#[tokio::test]
async fn live_session_unaffected_by_forwarding_record() {
    let addr = start_test_server().await;

    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let http = reqwest::Client::new();
    post_pair(&http, addr, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;
    post_forwarding(
        &http,
        addr,
        &mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000),
    )
    .await;
    let ruth_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(&pk_bytes));

    // Ruth is CONNECTED — a forwarding record she left behind (e.g.
    // migrated away and came back) must not shadow the live session:
    // the direct push wins before the forwarding check runs.
    let ruth_tok = obtain_bearer(addr, &pk_bytes).await;
    let mut ruth = connect_ws(addr, &ruth_tok).await;
    send_hello(&mut ruth).await;
    let _ = expect_ready(&mut ruth).await;

    let alice_pk = b"alice-pubkey-bytes";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let mut alice = connect_ws(addr, &alice_tok).await;
    send_hello(&mut alice).await;
    let _ = expect_ready(&mut alice).await;

    send_envelope_to(
        &mut alice,
        ruth_id,
        envelope_from(alice_id, b"welcome back"),
        [0xdd; 16],
    )
    .await;

    let d = loop {
        match next_server_frame(&mut ruth, Duration::from_secs(2)).await {
            Some(ServerFrame::Deliver(d)) => break d,
            Some(_) => {}
            None => panic!("expected Deliver to the live session"),
        }
    };
    assert_eq!(d.envelope.ciphertext, b"welcome back");

    let ack = loop {
        match next_server_frame(&mut alice, Duration::from_secs(2)).await {
            Some(ServerFrame::Ack(a)) => break a,
            Some(ServerFrame::Moved(m)) => {
                panic!("live session must Ack, not Moved: {m:?}")
            }
            Some(_) => {}
            None => panic!("expected Ack for the delivered deposit"),
        }
    };
    assert_eq!(ack.dedupe_key, DedupeKey::from_bytes([0xdd; 16]));
}

#[tokio::test]
async fn expired_forwarding_record_buffers_and_acks() {
    let (addr, state) = start_test_server_with_state().await;

    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let ruth_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(&pk_bytes));

    // Liveness keys off the relay-clock `stored_at_ms`, which the HTTP
    // POST always stamps "now" — so age the record through a direct
    // store insert: stored at t=1 is past FORWARDING_TTL_MS for any
    // wall-clock deposit that follows.
    let fwd = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 1);
    state.forwarding.put_if_newer(fwd, 1).unwrap();

    let alice_pk = b"alice-pubkey-bytes";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let mut alice = connect_ws(addr, &alice_tok).await;
    send_hello(&mut alice).await;
    let _ = expect_ready(&mut alice).await;

    send_envelope_to(
        &mut alice,
        ruth_id,
        envelope_from(alice_id, b"see you at the old relay"),
        [0xee; 16],
    )
    .await;

    // Expired forwarding is NOT the departed signal: today's
    // buffer+Ack behavior must be preserved.
    let ack = loop {
        match next_server_frame(&mut alice, Duration::from_secs(2)).await {
            Some(ServerFrame::Ack(a)) => break a,
            Some(ServerFrame::Moved(m)) => {
                panic!("expired forwarding record must not emit Moved: {m:?}")
            }
            Some(_) => {}
            None => panic!("expected Ack for the buffered deposit"),
        }
    };
    assert_eq!(ack.dedupe_key, DedupeKey::from_bytes([0xee; 16]));

    // The deposit was buffered: Ruth drains it on connect.
    let ruth_tok = obtain_bearer(addr, &pk_bytes).await;
    let mut ruth = connect_ws(addr, &ruth_tok).await;
    send_hello(&mut ruth).await;
    let _ = expect_ready(&mut ruth).await;
    let d = loop {
        match next_server_frame(&mut ruth, Duration::from_secs(2)).await {
            Some(ServerFrame::Deliver(d)) => break d,
            Some(_) => {}
            None => panic!("expected buffered Deliver on connect"),
        }
    };
    assert_eq!(d.envelope.ciphertext, b"see you at the old relay");
}

#[tokio::test]
async fn returned_home_pair_record_supersedes_forwarding() {
    let addr = start_test_server().await;

    // Ruth migrated away: pair-record + live forwarding record.
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let http = reqwest::Client::new();
    post_pair(&http, addr, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;
    post_forwarding(
        &http,
        addr,
        &mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000),
    )
    .await;
    let ruth_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(&pk_bytes));

    let alice_pk = b"alice-pubkey-bytes";
    let alice_id = AgentId::from_bytes(fetchit_relay_server::signature::derive_agent_id(alice_pk));
    let alice_tok = obtain_bearer(addr, alice_pk).await;
    let mut alice = connect_ws(addr, &alice_tok).await;
    send_hello(&mut alice).await;
    let _ = expect_ready(&mut alice).await;

    // While departed, the deposit bounces Moved.
    send_envelope_to(
        &mut alice,
        ruth_id,
        envelope_from(alice_id, b"first try"),
        [0x01; 16],
    )
    .await;
    match next_server_frame(&mut alice, Duration::from_secs(2)).await {
        Some(ServerFrame::Moved(_)) => {}
        other => panic!("expected Moved while departed, got {other:?}"),
    }

    // Ruth returns home inside the TTL: a NEWER accepted pair-record
    // supersedes the stale moved-to pointer, so deposits buffer+Ack
    // again instead of bouncing.
    post_pair(&http, addr, &mk_signed_pair(&dsa, &sk, &pk_bytes, 3_000)).await;
    send_envelope_to(
        &mut alice,
        ruth_id,
        envelope_from(alice_id, b"second try"),
        [0x02; 16],
    )
    .await;
    let ack = loop {
        match next_server_frame(&mut alice, Duration::from_secs(2)).await {
            Some(ServerFrame::Ack(a)) => break a,
            Some(ServerFrame::Moved(m)) => {
                panic!("superseded forwarding record must not bounce: {m:?}")
            }
            Some(_) => {}
            None => panic!("expected Ack after the agent returned home"),
        }
    };
    assert_eq!(ack.dedupe_key, DedupeKey::from_bytes([0x02; 16]));

    // And the buffered deposit reaches Ruth when she connects.
    let ruth_tok = obtain_bearer(addr, &pk_bytes).await;
    let mut ruth = connect_ws(addr, &ruth_tok).await;
    send_hello(&mut ruth).await;
    let _ = expect_ready(&mut ruth).await;
    let d = loop {
        match next_server_frame(&mut ruth, Duration::from_secs(2)).await {
            Some(ServerFrame::Deliver(d)) => break d,
            Some(_) => {}
            None => panic!("expected buffered Deliver on connect"),
        }
    };
    assert_eq!(d.envelope.ciphertext, b"second try");
}
