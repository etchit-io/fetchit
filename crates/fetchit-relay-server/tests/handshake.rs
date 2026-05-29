//! End-to-end: spin up a server, run two clients through challenge / verify /
//! WebSocket, send a message between them, and assert the recipient gets it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_proto::{
    from_bytes, to_bytes, Ack, AgentId, AuthChallenge, AuthVerifyRequest, AuthVerifyResponse, Bye,
    ByeReason, ClientFrame, DedupeKey, Deliver, EnvelopeKind, Hello, MachineId, Ready, Region,
    SendFrame, ServerFrame, TenantId, TransitEnvelope,
};
use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};

async fn start_test_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(addr, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
    let (router, _state) = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    // tiny yield so the server is accepting before clients dial
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
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

fn envelope_from(sender: AgentId, body: &[u8]) -> TransitEnvelope {
    TransitEnvelope {
        version: 2,
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
