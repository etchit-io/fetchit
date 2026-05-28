//! End-to-end: spin up a real server in-process, drive the client API
//! through send + receive, assert delivery.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_client::{
    Client, ClientConfig, MlDsaSigner, Signer, StaticKeySigner, X0xdSigner,
};
use fetchit_relay_proto::{AgentId, DedupeKey, EnvelopeKind, MachineId, Region, TransitEnvelope};
use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

async fn start_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(addr, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
    let (router, _state) = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

fn envelope_from(sender: AgentId, body: &[u8]) -> TransitEnvelope {
    TransitEnvelope {
        version: 1,
        kind: EnvelopeKind::Dm,
        group_id: None,
        tenant_id: None,
        sender_agent_id: sender,
        sender_machine_id: MachineId::from_bytes([0u8; 32]),
        timestamp_ms: 1,
        ciphertext: body.to_vec(),
        nonce: vec![0u8; 12],
        kem_ciphertext: vec![0u8; 32],
        sender_signature: vec![0u8; 32],
    }
}

#[tokio::test]
async fn client_round_trip_send_and_receive() {
    let addr = start_server().await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();

    let alice_signer = StaticKeySigner::from_public_key(b"alice-public-key".to_vec());
    let bob_signer = StaticKeySigner::from_public_key(b"bob-public-key-here".to_vec());
    let alice_id = AgentId::from_bytes(alice_signer.agent_id());
    let bob_id = AgentId::from_bytes(bob_signer.agent_id());

    let alice = Client::connect(ClientConfig::new(base.clone()), &alice_signer)
        .await
        .unwrap();
    let bob = Client::connect(ClientConfig::new(base), &bob_signer)
        .await
        .unwrap();

    let payload = b"hello from alice";
    let receipt = alice
        .send(
            bob_id,
            envelope_from(alice_id, payload),
            DedupeKey::from_bytes([0xaa; 16]),
        )
        .await
        .unwrap();
    assert!(receipt.accepted_at_ms > 0);

    let delivery = tokio::time::timeout(Duration::from_secs(2), bob.next_delivery())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.envelope.ciphertext, payload);
    assert_eq!(delivery.envelope.sender_agent_id, alice_id);
}

#[tokio::test]
async fn real_pq_signatures_authenticate_against_the_real_verifier() {
    use fetchit_relay_server::MlDsa65Verifier;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(addr, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(MlDsa65Verifier::new()));
    let (router, _state) = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let alice = MlDsaSigner::generate().unwrap();
    let bob = MlDsaSigner::generate().unwrap();
    let alice_id = AgentId::from_bytes(alice.agent_id());
    let bob_id = AgentId::from_bytes(bob.agent_id());

    let alice_client = Client::connect(ClientConfig::new(base.clone()), &alice)
        .await
        .unwrap();
    let bob_client = Client::connect(ClientConfig::new(base), &bob)
        .await
        .unwrap();

    let payload = b"signed across PQ";
    let receipt = alice_client
        .send(
            bob_id,
            envelope_from(alice_id, payload),
            DedupeKey::from_bytes([0xcc; 16]),
        )
        .await
        .unwrap();
    assert!(receipt.accepted_at_ms > 0);

    let delivery = tokio::time::timeout(Duration::from_secs(2), bob_client.next_delivery())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.envelope.ciphertext, payload);
    assert_eq!(delivery.envelope.sender_agent_id, alice_id);
}

/// Mock x0xd that holds a real ML-DSA-65 keypair and implements
/// `POST /agent/sign` with the same wire shape as the real daemon.
mod mock_x0xd {
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use fetchit_relay_proto::derive_agent_id;
    use saorsa_pqc::api::sig::{MlDsa, MlDsaSecretKey, MlDsaVariant};
    use serde::Deserialize;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    pub(super) struct MockState {
        pub(super) api_token: String,
        pub(super) dsa: MlDsa,
        pub(super) secret_key: MlDsaSecretKey,
        pub(super) public_key_b64: String,
        pub(super) agent_id_hex: String,
    }

    impl MockState {
        pub(super) fn fresh(api_token: impl Into<String>) -> Arc<Self> {
            let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
            let (public_key, secret_key) = dsa.generate_keypair().unwrap();
            let pk_bytes = public_key.to_bytes();
            let agent_id = derive_agent_id(&pk_bytes);
            Arc::new(Self {
                api_token: api_token.into(),
                dsa,
                secret_key,
                public_key_b64: B64.encode(&pk_bytes),
                agent_id_hex: hex::encode(agent_id),
            })
        }
    }

    #[derive(Deserialize)]
    struct SignRequest {
        payload_b64: String,
    }

    pub(super) async fn start(state: Arc<MockState>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/agent/sign", post(agent_sign))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        addr
    }

    async fn agent_sign(
        State(state): State<Arc<MockState>>,
        headers: HeaderMap,
        Json(req): Json<SignRequest>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected = format!("Bearer {}", state.api_token);
        if auth != expected {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "ok": false, "error": "bad token" })),
            );
        }
        let Ok(payload) = B64.decode(&req.payload_b64) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "bad base64" })),
            );
        };
        let sig = state.dsa.sign(&state.secret_key, &payload).unwrap();
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "agent_id": state.agent_id_hex,
                "public_key_b64": state.public_key_b64,
                "signature_b64": B64.encode(sig.to_bytes()),
                "algorithm": "x0x.agent-sign.v1.ml-dsa-65",
            })),
        )
    }
}

#[tokio::test]
async fn x0xd_signer_drives_relay_with_real_pq_signatures() {
    use fetchit_relay_server::MlDsa65Verifier;

    // Mock x0xd (holds the real ML-DSA-65 keypair).
    let x0xd_state = mock_x0xd::MockState::fresh("local-token");
    let x0xd_addr = mock_x0xd::start(x0xd_state.clone()).await;
    let x0xd_url = Url::parse(&format!("http://{x0xd_addr}/")).unwrap();

    // Relay using the real production verifier.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let relay_cfg = ServerConfig::defaults(relay_addr, Region::Nyc);
    let relay = Server::new(relay_cfg).with_verifier(Arc::new(MlDsa65Verifier::new()));
    let (router, _state) = relay.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // X0xdSigner connects to mock x0xd, retrieves agent identity.
    let signer = X0xdSigner::connect(x0xd_url, "local-token").await.unwrap();
    let my_id = AgentId::from_bytes(signer.agent_id());

    // Open a relay session driven by the x0xd-backed signer.
    let relay_base = Url::parse(&format!("http://{relay_addr}/")).unwrap();
    let client = Client::connect(ClientConfig::new(relay_base), &signer)
        .await
        .unwrap();

    // Sanity-check identity matches what x0xd reported.
    assert_eq!(
        hex::encode(my_id.as_bytes()),
        x0xd_state.agent_id_hex,
        "X0xdSigner agent id must match mock x0xd's reported agent id",
    );

    // Drive a self-loopback send (agent sending to itself); proves
    // every layer end-to-end (handshake, sign, verify, route, deliver).
    let payload = b"hello via x0xd-signed handshake";
    client
        .send(
            my_id,
            envelope_from(my_id, payload),
            DedupeKey::from_bytes([0xdd; 16]),
        )
        .await
        .unwrap();

    let delivery = tokio::time::timeout(Duration::from_secs(2), client.next_delivery())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.envelope.ciphertext, payload);
    assert_eq!(delivery.envelope.sender_agent_id, my_id);
}

#[tokio::test]
async fn x0xd_signer_rejects_wrong_token() {
    let x0xd_state = mock_x0xd::MockState::fresh("real-token");
    let addr = mock_x0xd::start(x0xd_state).await;
    let url = Url::parse(&format!("http://{addr}/")).unwrap();
    let err = X0xdSigner::connect(url, "wrong-token").await.unwrap_err();
    assert!(matches!(
        err,
        fetchit_relay_client::ClientError::AuthRejected(_)
    ));
}

#[tokio::test]
async fn client_resolves_default_capabilities_when_no_token() {
    let addr = start_server().await;
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = StaticKeySigner::from_public_key(b"some-key".to_vec());
    let client = Client::connect(ClientConfig::new(base), &signer)
        .await
        .unwrap();
    assert_eq!(
        client.effective_capabilities.max_envelopes_per_min,
        fetchit_relay_proto::DEFAULT_MAX_ENVELOPES_PER_MIN
    );
    assert_eq!(
        client.effective_capabilities.max_group_size,
        fetchit_relay_proto::DEFAULT_MAX_GROUP_SIZE
    );
}
