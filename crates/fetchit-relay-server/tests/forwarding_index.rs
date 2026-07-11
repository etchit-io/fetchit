//! End-to-end coverage for `/v1/forwarding/{POST,GET}` (Reachability V1,
//! TB2) through a live axum server. A forwarding record is verified
//! against the agent's ML-DSA-65 pubkey, which the relay reads from the
//! agent's **stored pair-record** — so every happy-path test posts a
//! pair-record first. The unit tests in `src/forwarding.rs::tests` cover
//! the store + TTL + error→status mapping; this file proves the full
//! HTTP path: the Option-A 412 precondition, real-signature verify, the
//! separate forwarding watermark + 409 contract, and the body cap.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_proto::pair_record::{
    forwarding_signing_input, pair_signing_input, ForwardingRecordV1, PairRecordV1,
};
use fetchit_relay_proto::{derive_agent_id, Region};
use fetchit_relay_server::{Server, ServerConfig};
use saorsa_pqc::api::sig::{MlDsa, MlDsaSecretKey, MlDsaVariant};
use serde_json::Value;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn spawn_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(bound, Region::Nyc);
    let server = Server::new(cfg);
    let (router, _state) = server.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    bound
}

fn agent_id_hex(pk_bytes: &[u8]) -> String {
    hex::encode(derive_agent_id(pk_bytes))
}

fn mk_signed_pair(dsa: &MlDsa, sk: &MlDsaSecretKey, pk_bytes: &[u8], issued: u64) -> PairRecordV1 {
    let id = agent_id_hex(pk_bytes);
    let kem = [0u8; 1184];
    let relays = vec!["https://old.relay.example".to_string()];
    let input = pair_signing_input(&id, pk_bytes, &kem, &relays, issued).unwrap();
    let sig = dsa
        .sign(sk, &fetchit_relay_proto::agent_sign_input(&input))
        .unwrap()
        .to_bytes();
    PairRecordV1 {
        record_version: fetchit_relay_proto::pair_record::RECORD_VERSION_V1,
        agent_id_hex: id,
        ml_dsa_pubkey_b64: B64.encode(pk_bytes),
        kem_pubkey_b64: B64.encode(kem),
        machine_id: String::new(),
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
    let sig = dsa
        .sign(sk, &fetchit_relay_proto::agent_sign_input(&input))
        .unwrap()
        .to_bytes();
    ForwardingRecordV1 {
        agent_id_hex: id,
        moved_to_relays: moved,
        issued_at_ms: issued,
        sig_b64: B64.encode(sig),
    }
}

async fn post_pair(client: &reqwest::Client, bound: SocketAddr, rec: &PairRecordV1) {
    let r = client
        .post(format!("http://{bound}/v1/pair-record"))
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

#[tokio::test]
async fn post_forwarding_after_pair_roundtrips() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let client = reqwest::Client::new();

    post_pair(&client, bound, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;
    let fwd = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000);

    let r = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&fwd)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let got: ForwardingRecordV1 = client
        .get(format!("http://{bound}/v1/forwarding/{}", fwd.agent_id_hex))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got, fwd);
}

#[tokio::test]
async fn post_forwarding_without_pair_record_is_412() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    // No pair-record posted first — the relay never knew this agent.
    let fwd = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000);

    let r = reqwest::Client::new()
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&fwd)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 412, "forwarding without a pair-record must 412");
    let body: Value = r.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("pair-record"));
}

#[tokio::test]
async fn post_forwarding_tampered_sig_is_403() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let client = reqwest::Client::new();
    post_pair(&client, bound, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;

    let mut fwd = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000);
    let mut sig = B64.decode(&fwd.sig_b64).unwrap();
    sig[0] ^= 0xff;
    fwd.sig_b64 = B64.encode(&sig);

    let r = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&fwd)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn post_forwarding_non_monotonic_is_409_with_current_watermark() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let client = reqwest::Client::new();
    post_pair(&client, bound, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;

    let first = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 500);
    let second = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 500); // not strictly greater

    let r1 = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    let r2 = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409);
    let body: Value = r2.json().await.unwrap();
    assert_eq!(
        body["current_issued_at_ms"].as_u64(),
        Some(500),
        "409 must carry the forwarding watermark, got {body:?}"
    );
}

#[tokio::test]
async fn get_unknown_forwarding_is_404() {
    let bound = spawn_server().await;
    let r = reqwest::Client::new()
        .get(format!("http://{bound}/v1/forwarding/{}", "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn newer_pair_record_supersedes_forwarding_get() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let client = reqwest::Client::new();

    // Migration order: pair-record, then the forwarding pointer.
    post_pair(&client, bound, &mk_signed_pair(&dsa, &sk, &pk_bytes, 1_000)).await;
    let fwd = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 2_000);
    let r = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&fwd)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // The agent returns home: a NEWER accepted pair-record retires the
    // stale moved-to pointer from GET without removing it.
    post_pair(&client, bound, &mk_signed_pair(&dsa, &sk, &pk_bytes, 3_000)).await;
    let r = client
        .get(format!("http://{bound}/v1/forwarding/{}", fwd.agent_id_hex))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        404,
        "superseded forwarding record must read as absent"
    );

    // The record was suppressed, not removed: the forwarding watermark
    // still holds, so replaying the captured record is still a 409.
    let r = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&fwd)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        409,
        "watermark must survive supersession to block replays"
    );

    // A genuinely newer forwarding record (the next migration) still
    // lands and serves.
    let fwd2 = mk_signed_forwarding(&dsa, &sk, &pk_bytes, 4_000);
    let r = client
        .post(format!("http://{bound}/v1/forwarding"))
        .json(&fwd2)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let got: ForwardingRecordV1 = client
        .get(format!(
            "http://{bound}/v1/forwarding/{}",
            fwd2.agent_id_hex
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got, fwd2);
}

#[tokio::test]
async fn post_forwarding_oversize_body_is_413() {
    let bound = spawn_server().await;
    let huge = serde_json::json!({
        "agent_id_hex":    "a".repeat(64),
        "moved_to_relays": ["x".repeat(20_000)],
        "issued_at_ms":    1u64,
        "sig_b64":         B64.encode([0u8; 3309]),
    });
    let body = serde_json::to_vec(&huge).unwrap();
    let r = reqwest::Client::new()
        .post(format!("http://{bound}/v1/forwarding"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
}
