//! End-to-end coverage for `/v1/pair-record/{POST,GET}` — drives the
//! production `verify_pair_record` (real ML-DSA-65 sigs over the
//! canonical `pair_signing_input`) through a live axum server bound on a
//! loopback port. The unit tests in `src/pair_record.rs::tests` cover the
//! in-memory store + error→status mapping; this file proves the full HTTP
//! path including signature verification, the per-agent monotonic
//! watermark (and its `current_issued_at_ms` 409 contract), and the body
//! cap.
//!
//! Each test spins a fresh server so the in-memory store is isolated. The
//! shared `mk_signed_record` helper builds a record from a freshly
//! generated ML-DSA-65 keypair and signs the real `pair_signing_input`,
//! so the relay exercises the production verify path, not a mock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_proto::pair_record::{pair_signing_input, PairRecordV1};
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

/// Build a single signed [`PairRecordV1`] from a real ML-DSA-65 keypair.
/// Returns the record; the caller keeps `dsa`/`sk`/`pk_bytes` to mint a
/// follow-up record with a higher `issued_at_ms` under the same agent.
fn mk_signed_record(
    dsa: &MlDsa,
    sk: &MlDsaSecretKey,
    pk_bytes: &[u8],
    issued_at_ms: u64,
) -> PairRecordV1 {
    let agent_id_hex = hex::encode(derive_agent_id(pk_bytes));
    let kem_bytes = [0u8; 1184]; // verifier only needs identical bytes, not a real KEM key
    let relays = vec!["https://relay.example".to_string()];
    let input = pair_signing_input(&agent_id_hex, pk_bytes, &kem_bytes, &relays, issued_at_ms)
        .expect("signing input");
    let sig_bytes = dsa
        .sign(sk, &fetchit_relay_proto::agent_sign_input(&input))
        .unwrap()
        .to_bytes();
    PairRecordV1 {
        record_version: fetchit_relay_proto::pair_record::RECORD_VERSION_V1,
        agent_id_hex,
        ml_dsa_pubkey_b64: B64.encode(pk_bytes),
        kem_pubkey_b64: B64.encode(kem_bytes),
        machine_id: String::new(),
        advertised_relays: relays,
        issued_at_ms,
        sig_b64: B64.encode(sig_bytes),
    }
}

#[tokio::test]
async fn post_then_get_roundtrips_a_valid_record() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let record = mk_signed_record(&dsa, &sk, &pk_bytes, 1_000);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let got: PairRecordV1 = client
        .get(format!(
            "http://{bound}/v1/pair-record/{}",
            record.agent_id_hex
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got, record);
}

#[tokio::test]
async fn post_rejects_agent_id_that_does_not_derive_from_pubkey() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let mut record = mk_signed_record(&dsa, &sk, &pk_bytes, 1);
    // Claim an agent_id that does not derive from the pubkey. The
    // derivation gate is impersonation → 403.
    record.agent_id_hex = "f".repeat(64);

    let resp = reqwest::Client::new()
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn post_rejects_tampered_signature() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let mut record = mk_signed_record(&dsa, &sk, &pk_bytes, 1);
    let mut sig = B64.decode(&record.sig_b64).unwrap();
    sig[0] ^= 0xff;
    record.sig_b64 = B64.encode(&sig);

    let resp = reqwest::Client::new()
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn post_rejects_non_monotonic_and_returns_current_watermark() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let first = mk_signed_record(&dsa, &sk, &pk_bytes, 100);
    let second = mk_signed_record(&dsa, &sk, &pk_bytes, 100); // not strictly greater

    let client = reqwest::Client::new();
    let r1 = client
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    let r2 = client
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409, "non-monotonic POST must return 409");
    let body: Value = r2.json().await.unwrap();
    // The contract field name + value are what the client retries against.
    assert_eq!(
        body["current_issued_at_ms"].as_u64(),
        Some(100),
        "409 body must carry current_issued_at_ms == stored watermark, got {body:?}"
    );
}

#[tokio::test]
async fn post_then_higher_issued_at_replaces() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let first = mk_signed_record(&dsa, &sk, &pk_bytes, 100);
    let second = mk_signed_record(&dsa, &sk, &pk_bytes, 101); // strictly greater

    let client = reqwest::Client::new();
    client
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&first)
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(format!("http://{bound}/v1/pair-record"))
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);

    let got: PairRecordV1 = client
        .get(format!(
            "http://{bound}/v1/pair-record/{}",
            first.agent_id_hex
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got.issued_at_ms, 101);
}

#[tokio::test]
async fn get_for_unknown_agent_returns_404() {
    let bound = spawn_server().await;
    let r = reqwest::Client::new()
        .get(format!("http://{bound}/v1/pair-record/{}", "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn post_rejects_oversize_body() {
    let bound = spawn_server().await;
    // Structurally plausible JSON that blows past the 16 KB cap.
    let huge = serde_json::json!({
        "agent_id_hex":      "a".repeat(64),
        "ml_dsa_pubkey_b64": B64.encode([0u8; 1952]),
        "kem_pubkey_b64":    "x".repeat(40_000),
        "advertised_relays": ["https://relay.example"],
        "issued_at_ms":      1u64,
        "sig_b64":           B64.encode([0u8; 3309]),
    });
    let body = serde_json::to_vec(&huge).unwrap();
    let r = reqwest::Client::new()
        .post(format!("http://{bound}/v1/pair-record"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
}
