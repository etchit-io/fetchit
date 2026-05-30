//! End-to-end coverage for `/v1/profile/{POST,GET,DELETE}` —
//! drives the production verifier (real ML-DSA-65 sigs) through a
//! live axum server bound on a loopback port. The unit tests in
//! `src/profile.rs::tests` cover the in-memory store + reject
//! paths against `AcceptAllVerifier`; this file proves the full
//! HTTP path including signature verification + monotonic
//! ratcheting + tombstone semantics.
//!
//! Each test spins a fresh server so the in-memory store is
//! isolated. The shared `mk_signed_record` helper builds a record
//! from a freshly-generated ML-DSA-65 keypair, computes the
//! canonical signing bytes (`SIGN_DOMAIN_PROFILE || jcs(record sans
//! sig)`), and injects the sig — so when the relay verifies, it
//! sees the real production code path, not a mock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use fetchit_relay_proto::{derive_agent_id, Region};
use fetchit_relay_server::profile::{ProfileIndexRecord, SIGN_DOMAIN_PROFILE};
use fetchit_relay_server::{Server, ServerConfig};
use saorsa_pqc::api::sig::{MlDsa, MlDsaSecretKey, MlDsaVariant};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

const TOMBSTONE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

/// Build a single signed profile-index record using a real
/// ML-DSA-65 keypair. Returns the (record, secret) so a test that
/// wants to issue a follow-up record with monotonically-increasing
/// `issued_at_ms` can sign the second one under the same `agent_id`.
fn mk_signed_record(
    dsa: &MlDsa,
    sk: &MlDsaSecretKey,
    pk_bytes: &[u8],
    profile_addr: &str,
    issued_at_ms: u64,
) -> ProfileIndexRecord {
    let agent_id_bytes = derive_agent_id(pk_bytes);
    let agent_id = hex::encode(agent_id_bytes);
    let unsigned = ProfileIndexRecord {
        agent_id: agent_id.clone(),
        profile_addr: profile_addr.to_string(),
        kem_pubkey: B64URL.encode([0u8; 1184]), // verifier ignores this field
        ml_dsa_pubkey: B64URL.encode(pk_bytes),
        issued_at_ms,
        sig: String::new(),
    };
    let mut v = serde_json::to_value(&unsigned).unwrap();
    v.as_object_mut().unwrap().remove("sig");
    let canonical = serde_jcs::to_vec(&v).unwrap();
    let mut sign_input = Vec::with_capacity(SIGN_DOMAIN_PROFILE.len() + canonical.len());
    sign_input.extend_from_slice(SIGN_DOMAIN_PROFILE);
    sign_input.extend_from_slice(&canonical);
    let sig_bytes = dsa.sign(sk, &sign_input).unwrap().to_bytes();
    ProfileIndexRecord {
        sig: B64URL.encode(sig_bytes),
        ..unsigned
    }
}

#[tokio::test]
async fn post_then_get_roundtrips_a_valid_record() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let record = mk_signed_record(&dsa, &sk, &pk_bytes, &"a".repeat(64), 1_000);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{bound}/v1/profile"))
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let got: ProfileIndexRecord = client
        .get(format!("http://{bound}/v1/profile/{}", record.agent_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got.profile_addr, record.profile_addr);
    assert_eq!(got.issued_at_ms, 1_000);
    assert_eq!(got.sig, record.sig);
}

#[tokio::test]
async fn post_rejects_agent_id_that_does_not_derive_from_pubkey() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let mut record = mk_signed_record(&dsa, &sk, &pk_bytes, &"a".repeat(64), 1);
    // Swap in a wrong agent_id post-sign. The sig is now valid for
    // the body that contains the wrong agent_id (since we re-sign
    // is what mk_signed_record assumes), but the agent_id derivation
    // gate fires before sig verify.
    record.agent_id = "f".repeat(64);

    let resp = reqwest::Client::new()
        .post(format!("http://{bound}/v1/profile"))
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("derive_agent_id"),
        "expected agent_id-derivation error, got {body:?}"
    );
}

#[tokio::test]
async fn post_rejects_non_monotonic_issued_at() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let first = mk_signed_record(&dsa, &sk, &pk_bytes, &"a".repeat(64), 100);
    let second = mk_signed_record(&dsa, &sk, &pk_bytes, &"b".repeat(64), 100); // same ts!

    let client = reqwest::Client::new();
    let r1 = client
        .post(format!("http://{bound}/v1/profile"))
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    let r2 = client
        .post(format!("http://{bound}/v1/profile"))
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409, "non-monotonic POST must return 409");
}

#[tokio::test]
async fn delete_tombstones_and_get_returns_404_until_undelete() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let live = mk_signed_record(&dsa, &sk, &pk_bytes, &"a".repeat(64), 100);
    let tombstone = mk_signed_record(&dsa, &sk, &pk_bytes, TOMBSTONE, 200);
    let undelete = mk_signed_record(&dsa, &sk, &pk_bytes, &"c".repeat(64), 300);

    let client = reqwest::Client::new();
    client
        .post(format!("http://{bound}/v1/profile"))
        .json(&live)
        .send()
        .await
        .unwrap();
    let r = client
        .delete(format!("http://{bound}/v1/profile/{}", live.agent_id))
        .json(&tombstone)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Tombstoned: GET surfaces 404.
    let get1 = client
        .get(format!("http://{bound}/v1/profile/{}", live.agent_id))
        .send()
        .await
        .unwrap();
    assert_eq!(get1.status(), 404, "tombstoned agent_id must 404");

    // Undelete with a higher issued_at_ms.
    let r2 = client
        .post(format!("http://{bound}/v1/profile"))
        .json(&undelete)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);
    let got: ProfileIndexRecord = client
        .get(format!("http://{bound}/v1/profile/{}", live.agent_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got.profile_addr, undelete.profile_addr);
}

#[tokio::test]
async fn get_for_unknown_agent_returns_404() {
    let bound = spawn_server().await;
    let r = reqwest::Client::new()
        .get(format!("http://{bound}/v1/profile/{}", "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn post_rejects_oversize_body() {
    let bound = spawn_server().await;
    // Build a body that's structurally valid-ish JSON but exceeds 32 KB.
    let huge: Arc<Value> = Arc::new(serde_json::json!({
        "agent_id":     "a".repeat(64),
        "profile_addr": "b".repeat(64),
        "kem_pubkey":   "x".repeat(40_000), // 40 KB of payload
        "ml_dsa_pubkey": B64URL.encode([0u8; 1952]),
        "issued_at_ms": 1u64,
        "sig":          B64URL.encode([0u8; 3309]),
    }));
    let body = serde_json::to_vec(&*huge).unwrap();
    let r = reqwest::Client::new()
        .post(format!("http://{bound}/v1/profile"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
}

#[tokio::test]
async fn post_rejects_tampered_signature() {
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let mut record = mk_signed_record(&dsa, &sk, &pk_bytes, &"a".repeat(64), 1);
    // Flip the first byte of the signature.
    let mut sig_bytes = B64URL.decode(&record.sig).unwrap();
    sig_bytes[0] ^= 0xff;
    record.sig = B64URL.encode(&sig_bytes);

    let resp = reqwest::Client::new()
        .post(format!("http://{bound}/v1/profile"))
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("signature verify"),
        "expected sig-verify error, got {body:?}"
    );
}

#[tokio::test]
async fn delete_rejects_non_tombstone_profile_addr() {
    // The DELETE handler insists the body's profile_addr be exactly
    // the all-zeros sentinel — otherwise a malformed DELETE could
    // accidentally point at a real Autonomi address while the server
    // still treats it as a tombstone-equivalent record.
    let bound = spawn_server().await;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let pk_bytes = pk.to_bytes();
    let not_a_tombstone = mk_signed_record(&dsa, &sk, &pk_bytes, &"a".repeat(64), 100);
    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{bound}/v1/profile/{}",
            not_a_tombstone.agent_id
        ))
        .json(&not_a_tombstone)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
