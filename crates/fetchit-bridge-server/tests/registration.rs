#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::net::SocketAddr;

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use fetchit_fedi::actor::{Actor, ActorIdentity};
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use serde_json::Value;
use tokio::net::TcpListener;

/// Mint a real ML-DSA-65-attested actor JSON-LD document for `handle`
/// whose canonical id is `actor_url`, mirroring `fetchit_fedi`'s internal
/// `test_attested` recipe. `spki_der` is opaque to the attestation path,
/// so a placeholder suffices for the foundation milestone.
fn mint_actor_doc_at(handle: &str, actor_url: &str) -> Value {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    let actor_url: url::Url = actor_url.parse().unwrap();
    let spki_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(&pk.to_bytes()));
    let input = signing_input(handle, &actor_url, &derived, &spki_der).unwrap();
    let sig = dsa
        .sign(&sk, &fetchit_relay_proto::agent_sign_input(&input))
        .unwrap()
        .to_bytes();
    let att = MlDsaAttestation::new(pk.to_bytes(), sig);
    let identity = ActorIdentity::new(
        handle.to_owned(),
        actor_url,
        derived,
        "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----\n".to_owned(),
        spki_der,
        att,
    );
    Actor::from_identity(&identity).unwrap().to_json_ld()
}

fn mint_actor_doc(handle: &str) -> Value {
    mint_actor_doc_at(handle, &format!("https://etchit.io/actors/{handle}"))
}

async fn start() -> (SocketAddr, Store) {
    start_limited(0, 0).await
}

/// Like [`start`] but with the registration limiter configured. A
/// `register_burst` of `0` disables it (the default for every other test).
async fn start_limited(register_burst: u32, register_per_min: u32) -> (SocketAddr, Store) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store = Store::open_in_memory().unwrap();
    let config = BridgeConfig {
        bind: addr,
        domain: "etchit.io".into(),
        db_path: "unused".into(),
        server_version: "test".into(),
        reserved_handles: BridgeConfig::default_reserved_handles(),
        register_burst,
        register_per_min,
        trusted_proxy_hops: 0,
        denylist_url: None,
        denylist_cache: None,
    };
    let (router, _state) = Server::new(config, store.clone()).router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, store)
}

#[tokio::test]
async fn register_valid_actor_is_created() {
    let (addr, store) = start().await;
    let doc = mint_actor_doc("alice");
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert!(store.actor_by_handle("alice").await.unwrap().is_some());
}

#[tokio::test]
async fn register_rejects_dummy_attestation() {
    let (addr, _store) = start().await;
    let handle = "mallory";
    let actor_url: url::Url = format!("https://etchit.io/actors/{handle}")
        .parse()
        .unwrap();
    let identity = ActorIdentity::new(
        handle.to_owned(),
        actor_url,
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        "PRIV".to_owned(),
        vec![0x01, 0x02, 0x03, 0x04],
        MlDsaAttestation::new(vec![0x11; 8], vec![0x22; 8]),
    );
    let doc = Actor::from_identity(&identity).unwrap().to_json_ld();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn reregister_same_actor_returns_200() {
    let (addr, _store) = start().await;
    let doc = mint_actor_doc("alice");
    let client = reqwest::Client::new();
    let first = client
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 201);
    let second = client
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200);
}

#[tokio::test]
async fn register_rejects_foreign_domain_actor_url() {
    let (addr, _store) = start().await;
    let doc = mint_actor_doc_at("alice", "https://evil.example/actors/alice");
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn register_rejects_path_handle_mismatch() {
    let (addr, _store) = start().await;
    // preferred_username = "alice" but the id path is /actors/bob.
    let doc = mint_actor_doc_at("alice", "https://etchit.io/actors/bob");
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn register_rejects_ported_actor_id() {
    let (addr, _store) = start().await;
    // Right host, right path, but an explicit non-default port -- the
    // bridge serves one canonical origin, so this must be rejected.
    let doc = mint_actor_doc_at("alice", "https://etchit.io:8443/actors/alice");
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn register_rejects_reserved_handle() {
    let (addr, _store) = start().await;
    // "admin" is well-formed, validly attested, correct-domain -- but a
    // reserved handle, so open registration must refuse it (403).
    let doc = mint_actor_doc("admin");
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn register_rejects_oversize_body() {
    let (addr, _store) = start().await;
    // A well-formed JSON body larger than the POST /actors cap. A real
    // attested actor document is ~10-20 KiB; this bounds an unauthenticated
    // endpoint against disk-fill / oversized-body DoS (cross-review P3).
    // The limit trips during body buffering, before attestation, so the
    // body need not be a valid actor doc.
    let big = "a".repeat(70 * 1024);
    let body = serde_json::json!({ "padding": big });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn register_rate_limited_after_burst() {
    // A 2-token burst with no refill: the 3rd POST from the same client
    // (loopback) must be rejected with 429, proving the limiter is wired on
    // POST /actors and keyed per IP. The third actor is itself valid, so a
    // 429 (not 201) shows the limiter rejects before the handler runs.
    let (addr, _store) = start_limited(2, 0).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/actors");

    let r1 = client
        .post(&url)
        .json(&mint_actor_doc("alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 201);
    let r2 = client
        .post(&url)
        .json(&mint_actor_doc("bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 201);
    let r3 = client
        .post(&url)
        .json(&mint_actor_doc("carol"))
        .send()
        .await
        .unwrap();
    assert_eq!(r3.status(), 429);
}
