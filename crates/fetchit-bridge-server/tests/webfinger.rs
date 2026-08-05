#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::net::SocketAddr;

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use fetchit_fedi::actor::{Actor, ActorIdentity};
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use serde_json::Value;
use tokio::net::TcpListener;

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store = Store::open_in_memory().unwrap();
    let config = BridgeConfig {
        bind: addr,
        domain: "etchit.io".into(),
        db_path: "unused".into(),
        server_version: "test".into(),
        reserved_handles: BridgeConfig::default_reserved_handles(),
        register_burst: 0,
        register_per_min: 0,
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
async fn resolves_registered_handle() {
    let (addr, _store) = start().await;
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&mint_actor_doc("alice"))
        .send()
        .await
        .unwrap();
    let jrd: Value = reqwest::get(format!(
        "http://{addr}/.well-known/webfinger?resource=acct:alice@etchit.io"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(jrd["subject"], "acct:alice@etchit.io");
    assert_eq!(jrd["links"][0]["rel"], "self");
    assert_eq!(jrd["links"][0]["type"], "application/activity+json");
    assert_eq!(jrd["links"][0]["href"], "https://etchit.io/actors/alice");
}

#[tokio::test]
async fn subject_uses_canonical_domain_casing() {
    let (addr, _store) = start().await;
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&mint_actor_doc("alice"))
        .send()
        .await
        .unwrap();
    // Domain matches case-insensitively, but the JRD subject must be the
    // canonical (configured) casing.
    let jrd: Value = reqwest::get(format!(
        "http://{addr}/.well-known/webfinger?resource=acct:alice@ETCHIT.IO"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(jrd["subject"], "acct:alice@etchit.io");
}

#[tokio::test]
async fn wrong_domain_is_404() {
    let (addr, _store) = start().await;
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&mint_actor_doc("alice"))
        .send()
        .await
        .unwrap();
    let resp = reqwest::get(format!(
        "http://{addr}/.well-known/webfinger?resource=acct:alice@evil.example"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn malformed_resource_is_400() {
    let (addr, _store) = start().await;
    let resp = reqwest::get(format!(
        "http://{addr}/.well-known/webfinger?resource=not-an-acct"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn unknown_handle_is_404() {
    let (addr, _store) = start().await;
    let resp = reqwest::get(format!(
        "http://{addr}/.well-known/webfinger?resource=acct:nobody@etchit.io"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);
}
