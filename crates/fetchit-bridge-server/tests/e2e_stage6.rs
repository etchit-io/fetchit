#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::net::SocketAddr;

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use fetchit_fedi::actor::{Actor, ActorIdentity};
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use serde_json::Value;
use tokio::net::TcpListener;

#[allow(dead_code)]
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

/// The full Stage-6 chain: register -> WebFinger-resolve -> fetch the
/// resolved actor doc -> cryptographically verify it. This is the gap
/// that blocked any verified post in prod.
#[tokio::test]
async fn register_resolve_fetch_verify() {
    let (addr, _store) = start().await;

    // 1. Register.
    let created = reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&mint_actor_doc("alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    // 2. WebFinger-resolve the handle to a canonical actor URL.
    let jrd: Value = reqwest::get(format!(
        "http://{addr}/.well-known/webfinger?resource=acct:alice@etchit.io"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let href = jrd["links"][0]["href"].as_str().unwrap();
    assert_eq!(href, "https://etchit.io/actors/alice");

    // 3. Fetch the actor doc. The canonical href points at the public
    //    domain (served by the CF Worker in prod); against this bridge
    //    we hit the same path directly.
    let path = url::Url::parse(href).unwrap().path().to_owned();
    let served: Value = reqwest::get(format!("http://{addr}{path}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 4. Verify: the served doc carries an attestation that checks out.
    let actor = fetchit_fedi::actor::Actor::from_json_ld(&served).unwrap();
    assert!(actor.verify_attestation().is_ok());
}
