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
    // x0x 0.29: attestation verify runs over the external-agent-sign framing.
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
async fn serves_registered_actor_doc_that_verifies() {
    let (addr, _store) = start().await;
    let doc = mint_actor_doc("alice");
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();

    let served: Value = reqwest::get(format!("http://{addr}/actors/alice"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let parsed = Actor::from_json_ld(&served).unwrap();
    assert!(parsed.verify_attestation().is_ok());
    assert_eq!(parsed.preferred_username, "alice");
}

#[tokio::test]
async fn followers_collection_is_empty_ordered_collection() {
    let (addr, _store) = start().await;
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&mint_actor_doc("alice"))
        .send()
        .await
        .unwrap();
    let coll: Value = reqwest::get(format!("http://{addr}/actors/alice/followers"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(coll["type"], "OrderedCollection");
    assert_eq!(coll["totalItems"], 0);
}

#[tokio::test]
async fn unknown_actor_is_404() {
    let (addr, _store) = start().await;
    let resp = reqwest::get(format!("http://{addr}/actors/nobody"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
