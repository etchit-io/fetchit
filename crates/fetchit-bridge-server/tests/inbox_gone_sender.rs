#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Unverifiable-sender inbox contract: only a `Delete` whose sender is
//! AUTHORITATIVELY gone (HTTP 404/410 on the actor fetch) is
//! acknowledged with 202 — that decision is unit-tested on
//! `gone_delete_shortcut` in `routes/inbox.rs`, since an authoritative
//! tombstone cannot be produced hermetically through the SSRF-guarded
//! fetch. What CAN be exercised end-to-end is the transient class: a
//! loopback sender URL fails the SSRF pre-flight, which must stay a
//! retryable 502 for EVERY activity type, `Delete` included — a
//! momentary outage must never eat a delivery.

use std::net::SocketAddr;

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use fetchit_fedi::actor::{Actor, ActorIdentity};
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
use serde_json::json;
use tokio::net::TcpListener;

fn mint_owner_doc(handle: &str) -> serde_json::Value {
    let actor_url: url::Url = format!("https://etchit.io/actors/{handle}")
        .parse()
        .unwrap();
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

async fn start() -> SocketAddr {
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
    let (router, _state) = Server::new(config, store).router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

const GONE_SENDER: &str = "https://127.0.0.1:1/users/erased";

#[tokio::test]
async fn delete_with_transient_sender_failure_stays_retryable() {
    let addr = start().await;
    let doc = mint_owner_doc("carol");
    let client = reqwest::Client::new();
    client
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();

    let delete = json!({
        "type": "Delete",
        "actor": GONE_SENDER,
        "object": GONE_SENDER,
    });
    let resp = client
        .post(format!("http://{addr}/actors/carol/inbox"))
        .header("content-type", "application/activity+json")
        .json(&delete)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        502,
        "a non-authoritative fetch failure must keep even a Delete retryable"
    );
}

#[tokio::test]
async fn non_delete_from_unfetchable_sender_stays_retryable() {
    let addr = start().await;
    let doc = mint_owner_doc("dave");
    let client = reqwest::Client::new();
    client
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();

    let follow = json!({
        "type": "Follow",
        "actor": GONE_SENDER,
        "object": "https://etchit.io/actors/dave",
    });
    let resp = client
        .post(format!("http://{addr}/actors/dave/inbox"))
        .header("content-type", "application/activity+json")
        .json(&follow)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        502,
        "a possibly-transient sender-fetch failure must stay retryable"
    );
}
