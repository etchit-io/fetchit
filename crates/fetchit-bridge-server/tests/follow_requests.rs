#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Inbound follow-request queue: the owner-authed list the device drains
//! plus the confirm-consumes contract (task #333, inbound Follow e2e).

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use fetchit_fedi::actor::{Actor, ActorIdentity};
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use fetchit_fedi::bridge_auth::canonical_request;
use saorsa_pqc::api::sig::{MlDsa, MlDsaSecretKey, MlDsaVariant};
use serde_json::Value;
use tokio::net::TcpListener;

const FOLLOWER: &str = "https://fosstodon.org/users/happyborg";
const FOLLOWER_INBOX: &str = "https://fosstodon.org/users/happyborg/inbox";

fn mint_owner(handle: &str) -> (Value, MlDsaSecretKey, String) {
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
        derived.clone(),
        "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----\n".to_owned(),
        spki_der,
        att,
    );
    let doc = Actor::from_identity(&identity).unwrap().to_json_ld();
    (doc, sk, derived)
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

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn signed_headers(
    sk: &MlDsaSecretKey,
    agent: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> reqwest::header::HeaderMap {
    let ts = now_ms();
    let canonical = canonical_request(method, path, ts, body);
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let sig = dsa
        .sign(sk, &fetchit_relay_proto::agent_sign_input(&canonical))
        .unwrap()
        .to_bytes();
    let mut h = reqwest::header::HeaderMap::new();
    h.insert("x-fetchit-agent", agent.parse().unwrap());
    h.insert("x-fetchit-ts", ts.to_string().parse().unwrap());
    h.insert("x-fetchit-sig", B64.encode(&sig).parse().unwrap());
    h
}

#[tokio::test]
async fn follow_requests_list_is_owner_authed_newest_first() {
    let (addr, store) = start().await;
    let (doc, sk, derived) = mint_owner("alice");
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();

    store
        .add_follow_request(&derived, FOLLOWER, FOLLOWER_INBOX, "their-follow-1", 1000)
        .await
        .unwrap();
    store
        .add_follow_request(
            &derived,
            "https://mas.to/users/stranger",
            "https://mas.to/users/stranger/inbox",
            "their-follow-2",
            2000,
        )
        .await
        .unwrap();

    let path = "/actors/alice/follow-requests";

    let unauthed = reqwest::get(format!("http://{addr}{path}")).await.unwrap();
    assert_eq!(unauthed.status(), 401);

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .headers(signed_headers(&sk, &derived, "GET", path, b""))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]["follower_actor_url"], "https://mas.to/users/stranger",
        "newest first"
    );
    assert_eq!(items[0]["follow_activity_id"], "their-follow-2");
    assert_eq!(items[1]["follower_actor_url"], FOLLOWER);
    assert_eq!(items[1]["follower_inbox_url"], FOLLOWER_INBOX);
}

#[tokio::test]
async fn confirm_consumes_the_queued_request() {
    let (addr, store) = start().await;
    let (doc, sk, derived) = mint_owner("bob2");
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    store
        .add_follow_request(&derived, FOLLOWER, FOLLOWER_INBOX, "their-follow-1", 1000)
        .await
        .unwrap();

    // The device delivered its signed Accept and confirms the follower.
    let path = "/actors/bob2/followers/confirm";
    let body = serde_json::to_vec(&serde_json::json!({
        "follower_actor_url": FOLLOWER,
        "follower_inbox_url": FOLLOWER_INBOX,
    }))
    .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .headers(signed_headers(&sk, &derived, "POST", path, &body))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Follower recorded; queue entry consumed.
    assert_eq!(
        store.followers_list(&derived).await.unwrap(),
        vec![FOLLOWER.to_owned()]
    );
    assert!(store
        .follow_requests_list(&derived)
        .await
        .unwrap()
        .is_empty());
}
