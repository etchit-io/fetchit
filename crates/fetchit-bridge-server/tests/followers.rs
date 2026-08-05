#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Followers endpoints: the owner-authed list + the public count-only
//! collection (messaging IA redesign P1, spec §9.3).

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

/// Mint a valid attested actor doc AND return the secret key + derived
/// agent id, so the test can sign `bridge-auth-v1` requests as the owner.
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

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Build the three `bridge-auth-v1` headers for a signed GET (empty body),
/// timestamped at the real clock so it lands inside the server's skew window.
fn signed_headers(
    sk: &MlDsaSecretKey,
    agent: &str,
    method: &str,
    path: &str,
) -> reqwest::header::HeaderMap {
    let ts = now_ms();
    let canonical = canonical_request(method, path, ts, b"");
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
async fn followers_list_is_owner_authed_and_lists_rows_newest_first() {
    let (addr, store) = start().await;
    let (doc, sk, derived) = mint_owner("alice");
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();

    // Seed two followers directly through the store (higher since_ms = newer).
    store
        .add_follower(
            &derived,
            "https://fosstodon.org/users/happyborg",
            "https://fosstodon.org/users/happyborg/inbox",
            1000,
        )
        .await
        .unwrap();
    store
        .add_follower(
            &derived,
            "https://mas.to/users/stranger",
            "https://mas.to/users/stranger/inbox",
            2000,
        )
        .await
        .unwrap();

    let path = "/actors/alice/followers/list";

    // Unauthenticated request is rejected.
    let unauthed = reqwest::get(format!("http://{addr}{path}")).await.unwrap();
    assert_eq!(unauthed.status(), 401);

    // Owner-authed request lists both, newest first.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .headers(signed_headers(&sk, &derived, "GET", path))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]["follower_actor_url"],
        "https://mas.to/users/stranger"
    );
    assert_eq!(
        items[1]["follower_actor_url"],
        "https://fosstodon.org/users/happyborg"
    );
}

#[tokio::test]
async fn public_followers_collection_reports_real_count_without_enumerating() {
    let (addr, store) = start().await;
    let (doc, _sk, derived) = mint_owner("bob");
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(&doc)
        .send()
        .await
        .unwrap();
    store
        .add_follower(
            &derived,
            "https://mas.to/users/x",
            "https://mas.to/users/x/inbox",
            1,
        )
        .await
        .unwrap();

    let coll: Value = reqwest::get(format!("http://{addr}/actors/bob/followers"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(coll["type"], "OrderedCollection");
    assert_eq!(coll["totalItems"], 1, "count is real");
    assert_eq!(
        coll["orderedItems"].as_array().unwrap().len(),
        0,
        "never enumerated publicly"
    );
}
