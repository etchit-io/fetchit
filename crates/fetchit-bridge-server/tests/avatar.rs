#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Own-avatar endpoints: public GET, owner-authed POST/DELETE, and the
//! icon's survival through the register → serve round trip.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use fetchit_fedi::actor::{Actor, ActorIdentity};
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use fetchit_fedi::avatar::MAX_AVATAR_BYTES;
use fetchit_fedi::bridge_auth::canonical_request;
use saorsa_pqc::api::sig::{MlDsa, MlDsaSecretKey, MlDsaVariant};
use serde_json::Value;
use tokio::net::TcpListener;

/// A minimal-but-real PNG header, so the magic check passes.
fn png(len: usize) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.resize(len.max(8), 0x42);
    v
}

fn owner_identity(handle: &str, icon: Option<&str>) -> (ActorIdentity, MlDsaSecretKey, String) {
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
    let identity = ActorIdentity::new(
        handle.to_owned(),
        actor_url,
        derived.clone(),
        "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----\n".to_owned(),
        spki_der,
        MlDsaAttestation::new(pk.to_bytes(), sig),
    )
    .with_icon(
        icon.map(str::to_owned),
        icon.map(|_| "image/jpeg".to_owned()),
    );
    (identity, sk, derived)
}

fn mint_owner(handle: &str) -> (Value, MlDsaSecretKey, String) {
    let (identity, sk, derived) = owner_identity(handle, None);
    (
        Actor::from_identity(&identity).unwrap().to_json_ld(),
        sk,
        derived,
    )
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

async fn register(addr: SocketAddr, doc: &Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/actors"))
        .json(doc)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn set_serve_and_clear_the_owner_avatar() {
    let (addr, _store) = start().await;
    let (doc, sk, derived) = mint_owner("alice");
    register(addr, &doc).await;
    let path = "/actors/alice/avatar";
    let url = format!("http://{addr}{path}");
    let body = png(64);

    // Nothing set yet.
    assert_eq!(reqwest::get(&url).await.unwrap().status(), 404);

    let resp = reqwest::Client::new()
        .post(&url)
        .headers(signed_headers(&sk, &derived, "POST", path, &body))
        .header("content-type", "image/png")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Public GET serves the bytes verbatim, typed, and non-sniffable.
    let got = reqwest::get(&url).await.unwrap();
    assert_eq!(got.status(), 200);
    assert_eq!(got.headers()["content-type"], "image/png");
    assert_eq!(
        got.headers().get_all("content-type").iter().count(),
        1,
        "exactly one content-type: a stray octet-stream beside it would \
         make the served type ambiguous"
    );
    assert_eq!(
        got.headers()["x-content-type-options"],
        "nosniff",
        "a hosted upload must never be sniffed into markup"
    );
    assert!(got.headers()["cache-control"]
        .to_str()
        .unwrap()
        .contains("max-age="));
    assert_eq!(got.bytes().await.unwrap().as_ref(), body.as_slice());

    // Delete clears it, idempotently.
    let del = reqwest::Client::new()
        .delete(&url)
        .headers(signed_headers(&sk, &derived, "DELETE", path, b""))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 200);
    assert_eq!(reqwest::get(&url).await.unwrap().status(), 404);
    let again = reqwest::Client::new()
        .delete(&url)
        .headers(signed_headers(&sk, &derived, "DELETE", path, b""))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200, "a repeat delete is not an error");
}

#[tokio::test]
async fn writes_require_the_handle_owner() {
    let (addr, _store) = start().await;
    let (doc, _sk, _derived) = mint_owner("alice");
    register(addr, &doc).await;
    // A second, unrelated identity — a valid signer that owns a
    // different handle.
    let (other_doc, other_sk, other_agent) = mint_owner("mallory");
    register(addr, &other_doc).await;

    let path = "/actors/alice/avatar";
    let url = format!("http://{addr}{path}");
    let body = png(32);

    let unauthed = reqwest::Client::new()
        .post(&url)
        .header("content-type", "image/png")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(unauthed.status(), 401, "no headers at all");

    let wrong_owner = reqwest::Client::new()
        .post(&url)
        .headers(signed_headers(&other_sk, &other_agent, "POST", path, &body))
        .header("content-type", "image/png")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        wrong_owner.status(),
        403,
        "another registered agent cannot set alice's picture"
    );

    let unauthed_delete = reqwest::Client::new().delete(&url).send().await.unwrap();
    assert_eq!(unauthed_delete.status(), 401);

    assert_eq!(
        reqwest::get(&url).await.unwrap().status(),
        404,
        "and nothing was stored"
    );
}

#[tokio::test]
async fn oversized_upload_is_rejected_with_413() {
    let (addr, _store) = start().await;
    let (doc, sk, derived) = mint_owner("alice");
    register(addr, &doc).await;
    let path = "/actors/alice/avatar";
    let body = png(MAX_AVATAR_BYTES + 1);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .headers(signed_headers(&sk, &derived, "POST", path, &body))
        .header("content-type", "image/png")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);

    // The cap is inclusive: exactly at the limit still works.
    let at_cap = png(MAX_AVATAR_BYTES);
    let ok = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .headers(signed_headers(&sk, &derived, "POST", path, &at_cap))
        .header("content-type", "image/png")
        .body(at_cap)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn only_real_images_of_an_allowed_type_are_stored() {
    let (addr, _store) = start().await;
    let (doc, sk, derived) = mint_owner("alice");
    register(addr, &doc).await;
    let path = "/actors/alice/avatar";
    let url = format!("http://{addr}{path}");

    // Disallowed / missing content types.
    for ct in ["image/svg+xml", "image/gif", "text/html"] {
        let body = png(16);
        let resp = reqwest::Client::new()
            .post(&url)
            .headers(signed_headers(&sk, &derived, "POST", path, &body))
            .header("content-type", ct)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 415, "{ct} must be refused");
    }

    // A declared image whose bytes are something else entirely — the
    // "host arbitrary content under our domain" case.
    let markup = b"<!doctype html><script>alert(1)</script>".to_vec();
    let resp = reqwest::Client::new()
        .post(&url)
        .headers(signed_headers(&sk, &derived, "POST", path, &markup))
        .header("content-type", "image/png")
        .body(markup)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 415);

    assert_eq!(reqwest::get(&url).await.unwrap().status(), 404);
}

#[tokio::test]
async fn the_icon_survives_register_then_get_actor() {
    // The bridge re-renders the document it stores, so an `icon` it
    // failed to parse would be a profile picture the user silently lost.
    let (addr, _store) = start().await;
    let (identity, _sk, _derived) =
        owner_identity("alice", Some("https://etchit.io/actors/alice/avatar"));
    let doc = Actor::from_identity(&identity).unwrap().to_json_ld();
    assert_eq!(register(addr, &doc).await.status(), 201);

    let served: Value = reqwest::get(format!("http://{addr}/actors/alice"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(served["icon"]["type"], "Image");
    assert_eq!(served["icon"]["mediaType"], "image/jpeg");
    assert_eq!(
        served["icon"]["url"], "https://etchit.io/actors/alice/avatar",
        "the icon must survive the bridge's parse + re-render"
    );

    // And an actor with no picture still serves no icon key at all.
    let (plain, _sk2, _d2) = mint_owner("bob");
    register(addr, &plain).await;
    let bob: Value = reqwest::get(format!("http://{addr}/actors/bob"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(bob.get("icon").is_none());
}
