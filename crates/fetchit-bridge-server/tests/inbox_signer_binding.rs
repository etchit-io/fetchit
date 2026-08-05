#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! The inbox binds its verification key to the signature's `keyId`, and
//! that binding is resolved BEFORE any network fetch.
//!
//! Ordering is the point. Until 2026-08-05 the key came from the
//! activity's `actor`, which made every forwarded delivery
//! unverifiable; the fix only holds if a request that names no usable
//! key is refused up front rather than sending us to fetch a key the
//! signer never claimed. Both cases below are decided from headers
//! alone, so they run hermetically — the SSRF guard refuses loopback,
//! so the fetch half of this route can never be exercised in-process
//! (see `inbox_gone_sender.rs`).
//!
//! The signer-vs-author decision itself is unit-tested on
//! `classify_provenance` in `routes/inbox.rs`, for the same reason.

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

/// Register `handle` and deliver `activity` to its inbox, attaching
/// `signature` as the `Signature` header when given.
async fn deliver(handle: &str, signature: Option<&str>) -> (u16, String) {
    let addr = start().await;
    let client = reqwest::Client::new();
    client
        .post(format!("http://{addr}/actors"))
        .json(&mint_owner_doc(handle))
        .send()
        .await
        .unwrap();

    // A remote author on a host we never contact: the request must be
    // refused before anything tries to reach it.
    let activity = json!({
        "type": "Create",
        "actor": "https://mastodon.online/users/codechimp",
        "object": { "type": "Note", "id": "https://mastodon.online/notes/1" },
    });
    let mut req = client
        .post(format!("http://{addr}/actors/{handle}/inbox"))
        .header("content-type", "application/activity+json")
        .header("date", "Tue, 05 Aug 2026 10:00:00 GMT");
    if let Some(sig) = signature {
        req = req.header("signature", sig);
    }
    let resp = req.json(&activity).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

#[tokio::test]
async fn delivery_with_no_signature_names_no_key_and_is_refused_up_front() {
    let (status, body) = deliver("erin", None).await;
    assert_eq!(status, 401, "a request naming no key cannot be verified");
    assert_eq!(
        body, "missing keyId",
        "the reason must say the key was never named — not `signature invalid`, \
         which is the conflation that hid the forwarding bug for weeks"
    );
}

#[tokio::test]
async fn delivery_whose_key_id_is_not_a_url_is_refused_up_front() {
    let (status, body) = deliver(
        "frank",
        Some(
            "keyId=\"not a url\",headers=\"(request-target) host date digest\",signature=\"AA==\"",
        ),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body, "keyId is not a url");
}
