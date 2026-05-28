//! End-to-end: spin up the trust service, submit a report, deny a
//! target, fetch the signed denylist, verify the signature.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::items_after_statements
)]

use fetchit_trust::{
    DenylistEntry, DenylistResponse, EntryKind, ReportKind, Server, ServerConfig, TargetIdentity,
};
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use serde::Serialize;
use std::net::SocketAddr;
use tempfile::tempdir;
use tokio::net::TcpListener;

async fn start_test_server() -> (SocketAddr, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = tempdir().unwrap();
    let cfg = ServerConfig::new(addr, dir.path().to_path_buf(), "test-v1");
    let server = Server::new(cfg).unwrap();
    let router = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    // Keep tempdir alive by leaking — test scope is short.
    std::mem::forget(dir);
    (addr, server)
}

#[tokio::test]
async fn health_endpoint_responds() {
    let (addr, _server) = start_test_server().await;
    let body: serde_json::Value = reqwest::get(format!("http://{addr}/v1/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["queued_reports"], 0);
}

#[tokio::test]
async fn submit_report_then_deny_then_fetch_signed_denylist() {
    let (addr, server) = start_test_server().await;

    let target = TargetIdentity::new(EntryKind::AgentId, "a".repeat(64));
    let submit = serde_json::json!({
        "target": target,
        "kind": "spam",
        "reason": "test report",
        "reporter_agent_id_hex": "b".repeat(64),
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/report"))
        .json(&submit)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);

    // Promote to denylist (simulates moderator approval).
    server
        .state()
        .storage
        .deny(DenylistEntry {
            target: target.clone(),
            added_at_ms: 1,
            reason: ReportKind::Spam,
        })
        .unwrap();

    let denylist: DenylistResponse = reqwest::get(format!("http://{addr}/v1/denylist/agent_ids"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(denylist.kind, EntryKind::AgentId);
    assert_eq!(denylist.entries.len(), 1);
    assert_eq!(denylist.entries[0].target, target);

    // Verify the issuer signature.
    #[derive(Serialize)]
    struct ToSign<'a> {
        etag: &'a str,
        generated_at_ms: u64,
        kind: EntryKind,
        entries: &'a [DenylistEntry],
    }
    let to_sign = ToSign {
        etag: denylist.etag.as_str(),
        generated_at_ms: denylist.generated_at_ms,
        kind: denylist.kind,
        entries: &denylist.entries,
    };
    let sign_bytes = postcard::to_allocvec(&to_sign).unwrap();
    let sig_bytes = hex::decode(&denylist.issuer_signature_hex).unwrap();

    let pk_resp: serde_json::Value = reqwest::get(format!("http://{addr}/v1/issuer/public_key"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pk_bytes = hex::decode(pk_resp["public_key_hex"].as_str().unwrap()).unwrap();

    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes).unwrap();
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes).unwrap();
    assert!(dsa.verify(&pk, &sign_bytes, &sig).unwrap());
}

#[tokio::test]
async fn xornames_denylist_round_trips_independently() {
    let (addr, server) = start_test_server().await;
    let xor_a = TargetIdentity::new(EntryKind::XorName, "c".repeat(64));
    let xor_b = TargetIdentity::new(EntryKind::XorName, "d".repeat(64));
    for t in [&xor_a, &xor_b] {
        server
            .state()
            .storage
            .deny(DenylistEntry {
                target: t.clone(),
                added_at_ms: 0,
                reason: ReportKind::AbusiveContent,
            })
            .unwrap();
    }
    let denylist: DenylistResponse = reqwest::get(format!("http://{addr}/v1/denylist/xornames"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(denylist.entries.len(), 2);
}
