//! Inbound federation denylist gate.
//!
//! The bridge terminates real federation traffic, so a moderated actor
//! must not be able to keep delivering here. The decision itself is
//! unit-tested in `src/denylist.rs`; what this file pins is the WIRING —
//! that a denylist handed to [`Server::with_denylist`] reaches the state
//! the inbox handler reads, and that the drop counter is exported.
//!
//! An end-to-end `403` cannot be produced hermetically: the gate runs on
//! the SIGNATURE-VERIFIED sender, and verification needs the sender's
//! actor document, which the SSRF-guarded fetch refuses to pull from a
//! loopback test server (the same constraint documented in
//! `inbox_gone_sender.rs`). Everything up to that fetch is exercised
//! there; everything after it is exercised here and in the unit tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::denylist::is_blocked_actor;
use fetchit_bridge_server::server::{BridgeState, Server};
use fetchit_bridge_server::store::Store;
use fetchit_trust_types::{DenylistQuery, EntryKind};
use tokio::net::TcpListener;

const BLOCKED: &str = "https://attacker.example/users/eve";
const ALLOWED: &str = "https://mastodon.example/users/alice";

struct BlocksOneActor;
impl DenylistQuery for BlocksOneActor {
    fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        matches!(kind, EntryKind::ActorUrl) && value == BLOCKED
    }
}

fn config(bind: SocketAddr) -> BridgeConfig {
    BridgeConfig {
        bind,
        domain: "etchit.io".into(),
        db_path: "unused".into(),
        server_version: "fetchit-bridge-server/test".into(),
        reserved_handles: BridgeConfig::default_reserved_handles(),
        register_burst: 0,
        register_per_min: 0,
        trusted_proxy_hops: 0,
        denylist_url: None,
        denylist_cache: None,
    }
}

async fn start(with_denylist: bool) -> (SocketAddr, Arc<BridgeState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store = Store::open_in_memory().unwrap();
    let server = Server::new(config(addr), store);
    let server = if with_denylist {
        server.with_denylist(Arc::new(BlocksOneActor))
    } else {
        server
    };
    let (router, state) = server.router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, state)
}

/// A wired denylist reaches the state the inbox handler consults, and
/// the exact expression that handler evaluates blocks the listed actor
/// while passing everyone else.
#[tokio::test]
async fn a_wired_denylist_reaches_the_inbox_state() {
    let (_addr, state) = start(true).await;
    assert!(state.denylist.is_some(), "the gate must be wired");
    assert!(is_blocked_actor(state.denylist.as_ref(), BLOCKED));
    assert!(!is_blocked_actor(state.denylist.as_ref(), ALLOWED));
    // Canonicalization runs inside the gate, so evasion by trailing
    // slash does not reach the store either.
    assert!(is_blocked_actor(
        state.denylist.as_ref(),
        &format!("{BLOCKED}/")
    ));
}

/// A bridge configured with no denylist accepts everyone — fail-open, so
/// a trust-service outage never takes federation down with it.
#[tokio::test]
async fn an_unwired_bridge_blocks_nobody() {
    let (_addr, state) = start(false).await;
    assert!(state.denylist.is_none());
    assert!(!is_blocked_actor(state.denylist.as_ref(), BLOCKED));
}

/// Ops needs to see the gate catching something; the counter is exported
/// unlabelled (the actor URL goes to the log, never a metric label).
#[tokio::test]
async fn the_drop_counter_is_exported_and_starts_at_zero() {
    let (addr, state) = start(true).await;
    let text = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("fetchit_bridge_inbox_denylisted_total"),
        "counter must be exported, got:\n{text}"
    );
    assert_eq!(state.metrics.inbox_denylisted_count(), 0);
    state.metrics.inc_inbox_denylisted();
    assert_eq!(state.metrics.inbox_denylisted_count(), 1);

    let text = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.lines()
            .any(|l| l.starts_with("fetchit_bridge_inbox_denylisted_total{") && l.ends_with(" 1")),
        "the increment must render, got:\n{text}"
    );
}
