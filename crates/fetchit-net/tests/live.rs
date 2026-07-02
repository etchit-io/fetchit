//! Live integration test against the Autonomi production network.
//!
//! `#[ignore]` by default — CI never runs this. Invoke manually:
//!
//! ```text
//! FETCHIT_LIVE_ADDR=<64-hex-etch-address> \
//!   cargo test -p fetchit-net --test live -- --ignored --nocapture
//! ```
//!
//! Set `FETCHIT_LIVE_PEERS` to a comma-separated list to override the
//! bundled `DEFAULT_PEERS`. Useful for testnet runs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_core::handlers::default_registry;
use fetchit_core::{Address, Hint, NetworkClient, RenderContext, Rendition};
use fetchit_net::{AutonomiClient, DEFAULT_PEERS};

fn parse_peers() -> Vec<String> {
    match std::env::var("FETCHIT_LIVE_PEERS") {
        Ok(s) => s.split(',').map(|p| p.trim().to_owned()).collect(),
        Err(_) => DEFAULT_PEERS.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "hits the live Autonomi network; requires FETCHIT_LIVE_ADDR"]
async fn fetches_known_address() {
    let Ok(addr_hex) = std::env::var("FETCHIT_LIVE_ADDR") else {
        eprintln!("FETCHIT_LIVE_ADDR not set — nothing to test");
        return;
    };
    let addr: Address = addr_hex.parse().expect("FETCHIT_LIVE_ADDR must be 64-hex");

    let peers = parse_peers();
    eprintln!("connecting to {} peer(s)…", peers.len());
    let client = AutonomiClient::connect(&peers)
        .await
        .expect("connect to live network");
    eprintln!("connected ({} peer(s))", client.peer_count().await);

    eprintln!("fetching {addr}…");
    let bytes = client.fetch(&addr).await.expect("fetch live address");
    eprintln!("fetched {} bytes", bytes.len());

    let rendition = default_registry()
        .render(bytes, &Hint::default(), &RenderContext::default())
        .expect("render live payload");

    eprintln!("rendered as: {}", rendition_kind(&rendition));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "hits the live Autonomi network; requires FETCHIT_LIVE_ADDR"]
async fn streams_known_address_matching_fetch() {
    let Ok(addr_hex) = std::env::var("FETCHIT_LIVE_ADDR") else {
        eprintln!("FETCHIT_LIVE_ADDR not set — nothing to test");
        return;
    };
    let addr: Address = addr_hex.parse().expect("FETCHIT_LIVE_ADDR must be 64-hex");

    let peers = parse_peers();
    let client = AutonomiClient::connect(&peers)
        .await
        .expect("connect to live network");

    // Drain the streamed chunks and compare against the one-shot fetch:
    // the progressive path must reassemble to exactly the same bytes.
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let stream = client.fetch_to_sink(&addr, tx, |_p| {});
    let collect = async {
        let mut buf = Vec::new();
        while let Some(item) = rx.recv().await {
            buf.extend_from_slice(item.expect("stream chunk ok").as_ref());
        }
        buf
    };
    let (total, streamed) = tokio::join!(stream, collect);
    let total = total.expect("stream to sink");

    let whole = client.fetch(&addr).await.expect("fetch live address");
    assert_eq!(streamed.len() as u64, total, "count matches streamed bytes");
    assert_eq!(
        streamed.as_slice(),
        whole.as_ref(),
        "stream equals one-shot fetch"
    );
    eprintln!("streamed {total} bytes, matching fetch()");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "hits the live Autonomi network; requires FETCHIT_LIVE_ADDR"]
async fn content_size_matches_fetched_length() {
    let Ok(addr_hex) = std::env::var("FETCHIT_LIVE_ADDR") else {
        eprintln!("FETCHIT_LIVE_ADDR not set - nothing to test");
        return;
    };
    let addr: Address = addr_hex.parse().expect("FETCHIT_LIVE_ADDR must be 64-hex");
    let client = AutonomiClient::connect(&parse_peers())
        .await
        .expect("connect to live network");
    let size = client.content_size(&addr).await.expect("content_size");
    let whole = client.fetch(&addr).await.expect("fetch");
    assert_eq!(size, whole.len() as u64, "data-map size equals fetched length");
}

fn rendition_kind(r: &Rendition) -> &'static str {
    match r {
        Rendition::Text { .. } => "text/plain",
        Rendition::Image { .. } => "image",
        Rendition::Audio { .. } => "audio",
        Rendition::Video { .. } => "video",
        Rendition::Pdf { .. } => "application/pdf",
        Rendition::Json { .. } => "application/json",
        Rendition::Tabular { .. } => "text/csv",
        Rendition::Archive { .. } => "archive",
        Rendition::EtchitEnvelope { .. } => "etchit/envelope-v1",
        Rendition::OpaqueBinary { .. } => "application/octet-stream",
        _ => "(unknown variant)",
    }
}
