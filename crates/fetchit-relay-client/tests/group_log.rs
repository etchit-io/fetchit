//! Group-log transport (#297 Lane A): the client issues `LogAppend` /
//! `LogFetch` and reassembles the chunked `LogRecords` reply. This is the
//! durable `CommitSource` seam the epoch-recovery driver plugs into — a
//! behind member fetches the commits it missed and applies them to catch up.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fetchit_relay_client::{Client, ClientConfig, StaticKeySigner};
use fetchit_relay_proto::{GroupId, LogRecordKind, Region};
use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
use tokio::net::TcpListener;
use url::Url;

async fn start_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(addr, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
    let (router, _state) = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

async fn connect(addr: SocketAddr, pk: &[u8]) -> Client {
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let signer = Arc::new(StaticKeySigner::from_public_key(pk.to_vec()));
    Client::connect(ClientConfig::new(base), signer)
        .await
        .unwrap()
}

#[tokio::test]
async fn append_then_fetch_returns_ordered_commits() {
    let addr = start_server().await;
    let client = connect(addr, b"alice-public-key").await;
    let group = GroupId::from_bytes([0x33; 32]);

    for payload in [b"c1".as_slice(), b"c2", b"c3"] {
        client
            .log_append(group, LogRecordKind::Commit, None, payload.to_vec())
            .unwrap();
    }

    let records = client.log_fetch(group, 0).await.unwrap();
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "relay-assigned seqs start at 1 and arrive ascending"
    );
    assert_eq!(records[0].payload, b"c1");
    assert_eq!(records[0].kind, LogRecordKind::Commit);
    assert_eq!(records[2].payload, b"c3");
}

#[tokio::test]
async fn fetch_since_returns_only_newer_records() {
    let addr = start_server().await;
    let client = connect(addr, b"alice-public-key").await;
    let group = GroupId::from_bytes([0x44; 32]);

    for payload in [b"a".as_slice(), b"b", b"c"] {
        client
            .log_append(group, LogRecordKind::Commit, None, payload.to_vec())
            .unwrap();
    }

    // since_seq = 2 skips seqs 1 and 2, returning only seq 3.
    let records = client.log_fetch(group, 2).await.unwrap();
    assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3]);
    assert_eq!(records[0].payload, b"c");
}

#[tokio::test]
async fn fetch_empty_log_returns_empty() {
    let addr = start_server().await;
    let client = connect(addr, b"alice-public-key").await;
    let group = GroupId::from_bytes([0x55; 32]);

    // A group with no appended records yields a single done=true frame with
    // no records — surfaced as an empty Vec, never a hang.
    let records = client.log_fetch(group, 0).await.unwrap();
    assert!(records.is_empty(), "empty log fetches to an empty Vec");
}
