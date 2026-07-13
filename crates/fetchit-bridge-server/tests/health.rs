//! Integration tests for `/health` and `/metrics` endpoints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;
use tokio::net::TcpListener;

async fn start() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = BridgeConfig {
        bind: addr,
        domain: "etchit.io".into(),
        db_path: "unused".into(),
        server_version: "fetchit-bridge-server/test".into(),
        reserved_handles: BridgeConfig::default_reserved_handles(),
        register_burst: 0,
        register_per_min: 0,
        trusted_proxy_hops: 0,
    };
    let store = Store::open_in_memory().unwrap();
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

#[tokio::test]
async fn health_reports_ok() {
    let addr = start().await;
    let body: serde_json::Value = reqwest::get(format!("http://{addr}/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["version"], "fetchit-bridge-server/test");
}

#[tokio::test]
async fn metrics_exposes_uptime() {
    let addr = start().await;
    let text = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("fetchit_bridge_uptime_seconds"));
}
