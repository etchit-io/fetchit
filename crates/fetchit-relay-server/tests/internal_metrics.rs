//! `/v1/metrics/internal` lives only on the loopback listener; it must
//! be invisible from the public listener and the loopback bind must
//! refuse any non-loopback address.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_proto::Region;
use fetchit_relay_server::{Server, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

async fn start_pair() -> (SocketAddr, SocketAddr) {
    let public_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public_listener.local_addr().unwrap();
    let internal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_addr = internal_listener.local_addr().unwrap();

    let mut cfg = ServerConfig::defaults(public_addr, Region::Nyc);
    cfg.internal_bind = Some(internal_addr);

    let server = Server::new(cfg);
    let (public_router, state) = server.router();
    let internal_router = Server::internal_router(Arc::clone(&state));

    tokio::spawn(async move {
        axum::serve(public_listener, public_router).await.unwrap();
    });
    tokio::spawn(async move {
        axum::serve(internal_listener, internal_router)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (public_addr, internal_addr)
}

#[tokio::test]
async fn internal_metrics_served_on_loopback_only() {
    let (public_addr, internal_addr) = start_pair().await;
    let http = reqwest::Client::new();

    let internal = http
        .get(format!("http://{internal_addr}/v1/metrics/internal"))
        .send()
        .await
        .unwrap();
    assert_eq!(internal.status(), 200, "internal endpoint should serve 200");
    let ct = internal
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        ct.starts_with("text/plain"),
        "expected prometheus text/plain content-type, got {ct:?}"
    );
    let body = internal.text().await.unwrap();
    assert!(
        body.contains("fetchit_relay_uptime_seconds"),
        "expected metric body, got first chars: {:?}",
        body.chars().take(80).collect::<String>()
    );

    let on_public = http
        .get(format!("http://{public_addr}/v1/metrics/internal"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        on_public.status(),
        404,
        "/v1/metrics/internal must not be served on the public listener"
    );
}

#[tokio::test]
async fn public_metrics_not_served_on_internal_listener() {
    let (_public_addr, internal_addr) = start_pair().await;
    let http = reqwest::Client::new();

    for path in [
        "/v1/metrics",
        "/v1/health",
        "/v1/auth/challenge",
        "/v1/ws",
    ] {
        let resp = http
            .get(format!("http://{internal_addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "internal listener must not host {path}, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn server_run_refuses_non_loopback_internal_bind() {
    let public_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public_listener.local_addr().unwrap();
    drop(public_listener);

    let mut cfg = ServerConfig::defaults(public_addr, Region::Nyc);
    cfg.internal_bind = Some(SocketAddr::from(([10, 0, 0, 1], 9088)));

    let server = Server::new(cfg);
    let err = server.run().await.expect_err("run() must reject non-loopback internal bind");
    let msg = err.to_string();
    assert!(
        msg.contains("loopback"),
        "expected loopback message, got {msg:?}"
    );
}
