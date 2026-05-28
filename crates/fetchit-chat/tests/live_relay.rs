//! Live chat-layer integration. Drives `fetchit_chat::Client` against
//! a real x0xd + a real fetchit relay; sends a self-DM; asserts it
//! comes back through the relay's inbound pump. Mirrors what the
//! desktop app does at startup.
//!
//! Ignored by default — run explicitly:
//!
//! ```text
//! FETCHIT_X0XD_LIVE_BASE=http://127.0.0.1:12700 \
//! FETCHIT_X0XD_LIVE_TOKEN=$(cat ~/.local/share/x0x/api-token) \
//! FETCHIT_RELAY_LIVE_URL=http://67.207.94.66:8088 \
//!     cargo test -p fetchit-chat --test live_relay -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::messages::decode_direct_message;
use fetchit_chat::Client;
use std::time::Duration;
use url::Url;

fn live_env() -> Option<(String, String, Url)> {
    let base = std::env::var("FETCHIT_X0XD_LIVE_BASE").ok()?;
    let token = std::env::var("FETCHIT_X0XD_LIVE_TOKEN").ok()?;
    let relay = std::env::var("FETCHIT_RELAY_LIVE_URL").ok()?;
    let relay = Url::parse(&relay).expect("FETCHIT_RELAY_LIVE_URL must be a valid URL");
    Some((base, token, relay))
}

#[tokio::test]
#[ignore = "broken after Task 8 chat-v2 encryption switch; awaits Task 10 rewire to use conversation::dispatch_inbound"]
async fn live_chat_self_dm_round_trips_through_relay() {
    let Some((base, token, relay)) = live_env() else {
        panic!(
            "FETCHIT_X0XD_LIVE_BASE, FETCHIT_X0XD_LIVE_TOKEN, and FETCHIT_RELAY_LIVE_URL must all be set for --ignored runs"
        );
    };

    eprintln!("[live-chat] building Client (x0xd={base}, relay={relay})");
    let client = Client::builder()
        .base_url(base)
        .token(token)
        .relay_url(relay)
        .build()
        .await
        .expect("Client::build must succeed against live x0xd + relay");

    let me = client.identity().me().await.expect("/agent must succeed");
    eprintln!("[live-chat] local agent_id: {}", me.agent_id);

    let mut inbound = client
        .take_transport_inbound("relay")
        .expect("relay transport inbound must be available");

    let body = format!("live-test self-DM @ {}", now_ms());
    eprintln!("[live-chat] sending self-DM: {body}");
    let receipt_id = client
        .messages()
        .send(&me.agent_id, &body, "live-test")
        .await
        .expect("send must succeed");
    eprintln!("[live-chat] sent — message id: {receipt_id:?}");

    let delivery = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("delivery must arrive within 5s")
        .expect("inbound stream must yield a delivery");
    let dm = decode_direct_message(delivery).expect("delivery must decode");
    assert_eq!(dm.body, body, "round-tripped body must match");
    assert_eq!(dm.from, me.agent_id, "sender must be me");
    eprintln!("[live-chat] received — body matches; round-trip confirmed");
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
