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

#[tokio::test]
#[ignore = "requires running x0xd + reachable relay + Alice's card file; see env vars FETCHIT_X0XD_LIVE_BASE / FETCHIT_X0XD_LIVE_TOKEN / FETCHIT_RELAY_LIVE_URL / FETCHIT_ALICE_CARD_PATH"]
async fn live_encrypted_dm_round_trips_via_alice() {
    use fetchit_chat::card::extended_card_from_uri;
    use fetchit_chat::conversation::InboundDispatch;
    use fetchit_chat::identity::AgentId;
    use fetchit_chat::Client;
    use std::time::Duration;
    use url::Url;

    let base = std::env::var("FETCHIT_X0XD_LIVE_BASE").expect("FETCHIT_X0XD_LIVE_BASE must be set");
    let token =
        std::env::var("FETCHIT_X0XD_LIVE_TOKEN").expect("FETCHIT_X0XD_LIVE_TOKEN must be set");
    let relay =
        std::env::var("FETCHIT_RELAY_LIVE_URL").expect("FETCHIT_RELAY_LIVE_URL must be set");
    let alice_card_path = std::env::var("FETCHIT_ALICE_CARD_PATH")
        .unwrap_or_else(|_| "/tmp/alice-card.txt".to_owned());

    let client = Client::builder()
        .base_url(base)
        .token(token)
        .relay_url(Url::parse(&relay).expect("relay url"))
        .passphrase("live-test-pw".to_owned())
        .data_dir(std::env::temp_dir().join("fetchit-live-test"))
        .build()
        .await
        .expect("client build");

    // Import Alice's card via the daemon import + local persistence
    // path (same flow as `chat_import_card`).
    let alice_uri = std::fs::read_to_string(&alice_card_path).expect("read alice card file");
    let alice_uri = alice_uri.trim();
    client
        .identity()
        .import_uri(alice_uri)
        .await
        .expect("identity import_uri");

    // Persist locally so the inbound verifier has Alice's ML-DSA pubkey.
    let alice_card = fetchit_chat::messages::StoredContactCard::from_share_uri(alice_uri)
        .expect("alice card from uri");
    let layout = client.layout().expect("client has chat state").clone();
    alice_card.save(&layout).expect("save alice card");

    // Lookup Alice's agent id locally from the imported card.
    let alice_card_json = extended_card_from_uri(alice_uri).expect("parse card json");
    let alice_agent_id_hex = alice_card_json["agent_id"]
        .as_str()
        .expect("card has agent_id")
        .to_owned();
    let alice_id = AgentId(alice_agent_id_hex);

    // Send the encrypted DM.
    let body = format!("encrypted v2 hello @ {}", now_ms());
    eprintln!("[live] sending: {body}");
    client
        .messages()
        .send(&alice_id, &body, "Josh")
        .await
        .expect("send dm");

    // Wait for Alice's echo on the inbound channel.
    let mut inbound = client
        .take_transport_inbound("relay")
        .expect("take_transport_inbound");
    let expected_echo = format!("[echo] {body}");

    let deadline = tokio::time::sleep(Duration::from_secs(8));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            () = &mut deadline => panic!("alice should echo within 8s"),
            env = inbound.recv() => {
                let env = env.expect("inbound channel closed");
                let Some(transit) = env.transit else { continue; };
                let identity = client.identity_arc().expect("identity").clone();
                let registry = client.registry_arc().expect("registry").clone();
                let result = fetchit_chat::conversation::dispatch_inbound(
                    transit,
                    identity.as_ref(),
                    registry.as_ref(),
                )
                .await
                .expect("dispatch");
                match result {
                    InboundDispatch::Message { payload, .. } => {
                        assert_eq!(payload.body, expected_echo);
                        eprintln!("[live] received: {} OK", payload.body);
                        return;
                    }
                    InboundDispatch::Welcomed { .. } | InboundDispatch::Rekeyed { .. } => {
                        eprintln!("[live] welcomed/rekeyed; waiting for message");
                    }
                    other => panic!("expected Message, got {other:?}"),
                }
            }
        }
    }
}
