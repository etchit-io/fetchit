//! Live smoke against a running `x0xd` on the local machine.
//!
//! Skipped by default — run explicitly with:
//!
//! ```text
//! cargo test -p fetchit-chat --test live -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::Client;

async fn client_or_skip() -> Option<Client> {
    match Client::auto().await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("x0xd not reachable; skipping: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "requires a running x0xd daemon"]
async fn live_health_and_identity() {
    let Some(c) = client_or_skip().await else {
        return;
    };
    c.health().await.expect("health");
    let me = c.identity().me().await.expect("identity");
    assert_eq!(me.agent_id.0.len(), 64);
    println!("agent_id={} machine_id={}", me.agent_id, me.machine_id);
}

#[tokio::test]
#[ignore = "requires a running x0xd daemon"]
async fn live_card_round_trip() {
    let Some(c) = client_or_skip().await else {
        return;
    };
    let card = c.identity().card("Test").await.expect("card");
    assert_eq!(card.display_name, "Test");
    let uri = card.to_share_uri().expect("uri");
    assert!(uri.starts_with("x0x://agent/"));
}

#[tokio::test]
#[ignore = "requires a running x0xd daemon"]
async fn live_contacts_listable() {
    let Some(c) = client_or_skip().await else {
        return;
    };
    let contacts = c.contacts().list().await.expect("contacts");
    println!("contacts: {}", contacts.len());
}

#[tokio::test]
#[ignore = "requires a running x0xd daemon"]
async fn live_presence_online() {
    let Some(c) = client_or_skip().await else {
        return;
    };
    let online = c.presence().online().await.expect("presence");
    println!("online agents: {}", online.len());
}

#[tokio::test]
#[ignore = "requires a running x0xd daemon"]
async fn live_group_create_decodes() {
    let Some(c) = client_or_skip().await else {
        return;
    };
    let g = c
        .groups()
        .create("live-decode-probe", Some("me"))
        .await
        .expect("create");
    println!("created group {} ({:?})", g.group_id.0, g.name);
    // Clean up.
    c.groups().leave(&g.group_id).await.expect("leave");
}
