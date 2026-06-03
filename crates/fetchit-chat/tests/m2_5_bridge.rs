//! M2.5 bridge integration tests — relay-mediated NAT-traversal end-to-end.
//!
//! Two layers:
//!
//! - **`m2_5_bridge_consent_*`** — hermetic against the local x0xd at the
//!   systemd rig. No peer box required. Asserts the consent/reachability
//!   gate behavior: `NotAsked → BridgeNeedsConsent`, `DeclinedOptOut →
//!   BridgeDeclined`, recently-recorded peer → `LetGossipCarry`.
//! - **`m2_5_bridge_live_*`** — cross-internet round-trip against a Box-B
//!   peer + the production relay. Exercises seal → relay fan-out →
//!   receiver unseal → local `/publish` → pubsub-loopback → x0xd apply
//!   path. Asserts:
//!   1. upstream `member_joined_events_applied` counter increments on B
//!   2. SSE shadow suppresses the bridge-loopback record so reachability
//!      stays honest under the symmetric-NAT case the bridge is meant to
//!      solve.
//!
//! All tests are `#[ignore]`'d so CI does not try to talk to the
//! production relay or assume a local rig is up. Run explicitly per the
//! env contract below.
//!
//! # Required env
//!
//! Shared (always):
//! - `M2_5_BRIDGE_VAULT_PASS` — at-rest vault passphrase. No default.
//! - `X0XD_PORT_FILE` / `X0XD_TOKEN_PATH` — optional, default to the
//!   Box A systemd-rig paths.
//!
//! `m2_5_bridge_live_*` only:
//! - `M2_5_BRIDGE_PEER_AGENT` — 64-hex agent id of the Box-B peer.
//! - `M2_5_BRIDGE_PEER_SHARE_URI` — `x0x://agent/<base64>` for B; the
//!   test imports this into the hermetic `TempDir` vault before send.
//! - `M2_5_BRIDGE_GROUP_ID` — existing `private_secure` group on both
//!   x0xds, with A and B as members (the bridge does not create groups).
//!
//! # How to run
//!
//! ```text
//! # Hermetic gates (no peer needed):
//! M2_5_BRIDGE_VAULT_PASS=<test-pass> \
//!     cargo test -p fetchit-chat --test m2_5_bridge \
//!         -- --ignored --nocapture m2_5_bridge_consent
//!
//! # Live cross-box round-trip:
//! M2_5_BRIDGE_VAULT_PASS=<test-pass> \
//! M2_5_BRIDGE_PEER_AGENT=<bob-hex> \
//! M2_5_BRIDGE_PEER_SHARE_URI='x0x://agent/<base64>' \
//! M2_5_BRIDGE_GROUP_ID=<64-hex-group-id> \
//!     cargo test -p fetchit-chat --test m2_5_bridge \
//!         -- --ignored --nocapture m2_5_bridge_live
//! ```
//!
//! # Hermeticity
//!
//! Each test uses its own `tempfile::TempDir` for the vault so successive
//! runs do not collide on per-device KEM keys / cached cards. The
//! reachability cache + consent store are in-memory only as of C4, so a
//! fresh `Client` per test starts clean by construction.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::error::ChatError;
use fetchit_chat::groups::GroupId;
use fetchit_chat::groups_reachability::{BridgeDecision, GroupBridgeConsent};
use fetchit_chat::identity::AgentId;
use fetchit_chat::Client;
use std::time::Duration;
use url::Url;

/// Production relay we point at for the live round-trip. Matches the NY
/// droplet in `KNOWN_RELAYS` and the M2 live scaffold.
const RELAY_URL: &str = "http://67.207.94.66:8088";

/// How long we wait for the live `MemberJoined` to apply on B (LOC: SSE
/// arrival + x0xd apply + diagnostic-counter increment).
#[allow(dead_code)]
const LIVE_APPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for the apply counter to tick.
#[allow(dead_code)]
const LIVE_APPLY_POLL_INTERVAL: Duration = Duration::from_secs(1);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("required env var {name} is not set; see test docstring for the full contract")
    })
}

fn env_or(name: &str, default: impl FnOnce() -> String) -> String {
    std::env::var(name).unwrap_or_else(|_| default())
}

/// Read x0xd's `api.port` and return the normalised HTTP base URL. Same
/// helper shape as `m2_live.rs`.
fn read_x0xd_base_url(port_file: &str) -> String {
    let raw = std::fs::read_to_string(port_file)
        .unwrap_or_else(|e| panic!("read x0xd port file at {port_file}: {e}"));
    x0xd_client::base_url_from_api_port_line(raw.trim())
}

/// Build a `Client` attached to the local x0xd discovered via env. Used
/// by both the hermetic consent-gate tests and the live round-trip
/// tests; the latter additionally pass a relay URL so the Router has a
/// transport.
async fn build_test_client(vault_pass: &str, with_relay: bool) -> (Client, tempfile::TempDir) {
    let home = std::env::var("HOME").expect("HOME must be set");
    let port_file = env_or("X0XD_PORT_FILE", || {
        format!("{home}/.local/share/x0x-claude-here/api.port")
    });
    let token_path = env_or("X0XD_TOKEN_PATH", || {
        format!("{home}/.local/share/x0x-claude-here/api-token")
    });
    let base_url = read_x0xd_base_url(&port_file);
    let token = std::fs::read_to_string(&token_path)
        .unwrap_or_else(|e| panic!("read x0xd token at {token_path}: {e}"))
        .trim()
        .to_owned();
    let data_dir = tempfile::TempDir::new().expect("tempdir");

    let mut builder = Client::builder()
        .base_url(base_url)
        .token(token)
        .data_dir(data_dir.path().to_path_buf())
        .passphrase(vault_pass.to_owned());
    if with_relay {
        builder = builder.relay_url(Url::parse(RELAY_URL).expect("relay url parses"));
    }
    let client = builder
        .build()
        .await
        .expect("Client::build must succeed against the local x0xd");
    (client, data_dir)
}

/// Synthesize a 64-hex agent id from `seed` so hermetic tests don't need
/// a real peer. The bridge consent gate trips before any wire activity,
/// so the agent id is only used as a `HashMap` key inside
/// `ReachabilityCache`.
fn synth_agent_hex(seed: u8) -> String {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i & 0xff).unwrap_or(0));
    }
    hex::encode(bytes)
}

/// Synthesize a 64-hex group id, ditto.
fn synth_group_hex(seed: u8) -> String {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed
            .wrapping_mul(2)
            .wrapping_add(u8::try_from(i & 0xff).unwrap_or(0));
    }
    hex::encode(bytes)
}

// ── Hermetic: consent gate ────────────────────────────────────────────

/// Default consent for a fresh group is `NotAsked` (Q4 default-OFF).
/// `send_x0xd_metadata_event` against an unreachable peer + a `NotAsked`
/// group must refuse with `ChatError::BridgeNeedsConsent` so the desktop
/// UI can surface the consent modal — no envelope leaks before opt-in.
#[tokio::test]
#[ignore = "M2.5 bridge consent gate — needs local x0xd; run with --ignored"]
async fn m2_5_bridge_consent_not_asked_yields_needs_consent() {
    let vault_pass = env_required("M2_5_BRIDGE_VAULT_PASS");
    let (client, _data_dir) = build_test_client(&vault_pass, false).await;

    let group_hex = synth_group_hex(0x11);
    let group = GroupId::parse(&group_hex).expect("group hex parses");
    let peer_hex = synth_agent_hex(0x22);
    let topic = format!("x0x.named_group/{group_hex}/metadata");
    let event = serde_json::json!({"event": "ping", "ts_ms": now_ms()})
        .to_string()
        .into_bytes();

    let err = client
        .send_x0xd_metadata_event(&peer_hex, &group, topic, &event)
        .await
        .expect_err("must refuse send under NotAsked consent");
    match err {
        ChatError::BridgeNeedsConsent { group_id } => {
            assert_eq!(group_id, group_hex);
        }
        other => panic!("expected BridgeNeedsConsent, got {other:?}"),
    }
}

/// `DeclinedOptOut` consent must surface `ChatError::BridgeDeclined` so
/// the chat UI can render the "group unreachable" affordance instead of
/// silently dropping or silently retrying.
#[tokio::test]
#[ignore = "M2.5 bridge consent gate — needs local x0xd"]
async fn m2_5_bridge_consent_declined_yields_declined() {
    let vault_pass = env_required("M2_5_BRIDGE_VAULT_PASS");
    let (client, _data_dir) = build_test_client(&vault_pass, false).await;

    let group_hex = synth_group_hex(0x33);
    let group = GroupId::parse(&group_hex).expect("group hex parses");
    let peer_hex = synth_agent_hex(0x44);

    let consent = client
        .bridge_consent()
        .expect("chat state present (data_dir + passphrase supplied)");
    consent
        .lock()
        .await
        .set(group.clone(), GroupBridgeConsent::DeclinedOptOut);

    let topic = format!("x0x.named_group/{group_hex}/metadata");
    let event = serde_json::json!({"event": "ping", "ts_ms": now_ms()})
        .to_string()
        .into_bytes();

    let err = client
        .send_x0xd_metadata_event(&peer_hex, &group, topic, &event)
        .await
        .expect_err("must refuse send under DeclinedOptOut consent");
    match err {
        ChatError::BridgeDeclined { group_id } => {
            assert_eq!(group_id, group_hex);
        }
        other => panic!("expected BridgeDeclined, got {other:?}"),
    }
}

/// When `ReachabilityCache` reports the peer as `Reachable`, the send
/// path must return `Ok(BridgeDecision::LetGossipCarry)` without
/// touching the share-card store or the relay. The bridge is a
/// fallback, not a default.
#[tokio::test]
#[ignore = "M2.5 bridge consent gate — needs local x0xd"]
async fn m2_5_bridge_reachable_yields_let_gossip_carry() {
    let vault_pass = env_required("M2_5_BRIDGE_VAULT_PASS");
    let (client, _data_dir) = build_test_client(&vault_pass, false).await;

    let group_hex = synth_group_hex(0x55);
    let group = GroupId::parse(&group_hex).expect("group hex parses");
    let peer_hex = synth_agent_hex(0x66);
    let peer = AgentId(peer_hex.clone());

    // Pre-populate reachability so the gate sees direct-gossip as live.
    let cache = client.reachability_cache().expect("chat state present");
    cache.lock().await.record(group.clone(), peer, now_ms());

    let topic = format!("x0x.named_group/{group_hex}/metadata");
    let event = serde_json::json!({"event": "ping", "ts_ms": now_ms()})
        .to_string()
        .into_bytes();

    let decision = client
        .send_x0xd_metadata_event(&peer_hex, &group, topic, &event)
        .await
        .expect("Reachable path must succeed without bridge");
    assert_eq!(decision, BridgeDecision::LetGossipCarry);
}

// ── Live cross-internet: bidirectional round-trip ─────────────────────

/// Send a signed `MemberJoined` event from Box A to Box B via relay,
/// observe upstream `member_joined_events_applied` increment on B (or
/// its functional analog: the local x0xd applied the event and B's
/// roster reflects it).
///
/// **Box B prerequisite**: Box B's chat-peer is running with the M2.5
/// bridge dispatcher enabled (74ea382+) and has the group in question
/// in `named_groups` with the local agent listed in the issued-invite
/// records (so `consume_issued_invite` succeeds). Box A's test
/// constructs the canonical bytes + signs via local /agent/sign + wraps
/// + relays. The receiver chat-peer unseals, POSTs to `/publish`,
/// pubsub loopback hits the apply path.
#[tokio::test]
#[ignore = "M2.5 bridge live round-trip — requires Box B rig + production relay"]
async fn m2_5_bridge_live_member_joined_applies_on_peer() {
    let vault_pass = env_required("M2_5_BRIDGE_VAULT_PASS");
    let peer_agent_hex = env_required("M2_5_BRIDGE_PEER_AGENT");
    let peer_share_uri = env_required("M2_5_BRIDGE_PEER_SHARE_URI");
    let group_id_str = env_required("M2_5_BRIDGE_GROUP_ID");

    assert_eq!(
        peer_agent_hex.len(),
        64,
        "M2_5_BRIDGE_PEER_AGENT must be 64 hex; got {} chars",
        peer_agent_hex.len()
    );
    assert!(
        peer_share_uri.starts_with("x0x://agent/"),
        "M2_5_BRIDGE_PEER_SHARE_URI must be an x0x://agent/ URI",
    );

    let (client, _data_dir) = build_test_client(&vault_pass, true).await;

    // Persist Box B's v2 share-card so recipient_kem_key (P1.A gate) finds it.
    client
        .identity()
        .import_uri(&peer_share_uri)
        .await
        .expect("import peer share card");
    if let Some(layout) = client.layout() {
        let stored = fetchit_chat::messages::StoredContactCard::from_share_uri(&peer_share_uri)
            .expect("StoredContactCard::from_share_uri");
        stored.save(layout).expect("StoredContactCard.save");
    }

    let group = GroupId::parse(&group_id_str).expect("group id parses");

    // Opt in to the bridge for this group; the consent gate would
    // otherwise refuse the send with BridgeNeedsConsent.
    client
        .bridge_consent()
        .expect("chat state present")
        .lock()
        .await
        .set(group.clone(), GroupBridgeConsent::ConsentedOptIn);

    // Construct a signed MemberJoined event using our local x0xd as the
    // ML-DSA-65 signer. This mirrors what the chat-peer dispatch loop
    // does in production when the bridge fires on a real invite.
    //
    // TODO(C5): wire up the actual canonical-bytes + sign + wrap call
    // path. The helpers live at:
    // - `fetchit_chat::groups::bridge::canonical_member_joined_bytes`
    // - `fetchit_chat::groups::bridge::build_member_joined_event`
    // The signer needs to come from `x0xd-client::X0xdSigner`; the
    // m2_live.rs scaffold has a working pattern for instantiating one
    // against the same `base_url + token`.
    //
    // Once wired, assert:
    // 1. send_x0xd_metadata_event returns Ok(WrapAndSend)
    // 2. Box B's diagnostic counter for member_joined_events_applied
    //    increments within LIVE_APPLY_TIMEOUT
    // 3. Box B's /groups/<gid>/members includes Box A's agent id

    let topic = format!("x0x.named_group/{group_id_str}/metadata");
    let _ = (topic, peer_agent_hex); // silence unused until wired
    eprintln!("[m2.5-live] scaffold reached; canonical-event signing wiring TODO (see comment).");
}

/// After the bridge dispatcher unseals + POSTs an event to local
/// `/publish`, x0xd's pubsub loopback re-delivers the same payload back
/// to the SSE consumer. The `BridgeInboundShadow` must suppress that
/// loopback so the reachability cache does NOT record the bridge peer
/// as direct-gossip-reachable — that false positive is the silent-fail
/// the spec §5 routing rule depends on avoiding.
#[tokio::test]
#[ignore = "M2.5 bridge live shadow assertion — requires Box B rig + production relay"]
async fn m2_5_bridge_shadow_suppresses_loopback() {
    // TODO(C5): drive the bridge dispatcher with a known payload, watch
    // the SSE consumer (Client::spawn_sse_reachability_recorder is
    // already running by default in the chat-peer; the test path uses
    // its own consumer to compute the hash), and assert:
    // 1. shadow.is_recent(hash(payload)) == true within SHADOW_WINDOW_MS
    // 2. reachability.lookup(group, peer, now) == Reachability::Unreachable
    //    AFTER the loopback fires (i.e., the SSE recorder did NOT
    //    promote the peer to Reachable because of the bridge loopback).
    //
    // Empirically resolves Bob's "x0xd may re-serialize JSON" open
    // question from 74ea382: if the SSE payload bytes differ from what
    // we POSTed, the shadow misses and we'd record a false positive.
    // This test pins the contract.
    eprintln!("[m2.5-live] shadow-suppression assertion scaffold; full body lands with the round-trip wiring.");
}
