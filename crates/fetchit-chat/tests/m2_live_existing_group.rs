//! M2 live PQ private-group round-trip against a **pre-existing**
//! group. Skips the `create_private_group` + invite + `add_member`
//! orchestration that [`super::m2_live`]'s
//! `m2_live_private_group_round_trip` runs, picking up a group that
//! already exists on both daemons — e.g. the wyse37↔wyse21 group
//! produced by the M2.5 close-gate PASS at `aef27a0`.
//!
//! # What this empirically pins
//!
//! The test sends N sealed PQ chat messages into the supplied group,
//! waits for the peer's chat-peer to echo each one back, and asserts
//! the cleartext round-trips into local `Conversation.history`. The
//! sender exercises [`Endpoint::send_private_group`] (x0xd
//! `/secure/encrypt` + ML-DSA-65 envelope sign + per-recipient relay
//! fanout); the receiver exercises [`Client::receive_private_group_envelope`]
//! (ML-DSA verify + x0xd `/secure/decrypt` + history push).
//!
//! Round-trip implies BOTH ends hold MLS state for the group:
//!
//! - Local `secure.encrypt` succeeds → local has MLS state.
//! - Local `secure.decrypt` succeeds on the peer's echo → local has
//!   MLS state for the peer's epoch.
//! - The peer's echo arriving at all → peer's `secure.encrypt` worked
//!   → peer has MLS state.
//!
//! So a clean PASS implicitly verifies the `TreeKEM` Welcome flow
//! landed on both sides, even when we never directly observe the
//! Welcome event itself.
//!
//! If the run fails at `secure.encrypt` ("no MLS state for `group_id`"
//! or similar), local side never received the Welcome — the bridge
//! (a) reverse-flow is the structural fix.
//!
//! # Required env
//!
//! - `M2_LIVE_PEER_AGENT` — 64-hex `agent_id` of the peer (echoer).
//! - `M2_LIVE_PEER_SHARE_URI` — `x0x://agent/<base64>` for the peer.
//!   Imported into the hermetic `TempDir` vault before any send so
//!   `receive_private_group_envelope`'s sender-verify gate finds the
//!   card.
//! - `M2_LIVE_EXISTING_GROUP_ID` — 64-hex `group_id` of an already-
//!   established group on both daemons.
//! - `M2_LIVE_VAULT_PASS` — at-rest vault passphrase.
//! - `X0XD_PORT_FILE` / `X0XD_TOKEN_PATH` — optional, default to the
//!   systemd-rig paths.
//!
//! # How to run
//!
//! ```text
//! M2_LIVE_PEER_AGENT=<peer-hex> \
//! M2_LIVE_PEER_SHARE_URI='x0x://agent/<base64>' \
//! M2_LIVE_EXISTING_GROUP_ID='<64-hex group id>' \
//! M2_LIVE_VAULT_PASS=<test-passphrase> \
//!     cargo test -p fetchit-chat --test m2_live_existing_group \
//!         -- --ignored --nocapture
//! ```
//!
//! # Hermeticity
//!
//! Uses `tempfile::TempDir` for fetchit-chat's at-rest vault so
//! successive runs don't collide on cached cards. x0xd's MLS state
//! lives in x0xd's own data dir (independent of the `TempDir`) and IS
//! shared across runs by construction — that's the point: we're
//! validating an already-set-up group, not creating one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::groups::GroupId;
use fetchit_chat::Client;
use std::time::Duration;
use url::Url;

/// How many messages we send into the group. Matches the M2 live
/// scaffold's `MIN_HISTORY_FROM_BOB` so the echo-handler tuning
/// transfers between tests.
const MESSAGE_COUNT: usize = 5;

/// Production NY relay.
const RELAY_URL: &str = "http://67.207.94.66:8088";

/// Total time we wait for all peer echoes after the last send.
const ECHO_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for echoes.
const ECHO_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Inter-send spacing so the echo handler isn't slammed.
const SEND_SPACING: Duration = Duration::from_secs(1);

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

fn read_x0xd_base_url(port_file: &str) -> String {
    let raw = std::fs::read_to_string(port_file)
        .unwrap_or_else(|e| panic!("read x0xd port file at {port_file}: {e}"));
    x0xd_client::base_url_from_api_port_line(raw.trim())
}

#[tokio::test]
#[ignore = "M2 live PQ group-chat round-trip against existing group; requires peer rig + production relay"]
#[allow(clippy::too_many_lines)]
async fn m2_live_private_group_round_trip_existing_group() {
    let home = std::env::var("HOME").expect("HOME must be set");
    let port_file = env_or("X0XD_PORT_FILE", || {
        format!("{home}/.local/share/x0x-claude-here/api.port")
    });
    let token_path = env_or("X0XD_TOKEN_PATH", || {
        format!("{home}/.local/share/x0x-claude-here/api-token")
    });
    let peer_agent_hex = env_required("M2_LIVE_PEER_AGENT");
    let peer_share_uri = env_required("M2_LIVE_PEER_SHARE_URI");
    let group_id_str = env_required("M2_LIVE_EXISTING_GROUP_ID");
    let vault_pass = env_required("M2_LIVE_VAULT_PASS");

    assert_eq!(
        peer_agent_hex.len(),
        64,
        "M2_LIVE_PEER_AGENT must be 64 hex chars; got {}",
        peer_agent_hex.len()
    );
    assert!(
        peer_share_uri.starts_with("x0x://agent/"),
        "M2_LIVE_PEER_SHARE_URI must be x0x://agent/ URI",
    );
    assert_eq!(
        group_id_str.len(),
        64,
        "M2_LIVE_EXISTING_GROUP_ID must be 64 hex chars; got {}",
        group_id_str.len()
    );

    let base_url = read_x0xd_base_url(&port_file);
    let token = std::fs::read_to_string(&token_path)
        .unwrap_or_else(|e| panic!("read x0xd token at {token_path}: {e}"))
        .trim()
        .to_owned();
    let relay = Url::parse(RELAY_URL).expect("relay url parses");

    let data_dir = tempfile::TempDir::new().expect("tempdir");
    eprintln!("[m2-live-eg] data_dir = {}", data_dir.path().display());
    eprintln!("[m2-live-eg] x0xd     = {base_url}");
    eprintln!("[m2-live-eg] relay    = {relay}");
    eprintln!("[m2-live-eg] peer     = {peer_agent_hex}");
    eprintln!("[m2-live-eg] group    = {group_id_str}");

    let client = Client::builder()
        .base_url(base_url)
        .token(token)
        .relay_url(relay)
        .data_dir(data_dir.path().to_path_buf())
        .passphrase(vault_pass)
        .build()
        .await
        .expect("Client::build must succeed against live x0xd + relay");

    // Spawn the default inbound dispatcher BEFORE any send so the
    // peer's echoes get routed into Conversation.history. Mirrors
    // m2_live.rs's pre-send setup.
    let _dispatcher = client
        .spawn_default_dispatcher()
        .expect("relay transport must be wired and inbound channel must be takeable exactly once");

    let me = client.identity().me().await.expect("/agent must succeed");
    eprintln!("[m2-live-eg] local agent_id = {}", me.agent_id);

    // Persist the peer's share card so receive_private_group_envelope
    // can ML-DSA-verify their echo envelopes. Mirrors m2_live.rs.
    client
        .identity()
        .import_uri(&peer_share_uri)
        .await
        .expect("import peer share URI");
    let layout = client
        .layout()
        .expect("client built with data_dir must expose a layout");
    let stored = fetchit_chat::messages::StoredContactCard::from_share_uri(&peer_share_uri)
        .expect("peer share URI must parse as v2/v3 StoredContactCard");
    stored
        .save(layout)
        .expect("persist peer card to TempDir vault");
    eprintln!(
        "[m2-live-eg] imported peer card for {}",
        &peer_agent_hex[..8.min(peer_agent_hex.len())]
    );

    let group_id = GroupId::parse(&group_id_str).expect("group_id parses");

    // Confirm the local agent is already a member of the existing
    // group. If not, the user has the wrong M2_LIVE_EXISTING_GROUP_ID
    // or never joined; we surface the mismatch loudly rather than
    // failing silently at send-time on an MLS-state-missing error.
    let roster = client
        .groups()
        .members(&group_id)
        .await
        .expect("groups.members against existing group");
    let local_agent_lower = me.agent_id.0.to_ascii_lowercase();
    let peer_agent_lower = peer_agent_hex.to_ascii_lowercase();
    let has_self = roster
        .iter()
        .any(|m| m.0.eq_ignore_ascii_case(&local_agent_lower));
    let has_peer = roster
        .iter()
        .any(|m| m.0.eq_ignore_ascii_case(&peer_agent_lower));
    assert!(
        has_self,
        "local agent {local_agent_lower} not in group {group_id_str} roster; \
         current members: {roster:?}",
    );
    assert!(
        has_peer,
        "peer {peer_agent_lower} not in group {group_id_str} roster; \
         current members: {roster:?}",
    );
    eprintln!("[m2-live-eg] roster verified (self + peer present)");

    // Send N PQ-sealed messages. If local x0xd lacks MLS state for
    // this group (Welcome reverse-flow never landed), the FIRST
    // send_private_group surfaces an x0xd /secure/encrypt error here
    // — that's the empirical signal that the bridge (a) Welcome
    // reverse-flow is the required next step.
    let send_started_at = now_ms();
    for i in 0..MESSAGE_COUNT {
        let body = format!("m2-live-eg #{i} @ {}", now_ms());
        eprintln!("[m2-live-eg] send: {body}");
        let receipt = client
            .messages()
            .send_private_group(&group_id_str, &body, "alice")
            .await
            .expect(
                "send_private_group must succeed; \
                     if it errors with MLS state missing, local agent never received \
                     TreeKEM Welcome → bridge (a) reverse-flow is the required next step",
            );
        eprintln!("[m2-live-eg]   receipt_id = {receipt:?}");
        tokio::time::sleep(SEND_SPACING).await;
    }

    // Wait for the peer's echoes to round-trip into local
    // Conversation.history. Each echo is a PQ-sealed envelope the
    // peer's chat-peer produces via its echo handler
    // (peer.rs:312-324). secure.decrypt on the inbound side is the
    // implicit Welcome-applied check.
    eprintln!("[m2-live-eg] awaiting {MESSAGE_COUNT} echoes from {peer_agent_hex} (up to {ECHO_TIMEOUT:?})");
    let registry = client
        .registry_arc()
        .expect("client built with chat state must expose a ConversationRegistry");
    let echo_deadline = tokio::time::Instant::now() + ECHO_TIMEOUT;
    let mut last_count: usize = 0;
    loop {
        let conv = registry
            .get(&group_id_str)
            .await
            .expect("registry.get must succeed")
            .expect("conversation must exist after at least one send_private_group");
        let from_peer_after_send: Vec<_> = conv
            .history
            .iter()
            .filter(|entry| {
                entry
                    .sender_agent_id_hex
                    .eq_ignore_ascii_case(&peer_agent_lower)
                    && entry.ts_ms >= send_started_at
            })
            .collect();
        if from_peer_after_send.len() != last_count {
            eprintln!(
                "[m2-live-eg] from-peer entries: {}",
                from_peer_after_send.len()
            );
            last_count = from_peer_after_send.len();
        }
        if from_peer_after_send.len() >= MESSAGE_COUNT {
            eprintln!(
                "[m2-live-eg] ALL {MESSAGE_COUNT} echoes received — PQ group round-trip PASS",
            );
            for (i, entry) in from_peer_after_send.iter().enumerate() {
                eprintln!(
                    "[m2-live-eg]   echo[{i}]: ts_ms={} body={:?}",
                    entry.ts_ms, entry.body,
                );
            }
            return;
        }
        assert!(
            tokio::time::Instant::now() < echo_deadline,
            "echo timeout: received {last_count} from-peer entries in window, expected {MESSAGE_COUNT}. \
             If 0 echoes: peer's secure.decrypt is likely failing — peer never received \
             TreeKEM Welcome → bridge (a) reverse-flow is the required next step. \
             If partial: relay or chat-peer dropping mid-flight; check the chat-peer journal.",
        );
        tokio::time::sleep(ECHO_POLL_INTERVAL).await;
    }
}
