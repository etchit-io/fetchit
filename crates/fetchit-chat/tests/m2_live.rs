//! M2 live cross-internet integration: Alice (this box) <-> NY relay <->
//! Bob (peer box). Exercises the full private-group round-trip end-to-
//! end against a real x0xd, the production relay at
//! `http://67.207.94.66:8088`, and Bob's chat-peer rig acting as the
//! second member.
//!
//! Scaffold lands here; Task 16 actually runs it three times in a 24h
//! window once Bob has wired an "echo into the same group" handler into
//! his chat-peer rig. With Task 12's per-recipient fanout, ML-DSA
//! verify, replay/dedup gate, `push_history`, self-source filter, and the
//! lazy Conversation creation on receive, this round-trip is meaningful
//! for the first time.
//!
//! # Required env at runtime
//!
//! - `M2_LIVE_PEER_AGENT` — Bob's 64-hex `agent_id` (REQUIRED, no
//!   sensible default).
//! - `M2_LIVE_VAULT_PASS` — at-rest vault passphrase (REQUIRED; the
//!   test refuses to invent a default so a stale on-disk vault doesn't
//!   get silently unlocked under a sentinel value).
//! - `M2_LIVE_GROUP_NAME` — optional; defaults to `m2-live-<epoch_ms>`
//!   so successive runs don't collide on Bob's roster.
//! - `X0XD_PORT_FILE` — optional; defaults to
//!   `$HOME/.local/share/x0x-claude-here/api.port` (the systemd rig).
//! - `X0XD_TOKEN_PATH` — optional; defaults to
//!   `$HOME/.local/share/x0x-claude-here/api-token`.
//!
//! # How to run
//!
//! ```text
//! M2_LIVE_PEER_AGENT=<bob-hex> \
//! M2_LIVE_VAULT_PASS=<test-passphrase> \
//!     cargo test -p fetchit-chat --test m2_live \
//!         -- --ignored --nocapture
//! ```
//!
//! # Pre-requisites
//!
//! - Box A's `x0xd-claude-here.service` and
//!   `fetchit-chat-peer-claude.service` both active.
//! - Box B running an equivalent rig PLUS an "echo any message
//!   received in the group back into the same group" handler in his
//!   chat-peer (Task 16 wires this).
//! - Bob has imported Alice's v2/v3 share card so envelope-signature
//!   verify succeeds on his side; Alice imports Bob's card via the
//!   normal pairing flow before this test runs (today: pasted by hand,
//!   pending automation).
//!
//! # Hermeticity
//!
//! Uses `tempfile::TempDir` for the vault and a timestamp-tagged group
//! name per run so Box A's persistent state stays clean. The `TempDir`
//! drop tears down the on-disk vault; the relay session ends when the
//! `Client` is dropped at the end of the test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::groups::GroupId;
use fetchit_chat::Client;
use std::time::Duration;
use url::Url;

/// Minimum history entries expected from Bob's echo handler. We send 5,
/// Bob's echo handler in Task 16 reflects each one back into the same
/// group, so 5 inbound entries from Bob should land in Alice's local
/// conversation history. If Task 16's echo handler isn't wired yet, the
/// run will fail this assertion with a clear delta — that's the point:
/// the scaffold pins the contract.
const MIN_HISTORY_FROM_BOB: usize = 5;

/// Relay we point at; matches the production NY droplet.
const RELAY_URL: &str = "http://67.207.94.66:8088";

/// How long we wait for Bob to join after we mint the invite.
const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Poll interval while waiting for Bob's join.
const JOIN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long we wait, after sending the last message, for Bob's echoes
/// to round-trip back into our local conversation history.
const ECHO_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for Bob's echoes.
const ECHO_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Inter-send delay so Bob's echo handler isn't racing five inbound
/// envelopes in the same tick.
const SEND_SPACING: Duration = Duration::from_secs(1);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn env_or(name: &str, default: impl FnOnce() -> String) -> String {
    std::env::var(name).unwrap_or_else(|_| default())
}

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("required env var {name} is not set; see test docstring for the full contract")
    })
}

/// Read `127.0.0.1:<port>` (or bare `<port>`) from x0xd's `api.port`,
/// return just the port as a string. Matches the parse the
/// `m2_publish_path_probe` example uses.
fn read_x0xd_port(port_file: &str) -> String {
    let raw = std::fs::read_to_string(port_file)
        .unwrap_or_else(|e| panic!("read x0xd port file at {port_file}: {e}"));
    let line = raw.trim();
    // x0xd may emit `host:port` (systemd rig) or bare `port`.
    line.rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| panic!("malformed api.port at {port_file}: {line:?}"))
        .to_owned()
}

#[tokio::test]
#[ignore = "M2 live cross-internet test; requires Box B chat-peer + echo handler. Run explicitly with --ignored. See test docstring for env contract."]
#[allow(clippy::too_many_lines)]
async fn m2_live_private_group_round_trip() {
    let home = std::env::var("HOME").expect("HOME must be set");

    let port_file = env_or("X0XD_PORT_FILE", || {
        format!("{home}/.local/share/x0x-claude-here/api.port")
    });
    let token_path = env_or("X0XD_TOKEN_PATH", || {
        format!("{home}/.local/share/x0x-claude-here/api-token")
    });
    let peer_agent_hex = env_required("M2_LIVE_PEER_AGENT");
    let vault_pass = env_required("M2_LIVE_VAULT_PASS");
    let group_name = env_or("M2_LIVE_GROUP_NAME", || format!("m2-live-{}", now_ms()));

    assert_eq!(
        peer_agent_hex.len(),
        64,
        "M2_LIVE_PEER_AGENT must be 64 hex chars; got {} chars",
        peer_agent_hex.len()
    );

    let port = read_x0xd_port(&port_file);
    let base_url = format!("http://127.0.0.1:{port}");
    let token = std::fs::read_to_string(&token_path)
        .unwrap_or_else(|e| panic!("read x0xd token at {token_path}: {e}"))
        .trim()
        .to_owned();
    let relay = Url::parse(RELAY_URL).expect("relay url parses");

    // TempDir so the vault + conversation registry are hermetic and the
    // test doesn't pollute Box A's persistent state.
    let data_dir = tempfile::TempDir::new().expect("tempdir");
    eprintln!("[m2-live] data_dir = {}", data_dir.path().display());
    eprintln!("[m2-live] x0xd     = {base_url}");
    eprintln!("[m2-live] relay    = {relay}");
    eprintln!("[m2-live] peer     = {peer_agent_hex}");
    eprintln!("[m2-live] group    = {group_name}");

    let client = Client::builder()
        .base_url(base_url)
        .token(token)
        .relay_url(relay)
        .data_dir(data_dir.path().to_path_buf())
        .passphrase(vault_pass)
        .build()
        .await
        .expect("Client::build must succeed against live x0xd + relay");

    let me = client.identity().me().await.expect("/agent must succeed");
    eprintln!("[m2-live] local agent_id = {}", me.agent_id);

    // Create the private group + seed the local Conversation in one
    // step. The bare `groups::create_private` would skip the seed and
    // leave send_private_group with nowhere to record history.
    let group = client
        .messages()
        .create_private_group(&group_name, Some("alice"))
        .await
        .expect("create_private_group");
    let group_id = group.group_id.clone();
    let group_id_hex = group_id.as_str().to_owned();
    eprintln!("[m2-live] group_id = {group_id_hex}");

    // Mint the invite. Bob pastes this manually in Task 15; Task 16
    // automates the handshake via the chat-pipe.
    let invite = client
        .groups()
        .invite(&group_id)
        .await
        .expect("groups.invite");
    eprintln!("[m2-live] >>> INVITE <<<");
    eprintln!("[m2-live] {}", invite.0);
    eprintln!("[m2-live] >>> END INVITE <<<");

    // Wait for Bob to join. We poll the live roster via x0xd until
    // member_count >= 2 (Alice + Bob).
    let join_deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
    loop {
        let members = client
            .groups()
            .members(&group_id)
            .await
            .expect("groups.members");
        eprintln!(
            "[m2-live] roster size = {} ({:?})",
            members.len(),
            members.iter().map(|m| &m.0).collect::<Vec<_>>()
        );
        if members.len() >= 2 {
            // Sanity-check Bob actually showed up under the expected id.
            assert!(
                members.iter().any(|m| m.0 == peer_agent_hex),
                "expected peer {peer_agent_hex} in roster but got {members:?}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < join_deadline,
            "Bob ({peer_agent_hex}) did not join group {group_id_hex} within {JOIN_TIMEOUT:?}",
        );
        tokio::time::sleep(JOIN_POLL_INTERVAL).await;
    }
    eprintln!("[m2-live] roster has Bob; sending payload");

    // Send 5 messages, spaced so Bob's echo handler isn't slammed.
    let send_started_at = now_ms();
    for i in 0..MIN_HISTORY_FROM_BOB {
        let body = format!("m2-live #{i}");
        eprintln!("[m2-live] send: {body}");
        let receipt = client
            .messages()
            .send_private_group(&group_id_hex, &body, "alice")
            .await
            .expect("send_private_group");
        eprintln!("[m2-live]   receipt_id = {receipt:?}");
        tokio::time::sleep(SEND_SPACING).await;
    }

    // Wait for Bob's echoes to land in our local conversation history.
    // The transport inbound pump on the relay drives
    // `receive_private_group_envelope`, which pushes onto
    // `Conversation.history` for any envelope where the sender is not
    // self. We count how many history entries have arrived FROM BOB
    // since send_started_at — that filter rejects any pre-existing
    // entries (there shouldn't be any in a TempDir vault, but be
    // defensive) and any self-echoes (impossible after Task 12's
    // self-source filter, but again defensive).
    let registry = client.registry_arc().expect("registry");
    let echo_deadline = tokio::time::Instant::now() + ECHO_TIMEOUT;
    let mut last_seen = 0usize;
    loop {
        let conv = registry
            .get(&group_id_hex)
            .await
            .expect("registry.get")
            .expect("conversation seeded by create_private_group");
        let from_bob: Vec<_> = conv
            .history
            .iter()
            .filter(|e| e.sender_agent_id_hex == peer_agent_hex && e.ts_ms >= send_started_at)
            .collect();
        if from_bob.len() != last_seen {
            eprintln!(
                "[m2-live] history from Bob so far: {} entries (total conv.history = {})",
                from_bob.len(),
                conv.history.len()
            );
            last_seen = from_bob.len();
        }
        if from_bob.len() >= MIN_HISTORY_FROM_BOB {
            eprintln!(
                "[m2-live] OK — received {} echoes from Bob (>= MIN_HISTORY_FROM_BOB={})",
                from_bob.len(),
                MIN_HISTORY_FROM_BOB
            );
            return;
        }
        let from_bob_len = from_bob.len();
        let total = conv.history.len();
        assert!(
            tokio::time::Instant::now() < echo_deadline,
            "expected >= {MIN_HISTORY_FROM_BOB} echoes from Bob within {ECHO_TIMEOUT:?}; got {from_bob_len} (total conv.history = {total}). \
             If Bob's echo handler is not wired yet, this assertion is the contract: Task 16 wires it.",
        );
        tokio::time::sleep(ECHO_POLL_INTERVAL).await;
    }
}

/// Compile-time sanity that `GroupId` round-trips through `parse` —
/// catches a wire-shape drift on Bob's side without needing the network.
/// Cheap, runs as part of the default `cargo test` since it's not
/// `#[ignore]`'d; pins that this test file compiles against the same
/// `groups` API the live path uses.
#[test]
fn group_id_round_trips_for_documentation() {
    let hex = "a".repeat(64);
    let id = GroupId::parse(&hex).expect("64-hex parses");
    assert_eq!(id.as_str(), hex);
}
