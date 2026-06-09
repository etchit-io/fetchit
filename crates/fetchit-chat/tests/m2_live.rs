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
//! - `M2_LIVE_PEER_SHARE_URI` — Bob's `x0x://agent/<base64>` v2/v3
//!   share card URI (REQUIRED). The test imports this into the
//!   hermetic `TempDir` vault before sending so
//!   `receive_private_group_envelope` can load Bob's
//!   `StoredContactCard` and ML-DSA-verify his echoes. Without it, the
//!   sender-verify step fails closed with `no card for envelope
//!   sender …` and Bob's echoes never reach `Conversation.history`.
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
//! M2_LIVE_PEER_SHARE_URI='x0x://agent/<base64>' \
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
//!   verify succeeds on his side; Alice imports Bob's card directly
//!   in-test by passing `M2_LIVE_PEER_SHARE_URI` (see env contract
//!   above).
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

/// How long the owner waits for the joiner to appear in `/members`
/// after minting the invite.
///
/// The Jun-8 joiner build enforces a hardcoded 60s convergence bound on
/// each `/groups/join` call with no flag to widen it, so one slow first
/// Welcome-pull (the ReaderExit tail) makes a single attempt bail. The
/// joiner hedges with a bounded retry-loop of up to ~8 attempts at 60s;
/// this owner-side budget covers that whole loop plus a final
/// convergence without masking a genuine wedge.
const JOIN_TIMEOUT: Duration = Duration::from_secs(600);

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

/// Read x0xd's `api.port` and return the normalised HTTP base URL.
///
/// Delegates to [`x0xd_client::base_url_from_api_port_line`] so this
/// scaffold, the `m2_publish_path_probe` example, and the production
/// `discover_in` path all share ONE definition of the file format. A
/// future change to what x0xd writes to `api.port` only has to land
/// in the discovery helper, not in three separate ad-hoc parsers.
fn read_x0xd_base_url(port_file: &str) -> String {
    let raw = std::fs::read_to_string(port_file)
        .unwrap_or_else(|e| panic!("read x0xd port file at {port_file}: {e}"));
    let line = raw.trim();
    assert!(!line.is_empty(), "malformed api.port at {port_file}: empty");
    x0xd_client::base_url_from_api_port_line(line)
}

#[tokio::test]
#[ignore = "M2 live cross-internet test; requires Box B chat-peer + echo handler. Run explicitly with --ignored. See test docstring for env contract."]
#[allow(clippy::too_many_lines)]
async fn m2_live_private_group_round_trip() {
    let home = std::env::var("HOME").expect("HOME must be set");

    let topology = std::env::var("FETCHIT_TEST_TOPOLOGY").unwrap_or_else(|_| "wyse".to_owned());

    let port_file = env_or("X0XD_PORT_FILE", || {
        format!("{home}/.local/share/x0x-claude-here/api.port")
    });
    let token_path = env_or("X0XD_TOKEN_PATH", || {
        format!("{home}/.local/share/x0x-claude-here/api-token")
    });
    let peer_agent_hex = env_required("M2_LIVE_PEER_AGENT");
    let peer_share_uri = env_required("M2_LIVE_PEER_SHARE_URI");
    let vault_pass = env_required("M2_LIVE_VAULT_PASS");
    let group_name = env_or("M2_LIVE_GROUP_NAME", || format!("m2-live-{}", now_ms()));

    tracing::info!(target: "m2_live", %topology, "soak round starting");

    assert_eq!(
        peer_agent_hex.len(),
        64,
        "M2_LIVE_PEER_AGENT must be 64 hex chars; got {} chars",
        peer_agent_hex.len()
    );
    assert!(
        peer_share_uri.starts_with("x0x://agent/"),
        "M2_LIVE_PEER_SHARE_URI must be an x0x://agent/ URI; got {} bytes",
        peer_share_uri.len()
    );

    let base_url = read_x0xd_base_url(&port_file);
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

    // Spawn the default inbound dispatcher BEFORE any send so Bob's
    // echoes (or any other relay-inbound) land in
    // `Conversation.history` instead of piling up on the relay
    // transport's mpsc until the test times out.
    //
    // Without this, `receive_private_group_envelope` is never called
    // and the `MIN_HISTORY_FROM_BOB` assertion at the bottom of the
    // test will trivially fail with `0 from-Bob entries` regardless of
    // Bob's echo handler being correct, regardless of join timing, and
    // regardless of card-import being in place. Discovered the hard
    // way during Round 2 (autopsy 2026-06-03): the cleanest fix is one
    // helper on `Client` that mirrors `peer.rs::decode_inbound`'s
    // routing logic — `is_private_group_envelope` → x0xd
    // `/secure/decrypt`; else → legacy `dispatch_inbound`.
    let _dispatcher = client
        .spawn_default_dispatcher()
        .expect("relay transport must be wired and inbound channel must be takeable exactly once");

    let me = client.identity().me().await.expect("/agent must succeed");
    eprintln!("[m2-live] local agent_id = {}", me.agent_id);

    // Write owner's share URI so the joiner can pre-import it before
    // /groups/join. Without this, the joiner has no card for the owner
    // and inbound sender-verify fails with "no card for envelope sender
    // <owner-hex>" on every PrivateGroupChat envelope. Matches the
    // out-of-band "manual prep" step the original Box A<->Box B rig
    // relied on; formalising it here so the wyse21<->wyse37 harness
    // converges symmetrically without a human-in-the-loop card swap.
    let owner_uri = client
        .identity()
        .extended_share_uri("alice")
        .await
        .expect("extended_share_uri");
    let owner_uri_path = std::env::var("M2_LIVE_OWNER_SHARE_URI")
        .unwrap_or_else(|_| "/tmp/m2-live-owner-share-uri.txt".to_string());
    std::fs::write(&owner_uri_path, &owner_uri)
        .unwrap_or_else(|e| panic!("write owner share uri to {owner_uri_path}: {e}"));
    eprintln!("[m2-live] owner share URI written to {owner_uri_path}");
    eprintln!(
        "[m2-live] Joiner-side: pass --owner-card-uri-file {owner_uri_path} to chat-peer join"
    );

    // Import Bob's share card into the hermetic TempDir vault. Without
    // this, `receive_private_group_envelope` fails closed on
    // `StoredContactCard::load(layout, sender) == None` for every echo
    // Bob sends, so his replies never reach `Conversation.history`.
    // Mirrors `peer.rs::run_import` — the same code path the real shell
    // uses — so the test exercises the production import flow rather
    // than constructing a card by hand.
    client
        .identity()
        .import_uri(&peer_share_uri)
        .await
        .expect("import Bob's share URI into x0xd's /cards");
    let layout = client
        .layout()
        .expect("client built with data_dir must expose a layout");
    let stored = fetchit_chat::messages::StoredContactCard::from_share_uri(&peer_share_uri)
        .expect("Bob's share URI must parse as v2/v3 StoredContactCard");
    stored
        .save(layout)
        .expect("persist Bob's card to TempDir vault");
    eprintln!(
        "[m2-live] imported peer card for {}",
        &peer_agent_hex[..8.min(peer_agent_hex.len())]
    );

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

    // Mint the invite. The joiner's chat-peer (running
    // `Mode::Join --invite-file <path>`) reads this and calls
    // `Client::groups().join(invite)` on the other box, which drives
    // the daemon's `/groups/join` -> Welcome-fetch path. That is the
    // surface David's v0.21.3 `63b5c63` retry-fix patches; the earlier
    // `add_member`-driven flow we replaced here bypassed it entirely
    // and so never actually exercised the fix.
    let invite = client
        .groups()
        .invite(&group_id)
        .await
        .expect("groups.invite");
    eprintln!("[m2-live] >>> INVITE <<<");
    eprintln!("[m2-live] {}", invite.0);
    eprintln!("[m2-live] >>> END INVITE <<<");

    // Write the invite to a file that the joiner's chat-peer (running
    // `Mode::Join --invite-file <path>` on the other box) reads to
    // drive `/groups/join`. The default `/tmp/m2-live-invite.json`
    // path matches the wyse21<->wyse37 empirical's scp pipeline; the
    // env-var override exists for ad-hoc reruns on a different rig.
    let invite_path = std::env::var("M2_LIVE_INVITE_FILE")
        .unwrap_or_else(|_| "/tmp/m2-live-invite.json".to_string());
    std::fs::write(&invite_path, &invite.0)
        .unwrap_or_else(|e| panic!("write invite to {invite_path}: {e}"));
    eprintln!("[m2-live] invite written to {invite_path}");
    eprintln!("[m2-live] WAITING_FOR_JOINER_JOIN <<<");
    eprintln!(
        "[m2-live] Joiner-side action required: run `chat-peer ... join --invite-file {invite_path}`"
    );

    // Poll the live roster via x0xd until member_count >= 2. The
    // joiner's bounded `/groups/join` retry-loop lands them via gossip
    // catch-up, which the owner observes through /members. Each join
    // attempt has a hardcoded 60s convergence bound on the joiner box,
    // so a slow first Welcome-pull bails one attempt; the retry-loop
    // re-fires until it converges or exhausts its budget, at which point
    // this loop times out with the diagnostic below.
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
            assert!(
                members.iter().any(|m| m.0 == peer_agent_hex),
                "expected peer {peer_agent_hex} in roster but got {members:?}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < join_deadline,
            "joiner ({peer_agent_hex}) did not appear in /members for group {group_id_hex} within {JOIN_TIMEOUT:?}; the joiner's bounded join retry-loop likely exhausted against a persistent gossip or Welcome-fetch wedge",
        );
        tokio::time::sleep(JOIN_POLL_INTERVAL).await;
    }
    eprintln!("[m2-live] joiner converged; proceeding to message round-trip");

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

#[test]
fn topology_defaults_to_wyse_when_env_unset() {
    std::env::remove_var("FETCHIT_TEST_TOPOLOGY");
    let topology = std::env::var("FETCHIT_TEST_TOPOLOGY").unwrap_or_else(|_| "wyse".to_owned());
    assert_eq!(topology, "wyse");
}
