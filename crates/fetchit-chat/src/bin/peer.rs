//! `fetchit-chat-peer` — headless chat peer for testing.
//!
//! Drives `fetchit_chat::Client` against a local x0xd + a relay, with
//! no GUI. Four modes:
//!
//! - `echo` — auto-echo every inbound DM back to its sender. Useful
//!   for confirming relay round-trips from a different machine without
//!   needing a human at the keyboard.
//! - `chat` — interactive: stdin lines are sent to a configured peer,
//!   inbound DMs printed to stdout. Like a tiny CLI chat client.
//! - `card` — print this peer's share URI (so the other side can
//!   import it) and exit.
//! - `import` — read a peer's share URI from a file (the v2 form is
//!   ~12 KB, too large for a CLI arg) and add it to the local contact
//!   store. Required before `chat` can encrypt to that peer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_errors_doc
)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fetchit_chat::conversation::{dispatch_inbound, InboundDispatch};
use fetchit_chat::identity::AgentId;
use fetchit_chat::messages::decode_direct_message;
use fetchit_chat::transport::InboundEnvelope;
use fetchit_chat::Client;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;

/// Decoded inbound suitable for the peer to display + reply to.
struct PeerInbound {
    from: AgentId,
    body: String,
}

#[derive(Parser, Debug)]
#[command(name = "fetchit-chat-peer", version, about)]
struct Cli {
    /// x0xd HTTP base URL (e.g. `http://127.0.0.1:12700`).
    #[arg(
        long,
        env = "FETCHIT_X0XD_BASE",
        default_value = "http://127.0.0.1:12700"
    )]
    x0xd_base: String,

    /// x0xd API token (read from this path if not supplied directly).
    #[arg(long, env = "FETCHIT_X0XD_TOKEN")]
    x0xd_token: Option<String>,

    /// Path to read the API token from when `--x0xd-token` is not set.
    #[arg(long, default_value = "/root/.local/share/x0x/api-token")]
    x0xd_token_path: String,

    /// Relay base URL (e.g. `http://67.207.94.66:8088`).
    #[arg(
        long,
        env = "FETCHIT_RELAY_URL",
        default_value = "http://67.207.94.66:8088"
    )]
    relay: Url,

    /// Display name presented on outbound messages.
    #[arg(long, default_value = "Peer")]
    display_name: String,

    /// Where to keep the at-rest vault (identity, conversations, contacts).
    #[arg(long, default_value = "/opt/alice/fetchit-data")]
    data_dir: PathBuf,

    /// Argon2id passphrase for the at-rest vault on headless installs
    /// (no OS keystore). Set via the `FETCHIT_PASSPHRASE` env var only —
    /// avoid CLI literals so the secret doesn't appear in /proc/cmdline
    /// or shell history. For systemd unit files, prefer the
    /// passphrase-file path with mode 0o600 instead of an environment
    /// variable.
    #[arg(env = "FETCHIT_PASSPHRASE", hide = true)]
    passphrase_env: Option<String>,

    /// Path to a file containing the Argon2id passphrase (whitespace
    /// trimmed). Preferred over `FETCHIT_PASSPHRASE` for systemd /
    /// container installs — file can be locked down with mode 0o600.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Auto-echo every inbound DM back to its sender.
    Echo,
    /// Print the local peer's share URI and exit.
    Card,
    /// Interactive chat — stdin → send to `peer`; inbound → stdout.
    Chat {
        /// Hex agent id of the peer to send stdin lines to.
        #[arg(long)]
        peer: String,
    },
    /// Import a peer's share URI into the local contact store. Required
    /// before `chat` can build a Conversation against that peer (the
    /// peer's ML-KEM-768 pubkey lives inside the v2 card).
    Import {
        /// Path to a UTF-8 file holding the full `x0x://agent/…` URI on
        /// a single line. File-based to side-step OS argv limits — v2
        /// cards are 10-15 KB.
        #[arg(long)]
        uri_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let token = resolve_token(&cli)?;
    let passphrase = resolve_passphrase(&cli)?;

    let mut builder = Client::builder()
        .base_url(&cli.x0xd_base)
        .token(&token)
        .relay_url(cli.relay.clone())
        .data_dir(cli.data_dir.clone());
    if let Some(p) = passphrase {
        builder = builder.passphrase(p);
    }
    let client = builder.build().await.context("build Client")?;

    let me = client.identity().me().await.context("read /agent")?;
    eprintln!("[peer] agent_id: {}", me.agent_id);
    eprintln!("[peer] display: {}", cli.display_name);
    eprintln!("[peer] relay: {}", cli.relay);

    match cli.mode {
        Mode::Card => {
            let uri = client
                .identity()
                .extended_share_uri(&cli.display_name)
                .await
                .context("generate extended share uri")?;
            println!("{uri}");
            Ok(())
        }
        Mode::Echo => run_echo(&client, &cli.display_name).await,
        Mode::Chat { peer } => run_chat(&client, &cli.display_name, &peer).await,
        Mode::Import { uri_file } => run_import(&client, &uri_file).await,
    }
}

async fn run_import(client: &Client, uri_file: &std::path::Path) -> Result<()> {
    let raw = std::fs::read_to_string(uri_file)
        .with_context(|| format!("read uri file at {}", uri_file.display()))?;
    let uri = raw.trim();
    if !uri.starts_with("x0x://agent/") {
        anyhow::bail!(
            "uri file does not start with x0x://agent/ — got {} bytes",
            uri.len()
        );
    }
    eprintln!(
        "[peer] importing {} byte URI from {}",
        uri.len(),
        uri_file.display()
    );
    client
        .identity()
        .import_uri(uri)
        .await
        .context("import_uri (x0xd /agent/card/import)")?;
    if let Some(layout) = client.layout() {
        match fetchit_chat::messages::StoredContactCard::from_share_uri(uri) {
            Ok(stored) => {
                stored.save(layout).context("StoredContactCard.save")?;
                eprintln!("[peer] persisted v2 contact card to local layout");
            }
            Err(e) => {
                eprintln!("[peer] v2 fields not parsed ({e}); the legacy import still landed");
            }
        }
    } else {
        eprintln!("[peer] no local layout (REST-only client); v2 fields not persisted");
    }
    Ok(())
}

fn resolve_token(cli: &Cli) -> Result<String> {
    if let Some(t) = cli.x0xd_token.as_deref() {
        return Ok(t.trim().to_owned());
    }
    let raw = std::fs::read_to_string(&cli.x0xd_token_path)
        .with_context(|| format!("read x0xd api token at {}", cli.x0xd_token_path))?;
    Ok(raw.trim().to_owned())
}

fn resolve_passphrase(cli: &Cli) -> Result<Option<String>> {
    if let Some(path) = cli.passphrase_file.as_ref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read passphrase file at {}", path.display()))?;
        return Ok(Some(raw.trim().to_owned()));
    }
    Ok(cli.passphrase_env.clone().map(|s| s.trim().to_owned()))
}

async fn decode_inbound(client: &Client, mut env: InboundEnvelope) -> Option<PeerInbound> {
    // Chat-v2 envelopes (TransitEnvelope present) go through the
    // conversation dispatcher so we get a decrypted MessagePayload.
    if let Some(transit) = env.transit.take() {
        let identity = client.identity_arc()?;
        let registry = client.registry_arc()?;
        match dispatch_inbound(transit, identity.as_ref(), registry.as_ref()).await {
            Ok(InboundDispatch::Message {
                group_id_hex,
                sender_agent_id_hex,
                payload,
            }) => {
                let Ok(from) = AgentId::parse(sender_agent_id_hex.clone()) else {
                    return None;
                };
                if let Some(message_id) = payload.message_id.as_deref() {
                    let received_at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    if let Err(e) = client
                        .messages()
                        .send_receipt(
                            &group_id_hex,
                            message_id,
                            &sender_agent_id_hex,
                            received_at_ms,
                        )
                        .await
                    {
                        eprintln!("[peer] receipt send error: {e}");
                    }
                }
                Some(PeerInbound {
                    from,
                    body: payload.body,
                })
            }
            Ok(InboundDispatch::Receipt { message_id, .. }) => {
                eprintln!("[peer] got receipt for message_id={message_id}");
                None
            }
            Ok(other) => {
                eprintln!("[peer] dispatch returned non-message: {other:?}");
                None
            }
            Err(e) => {
                eprintln!("[peer] dispatch error: {e}");
                None
            }
        }
    } else {
        // Legacy plaintext envelope — used by transports that don't
        // speak the v2 conversation wire format.
        match decode_direct_message(env) {
            Ok(dm) => Some(PeerInbound {
                from: dm.from,
                body: dm.body,
            }),
            Err(e) => {
                eprintln!("[peer] decode error: {e}");
                None
            }
        }
    }
}

/// Maximum number of attempts `send_with_retry` makes before giving up
/// and propagating the last error to the caller. Five attempts at the
/// default 200ms base delay caps total stall at roughly 6.2 seconds —
/// long enough to ride out a daemon restart, short enough that a
/// genuinely-down peer still surfaces quickly.
const SEND_MAX_ATTEMPTS: u32 = 5;

/// Initial delay between retries; doubles per attempt (200, 400, 800,
/// 1600, 3200 ms). Picked to overlap the typical x0xd cold-start time
/// without introducing a perceivable pause on the happy path (first
/// attempt fires before any sleep).
const SEND_BASE_DELAY_MS: u64 = 200;

/// Bounded retry with exponential backoff. The pair-rig (chat-pipe
/// driven `tail -F ... | peer chat`) used to drop a send when x0xd's
/// `/agent/sign` was momentarily unreachable — log the error, move on,
/// the queued line was gone forever. This helper retries the operation
/// up to [`SEND_MAX_ATTEMPTS`] times so a transient daemon hiccup
/// doesn't silently shred chat messages.
///
/// All errors are treated as potentially transient. For a dev rig that
/// trade-off is the right one: a genuinely-permanent failure surfaces
/// once we exhaust attempts; nothing about the workflow is rate-bounded
/// hard enough to make over-retry an issue.
async fn send_with_retry<F, Fut, T, E>(label: &str, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt: u32 = 0;
    loop {
        match op().await {
            Ok(v) => {
                if attempt > 0 {
                    eprintln!("[peer] {label} ok after {attempt} retries");
                }
                return Ok(v);
            }
            Err(e) => {
                attempt = attempt.saturating_add(1);
                if attempt >= SEND_MAX_ATTEMPTS {
                    eprintln!(
                        "[peer] {label} permanently failed after {attempt} attempts: {e}"
                    );
                    return Err(e);
                }
                let delay = SEND_BASE_DELAY_MS.saturating_mul(1u64 << (attempt - 1));
                eprintln!(
                    "[peer] {label} attempt {attempt}/{SEND_MAX_ATTEMPTS} failed ({e}); retrying in {delay}ms"
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
    }
}

async fn run_echo(client: &Client, display_name: &str) -> Result<()> {
    let mut inbound = client
        .take_transport_inbound("relay")
        .context("relay inbound already taken")?;
    eprintln!("[peer] echo mode — auto-replying to every inbound DM");
    while let Some(env) = inbound.recv().await {
        let Some(dm) = decode_inbound(client, env).await else {
            continue;
        };
        eprintln!("[peer] in: from={} body={:?}", short(&dm.from.0), dm.body);
        let reply = format!("[echo] {}", dm.body);
        // Bind `messages()` to a local so the closure captures the
        // handle by reference — the per-call temporary
        // `client.messages()` returns is dropped before the future
        // it produces awaits, which the borrow checker rejects.
        let messages = client.messages();
        let sender = send_with_retry("echo send", || {
            messages.send(&dm.from, &reply, display_name)
        })
        .await;
        match sender {
            Ok(id) => eprintln!("[peer] out: {reply:?} (message_id={id:?})"),
            Err(e) => eprintln!("[peer] echo send error: {e}"),
        }
    }
    eprintln!("[peer] inbound channel closed; exiting");
    Ok(())
}

async fn run_chat(client: &Client, display_name: &str, peer_hex: &str) -> Result<()> {
    let peer = AgentId::parse(peer_hex.to_owned()).context("invalid peer agent id")?;
    let mut inbound = client
        .take_transport_inbound("relay")
        .context("relay inbound already taken")?;

    let client_clone = client.clone();
    let reader_handle = tokio::spawn(async move {
        while let Some(env) = inbound.recv().await {
            if let Some(dm) = decode_inbound(&client_clone, env).await {
                println!("[{}] {}", short(&dm.from.0), dm.body);
            }
        }
    });

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = stdin.next_line().await? {
        if line.is_empty() {
            continue;
        }
        // Bind `messages()` to a local for the same lifetime reason
        // as in `run_echo` — see comment there.
        let messages = client.messages();
        let send_result = send_with_retry("chat send", || {
            messages.send(&peer, &line, display_name)
        })
        .await;
        match send_result {
            Ok(id) => eprintln!("[peer] sent — id={id:?}"),
            Err(e) => eprintln!("[peer] send error: {e}"),
        }
    }
    drop(reader_handle);
    let _ = tokio::time::timeout(
        Duration::from_millis(50),
        futures_util::future::pending::<()>(),
    )
    .await;
    Ok(())
}

fn short(id_hex: &str) -> &str {
    &id_hex[..id_hex.len().min(8)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_with_retry_returns_first_ok() {
        let calls = Cell::new(0u32);
        let out = send_with_retry::<_, _, &'static str, &'static str>("test", || {
            let c = calls.get();
            calls.set(c + 1);
            async move { Ok("payload") }
        })
        .await;
        assert_eq!(out, Ok("payload"));
        assert_eq!(calls.get(), 1, "happy path must not retry");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_with_retry_retries_until_success() {
        let calls = Cell::new(0u32);
        let out = send_with_retry::<_, _, u32, &'static str>("test", || {
            let n = calls.get();
            calls.set(n + 1);
            async move {
                if n < 3 {
                    Err("flake")
                } else {
                    Ok(n)
                }
            }
        })
        .await;
        assert_eq!(out, Ok(3));
        assert_eq!(calls.get(), 4, "three retries then success on the fourth");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_with_retry_gives_up_after_max_attempts() {
        let calls = Cell::new(0u32);
        let out = send_with_retry::<_, _, (), &'static str>("test", || {
            calls.set(calls.get() + 1);
            async move { Err("dead") }
        })
        .await;
        assert_eq!(out, Err("dead"));
        assert_eq!(
            calls.get(),
            SEND_MAX_ATTEMPTS,
            "every attempt must have run before surfacing the error",
        );
    }
}
