//! `fetchit-chat-peer` — headless chat peer for testing.
//!
//! Drives `fetchit_chat::Client` against a local x0xd + a relay, with
//! no GUI. Three modes:
//!
//! - `echo` — auto-echo every inbound DM back to its sender. Useful
//!   for confirming relay round-trips from a different machine without
//!   needing a human at the keyboard.
//! - `chat` — interactive: stdin lines are sent to a configured peer,
//!   inbound DMs printed to stdout. Like a tiny CLI chat client.
//! - `card` — print this peer's share URI (so the other side can
//!   import it) and exit.

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
    }
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
        let sender = client.messages().send(&dm.from, &reply, display_name).await;
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
        match client.messages().send(&peer, &line, display_name).await {
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
