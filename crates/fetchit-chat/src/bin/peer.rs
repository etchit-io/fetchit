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
use fetchit_chat::messages::decode_direct_message;
use fetchit_chat::Client;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;

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

    let client = Client::builder()
        .base_url(&cli.x0xd_base)
        .token(&token)
        .relay_url(cli.relay.clone())
        .build()
        .await
        .context("build Client")?;

    let me = client.identity().me().await.context("read /agent")?;
    eprintln!("[peer] agent_id: {}", me.agent_id);
    eprintln!("[peer] display: {}", cli.display_name);
    eprintln!("[peer] relay: {}", cli.relay);

    match cli.mode {
        Mode::Card => {
            let card = client
                .identity()
                .card(&cli.display_name)
                .await
                .context("generate card")?;
            let uri = card.to_share_uri().context("encode share uri")?;
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

async fn run_echo(client: &Client, display_name: &str) -> Result<()> {
    let mut inbound = client
        .take_transport_inbound("relay")
        .context("relay inbound already taken")?;
    eprintln!("[peer] echo mode — auto-replying to every inbound DM");
    while let Some(env) = inbound.recv().await {
        let dm = match decode_direct_message(env) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[peer] decode error: {e}");
                continue;
            }
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
    use fetchit_chat::identity::AgentId;
    let peer = AgentId::parse(peer_hex.to_owned()).context("invalid peer agent id")?;
    let mut inbound = client
        .take_transport_inbound("relay")
        .context("relay inbound already taken")?;

    let reader_handle = tokio::spawn(async move {
        while let Some(env) = inbound.recv().await {
            match decode_direct_message(env) {
                Ok(dm) => println!("[{}] {}", short(&dm.from.0), dm.body),
                Err(e) => eprintln!("[peer] decode: {e}"),
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
