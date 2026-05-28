//! `fetchit-relay-cli` — minimal driver for cross-internet smoke testing.
//!
//! Subcommands:
//! - `keygen`: generate an ML-DSA-65 keypair and write it to a JSON file
//! - `show-id`: print the agent id derived from an existing keypair
//! - `connect`: open a session against a relay, ferry stdin → send and
//!   incoming envelopes → stdout

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_errors_doc
)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fetchit_relay_client::{Client, ClientConfig, MlDsaSigner, Signer};
use fetchit_relay_proto::{AgentId, DedupeKey, EnvelopeKind, MachineId, TransitEnvelope};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;

#[derive(Parser, Debug)]
#[command(name = "fetchit-relay-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a fresh ML-DSA-65 keypair.
    Keygen {
        /// Where to write the keypair JSON.
        #[arg(short, long, default_value = "fetchit-relay-cli.key.json")]
        out: PathBuf,
    },
    /// Print the agent id for a keypair file.
    ShowId {
        /// Keypair JSON file.
        #[arg(short, long, default_value = "fetchit-relay-cli.key.json")]
        key: PathBuf,
    },
    /// Open a relay session and ferry stdin → send / incoming → stdout.
    Connect {
        /// Relay base URL (e.g. <http://1.2.3.4:8088>).
        #[arg(short, long)]
        relay: Url,
        /// Keypair JSON file.
        #[arg(short, long, default_value = "fetchit-relay-cli.key.json")]
        key: PathBuf,
        /// Peer's agent id (64 hex chars) — every stdin line is sent there.
        #[arg(short, long)]
        peer: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    public_key_hex: String,
    secret_key_hex: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Keygen { out } => keygen(&out),
        Command::ShowId { key } => show_id(&key),
        Command::Connect { relay, key, peer } => connect(relay, &key, peer).await,
    }
}

fn keygen(out: &PathBuf) -> Result<()> {
    let signer = MlDsaSigner::generate().map_err(anyhow::Error::msg)?;
    let key_file = KeyFile {
        public_key_hex: hex::encode(signer.public_key()),
        secret_key_hex: hex::encode(signer.secret_key_bytes()),
    };
    std::fs::write(out, serde_json::to_vec_pretty(&key_file)?)
        .with_context(|| format!("write {}", out.display()))?;
    let agent_id_hex = hex::encode(signer.agent_id());
    println!("wrote {}", out.display());
    println!("agent_id: {agent_id_hex}");
    Ok(())
}

fn show_id(key: &PathBuf) -> Result<()> {
    let signer = load_signer(key)?;
    println!("{}", hex::encode(signer.agent_id()));
    Ok(())
}

async fn connect(relay: Url, key: &PathBuf, peer: Option<String>) -> Result<()> {
    let signer = load_signer(key)?;
    let agent_id_hex = hex::encode(signer.agent_id());
    eprintln!("[cli] agent_id: {agent_id_hex}");
    eprintln!("[cli] dialing {relay}");

    let client = Client::connect(ClientConfig::new(relay), &signer)
        .await
        .context("relay connect")?;
    eprintln!(
        "[cli] connected; max_envelopes_per_min={}, max_envelope_bytes={}",
        client.effective_capabilities.max_envelopes_per_min,
        client.effective_capabilities.max_envelope_bytes
    );

    let me = AgentId::from_bytes(signer.agent_id());
    let peer_id = peer
        .as_deref()
        .map(parse_agent_id)
        .transpose()
        .context("invalid peer id")?;

    if peer_id.is_some() {
        eprintln!("[cli] type lines and press enter to send; ctrl-c to quit");
    } else {
        eprintln!("[cli] no peer set — listening only");
    }

    if let Some(peer_id) = peer_id {
        tokio::select! {
            r = listen_loop(&client, &agent_id_hex) => r?,
            r = send_loop(&client, me, peer_id) => r?,
        }
    } else {
        listen_loop(&client, &agent_id_hex).await?;
    }
    Ok(())
}

async fn listen_loop(client: &Client, agent_label: &str) -> Result<()> {
    loop {
        let Some(d) = client.next_delivery().await else {
            eprintln!("[cli] inbox closed");
            break;
        };
        let from = hex::encode(d.envelope.sender_agent_id.as_bytes());
        let body = String::from_utf8_lossy(&d.envelope.ciphertext);
        println!(
            "[{agent_label}] from {} @ {}: {body}",
            short(&from),
            d.delivered_at_ms
        );
    }
    Ok(())
}

async fn send_loop(client: &Client, me: AgentId, peer_id: AgentId) -> Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut counter: u64 = 0;
    loop {
        let Some(line) = lines.next_line().await? else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        let env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: me,
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: now_ms(),
            epoch: 0,
            ciphertext: line.into_bytes(),
            nonce: vec![],
            kem_ciphertext: vec![],
            sender_signature: vec![],
        };
        counter = counter.wrapping_add(1);
        let mut dedupe = [0u8; 16];
        dedupe[..8].copy_from_slice(&counter.to_le_bytes());
        let key = DedupeKey::from_bytes(dedupe);
        match client.send(peer_id, env, key).await {
            Ok(r) => eprintln!("[cli] sent — accepted_at {}", r.accepted_at_ms),
            Err(e) => eprintln!("[cli] send error: {e}"),
        }
    }
    Ok(())
}

fn load_signer(key: &PathBuf) -> Result<MlDsaSigner> {
    let bytes = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
    let kf: KeyFile = serde_json::from_slice(&bytes)?;
    let pk = hex::decode(&kf.public_key_hex).context("public_key_hex")?;
    let sk = hex::decode(&kf.secret_key_hex).context("secret_key_hex")?;
    MlDsaSigner::from_bytes(&pk, &sk).map_err(anyhow::Error::msg)
}

fn parse_agent_id(s: &str) -> Result<AgentId> {
    let raw = hex::decode(s).context("hex decode")?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent id must be 32 bytes (64 hex)"))?;
    Ok(AgentId::from_bytes(arr))
}

fn short(id_hex: &str) -> &str {
    &id_hex[..id_hex.len().min(8)]
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}
