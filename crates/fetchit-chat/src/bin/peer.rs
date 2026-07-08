//! `fetchit-chat-peer` — headless chat peer for testing.
//!
//! Drives `fetchit_chat::Client` against a relay, with no GUI. By
//! default it signs through a local x0xd; pass `--daemonless` to sign
//! with a local ML-DSA-65 vault key instead and run with no daemon at
//! all -- each `--data-dir` is then a distinct identity, which is how
//! the cross-device soak fleet packs many peers onto one host. Nine
//! modes:
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
//! - `join`: read an invite payload from a file and call
//!   `Client::groups().join(...)`, then enter echo mode for the
//!   just-joined group. Used by the `m2_live` cross-NAT empirical to
//!   drive the joiner-side `/groups/join` -> Welcome-fetch path that
//!   David's v0.21.3 `63b5c63` retry-fix targets.
//! - `mint-actor` — mint (or reuse) the fediverse actor identity for a
//!   handle, write the registration-ready actor JSON-LD document, and
//!   print the curl line that registers it with the bridge.
//! - `pair-share` — publish this peer's pointer pair record to the
//!   relay, then print the resulting `x0x://pair/...` URI to stdout.
//!   Scripts can capture the URI directly; diagnostics go to stderr.
//! - `pair-import --uri <u>` — import a contact from a short
//!   `x0x://pair/...` pointer URI (resolves the relay-hosted record).
//! - `pair-migrate --to <url>` — move this peer's primary relay to
//!   `<url>`: republish the pair record at the new relay and post a
//!   forwarding record at the old (still-alive) one, then print the new
//!   relay URL to stdout. The region-change half of the pairing flow.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_errors_doc
)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fetchit_chat::conversation::{dispatch_inbound, InboundDispatch};
use fetchit_chat::groups::{GroupId, GroupInvite, JoinOutcome};
use fetchit_chat::identity::AgentId;
use fetchit_chat::messages::{
    decode_direct_message, is_private_group_envelope, PrivateGroupReceive,
};
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

    /// Path to x0xd's `api.port` discovery file. When set, the embedded
    /// signer self-heals across daemon restarts (transparent retry on
    /// connect-refused after re-reading the port file). Recommended for
    /// the systemd-supervised rig so an x0xd port drift doesn't wedge
    /// the binary against a stale URL for the rest of the session.
    #[arg(long)]
    x0xd_port_file: Option<PathBuf>,

    /// Run **daemonless**: no x0xd. Sign with a local ML-DSA-65 keypair
    /// persisted in the data-dir vault instead of an `X0xdSigner`, skip
    /// x0xd discovery + the `TreeKEM` version probe, and derive this peer's
    /// agent id from that local key. Each `--data-dir` is therefore its
    /// own stable identity -- the model the cross-device soak fleet uses
    /// to pack many peers onto one host without a matching swarm of x0xd
    /// daemons. Requires a vault passphrase (`FETCHIT_PASSPHRASE` /
    /// `--passphrase-file`); the `--x0xd-*` flags are ignored. DM
    /// send/receive over the relay work; daemon-backed surfaces (group
    /// join, v2-card mint, SSE reachability) do not.
    #[arg(long)]
    daemonless: bool,

    /// Relay base URL (e.g. `https://nyc-relay.etchit.io`).
    #[arg(
        long,
        env = "FETCHIT_RELAY_URL",
        default_value = "https://nyc-relay.etchit.io"
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
    /// Interactive chat — read outbound lines from stdin (or a file when
    /// `--outbox-file` is set) and send them to `peer`. Inbound DMs print
    /// to stdout.
    ///
    /// When `--outbox-file` + `--cursor-file` are supplied, the binary
    /// runs in **persistent** mode: lines are read from the file
    /// starting at the cursor offset and the cursor advances atomically
    /// after each acked send. A permanent send failure aborts with exit
    /// code 2 so systemd (`Restart=always`, `BindsTo=`) brings the
    /// binary back up against a freshly-resolved x0xd port without
    /// losing queued lines. This is the rig that powers the
    /// `/tmp/claude-pair/to-bob.txt` pair-chat.
    Chat {
        /// Hex agent id of the peer to send lines to.
        #[arg(long)]
        peer: String,

        /// Path to a UTF-8 outbox file. When set, the binary reads
        /// outbound lines from this file (resuming from `--cursor-file`)
        /// instead of stdin. Pair with `--cursor-file`.
        #[arg(long)]
        outbox_file: Option<PathBuf>,

        /// Persisted byte-offset cursor into `--outbox-file`. Atomically
        /// rewritten after each successful send so a chat-peer restart
        /// resumes without re-sending acked lines or dropping queued
        /// ones. Required when `--outbox-file` is set.
        #[arg(long)]
        cursor_file: Option<PathBuf>,
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
    /// Read an invite payload from `invite_file` and call
    /// `Client::groups().join(invite)`. Used by the `m2_live` cross-NAT
    /// empirical to drive the joiner-side `/groups/join` -> Welcome-fetch
    /// path (the surface David's v0.21.3 `63b5c63` retry-fix targets).
    ///
    /// After `/groups/join` succeeds, this subcommand enters echo mode
    /// for the just-joined group: any private-group message received
    /// from a group peer is echoed back via `send_private_group`. Exits
    /// when the caller sends SIGTERM (or the binary's persistent-mode
    /// signal pipeline catches it).
    Join {
        /// Path to a UTF-8 file containing the invite payload (the full
        /// `x0x://invite/<base64>` URI as produced by
        /// `Client::groups().invite(...)`).
        #[arg(long)]
        invite_file: PathBuf,

        /// Optional path to a UTF-8 file containing the owner's
        /// `x0x://agent/<base64>` share URI. When set, the joiner
        /// imports the owner's contact card BEFORE calling
        /// `/groups/join`. Required when the owner's card has not been
        /// imported through a prior `Import` run in the same data-dir;
        /// without it the joiner has no card to verify inbound
        /// `PrivateGroupChat` envelope signatures and every echo from
        /// the owner is dropped with `no card for envelope sender
        /// <owner-hex>`.
        #[arg(long)]
        owner_card_uri_file: Option<PathBuf>,
    },
    /// Mint (or reuse) the fediverse actor identity for `--handle`,
    /// write the registration-ready actor JSON-LD document, and print
    /// the curl line that POSTs it to the bridge's `POST /actors`.
    /// The document is self-verified via `Actor::verify_attestation`
    /// before it is written, so an emitted file always passes the
    /// bridge's identity gate or this command fails loudly instead.
    MintActor {
        /// Local-part to claim (`@<handle>@<domain>`). The bridge
        /// accepts ASCII alphanumerics plus `_` and `-`, max 64 chars,
        /// and rejects reserved handles with 403.
        #[arg(long)]
        handle: String,

        /// Fediverse host the bridge serves the handle under.
        #[arg(long, default_value = "etchit.io")]
        domain: String,

        /// Where to write the actor JSON-LD document.
        #[arg(long, default_value = "actor.json")]
        out: PathBuf,

        /// Registration endpoint for the printed curl line. Defaults
        /// to `https://<domain>/actors`; point it at the bridge origin
        /// directly when the fronting Worker does not route the bare
        /// `/actors` path.
        #[arg(long)]
        post_url: Option<String>,
    },
    /// Publish this peer's pointer pair record to the relay, then print
    /// the resulting `x0x://pair/<agent_id_hex>?r=<relay>` URI to
    /// stdout. The publish step guarantees the URI resolves immediately
    /// on import; a publish failure exits non-zero and prints nothing to
    /// stdout. Mirrors the desktop `chat_pair_share_uri` command.
    PairShare,
    /// Import a contact from a short pointer URI
    /// (`x0x://pair/<agent_id_hex>?r=<relay>`). Resolves the
    /// relay-hosted pair record, verifies it, and persists a contact
    /// card. The URI is taken inline as `--uri` because pointer URIs are
    /// at most 512 bytes -- unlike v2 share cards (~12 KB) which require
    /// file indirection to avoid argv limits.
    PairImport {
        /// The `x0x://pair/<agent_id_hex>?r=<relay>` pointer URI to
        /// resolve and import.
        #[arg(long)]
        uri: String,
    },
    /// Migrate this peer's pinned primary relay to `--to`, the
    /// user-driven region change. Swaps the multi-home primary, then
    /// republishes the pair record at the new relay and posts a signed
    /// forwarding record at the OLD (still-alive) relay so stale senders
    /// rediscover us. Both relays must be reachable: this is the
    /// planned-migration path, not failover. On success the new relay
    /// URL is printed to stdout; a failed slot-0 swap exits non-zero
    /// without touching client state.
    PairMigrate {
        /// The new primary relay base URL to migrate to
        /// (e.g. `https://nyc-relay.etchit.io`).
        #[arg(long)]
        to: String,
    },
    /// Create a private MLS group (PQ `TreeKEM`), mint a fresh invite
    /// link for it, and print both to stdout on labeled lines:
    /// `group_id=<id>` then `invite=<x0x://invite/...>`. Used by the
    /// soak fleet's owner side to stand up a group whose invite link is
    /// then handed to the joiner peers' `group-chat --invite-file`.
    /// x0xd-backed (DAEMON mode): private groups are daemon-gated, so
    /// this mode is unavailable under `--daemonless`.
    GroupCreate {
        /// Human-readable group name passed to `create_private`.
        #[arg(long)]
        name: String,
    },
    /// Join (optionally) and then run a persistent group send/receive
    /// loop against `--group`. Mirrors `Chat`'s atomic-cursor outbox
    /// rig, but the send path fans out through
    /// `Client::messages().send_private_group(...)` instead of a DM. When
    /// `--invite-file` is set the peer joins via that invite link
    /// before entering the loop; when `--outbox-file` + `--cursor-file`
    /// are set the loop drains outbound lines from disk (resuming from
    /// the cursor) the same way `Chat` does, otherwise it just runs the
    /// inbound pump. x0xd-backed (DAEMON mode): groups are daemon-gated,
    /// so this mode is unavailable under `--daemonless`.
    GroupChat(GroupChatArgs),
    /// Mint a FRESH single-use invite for an EXISTING group (`--group`),
    /// printing `invite=<x0x://invite/...>` on stdout. Run once PER
    /// invitee: x0xd invites are single-use, so reusing one invite admits
    /// only the first joiner. This is how a group grows past two members.
    /// x0xd-backed (DAEMON mode): unavailable under `--daemonless`.
    GroupInvite {
        /// Group id (mls hex) to mint an invite for. Validated by
        /// [`GroupId::parse`].
        #[arg(long)]
        group: String,
    },
}

/// Parsed `group-chat` arguments. A standalone [`clap::Args`] group so
/// the `Mode::GroupChat` variant stays a one-line tuple and the `main`
/// dispatch arm stays short.
#[derive(clap::Args, Debug)]
struct GroupChatArgs {
    /// Group id to send into. Validated by [`GroupId::parse`] before
    /// any send so a malformed id can't reach the x0xd path.
    #[arg(long)]
    group: String,

    /// Optional path to a UTF-8 file holding the full
    /// `x0x://invite/<base64>` link on a single line. When set, the
    /// peer joins the group via this invite before entering the loop
    /// (the joiner side of the soak group).
    #[arg(long)]
    invite_file: Option<PathBuf>,

    /// Drive the join through the engine-A cross-NAT bridge
    /// ([`Client::join_group_bridged`]) instead of the direct
    /// `groups().join`. The joiner bridges its native `member_joined` to a
    /// NAT'd owner over the relay and converges on the bridged-back inline
    /// welcome -- the gossip-independent FALLBACK for the dual-NAT corner
    /// (the cross-NAT ship-gate exercises it with gossip disabled to isolate
    /// it; the direct `groups().join` is the primary path). Requires `--invite-file`.
    #[arg(long)]
    engine_a: bool,

    /// Drive the join through the v1 shared join policy
    /// ([`Client::join_group_auto`]): best-effort native warm-gossip
    /// convergence first (so existing members converge over gossip), then
    /// always bridge the `TreeKEM` Welcome over the relay so the joiner is
    /// guaranteed encryptable even when roster-active-but-keyless. This is
    /// the path the app shells use. Mutually exclusive with `--engine-a`;
    /// requires `--invite-file`.
    #[arg(long)]
    auto: bool,

    /// Drive the join through the durable pending-join path
    /// ([`Client::join_group_durable`]): `join_post` runs at most once per
    /// invite ever, and a join that cannot converge now (owner offline)
    /// becomes a persisted `Pending` that the lifetime resume pump
    /// auto-completes when the owner returns -- never a hard error, never a
    /// re-spent invite. Mutually exclusive with `--auto`/`--engine-a`;
    /// requires `--invite-file`.
    #[arg(long)]
    durable: bool,

    /// Path to a UTF-8 outbox file. When set, outbound group lines are
    /// read from this file (resuming from `--cursor-file`) instead of
    /// stdin staying idle. Pair with `--cursor-file`.
    #[arg(long)]
    outbox_file: Option<PathBuf>,

    /// Persisted byte-offset cursor into `--outbox-file`. Atomically
    /// rewritten after each acked send so a restart resumes without
    /// re-sending acked lines. Required when `--outbox-file` is set.
    #[arg(long)]
    cursor_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 cannot auto-determine its process CryptoProvider when both
    // aws-lc-rs and ring are in the dependency graph (the x0xd embed pulls
    // both), so the first TLS use panics. Install aws-lc-rs explicitly -- it
    // backs ant-quic's PQC and the relay TLS. Idempotent: a later call returns
    // Err once a provider is set; we ignore it.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    let token = resolve_token(&cli)?;
    let passphrase = resolve_passphrase(&cli)?;
    require_daemonless_passphrase(cli.daemonless, passphrase.as_deref())?;
    // The fedi vault unseals with the same custody the builder installs:
    // the Client retains the passphrase, so fedi paths need no copy here.

    let mut builder = Client::builder()
        .relay_url(cli.relay.clone())
        .data_dir(cli.data_dir.clone());
    if cli.daemonless {
        // No x0xd: sign with the local ML-DSA-65 vault key and skip
        // discovery + the version probe. The agent id below is derived
        // from that same vault, so each --data-dir is a distinct peer.
        eprintln!("[peer] daemonless -- local vault signer, no x0xd");
        builder = builder.daemonless(true);
    } else {
        builder = builder.base_url(&cli.x0xd_base).token(&token);
        if let Some(port_file) = cli.x0xd_port_file.clone() {
            eprintln!(
                "[peer] x0xd signer self-heal enabled via {}",
                port_file.display()
            );
            builder = builder.x0xd_port_file(port_file);
        }
    }
    if let Some(p) = passphrase {
        builder = builder.passphrase(p);
    }
    let client = builder.build().await.context("build Client")?;

    // Read the agent id from local chat state rather than x0xd `/agent`:
    // it is populated in both the daemon and daemonless paths, so this
    // one accessor covers both (the daemonless sentinel base URL has no
    // live `/agent` to GET).
    let agent_id_hex = client
        .local_agent_id_hex()
        .context("client has no local identity (need --data-dir or --relay)")?;
    eprintln!("[peer] agent_id: {agent_id_hex}");
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
        Mode::Chat {
            peer,
            outbox_file,
            cursor_file,
        } => match (outbox_file, cursor_file) {
            (None, None) => run_chat(&client, &cli.display_name, &peer).await,
            (Some(o), Some(c)) => run_chat_outbox(&client, &cli.display_name, &peer, &o, &c).await,
            (None, Some(_)) | (Some(_), None) => {
                anyhow::bail!("--outbox-file and --cursor-file must both be set or both omitted")
            }
        },
        Mode::Import { uri_file } => run_import(&client, &uri_file).await,
        Mode::Join {
            invite_file,
            owner_card_uri_file,
        } => {
            run_join(
                &client,
                &cli.display_name,
                &invite_file,
                owner_card_uri_file.as_deref(),
            )
            .await
        }
        Mode::MintActor {
            handle,
            domain,
            out,
            post_url,
        } => {
            run_mint_actor(
                &client,
                &agent_id_hex,
                &handle,
                &domain,
                &out,
                post_url.as_deref(),
            )
            .await
        }
        Mode::PairShare => run_pair_share(&client, cli.relay.as_str()).await,
        Mode::PairImport { uri } => run_pair_import(&client, &uri).await,
        Mode::PairMigrate { to } => run_pair_migrate(&client, &to).await,
        Mode::GroupCreate { name } => run_group_create(&client, &cli.display_name, &name).await,
        Mode::GroupChat(args) => run_group_chat(&client, &cli.display_name, &args).await,
        Mode::GroupInvite { group } => run_group_invite(&client, &group).await,
    }
}

async fn run_mint_actor(
    client: &Client,
    live_agent_id: &str,
    handle: &str,
    domain: &str,
    out: &std::path::Path,
    post_url: Option<&str>,
) -> Result<()> {
    let identity = if let Some(existing) = client
        .load_actor_identity(handle)
        .await
        .context("load_actor_identity")?
    {
        eprintln!("[peer] reusing persisted actor identity for {handle:?}");
        existing
    } else {
        eprintln!("[peer] minting fresh actor identity for {handle:?} on {domain}");
        client
            .mint_actor_identity(handle, domain)
            .await
            .context("mint_actor_identity")?
    };

    if identity.agent_id_hex != live_agent_id {
        // Still self-consistent (the bridge will accept it), but the
        // handle would bind to a key other than the one this daemon
        // currently holds — almost always a stale vault.
        eprintln!(
            "[peer] WARNING: persisted actor identity binds agent {}, but the live x0xd agent \
             is {live_agent_id}; delete the fedi vault for {handle:?} and re-run to bind the \
             live key",
            identity.agent_id_hex
        );
    }

    let actor =
        fetchit_fedi::actor::Actor::from_identity(&identity).context("Actor::from_identity")?;
    let derived = actor
        .verify_attestation()
        .context("self-verify attestation")?;
    anyhow::ensure!(
        derived == identity.agent_id_hex,
        "self-verify derived agent {derived} but the identity claims {}; refusing to emit",
        identity.agent_id_hex
    );

    let doc =
        serde_json::to_string_pretty(&actor.to_json_ld()).context("serialize actor JSON-LD")?;
    std::fs::write(out, &doc).with_context(|| format!("write {}", out.display()))?;

    let target = post_url.map_or_else(|| default_actors_post_url(domain), str::to_string);
    eprintln!("[peer] actor document self-verified (agent {derived})");
    eprintln!("[peer] wrote {} ({} bytes)", out.display(), doc.len());
    eprintln!(
        "[peer] register with the line below \
         (201 created / 200 idempotent / 403 reserved-or-foreign-id / 409 handle taken):"
    );
    println!("{}", registration_curl_line(&target, out));
    Ok(())
}

fn default_actors_post_url(domain: &str) -> String {
    format!("https://{domain}/actors")
}

fn registration_curl_line(post_url: &str, doc: &std::path::Path) -> String {
    format!(
        "curl -sS -i -X POST '{post_url}' -H 'content-type: application/json' --data-binary @'{}'",
        doc.display()
    )
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
                stored
                    .save_imported(layout)
                    .context("StoredContactCard.save")?;
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

/// Publish the pair record to `relay_str`, then emit the pointer URI to
/// stdout. Publish runs first so the URI resolves immediately on import.
async fn run_pair_share(client: &Client, relay_str: &str) -> Result<()> {
    client
        .publish_pair_record()
        .await
        .context("publish pair record")?;
    let agent_id_hex = client
        .local_agent_id_hex()
        .context("client has no local identity")?;
    let uri = fetchit_chat::pair_uri::emit_pair_uri(&agent_id_hex, &[relay_str.to_owned()])
        .map_err(|e| anyhow::anyhow!("emit pair uri: {e}"))?;
    println!("{uri}");
    Ok(())
}

/// Resolve and import a contact from a short pointer URI.
async fn run_pair_import(client: &Client, uri: &str) -> Result<()> {
    let uri = uri.trim();
    eprintln!("[peer] importing pair URI ({} bytes)", uri.len());
    client
        .import_pair_uri(uri)
        .await
        .context("import_pair_uri")?;
    eprintln!("[peer] pair import done");
    Ok(())
}

/// Migrate the pinned primary relay to `to`, then emit the new relay URL
/// to stdout. `migrate_primary` republishes the pair record at the new
/// relay and posts a forwarding record at the old one; both relays must
/// be alive for the heal to land.
async fn run_pair_migrate(client: &Client, to: &str) -> Result<()> {
    let to = to.trim();
    eprintln!("[peer] migrating primary relay to {to}");
    client
        .migrate_primary(to)
        .await
        .context("migrate primary")?;
    eprintln!("[peer] pair migrate done");
    println!("{to}");
    Ok(())
}

/// Create a private MLS group, mint an invite link for it, and emit both
/// on labeled stdout lines (`group_id=…` then `invite=…`) so the soak
/// fleet's owner side can capture them and hand the invite to joiner
/// peers. Diagnostics go to stderr; only the two labeled lines reach
/// stdout so a calling script can grep them deterministically.
async fn run_group_create(client: &Client, display_name: &str, name: &str) -> Result<()> {
    let g = client
        .groups()
        .create_private(name, Some(display_name))
        .await
        .context("create_private group")?;
    let inv = client
        .groups()
        .invite(&g.group_id)
        .await
        .context("mint group invite")?;
    println!("group_id={}", g.group_id.as_str());
    println!("invite={}", inv.0);
    eprintln!("[peer] group created group_id={}", g.group_id.as_str());
    Ok(())
}

/// Mint a FRESH single-use invite for an EXISTING group and print it on a
/// labeled stdout line (`invite=<x0x://invite/...>`). Each call yields a
/// distinct one-time invite that captures the group's CURRENT state, so a
/// group OWNER runs this once per invitee to grow the group past two
/// members. Reusing a single invite admits only the first joiner because
/// x0xd invites are single-use (the owner consumes the secret on apply).
/// Diagnostics go to stderr; only the `invite=` line reaches stdout so a
/// calling script can grep it deterministically.
async fn run_group_invite(client: &Client, group: &str) -> Result<()> {
    let gid = GroupId::parse(group).context("invalid group id")?;
    let inv = client
        .groups()
        .invite(&gid)
        .await
        .context("mint group invite")?;
    println!("invite={}", inv.0);
    eprintln!("[peer] minted fresh single-use invite for group {group}");
    Ok(())
}

/// Perform the invite join per the selected policy. `--durable` is the
/// pending-join path: a non-converged join returns as a persisted `Pending`
/// (the lifetime resume pump completes it) instead of erroring, so an invite
/// is never wasted and the join auto-completes when the owner is next
/// reachable. The other policies converge-or-error exactly as before.
async fn join_via_invite(
    client: &Client,
    invite: &GroupInvite,
    display_name: &str,
    args: &GroupChatArgs,
) -> Result<()> {
    if args.engine_a && args.auto {
        anyhow::bail!("--engine-a and --auto are mutually exclusive");
    }
    if args.durable && (args.auto || args.engine_a) {
        anyhow::bail!("--durable is mutually exclusive with --auto/--engine-a");
    }
    if args.durable {
        eprintln!("[peer] joining via the durable path (join_group_durable)");
        match client
            .join_group_durable(invite, Some(display_name))
            .await
            .context("Client::join_group_durable(invite)")?
        {
            JoinOutcome::Converged(group) => eprintln!(
                "[peer] joined group {} (membership convergence confirmed)",
                group.group_id.as_str(),
            ),
            JoinOutcome::Pending { group_id } => eprintln!(
                "[peer] join PENDING for {group_id} -- owner not yet reachable; the \
                 resume pump will auto-complete it with no user action. Entering the \
                 group loop now.",
            ),
        }
        return Ok(());
    }
    let group = if args.auto {
        eprintln!("[peer] joining via the v1 shared policy (join_group_auto)");
        client
            .join_group_auto(invite, Some(display_name))
            .await
            .context("Client::join_group_auto(invite)")?
    } else if args.engine_a {
        eprintln!("[peer] joining via engine-A cross-NAT bridge (join_group_bridged)");
        client
            .join_group_bridged(invite, Some(display_name))
            .await
            .context("Client::join_group_bridged(invite)")?
    } else {
        client
            .groups()
            .join(invite, Some(display_name))
            .await
            .context("Client::groups().join(invite)")?
    };
    eprintln!(
        "[peer] joined group {} (membership convergence confirmed)",
        group.group_id.as_str(),
    );
    Ok(())
}

/// Spawn the durable-join resume pump for the peer's lifetime: re-drive any
/// persisted pending join to convergence on the driver's backoff. A join that
/// could not converge at startup (owner offline) auto-completes here the
/// moment the owner returns -- no user action, no re-spent invite, never a
/// hard error. A pure no-op when nothing is pending; logs the pending set
/// shrinking so the acceptance run (kill a seat mid-join, watch it rejoin)
/// has a clear convergence signal.
fn spawn_durable_join_pump(client: &Client) {
    let pump_client = client.clone();
    tokio::spawn(async move {
        use std::collections::HashSet;
        let mut prev: HashSet<String> = HashSet::new();
        loop {
            if let Err(e) = pump_client.drive_pending_joins_once().await {
                eprintln!("[peer] pending-join pump error: {e}");
            }
            let now: HashSet<String> = pump_client
                .pending_joins()
                .unwrap_or_default()
                .into_iter()
                .collect();
            for gid in prev.difference(&now) {
                eprintln!(
                    "[peer] durable join CONVERGED for {gid} -- now fully joined, no \
                     user action taken"
                );
            }
            prev = now;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

/// Persistent group send/receive loop. When `invite_file` is set the
/// peer joins the group via that invite link first. The loop then
/// mirrors [`run_chat_outbox`]'s atomic-cursor rig -- a spawned inbound
/// reader (routing private-group envelopes through
/// [`decode_private_group`]) plus the SSE reachability recorder -- but
/// the SEND path fans out through `Client::messages().send_private_group(...)` instead
/// of a DM. Like `Chat`, `--outbox-file` and `--cursor-file` must be
/// supplied together; with neither, only the inbound pump runs.
async fn run_group_chat(client: &Client, display_name: &str, args: &GroupChatArgs) -> Result<()> {
    let group_hex = args.group.as_str();
    let gid = GroupId::parse(group_hex).context("invalid group id")?;

    // Start the inbound relay reader BEFORE any join. Engine-A's
    // `join_group_bridged` blocks until membership converges, and the
    // owner's bridged join-result -- the authoritative `MemberAdded` that
    // flips this joiner active -- arrives on this relay stream. It must be
    // drained and dispatched (`decode_inbound` -> `dispatch_inbound_bridge`,
    // which stages it into the local x0xd for the daemon's join-result poll
    // to apply) WHILE the join waits, mirroring a real shell's always-on
    // inbound pump. Spawning the reader after the join (the prior order)
    // deadlocked the joiner: nothing consumed the reply, so membership never
    // converged and the join timed out.
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

    if let Some(invite_path) = args.invite_file.as_deref() {
        // Read the single-line x0x://invite/<base64> link as written by
        // the owner-side `group-create` driver (trimmed so a trailing
        // newline from `echo` doesn't break the daemon's parser).
        let raw = std::fs::read_to_string(invite_path)
            .with_context(|| format!("read invite file at {}", invite_path.display()))?;
        let invite = GroupInvite(raw.trim().to_owned());
        if !invite.0.starts_with("x0x://invite/") {
            anyhow::bail!(
                "invite file does not start with x0x://invite/ (got {} bytes)",
                invite.0.len()
            );
        }
        eprintln!(
            "[peer] joining group via invite ({} bytes from {})",
            invite.0.len(),
            invite_path.display(),
        );
        join_via_invite(client, &invite, display_name, args).await?;
    }

    // Durable-join resume pump: complete any persisted pending join whenever
    // the owner's daemon is next reachable -- no user action, no re-spent
    // invite, never a hard error. See `spawn_durable_join_pump`.
    if args.durable {
        spawn_durable_join_pump(client);
    }

    match (args.outbox_file.as_deref(), args.cursor_file.as_deref()) {
        (None, None) => {
            run_group_chat_loop(client, &gid, group_hex, display_name, None, reader_handle).await
        }
        (Some(o), Some(c)) => {
            run_group_chat_loop(
                client,
                &gid,
                group_hex,
                display_name,
                Some((o, c)),
                reader_handle,
            )
            .await
        }
        (None, Some(_)) | (Some(_), None) => {
            anyhow::bail!("--outbox-file and --cursor-file must both be set or both omitted")
        }
    }
}

/// Inner group loop shared by the stdin-idle and outbox-driven forms of
/// `run_group_chat`. The inbound relay reader is spawned by the caller
/// (`run_group_chat`, before any join) and handed in as `reader_handle`;
/// this loop spawns the SSE reachability recorder and, when `outbox` is
/// `Some((outbox_file, cursor_file))`, drains outbound lines from disk
/// through `Client::messages().send_private_group(...)`, advancing the
/// cursor atomically on each ack, exactly like the DM rig. When `outbox`
/// is `None` it keeps the inbound reader alive until the relay channel
/// closes.
async fn run_group_chat_loop(
    client: &Client,
    gid: &GroupId,
    group_hex: &str,
    display_name: &str,
    outbox: Option<(&std::path::Path, &std::path::Path)>,
    reader_handle: tokio::task::JoinHandle<()>,
) -> Result<()> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    match client.spawn_sse_reachability_recorder() {
        Ok(_handle) => eprintln!("[peer] sse reachability recorder started"),
        Err(e) => eprintln!("[peer] sse reachability recorder not started: {e}"),
    }

    let Some((outbox_file, cursor_file)) = outbox else {
        // Inbound-only: no outbox, so just keep the reader alive until
        // the relay channel closes (or the binary is signalled).
        eprintln!("[peer] group inbound-only mode -- no outbox configured");
        let _ = reader_handle.await;
        eprintln!("[peer] inbound channel closed; exiting");
        return Ok(());
    };

    if let Some(parent) = cursor_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create cursor parent {}", parent.display()))?;
    }
    if !outbox_file.exists() {
        std::fs::write(outbox_file, b"")
            .with_context(|| format!("create outbox {}", outbox_file.display()))?;
    }

    let mut pos: u64 = read_cursor(cursor_file).unwrap_or(0);
    eprintln!(
        "[peer] group={} outbox={} cursor={}@{}",
        short(group_hex),
        outbox_file.display(),
        cursor_file.display(),
        pos,
    );

    // Snapshot the roster size ONCE for the per-send log field. members()
    // is an x0xd read; calling it after every send (at soak volume) is a
    // round-trip per message for a cosmetic field nothing parses. A late
    // joiner is not reflected here -- fine for a log hint (group-status
    // counts group-sent lines, not this).
    let member_count = client.groups().members(gid).await.map_or(0, |m| m.len());

    loop {
        let f = std::fs::File::open(outbox_file)
            .with_context(|| format!("open outbox {}", outbox_file.display()))?;
        let file_len = f.metadata()?.len();
        if pos > file_len {
            eprintln!("[peer] outbox truncated (cursor {pos} > size {file_len}); resetting cursor");
            pos = 0;
            write_cursor_atomic(cursor_file, pos)?;
        }
        let mut buf_reader = BufReader::new(f);
        buf_reader.seek(SeekFrom::Start(pos))?;
        let mut any_progress = false;
        for line_result in buf_reader.lines() {
            let line = line_result.context("read outbox line")?;
            let line_bytes = line.len() as u64 + 1; // +1 for newline
            if line.is_empty() {
                pos = pos.saturating_add(line_bytes);
                write_cursor_atomic(cursor_file, pos)?;
                any_progress = true;
                continue;
            }
            // Private MLS groups send through messages().send_private_group
            // (encrypt-then-fanout per roster member); groups().send is the
            // SignedPublic path and x0xd rejects it for a private group with
            // "group is not SignedPublic". members() (a read) stays on groups().
            let messages = client.messages();
            let send_result = send_with_retry("group send", || {
                messages.send_private_group(group_hex, &line, display_name)
            })
            .await;
            match send_result {
                Ok(id) => {
                    let id_or_none = id.message_id.as_deref().unwrap_or("none");
                    eprintln!(
                        "[peer] group-sent id={id_or_none} group={} members={member_count}",
                        short(group_hex),
                    );
                    pos = pos.saturating_add(line_bytes);
                    write_cursor_atomic(cursor_file, pos)?;
                    any_progress = true;
                }
                Err(e) => {
                    eprintln!(
                        "[peer] group-outbox send permanent fail: {e}; exiting 2 for systemd restart",
                    );
                    drop(reader_handle);
                    std::process::exit(2);
                }
            }
        }
        if !any_progress {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// One step in the join sequence. Surfaced as a typed plan so the
/// ordering invariant (`ImportOwnerCard` must precede `Join`) can be
/// pinned by a unit test without having to spin up a real `Client` +
/// daemon. See `plan_join_steps`. Membership-convergence polling is
/// now folded into `Client::groups::join` itself, so the post-join
/// step has been removed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JoinStep {
    /// Import the owner's contact card before /groups/join. Carries
    /// the path the URI is read from at execution time so the test can
    /// assert it round-trips unchanged from the CLI arg.
    ImportOwnerCard(PathBuf),
    /// Call `Client::groups().join(invite)`; the call blocks until
    /// joiner-side x0xd has applied `MemberAdded`.
    Join,
}

/// Build the ordered list of steps `run_join` will perform for a given
/// `owner_card_uri_file` setting. Pure, side-effect-free; the actual
/// I/O lives in `run_join`. Extracted so the
/// "import-before-join when set" / "join-only when unset" ordering
/// invariant can be unit-tested without a real `Client`.
fn plan_join_steps(owner_card_uri_file: Option<&std::path::Path>) -> Vec<JoinStep> {
    let mut steps = Vec::with_capacity(2);
    if let Some(path) = owner_card_uri_file {
        steps.push(JoinStep::ImportOwnerCard(path.to_path_buf()));
    }
    steps.push(JoinStep::Join);
    steps
}

async fn run_join(
    client: &Client,
    display_name: &str,
    invite_file: &std::path::Path,
    owner_card_uri_file: Option<&std::path::Path>,
) -> Result<()> {
    // Pin the ordering invariant at the entry point: every step we run
    // below is a faithful interpretation of the typed plan, so the
    // unit test on `plan_join_steps` doubles as a contract check on
    // this fn. If a future refactor reorders the I/O without updating
    // `plan_join_steps`, the test starts disagreeing with reality.
    let steps = plan_join_steps(owner_card_uri_file);
    for step in steps {
        match step {
            JoinStep::ImportOwnerCard(uri_path) => {
                // Import the owner's share URI BEFORE /groups/join so
                // the joiner has a card to verify inbound
                // `PrivateGroupChat` envelopes. Without this the
                // sender-verify check inside
                // `receive_private_group_envelope` fails closed on
                // every envelope the owner emits and the joiner's
                // local conversation stays empty regardless of how
                // many round-trips succeed at the relay layer.
                let raw = std::fs::read_to_string(&uri_path)
                    .with_context(|| format!("read owner card URI from {}", uri_path.display()))?;
                let uri = raw.trim();
                if !uri.starts_with("x0x://agent/") {
                    anyhow::bail!(
                        "owner card URI file does not start with x0x://agent/ (got {} bytes)",
                        uri.len()
                    );
                }
                eprintln!(
                    "[peer] importing owner card ({} bytes) from {}",
                    uri.len(),
                    uri_path.display(),
                );
                client
                    .identity()
                    .import_uri(uri)
                    .await
                    .context("import owner card URI before /groups/join")?;
                if let Some(layout) = client.layout() {
                    match fetchit_chat::messages::StoredContactCard::from_share_uri(uri) {
                        Ok(stored) => {
                            stored
                                .save_imported(layout)
                                .context("StoredContactCard.save (owner card)")?;
                            eprintln!("[peer] persisted owner contact card to local layout");
                        }
                        Err(e) => {
                            eprintln!(
                                "[peer] owner v2 fields not parsed ({e}); the legacy import still landed",
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "[peer] no local layout (REST-only client); owner v2 fields not persisted"
                    );
                }
            }
            JoinStep::Join => {
                // Read the invite payload as written by the m2_live
                // owner-side driver: a single x0x://invite/<base64>
                // URI on disk (trimmed of surrounding whitespace so a
                // trailing newline from `echo` doesn't break the
                // daemon's parser).
                let raw = std::fs::read_to_string(invite_file)
                    .with_context(|| format!("read invite file at {}", invite_file.display()))?;
                let invite = GroupInvite(raw.trim().to_owned());
                if !invite.0.starts_with("x0x://invite/") {
                    anyhow::bail!(
                        "invite file does not start with x0x://invite/ (got {} bytes)",
                        invite.0.len()
                    );
                }
                eprintln!(
                    "[peer] joining group via invite ({} bytes from {})",
                    invite.0.len(),
                    invite_file.display(),
                );
                // The /groups/join call is what David's v0.21.3
                // 63b5c63 retry-fix patches on the daemon side: if the
                // Welcome-blob fetch from the inviter's daemon flakes
                // (transient relay/gossip drop), x0xd now retries with
                // backoff before failing closed.
                let group = client
                    .groups()
                    .join(&invite, Some(display_name))
                    .await
                    .context("Client::groups().join(invite)")?;
                eprintln!(
                    "[peer] joined group {} (membership convergence confirmed)",
                    group.group_id.as_str(),
                );
                // Pre-resolve base-member sender keys so their first
                // group message decrypts without a prior DM pairing. The
                // converged /members roster is the base-member source
                // (x0xd invites carry no member-key block). 404 / absent
                // members are skipped; they fall to the on-receive
                // lazy-fetch path.
                match client.groups().members(&group.group_id).await {
                    Ok(members) => {
                        let self_hex = client.local_agent_id_hex().unwrap_or_default();
                        let self_id = AgentId(self_hex);
                        match client
                            .messages()
                            .prefetch_group_member_cards(&members, &self_id)
                            .await
                        {
                            Ok((resolved, skipped)) => eprintln!(
                                "[peer] base-member key prefetch: {resolved} resolved, {skipped} skipped",
                            ),
                            Err(e) => eprintln!("[peer] base-member key prefetch failed: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[peer] roster fetch for key prefetch failed: {e}"),
                }
                eprintln!(
                    "[peer] entering echo loop for group {}",
                    group.group_id.as_str()
                );
            }
        }
    }
    // The Mode::Echo loop already routes private-group envelopes
    // through `decode_private_group`, which echoes the body back into
    // the same group via `send_private_group`. Once `/groups/join` +
    // the x0xd-side `MemberAdded` apply both land, the owner's
    // `send_private_group` fanout will address an envelope to this
    // peer; the echo fires as a side effect inside
    // `decode_private_group`.
    run_echo(client, display_name).await
}

fn resolve_token(cli: &Cli) -> Result<String> {
    // Daemonless peers have no x0xd, hence no API token to read. Return
    // an empty token without touching the (often absent) token file so a
    // headless soak peer doesn't fail on a missing api-token path.
    if cli.daemonless {
        return Ok(String::new());
    }
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

/// Daemonless peers seal their identity vault with the Argon2id
/// passphrase. A headless soak host has no OS keychain, so without a
/// passphrase the engine's master-key resolution falls back to the
/// keychain source and fails opaquely. Reject the missing passphrase
/// here with an actionable message instead.
fn require_daemonless_passphrase(daemonless: bool, passphrase: Option<&str>) -> Result<()> {
    if daemonless && passphrase.is_none_or(str::is_empty) {
        anyhow::bail!(
            "daemonless mode requires a vault passphrase; set FETCHIT_PASSPHRASE or --passphrase-file"
        );
    }
    Ok(())
}

/// Decode + dispatch a private-secure-group envelope. Returns Some
/// when the body is fresh and should be surfaced to the user; None on
/// self-source, replay, decrypt failure, or any of the verify/lookup
/// edge cases.
async fn decode_private_group(
    client: &Client,
    transit: &fetchit_relay_proto::TransitEnvelope,
) -> Option<PeerInbound> {
    // Self-source filter: our own sends fan out via the relay and can
    // echo back to us (especially when running both ends of a test).
    // Drop self-as-sender envelopes BEFORE the decrypt path so a
    // same-machine Alice<->Alice loop can't produce phantom history
    // entries. The signature check inside
    // `receive_private_group_envelope` would also fail if our
    // card-cache didn't carry our own card — but short-circuiting
    // here is cheaper and clearer.
    let self_hex = client
        .identity_arc()
        .map(|identity| identity.agent_id_hex().to_owned())
        .unwrap_or_default();
    if !self_hex.is_empty() && hex::encode(transit.sender_agent_id.as_bytes()) == self_hex {
        return None;
    }
    let group_id_hex = transit
        .group_id
        .as_ref()
        .map(|g| hex::encode(g.as_bytes()))
        .unwrap_or_default();
    if group_id_hex.is_empty() {
        eprintln!("[peer] private-group envelope without group_id");
        return None;
    }
    let messages = client.messages();
    match messages
        .receive_private_group_envelope(transit, &group_id_hex)
        .await
    {
        Ok(PrivateGroupReceive::Persisted(entry)) => {
            // Soak-collector receive anchor. Metadata only (message id +
            // group/receiver/sender prefixes) -- never the body; see the
            // SECURITY.md note on the body_len line below. `message_id`
            // is a bare `String` here (HistoryEntry, not the
            // `Option`-shaped DM payload), so an empty id folds to
            // "none" to match the inbound-msg line's reporting shape.
            let msg_id = if entry.message_id.is_empty() {
                "none"
            } else {
                entry.message_id.as_str()
            };
            eprintln!(
                "[peer] group-inbound id={} group={} rcvr={} sender={}",
                msg_id,
                short(&group_id_hex),
                short(&self_hex),
                short(&entry.sender_agent_id_hex),
            );
            // Logs metadata only — sender + group prefixes + payload
            // size. Printing the plaintext body would land in stderr
            // which the systemd unit pipes to journalctl AND the
            // chat-peer-start wrapper appends to PEER_RX_LOG, both
            // long-lived destinations that the relay-metadata-hiding
            // claims in `crates/fetchit-chat/SECURITY.md` promise to
            // keep plaintext out of. Body size is observable enough
            // for live-test debugging without breaking the promise.
            eprintln!(
                "[peer] private-group: from={} group={} body_len={}",
                short(&entry.sender_agent_id_hex),
                short(&group_id_hex),
                entry.body.len()
            );
            // Opt-in plaintext surface for an INTERACTIVE comms peer (a
            // human chatting through this rig), NOT the soak/systemd peer.
            // Defaults OFF so the metadata-only promise above holds for the
            // long-lived journalctl / PEER_RX_LOG destinations; only a
            // manually-run peer that sets FETCHIT_PEER_GROUP_PRINT=1 (its
            // stdout going to a private, operator-chosen file) prints the
            // decrypted body, on stdout, as a clean monitorable line.
            if std::env::var("FETCHIT_PEER_GROUP_PRINT").as_deref() == Ok("1") {
                println!(
                    "[group {}] {}",
                    short(&entry.sender_agent_id_hex),
                    entry.body
                );
            }
            // The M2 echo is opt-out: a group soak peer sets
            // FETCHIT_PEER_ECHO=0 so the group does not self-amplify --
            // every non-author member echoing every message (including
            // other echoes) grows multiplicatively and drowns the
            // coverage metric. Echo-off returns None so the reader does
            // not print the body either; the metadata anchors above are
            // all the soak collector needs. Default keeps M2 behavior.
            if std::env::var("FETCHIT_PEER_ECHO").as_deref() == Ok("0") {
                return None;
            }
            // M2 live-test echo handler. Bounces the body back into
            // the same group so the test asserter sees an inbound
            // from us. Self-source filter at the top of this fn drops
            // our own re-receipt. Wrap as fire-and-forget — a send
            // failure during a test run should log + continue so we
            // don't wedge the inbound pump.
            let echo_body = format!("echo: {}", entry.body);
            if let Err(e) = client
                .messages()
                .send_private_group(&group_id_hex, &echo_body, "bob")
                .await
            {
                eprintln!("[peer] echo send error: {e}");
            }
            let from = AgentId::parse(entry.sender_agent_id_hex).ok()?;
            Some(PeerInbound {
                from,
                body: entry.body,
            })
        }
        Ok(PrivateGroupReceive::Replay) => {
            eprintln!("[peer] private-group: replay dropped");
            None
        }
        Err(e) => {
            // Soak-collector decrypt-fail anchor. Metadata only -- group
            // prefix + sender prefix; the plaintext never existed at this
            // layer (decrypt failed) so there is nothing sensitive to
            // leak beyond the routing ids the relay already sees.
            eprintln!(
                "[peer] group-decrypt-fail group={} sender={}",
                short(&group_id_hex),
                short(&hex::encode(transit.sender_agent_id.as_bytes())),
            );
            eprintln!("[peer] private-group decrypt error: {e}");
            None
        }
    }
}

async fn decode_inbound(client: &Client, mut env: InboundEnvelope) -> Option<PeerInbound> {
    // Chat-v2 envelopes (TransitEnvelope present) go through the
    // conversation dispatcher so we get a decrypted MessagePayload.
    if let Some(transit) = env.transit.take() {
        // Diagnostic — pre-routing peek at envelope shape so the rig
        // can be debugged when a sender's classification drifts (e.g.
        // when Alice's pipe started routing chat-pipe DMs through
        // send_private_group and my peer mis-routed them via
        // `is_private_group_envelope`, leaving them to fail postcard
        // decode with no visibility into WHY). Metadata only; the
        // body is sealed and never touched at this layer.
        let sender_hex = hex::encode(transit.sender_agent_id.as_bytes());
        let group_hex = transit.group_id.as_ref().map(|g| hex::encode(g.as_bytes()));
        eprintln!(
            "[peer] inbound: kind={:?} sender={} group_id={} ct_len={} kem_len={} epoch={}",
            transit.kind,
            short(&sender_hex),
            group_hex.as_deref().map_or("none", short),
            transit.ciphertext.len(),
            transit.kem_ciphertext.len(),
            transit.epoch,
        );
        // M2.5 bridge path: `EnvelopeKind::X0xdGroupMetadataEvent`
        // tunnels a signed x0xd `NamedGroupMetadataEvent` through the
        // relay when the gossip mesh can't reach a peer. The client
        // helper unseals, postcards out the wrapper, and POSTs the
        // inner JSON payload to local x0xd `/publish`; pubsub-loopback
        // then advances local MLS state via the normal apply path.
        if matches!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent
        ) {
            if let Err(e) = client.dispatch_inbound_bridge(&transit).await {
                eprintln!("[peer] bridge dispatch error: {e}");
            }
            return None;
        }
        // M2 private-group path: GroupChat envelopes whose
        // kem_ciphertext is empty are PQ-TreeKEM frames produced by
        // x0xd's /secure/encrypt. Routed via the shared
        // `is_private_group_envelope` predicate so the discriminator
        // lives in one place (the messages module) and a future DM
        // transport that legitimately leaves kem_ciphertext empty
        // doesn't silently start misrouting here.
        if is_private_group_envelope(&transit) {
            return decode_private_group(client, &transit).await;
        }
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
                    // Receive-side anchor for the soak collector (bare hex id,
                    // metadata only -- never the body; see the sent/receipt lines).
                    eprintln!(
                        "[peer] inbound-msg id={message_id} sender={}",
                        short(&sender_agent_id_hex)
                    );
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
                    eprintln!("[peer] {label} permanently failed after {attempt} attempts: {e}");
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
            messages.send(&dm.from, &reply, display_name, None, None)
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

    // M2.5 — background task pumps x0xd's `/events` SSE into the
    // reachability cache. Without this, every `(group, member)` stays
    // `Unreachable` and every bridge-eligible send routes through the
    // consent modal even after the user has opted in. Bridge-loopback
    // events are filtered via the shadow set the dispatcher marks
    // before `POST /publish`, and self-publish loopbacks are filtered
    // by the `from == local_agent_id` guard inside the recorder.
    match client.spawn_sse_reachability_recorder() {
        Ok(_handle) => eprintln!("[peer] sse reachability recorder started"),
        Err(e) => eprintln!("[peer] sse reachability recorder not started: {e}"),
    }

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = stdin.next_line().await? {
        if line.is_empty() {
            continue;
        }
        // Bind `messages()` to a local for the same lifetime reason
        // as in `run_echo` — see comment there.
        let messages = client.messages();
        let send_result = send_with_retry("chat send", || {
            messages.send(&peer, &line, display_name, None, None)
        })
        .await;
        match send_result {
            Ok(id) => eprintln!("[peer] sent -- id={id:?}"),
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

/// Persistent `chat` mode: read outbound lines from `outbox_file` past
/// the byte offset recorded in `cursor_file`, send each, advance the
/// cursor atomically on ack. Exits with status 2 on permanent send
/// failure so the systemd wrapper rebuilds the binary with a fresh
/// `--x0xd-base` (resolved from `api.port` at unit-start time).
///
/// Cursor semantics:
/// - Missing or empty cursor file → start at offset 0.
/// - Cursor past EOF → wait for new bytes (legitimate after a sync).
/// - Cursor advances by `line.len() + 1` (the trailing newline) once
///   the line's send returns `Ok`. The write is `write(.tmp) + rename`
///   so a crash mid-update leaves the previous cursor intact — never
///   half-written, never lost.
///
/// Polling interval is intentionally a humble 250ms: this rig handles
/// human keystrokes from one Claude session to another, not high-rate
/// traffic. `inotify` would be tighter but introduces a platform
/// dependency the dev rig has no need for.
async fn run_chat_outbox(
    client: &Client,
    display_name: &str,
    peer_hex: &str,
    outbox_file: &std::path::Path,
    cursor_file: &std::path::Path,
) -> Result<()> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

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

    match client.spawn_sse_reachability_recorder() {
        Ok(_handle) => eprintln!("[peer] sse reachability recorder started"),
        Err(e) => eprintln!("[peer] sse reachability recorder not started: {e}"),
    }

    if let Some(parent) = cursor_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create cursor parent {}", parent.display()))?;
    }
    if !outbox_file.exists() {
        std::fs::write(outbox_file, b"")
            .with_context(|| format!("create outbox {}", outbox_file.display()))?;
    }

    let mut pos: u64 = read_cursor(cursor_file).unwrap_or(0);
    eprintln!(
        "[peer] outbox={} cursor={}@{}",
        outbox_file.display(),
        cursor_file.display(),
        pos,
    );

    loop {
        let f = std::fs::File::open(outbox_file)
            .with_context(|| format!("open outbox {}", outbox_file.display()))?;
        let file_len = f.metadata()?.len();
        if pos > file_len {
            // Outbox was truncated/rotated under us. Reset to head so we
            // don't silently skip newly-rewritten lines.
            eprintln!("[peer] outbox truncated (cursor {pos} > size {file_len}); resetting cursor");
            pos = 0;
            write_cursor_atomic(cursor_file, pos)?;
        }
        let mut buf_reader = BufReader::new(f);
        buf_reader.seek(SeekFrom::Start(pos))?;
        let mut any_progress = false;
        for line_result in buf_reader.lines() {
            let line = line_result.context("read outbox line")?;
            let line_bytes = line.len() as u64 + 1; // +1 for newline
            if line.is_empty() {
                pos = pos.saturating_add(line_bytes);
                write_cursor_atomic(cursor_file, pos)?;
                any_progress = true;
                continue;
            }
            let messages = client.messages();
            let send_result = send_with_retry("chat send", || {
                messages.send(&peer, &line, display_name, None, None)
            })
            .await;
            match send_result {
                Ok(id) => {
                    eprintln!("[peer] sent -- id={id:?}");
                    pos = pos.saturating_add(line_bytes);
                    write_cursor_atomic(cursor_file, pos)?;
                    any_progress = true;
                }
                Err(e) => {
                    eprintln!(
                        "[peer] chat-outbox send permanent fail: {e}; exiting 2 for systemd restart",
                    );
                    drop(reader_handle);
                    std::process::exit(2);
                }
            }
        }
        if !any_progress {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Read a u64 byte-offset cursor from `path`. Missing or unparseable
/// values fold to `Ok(0)` so a fresh rig starts at the head of the
/// outbox without ceremony.
fn read_cursor(path: &std::path::Path) -> std::io::Result<u64> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    Ok(trimmed.parse().unwrap_or(0))
}

/// Atomically rewrite the cursor file. On `data=writeback` mounts the
/// rename can land before the data is durable, leaving an empty `.tmp`
/// visible after a crash — which would reset the cursor to 0 on the
/// next read and replay the entire outbox (duplicate-send hazard).
/// Defend by `sync_all()`-ing the file handle before close, then
/// rename. The data-before-metadata order is now durable regardless of
/// mount mode.
///
/// (Per Bob's cross-review of `b552a65` 2026-06-03 — P0-A finding.)
fn write_cursor_atomic(path: &std::path::Path, pos: u64) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(pos.to_string().as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn short(id_hex: &str) -> &str {
    &id_hex[..id_hex.len().min(8)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
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

    // ── outbox-cursor file helpers ────────────────────────────────────

    #[test]
    fn write_cursor_atomic_persists_value_and_no_tmp_residue() {
        let tmp = tempfile::tempdir().unwrap();
        let cursor = tmp.path().join("chat-peer.cursor");
        write_cursor_atomic(&cursor, 12_345).expect("write");
        assert_eq!(read_cursor(&cursor).unwrap(), 12_345);
        // The .tmp helper must be renamed away — leaving it around
        // would confuse a future write that overwrites the .tmp.
        assert!(!cursor.with_extension("tmp").exists());
    }

    #[test]
    fn write_cursor_atomic_overwrite_replaces_value() {
        let tmp = tempfile::tempdir().unwrap();
        let cursor = tmp.path().join("chat-peer.cursor");
        write_cursor_atomic(&cursor, 100).unwrap();
        write_cursor_atomic(&cursor, 9_001).unwrap();
        assert_eq!(read_cursor(&cursor).unwrap(), 9_001);
    }

    #[test]
    fn read_cursor_missing_file_yields_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let cursor = tmp.path().join("never-written.cursor");
        // The wrapper at the call site (`run_chat_outbox`) folds
        // `Err` to `0` via `unwrap_or(0)`. The helper itself surfaces
        // the IO error so callers can distinguish "no cursor yet"
        // from "cursor file is unreadable for some other reason".
        let err = read_cursor(&cursor).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn read_cursor_unparseable_value_yields_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let cursor = tmp.path().join("chat-peer.cursor");
        std::fs::write(&cursor, "not-a-number").unwrap();
        // Defensive fold: an outbox should not be replayed from a
        // garbage cursor value either. `0` is the safest restart
        // point because the de-dup logic in the relay-side outbox
        // catches the resends on the next layer.
        assert_eq!(read_cursor(&cursor).unwrap(), 0);
    }

    #[test]
    fn read_cursor_with_trailing_whitespace_parses_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let cursor = tmp.path().join("chat-peer.cursor");
        std::fs::write(&cursor, "  17860 \n").unwrap();
        assert_eq!(read_cursor(&cursor).unwrap(), 17_860);
    }

    // ── plan_join_steps ordering invariant ────────────────────────────

    #[test]
    fn plan_join_steps_imports_owner_card_before_join_when_set() {
        // The whole point of the owner-card-uri-file path: with the
        // owner's card in hand before /groups/join runs, the joiner
        // can sender-verify the owner's inbound `PrivateGroupChat`
        // envelopes. If a refactor swaps these two steps, the joiner
        // re-introduces the empirical-busting "no card for envelope
        // sender" failure that motivated this patch in the first
        // place. Pin the ordering at the type level.
        let owner_path = PathBuf::from("/tmp/m2-live-owner-share-uri.txt");
        let steps = plan_join_steps(Some(owner_path.as_path()));
        assert_eq!(
            steps,
            vec![JoinStep::ImportOwnerCard(owner_path), JoinStep::Join,],
            "owner card import precedes /groups/join",
        );
    }

    #[test]
    fn plan_join_steps_join_only_when_owner_path_absent() {
        // When the joiner is driven without an owner-card path,
        // either a previous `Import` run in the same data-dir
        // persisted it or the operator is exercising the
        // fail-open-on-missing-card path that v0.21.0 shipped.
        // Membership-convergence polling is now folded into
        // `Client::groups::join` itself, so the plan emits just one
        // step here.
        let steps = plan_join_steps(None);
        assert_eq!(steps, vec![JoinStep::Join]);
    }

    // ── mint-actor registration emission ──────────────────────────────

    #[test]
    fn default_actors_post_url_targets_the_bare_actors_route() {
        // The bridge mounts registration at exactly `/actors` — no
        // version prefix, no trailing slash. A drifted default here
        // would emit curl lines that 404 at the edge.
        assert_eq!(
            default_actors_post_url("etchit.io"),
            "https://etchit.io/actors"
        );
    }

    #[test]
    fn registration_curl_line_posts_the_doc_as_json() {
        let line = registration_curl_line(
            "https://etchit.io/actors",
            std::path::Path::new("actor.json"),
        );
        assert!(
            line.contains("-X POST 'https://etchit.io/actors'"),
            "{line}"
        );
        assert!(line.contains("content-type: application/json"), "{line}");
        assert!(line.contains("--data-binary @'actor.json'"), "{line}");
        // `-i` so the operator sees the status line the bridge picked
        // (201 created vs 200 idempotent vs 403/409 rejections).
        assert!(line.contains(" -i "), "{line}");
    }

    #[test]
    fn registration_curl_line_respects_a_custom_post_url() {
        // The Worker-vs-direct-origin question is an operator decision;
        // the override must flow through verbatim.
        let line = registration_curl_line(
            "https://bridge-origin.etchit.io/actors",
            std::path::Path::new("/tmp/hello.json"),
        );
        assert!(
            line.contains("'https://bridge-origin.etchit.io/actors'"),
            "{line}"
        );
        assert!(line.contains("@'/tmp/hello.json'"), "{line}");
    }

    // ── daemonless connection profile ─────────────────────────────────

    #[test]
    fn resolve_token_daemonless_returns_empty_without_reading_file() {
        // A daemonless peer has no x0xd and therefore no API token. The
        // default token path points at /root/... which is absent on a
        // dev/CI box; daemonless must NOT try to read it (that errors).
        let cli = Cli::parse_from([
            "fetchit-chat-peer",
            "--daemonless",
            "--x0xd-token-path",
            "/nonexistent/definitely/not/here",
            "echo",
        ]);
        assert_eq!(resolve_token(&cli).unwrap(), "");
    }

    #[test]
    fn resolve_token_uses_inline_token_trimmed() {
        let cli = Cli::parse_from([
            "fetchit-chat-peer",
            "--x0xd-token",
            "  inline-secret  ",
            "echo",
        ]);
        assert_eq!(resolve_token(&cli).unwrap(), "inline-secret");
    }

    #[test]
    fn resolve_token_daemon_reads_token_path_file() {
        let tmp = tempfile::tempdir().unwrap();
        let tok = tmp.path().join("api-token");
        std::fs::write(&tok, "file-token\n").unwrap();
        let cli = Cli::parse_from([
            "fetchit-chat-peer",
            "--x0xd-token-path",
            tok.to_str().unwrap(),
            "echo",
        ]);
        assert_eq!(resolve_token(&cli).unwrap(), "file-token");
    }

    #[test]
    fn daemonless_without_passphrase_is_rejected() {
        // No OS keychain on a headless soak host -> a missing passphrase
        // can't be recovered; fail fast with an actionable message.
        let err = require_daemonless_passphrase(true, None).unwrap_err();
        assert!(err.to_string().contains("passphrase"), "{err}");
    }

    #[test]
    fn daemonless_with_empty_passphrase_is_rejected() {
        let err = require_daemonless_passphrase(true, Some("")).unwrap_err();
        assert!(err.to_string().contains("passphrase"), "{err}");
    }

    #[test]
    fn daemonless_with_passphrase_is_accepted() {
        assert!(require_daemonless_passphrase(true, Some("hunter2")).is_ok());
    }

    #[test]
    fn daemon_mode_does_not_require_passphrase() {
        // The x0xd path resolves identity from the daemon, so a
        // passphrase stays optional (keychain fallback) there.
        assert!(require_daemonless_passphrase(false, None).is_ok());
    }

    // ── group-create / group-chat arg parsing ─────────────────────────

    #[test]
    fn group_create_parses_name() {
        // group-create takes a single --name; the handler then drives
        // create_private + invite and prints the two labeled lines.
        let cli = Cli::parse_from(["fetchit-chat-peer", "group-create", "--name", "soak-grp"]);
        match cli.mode {
            Mode::GroupCreate { name } => assert_eq!(name, "soak-grp"),
            other => panic!("expected GroupCreate, got {other:?}"),
        }
    }

    #[test]
    fn group_chat_parses_group_only() {
        // The minimal form: --group with no invite/outbox/cursor. Used
        // when the data-dir has already joined the group and stdin (no
        // outbox) is irrelevant -- the loop still runs the inbound pump.
        let cli = Cli::parse_from(["fetchit-chat-peer", "group-chat", "--group", "soak-grp"]);
        match cli.mode {
            Mode::GroupChat(args) => {
                assert_eq!(args.group, "soak-grp");
                assert_eq!(args.invite_file, None);
                assert_eq!(args.outbox_file, None);
                assert_eq!(args.cursor_file, None);
            }
            other => panic!("expected GroupChat, got {other:?}"),
        }
    }

    #[test]
    fn group_chat_parses_full_outbox_form() {
        // The persistent soak form: join via --invite-file, then drive
        // the atomic-cursor outbox the same way Chat does.
        let cli = Cli::parse_from([
            "fetchit-chat-peer",
            "group-chat",
            "--group",
            "soak-grp",
            "--invite-file",
            "/tmp/invite.txt",
            "--outbox-file",
            "/tmp/outbox.txt",
            "--cursor-file",
            "/tmp/cursor",
        ]);
        match cli.mode {
            Mode::GroupChat(args) => {
                assert_eq!(args.group, "soak-grp");
                assert_eq!(args.invite_file, Some(PathBuf::from("/tmp/invite.txt")));
                assert_eq!(args.outbox_file, Some(PathBuf::from("/tmp/outbox.txt")));
                assert_eq!(args.cursor_file, Some(PathBuf::from("/tmp/cursor")));
            }
            other => panic!("expected GroupChat, got {other:?}"),
        }
    }
}
