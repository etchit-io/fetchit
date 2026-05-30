//! Tauri bridge for the chat surface — x0xd (identity / contacts /
//! presence / groups) + fetchit relay (DM transport).
//!
//! Lazily builds a [`fetchit_chat::Client`] on first use, configured
//! with the relay URL from settings, exposes a typed command surface
//! to the frontend, and runs background pumps that forward inbound
//! events (relay deliveries, x0xd SSE) to Tauri events
//! (`chat:event`, `chat:presence`, `chat:dm`, `chat:conversation`,
//! `chat:warn`).

use fetchit_chat::contacts::TrustLevel;
use fetchit_chat::conversation::{dispatch_inbound, InboundDispatch};
use fetchit_chat::groups::{GroupId, GroupInvite};
use fetchit_chat::identity::{AgentCard, AgentId};
use fetchit_chat::messages::{DirectMessage, StoredContactCard};
use fetchit_chat::{Client, Event};
use fetchit_relay_proto::AgentId as RelayAgentId;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use url::Url;

const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// Tauri-managed handle to the lazily-built chat client.
#[derive(Clone)]
pub struct ChatState {
    client: Arc<Mutex<Option<Client>>>,
    relay_url: Url,
    data_dir: PathBuf,
    // Plain heap memory — no `zeroize` wrapper because the slot is
    // rebuilt on every set and the UX target accepts the trade-off.
    // Long-term hardening would route this through a `SecretString`
    // crate that zeroes on drop and resists swap-file leaks.
    passphrase: Arc<Mutex<Option<String>>>,
    /// Opt-in toggle for the LAN-direct transport. Stored as an atomic
    /// so `set_lan_direct_enabled` can flip it without holding the
    /// chat-client lock; the flag is read on next `get()` after an
    /// `invalidate()`.
    lan_direct_enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl ChatState {
    /// Build a fresh `ChatState` bound to the supplied relay URL +
    /// chat data dir. `passphrase` is an optional Argon2id passphrase
    /// for headless installs without a working keystore.
    ///
    /// # Errors
    /// Returns the parse error if `relay_url` is not a valid URL.
    pub fn new(
        relay_url: &str,
        data_dir: PathBuf,
        passphrase: Option<String>,
        lan_direct_enabled: bool,
    ) -> Result<Self, String> {
        let url = Url::parse(relay_url).map_err(|e| format!("invalid relay url: {e}"))?;
        Ok(Self {
            client: Arc::new(Mutex::new(None)),
            relay_url: url,
            data_dir,
            passphrase: Arc::new(Mutex::new(passphrase)),
            lan_direct_enabled: Arc::new(std::sync::atomic::AtomicBool::new(lan_direct_enabled)),
        })
    }

    async fn get(&self) -> Result<Client, String> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let passphrase = self.passphrase.lock().await.clone();
        let lan = self
            .lan_direct_enabled
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut builder = Client::builder()
            .relay_url(self.relay_url.clone())
            .data_dir(self.data_dir.clone())
            .enable_lan_direct(lan);
        if let Some(p) = passphrase {
            builder = builder.passphrase(p);
        }
        let c = builder.build().await.map_err(|e| e.to_string())?;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Read the current opt-in flag for LAN-direct delivery. Used by
    /// the Nearby-section frontend wiring (lands in a follow-up
    /// commit alongside the sidebar surface).
    #[allow(dead_code)]
    pub fn lan_direct_enabled(&self) -> bool {
        self.lan_direct_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Flip the opt-in flag and force a rebuild on the next chat call
    /// so the new transport set takes effect.
    pub async fn set_lan_direct_enabled(&self, enabled: bool) {
        self.lan_direct_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        self.invalidate().await;
    }

    /// Force the next call to rebuild — used after a daemon restart
    /// or relay reconnect invalidates the cached client.
    async fn invalidate(&self) {
        *self.client.lock().await = None;
    }
}

/// Wrapper around an identity card with the user-facing share URI
/// pre-computed so the frontend doesn't have to re-encode.
#[derive(Debug, Serialize)]
pub struct CardWithUri {
    card: AgentCard,
    uri: String,
}

/// One row of the Nearby sidebar surface — a LAN-announced peer the
/// transport's mDNS browser has resolved. The frontend filters out
/// `AgentId`s already in its contact store before rendering.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbyPeer {
    /// 64-char hex agent id of the announced peer.
    pub agent_id: String,
    /// First resolved IP from the mDNS record.
    pub ip: String,
    /// Advertised TCP port for the LAN-direct listener.
    pub port: u16,
    /// `Instant::elapsed` since last resolve, in milliseconds.
    pub last_seen_ms_ago: u64,
}

/// Snapshot the LAN-direct peer table — every fresh announce the
/// mDNS browser has resolved. The frontend filters `AgentId`s
/// already in contacts before rendering the Nearby section.
///
/// Returns an empty list when LAN-direct is disabled.
#[tauri::command]
pub async fn chat_list_nearby(
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<NearbyPeer>, String> {
    let client = state.get().await?;
    let Some(lan) = client.lan_transport_arc() else {
        return Ok(Vec::new());
    };
    Ok(lan
        .peer_table()
        .snapshot()
        .into_iter()
        .map(|r| NearbyPeer {
            agent_id: r.agent_id.0,
            ip: r.ip.to_string(),
            port: r.port,
            last_seen_ms_ago: u64::try_from(r.last_seen.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
        .collect())
}

#[tauri::command]
pub async fn chat_health(state: tauri::State<'_, ChatState>) -> Result<bool, String> {
    state
        .get()
        .await?
        .health()
        .await
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
pub async fn chat_identity(
    state: tauri::State<'_, ChatState>,
) -> Result<fetchit_chat::identity::AgentIdentity, String> {
    state
        .get()
        .await?
        .identity()
        .me()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_card(
    state: tauri::State<'_, ChatState>,
    display_name: String,
) -> Result<CardWithUri, String> {
    let client = state.get().await?;
    let card = client
        .identity()
        .card(&display_name)
        .await
        .map_err(|e| e.to_string())?;
    let uri = client
        .identity()
        .extended_share_uri(&display_name)
        .await
        .map_err(|e| e.to_string())?;
    Ok(CardWithUri { card, uri })
}

#[tauri::command]
pub async fn chat_import_card(
    state: tauri::State<'_, ChatState>,
    uri: String,
) -> Result<(), String> {
    // Validate the URI client-side so a malformed paste surfaces a
    // clear error before we hit the daemon.
    AgentCard::from_share_uri(&uri).map_err(|e| e.to_string())?;
    let client = state.get().await?;
    client
        .identity()
        .import_uri(&uri)
        .await
        .map_err(|e| e.to_string())?;
    // Persist the v2 card locally so `chat_send_dm` can bootstrap a
    // Conversation against the peer's KEM key. Best-effort: legacy
    // x0x://agent URIs without v2 fields are silently skipped.
    if let Some(layout) = client.layout() {
        if let Ok(stored) = StoredContactCard::from_share_uri(&uri) {
            if let Err(e) = stored.save(layout) {
                eprintln!("[fetchit][chat] persist v2 card: {e}");
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn chat_contacts(
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<fetchit_chat::contacts::Contact>, String> {
    state
        .get()
        .await?
        .contacts()
        .list()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_set_trust(
    state: tauri::State<'_, ChatState>,
    agent_id: String,
    level: TrustLevel,
) -> Result<(), String> {
    let id = AgentId::parse(agent_id).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .contacts()
        .set_trust(&id, level)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_remove_contact(
    state: tauri::State<'_, ChatState>,
    agent_id: String,
) -> Result<(), String> {
    let id = AgentId::parse(agent_id).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .contacts()
        .remove(&id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_send_dm(
    state: tauri::State<'_, ChatState>,
    to: String,
    body: String,
    sender_name: Option<String>,
) -> Result<Option<String>, String> {
    let id = AgentId::parse(to).map_err(|e| e.to_string())?;
    let name = sender_name.unwrap_or_else(|| "fetchit".to_string());
    state
        .get()
        .await?
        .messages()
        .send(&id, &body, &name)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_dm_connect(
    state: tauri::State<'_, ChatState>,
    agent_id: String,
) -> Result<(), String> {
    let id = AgentId::parse(agent_id).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .messages()
        .connect(&id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_presence_online(
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<fetchit_chat::presence::OnlineAgent>, String> {
    state
        .get()
        .await?
        .presence()
        .online()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_groups_list(
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<fetchit_chat::groups::Group>, String> {
    state
        .get()
        .await?
        .groups()
        .list()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_create(
    state: tauri::State<'_, ChatState>,
    name: String,
    display_name: Option<String>,
) -> Result<fetchit_chat::groups::Group, String> {
    state
        .get()
        .await?
        .groups()
        .create(&name, display_name.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_invite(
    state: tauri::State<'_, ChatState>,
    group_id: String,
) -> Result<String, String> {
    let invite = state
        .get()
        .await?
        .groups()
        .invite(&GroupId(group_id))
        .await
        .map_err(|e| e.to_string())?;
    Ok(invite.0)
}

#[tauri::command]
pub async fn chat_group_join(
    state: tauri::State<'_, ChatState>,
    invite: String,
    display_name: Option<String>,
) -> Result<fetchit_chat::groups::Group, String> {
    state
        .get()
        .await?
        .groups()
        .join(&GroupInvite(invite), display_name.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_send(
    state: tauri::State<'_, ChatState>,
    group_id: String,
    body: String,
) -> Result<Option<String>, String> {
    state
        .get()
        .await?
        .groups()
        .send(&GroupId(group_id), &body)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_leave(
    state: tauri::State<'_, ChatState>,
    group_id: String,
) -> Result<(), String> {
    state
        .get()
        .await?
        .groups()
        .leave(&GroupId(group_id))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_messages(
    state: tauri::State<'_, ChatState>,
    group_id: String,
) -> Result<Vec<fetchit_chat::groups::GroupMessage>, String> {
    state
        .get()
        .await?
        .groups()
        .history(&GroupId(group_id))
        .await
        .map_err(|e| e.to_string())
}

/// Enrol (or update) the Argon2id passphrase used to unlock the chat
/// at-rest vault on headless Linux installs without a working Secret
/// Service. Forces the next call to `state.get()` to rebuild the
/// `Client` so the new passphrase takes effect.
#[tauri::command]
pub async fn chat_set_passphrase(
    state: tauri::State<'_, ChatState>,
    passphrase: String,
) -> Result<(), String> {
    *state.passphrase.lock().await = Some(passphrase);
    state.invalidate().await;
    Ok(())
}

/// Flip the conversation identified by `group_id_hex` from
/// `TrustState::Pending` to `TrustState::Confirmed` and persist.
/// The UI calls this after the user accepts a TOFU contact request
/// surfaced by the `chat:contact-request` event.
///
/// # Errors
/// Returns a stringified error if the client is in REST-only mode,
/// the conversation isn't on disk, or the vault save fails.
/// Subscribe to relay-level presence transitions for `agent_ids` (hex).
///
/// The relay immediately echoes the current online state for each
/// requested agent, and pushes a `chat:presence` event on every
/// subsequent transition. The watch set is owned by the relay client
/// and rehydrated automatically on reconnect.
#[tauri::command]
pub async fn chat_watch_presence(
    state: tauri::State<'_, ChatState>,
    agent_ids: Vec<String>,
) -> Result<(), String> {
    let parsed = parse_relay_agent_ids(&agent_ids)?;
    let client = state.get().await?;
    client
        .watch_relay_presence(&parsed)
        .map_err(|e| e.to_string())
}

/// Drop the relay-level presence subscription for `agent_ids` (hex).
#[tauri::command]
pub async fn chat_unwatch_presence(
    state: tauri::State<'_, ChatState>,
    agent_ids: Vec<String>,
) -> Result<(), String> {
    let parsed = parse_relay_agent_ids(&agent_ids)?;
    let client = state.get().await?;
    client
        .unwatch_relay_presence(&parsed)
        .map_err(|e| e.to_string())
}

fn parse_relay_agent_ids(hex_ids: &[String]) -> Result<Vec<RelayAgentId>, String> {
    let mut out = Vec::with_capacity(hex_ids.len());
    for id in hex_ids {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(id, &mut bytes).map_err(|e| format!("agent_id hex {id}: {e}"))?;
        out.push(RelayAgentId::from_bytes(bytes));
    }
    Ok(out)
}

#[tauri::command]
pub async fn chat_confirm_contact(
    state: tauri::State<'_, ChatState>,
    group_id_hex: String,
) -> Result<(), String> {
    let client = state.get().await?;
    let registry = client.registry_arc().ok_or("no chat state")?;
    let mut conv = registry
        .get(&group_id_hex)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("conversation not found")?;
    conv.confirm_trust();
    registry.save(&conv).await.map_err(|e| e.to_string())
}

/// Spawn the background event pumps:
///
/// - **Relay inbound** — drains the relay transport's inbound channel
///   and dispatches each delivery through `conversation::dispatch_inbound`.
/// - **x0xd presence SSE** — keeps presence + contact / group state
///   in sync; unchanged by the relay migration.
/// - **x0xd unified SSE** — catch-all for events the relay isn't
///   responsible for (gossip, contacts, groups).
pub fn spawn_event_pump(app: AppHandle, state: ChatState) {
    spawn_x0xd_supervisor(state.clone());
    spawn_daemon_watcher(app.clone(), state.clone());
    spawn_relay_inbound(app.clone(), state.clone());
    spawn_lan_inbound(app.clone(), state.clone());
    spawn_lan_mdns(app.clone(), state.clone());
    spawn_relay_presence(app.clone(), state.clone());
    spawn_presence(app.clone(), state.clone());
    spawn_unified(app, state);
}

/// Background task that supervises the local x0xd daemon process.
///
/// Polls discovery every 5 s; whenever x0xd isn't reachable, locates
/// the `x0x` CLI binary and runs `x0x start` to bring the daemon back.
/// `x0x start` self-daemonises and exits, so this task doesn't own a
/// long-lived child handle — it just observes and re-invokes.
///
/// Why this exists: x0xd 0.19.x auto-upgrades itself in-place and exits
/// with the comment "for service manager restart" — assuming systemd or
/// launchd will respawn it. On headless installs, dev shells, and
/// macOS/Windows machines without a service unit, the daemon stays dead
/// and the chat panel silently breaks. This task is fetch>it owning
/// the lifecycle itself so the user never has to know about x0xd's
/// existence, much less its upgrade lifecycle. See issue #153.
///
/// Behaviour:
///
/// - On a fresh box where x0xd has never run, `discover_local` errors
///   out and the supervisor finds an `x0x` binary and starts it.
/// - On a box where x0xd was running and exited (auto-upgrade or
///   crash), the supervisor restarts it within ~5 seconds.
/// - When x0xd is reachable, the supervisor does nothing — no probes,
///   no restarts, no traffic to /agent. The daemon-watcher
///   ([`spawn_daemon_watcher`]) handles the credentials-changed case
///   separately.
/// - If no `x0x` binary can be located (no PATH entry, no install at
///   ~/.local/bin), the supervisor logs once and continues polling
///   silently — no point spamming the log every 5 s.
fn spawn_x0xd_supervisor(state: ChatState) {
    tauri::async_runtime::spawn(async move {
        // Brief initial delay so the very first probe doesn't race the
        // app's own initialisation (build_chat_state may itself trigger
        // discovery while we're still setting up).
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Locate `x0x` once. If it's not on disk we can't self-heal,
        // so log once and stop polling rather than thrash. A future
        // installer that bundles x0xd will write it to a known
        // location and this becomes a no-op.
        let Some(bin) = locate_x0x_binary() else {
            log_pump(
                "[supervisor] no `x0x` binary found in PATH or ~/.local/bin; \
                 chat won't self-heal when x0xd dies. install x0x to fix.",
            );
            return;
        };
        log_pump(&format!("[supervisor] watching x0xd via {}", bin.display()));

        let mut warned_failed_start = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            if fetchit_chat::discovery::discover_local().await.is_ok() {
                warned_failed_start = false;
                continue;
            }

            log_pump("[supervisor] x0xd not reachable; invoking `x0x start`");

            // `x0x start` forks the daemon and the foreground process
            // exits cleanly. We wait for that exit so we don't loop
            // before the daemon's even bound its API port.
            let start_result = tokio::process::Command::new(&bin)
                .arg("start")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;

            match start_result {
                Ok(s) if s.success() => {
                    // Wait up to ~10 s for the daemon to actually publish
                    // its api.port. Invalidate the cached chat client so
                    // the next call rebuilds with the fresh credentials.
                    for _ in 0..20 {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        if fetchit_chat::discovery::discover_local().await.is_ok() {
                            state.invalidate().await;
                            log_pump("[supervisor] x0xd is up");
                            warned_failed_start = false;
                            break;
                        }
                    }
                }
                Ok(s) => {
                    if !warned_failed_start {
                        log_pump(&format!(
                            "[supervisor] `x0x start` exited with status {s}; \
                             leaving daemon-watcher to surface the failure to the UI"
                        ));
                        warned_failed_start = true;
                    }
                }
                Err(e) => {
                    if !warned_failed_start {
                        log_pump(&format!("[supervisor] failed to spawn `x0x start`: {e}"));
                        warned_failed_start = true;
                    }
                }
            }
        }
    });
}

/// Find the `x0x` CLI binary. Checks `PATH` first via `which`, then a
/// short list of well-known install locations so the supervisor works
/// even when `PATH` is missing the user's local bin dir (a common
/// case when fetch>it is launched from a desktop launcher rather than
/// a shell that has sourced ~/.bashrc).
fn locate_x0x_binary() -> Option<std::path::PathBuf> {
    if let Ok(out) = std::process::Command::new("which").arg("x0x").output() {
        if out.status.success() {
            let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !trimmed.is_empty() {
                return Some(std::path::PathBuf::from(trimmed));
            }
        }
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mut candidates = Vec::new();
    if let Some(h) = home {
        candidates.push(h.join(".local/bin/x0x"));
    }
    candidates.push(std::path::PathBuf::from("/usr/local/bin/x0x"));
    candidates.push(std::path::PathBuf::from("/opt/x0x/bin/x0x"));
    candidates.into_iter().find(|p| p.is_file())
}

/// Tag the chat panel can paint on its daemon-status pill. Emitted
/// over the `chat:daemon-status` Tauri event whenever the watcher
/// observes a change in x0xd's discoverability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DaemonStatus {
    /// x0xd discoverable and credentials match what the cached client
    /// was built against. Local sign path expected to work.
    Connected,
    /// x0xd was previously discoverable but its credentials changed
    /// (typically because the daemon restarted with a new token). The
    /// cached chat client has been invalidated; the next chat call
    /// will rebuild against the new credentials.
    Reconnecting,
    /// x0xd's `api.port` / `api-token` files are missing. Daemon is
    /// down. The frontend should show the "Reconnecting…" badge and
    /// stop trying to send.
    Down,
}

/// Background task that watches x0xd's data-dir signature so the
/// chat panel self-heals when the daemon restarts (or
/// auto-upgrades — see issue #153) without requiring the user to
/// re-open the panel.
///
/// Polls `discover_local()` every 3 seconds, compares the
/// (port, token) tuple, and invalidates the cached chat client +
/// emits `chat:daemon-status` whenever it changes or disappears.
/// The next chat operation rebuilds against the new endpoint.
///
/// File-watch over HTTP-probe because: (a) we don't want to spam
/// `/agent` every 3 s for every running fetchit-desktop on a box;
/// (b) the failure modes we've seen all manifest as the daemon
/// rewriting `api.port` / `api-token` on restart, which is exactly
/// what `discover_local` picks up.
fn spawn_daemon_watcher(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        let mut last_sig: Option<(String, String)> = None;
        let mut last_emitted: Option<DaemonStatus> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let cur_sig = match fetchit_chat::discovery::discover_local().await {
                Ok(ep) => Some((ep.base_url, ep.token)),
                Err(_) => None,
            };

            // Determine the status change, if any.
            let status = match (&last_sig, &cur_sig) {
                (None, None) => continue, // pre-existing or stable absence; nothing to report
                (None, Some(_)) => DaemonStatus::Connected,
                (Some(_), None) => DaemonStatus::Down,
                (Some(a), Some(b)) if a == b => DaemonStatus::Connected,
                (Some(_), Some(_)) => DaemonStatus::Reconnecting,
            };

            // Invalidate when the signature changed (rotated credentials
            // OR daemon disappeared) so the next chat call rebuilds.
            if last_sig.as_ref() != cur_sig.as_ref() && last_sig.is_some() {
                state.invalidate().await;
                log_pump("[daemon-watcher] x0xd signature changed, client invalidated");
            }

            // Only emit on edges so the frontend isn't spammed with
            // duplicate "connected" events every 3 s.
            if last_emitted != Some(status) {
                let _ = app.emit("chat:daemon-status", status);
                last_emitted = Some(status);
            }

            last_sig = cur_sig;
        }
    });
}

/// Drive the mDNS lifecycle alongside the LAN-direct transport.
///
/// On each rebuild of the chat client that has LAN enabled, this task
/// spins up a `mdns_sd::ServiceDaemon`, registers a
/// `_fetchit-chat._tcp.local.` service info pointing at the listener's
/// bound port, and pumps `ServiceEvent::ServiceResolved` into the
/// transport's `LanPeerTable`. The daemon runs on its own OS thread
/// (mdns-sd's design), so we just hold the handle alive until the
/// client invalidates and tear down.
///
/// While the daemon is up, emits a `chat:nearby` event every five
/// seconds carrying the current `LanPeerTable` snapshot. The frontend
/// filters its own contacts out client-side.
fn spawn_lan_mdns(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                // Client unavailable: emit an empty snapshot so the
                // Nearby section drains, then back off.
                let _ = app.emit("chat:nearby", &Vec::<NearbyPeer>::new());
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let (Some(lan), Some(bound)) =
                (client.lan_transport_arc().cloned(), client.lan_bound_addr())
            else {
                // LAN-direct isn't wired this round (toggle off or
                // builder path skipped). Drain any prior Nearby state
                // on the UI side, then back off.
                let _ = app.emit("chat:nearby", &Vec::<NearbyPeer>::new());
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };

            let aid_hex = lan.local_agent_id().0.clone();
            let table = lan.peer_table().clone();

            let Some(_daemon) = start_lan_mdns_daemon(&aid_hex, bound.port(), table.clone()) else {
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };

            // Hold the daemon alive until the cached client is replaced
            // (toggle flip or invalidate). While holding, emit the
            // current peer-table snapshot every 5s so the Nearby
            // sidebar stays fresh.
            let lan_for_check = lan.clone();
            loop {
                let snapshot = nearby_snapshot(&table);
                let _ = app.emit("chat:nearby", &snapshot);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let same = match state.client.lock().await.as_ref() {
                    Some(c) => c
                        .lan_transport_arc()
                        .is_some_and(|t| Arc::ptr_eq(t, &lan_for_check)),
                    None => false,
                };
                if !same {
                    log_pump("[lan-mdns] client invalidated; tearing down");
                    let _ = app.emit("chat:nearby", &Vec::<NearbyPeer>::new());
                    break;
                }
            }
            // _daemon drops here -> mdns-sd's daemon thread exits.
        }
    });
}

fn nearby_snapshot(table: &fetchit_chat::lan_discovery::LanPeerTable) -> Vec<NearbyPeer> {
    table
        .snapshot()
        .into_iter()
        .map(|r| NearbyPeer {
            agent_id: r.agent_id.0,
            ip: r.ip.to_string(),
            port: r.port,
            last_seen_ms_ago: u64::try_from(r.last_seen.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
        .collect()
}

/// Start a `ServiceDaemon`, register one `_fetchit-chat._tcp.local.`
/// service info, and attach the browser pump to `table`. Returns the
/// daemon handle (drop = teardown) on success.
fn start_lan_mdns_daemon(
    aid_hex: &str,
    port: u16,
    table: Arc<fetchit_chat::lan_discovery::LanPeerTable>,
) -> Option<mdns_sd::ServiceDaemon> {
    let daemon = match mdns_sd::ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            log_pump(&format!("[lan-mdns] daemon: {e}"));
            return None;
        }
    };
    let aid_short = &aid_hex[..aid_hex.len().min(12)];
    let instance = format!("fetchit-{aid_short}");
    let hostname = format!("fetchit-{aid_short}.local.");
    let ips = local_lan_ipv4s();
    if ips.is_empty() {
        log_pump("[lan-mdns] no routable IPv4 interfaces; skipping announce");
        let _ = daemon.shutdown();
        return None;
    }
    let info = match fetchit_chat::lan_discovery::build_service_info(
        &instance, &hostname, &ips, port, aid_hex,
    ) {
        Ok(i) => i,
        Err(e) => {
            log_pump(&format!("[lan-mdns] service info: {e}"));
            let _ = daemon.shutdown();
            return None;
        }
    };
    if let Err(e) = daemon.register(info) {
        log_pump(&format!("[lan-mdns] register: {e}"));
        let _ = daemon.shutdown();
        return None;
    }
    if let Err(e) = fetchit_chat::lan_discovery::spawn_browser(&daemon, table) {
        log_pump(&format!("[lan-mdns] browse: {e}"));
        let _ = daemon.shutdown();
        return None;
    }
    log_pump(&format!("[lan-mdns] announce + browse on port {port}"));
    Some(daemon)
}

/// Enumerate non-loopback IPv4 interfaces the host can announce on.
/// Loopback is filtered so two distinct processes on one box don't
/// fight over the `127.0.0.1:...` advertisement; LAN-direct is meant
/// for cross-host delivery, not self-loopback.
fn local_lan_ipv4s() -> Vec<std::net::IpAddr> {
    match if_addrs::get_if_addrs() {
        Ok(addrs) => addrs
            .into_iter()
            .filter(|i| !i.is_loopback())
            .filter_map(|i| match i.ip() {
                std::net::IpAddr::V4(v4) => Some(std::net::IpAddr::V4(v4)),
                std::net::IpAddr::V6(_) => None,
            })
            .collect(),
        Err(e) => {
            log_pump(&format!("[lan-mdns] if_addrs: {e}"));
            Vec::new()
        }
    }
}

/// Mirror of [`spawn_relay_inbound`] for the LAN-direct transport.
///
/// `handle_inbound` is transport-agnostic — it dispatches on
/// `env.transit`, not `transport_name` — so the same handler covers
/// both transports verbatim. When LAN-direct is disabled in settings,
/// `take_transport_inbound("lan-direct")` returns `None` and the pump
/// reconnects on a backoff until the toggle flips on.
fn spawn_lan_inbound(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let (Some(identity), Some(registry)) = (client.identity_arc(), client.registry_arc())
            else {
                log_pump("[lan-direct] client built without chat state; abandoning pump");
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let Some(mut rx) = client.take_transport_inbound("lan-direct") else {
                // Either lan-direct isn't wired (toggle off) or the
                // inbound was already taken. Reconnect after a
                // backoff; cheap and self-correcting once the toggle
                // flips on.
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            log_pump("[lan-direct] inbound open");
            while let Some(env) = rx.recv().await {
                handle_inbound(&app, &client, identity.as_ref(), registry.as_ref(), env).await;
            }
            log_pump("[lan-direct] inbound closed; reconnecting");
            state.invalidate().await;
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

fn spawn_relay_presence(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            log_pump("[relay-presence] drain start");
            while let Some(update) = client.next_relay_presence().await {
                let _ = app.emit(
                    "chat:presence",
                    serde_json::json!({
                        "source": "relay",
                        "agent_id": hex::encode(update.agent_id.as_bytes()),
                        "online": update.online,
                    }),
                );
            }
            log_pump("[relay-presence] drain ended; will reattach on rebuild");
            state.invalidate().await;
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

fn spawn_relay_inbound(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let (Some(identity), Some(registry)) = (client.identity_arc(), client.registry_arc())
            else {
                log_pump("[relay] client built without chat state; abandoning pump");
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let Some(mut rx) = client.take_transport_inbound("relay") else {
                log_pump("[relay] inbound already taken; forcing reconnect");
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            log_pump("[relay] inbound open");
            while let Some(env) = rx.recv().await {
                handle_inbound(&app, &client, identity.as_ref(), registry.as_ref(), env).await;
            }
            log_pump("[relay] inbound closed; reconnecting");
            state.invalidate().await;
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

#[allow(clippy::too_many_lines)]
async fn handle_inbound(
    app: &AppHandle,
    client: &Client,
    identity: &fetchit_chat::FetchitIdentity,
    registry: &fetchit_chat::conversation::ConversationRegistry,
    mut env: fetchit_chat::transport::InboundEnvelope,
) {
    if let Some(transit) = env.transit.take() {
        match dispatch_inbound(transit, identity, registry).await {
            Ok(
                InboundDispatch::Welcomed { conversation }
                | InboundDispatch::Rekeyed { conversation },
            ) => {
                let _ = app.emit("chat:conversation", &conversation);
            }
            Ok(InboundDispatch::WelcomedPending { conversation }) => {
                // TOFU first-contact welcome from a sender we'd never
                // heard from. Surface as a contact request so the UI
                // can prompt the user before treating it as a normal
                // conversation.
                let _ = app.emit("chat:contact-request", &conversation);
            }
            Ok(InboundDispatch::WelcomeIgnored) => {
                // Stale or duplicate welcome — no UI signal.
            }
            Ok(InboundDispatch::Message {
                group_id_hex,
                sender_agent_id_hex,
                payload,
            }) => {
                let dm = DirectMessage {
                    from: AgentId(sender_agent_id_hex.clone()),
                    to: None,
                    body: payload.body.clone(),
                    sender_name: payload.sender_name.clone(),
                    timestamp_ms: Some(payload.ts_ms),
                    message_id: payload.message_id.clone(),
                    verified: Some(true),
                };
                let _ = app.emit("chat:dm", &dm);
                let _ = app.emit("chat:event", &Event::DirectMessage(dm));

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
                        log_pump(&format!("[relay] receipt send: {e}"));
                    }
                }
            }
            Ok(InboundDispatch::Receipt {
                group_id_hex,
                sender_agent_id_hex,
                message_id,
                received_at_ms,
            }) => {
                let _ = app.emit(
                    "chat:receipt",
                    serde_json::json!({
                        "group_id": group_id_hex,
                        "sender": sender_agent_id_hex,
                        "message_id": message_id,
                        "received_at_ms": received_at_ms,
                    }),
                );
            }
            Ok(InboundDispatch::StaleEpoch {
                group_id_hex,
                epoch,
            }) => {
                let _ = app.emit(
                    "chat:warn",
                    serde_json::json!({
                        "kind": "stale_epoch",
                        "group_id": group_id_hex,
                        "epoch": epoch,
                    }),
                );
            }
            Ok(InboundDispatch::KemDecapFailed) => {
                let _ = app.emit(
                    "chat:warn",
                    serde_json::json!({ "kind": "kem_decap_failed" }),
                );
            }
            Ok(InboundDispatch::AeadOpenFailed {
                group_id_hex,
                epoch,
            }) => {
                let _ = app.emit(
                    "chat:warn",
                    serde_json::json!({
                        "kind": "aead_open_failed",
                        "group_id": group_id_hex,
                        "epoch": epoch,
                    }),
                );
            }
            Ok(InboundDispatch::Dropped { kind, sender }) => {
                let _ = app.emit(
                    "chat:warn",
                    serde_json::json!({
                        "kind": kind,
                        "sender": sender,
                    }),
                );
            }
            Err(e) => {
                log_pump(&format!("[relay] dispatch error: {e}"));
            }
        }
    } else {
        // Transports that don't carry a TransitEnvelope fall through
        // to the legacy plaintext-envelope decoder.
        match fetchit_chat::messages::decode_direct_message(env) {
            Ok(dm) => {
                let _ = app.emit("chat:dm", &dm);
                let _ = app.emit("chat:event", &Event::DirectMessage(dm));
            }
            Err(e) => log_pump(&format!("[relay] decode: {e}")),
        }
    }
}

fn spawn_presence(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let mut stream = match client.presence_events().await {
                Ok(s) => s,
                Err(e) => {
                    log_pump(&format!("[presence] open failed: {e}"));
                    state.invalidate().await;
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
            };
            log_pump("[presence] stream open");
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => emit(&app, &ev),
                    Err(e) => {
                        log_pump(&format!("[presence] error: {e}"));
                        break;
                    }
                }
            }
            log_pump("[presence] ended; reconnecting");
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

fn spawn_unified(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let mut stream = match client.events().await {
                Ok(s) => s,
                Err(e) => {
                    log_pump(&format!("[unified] open failed: {e}"));
                    state.invalidate().await;
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
            };
            log_pump("[unified] stream open");
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => emit(&app, &ev),
                    Err(e) => {
                        log_pump(&format!("[unified] error: {e}"));
                        break;
                    }
                }
            }
            log_pump("[unified] ended; reconnecting");
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

fn emit(app: &AppHandle, ev: &Event) {
    let _ = app.emit("chat:event", ev);
    match ev {
        Event::DirectMessage(dm) => {
            let _ = app.emit("chat:dm", dm);
        }
        // x0xd's presence stream is a noisy local-activity signal —
        // route it on its own event name so the UI can choose to
        // ignore it. `chat:presence` is reserved for the authoritative
        // relay-level signal from `spawn_relay_presence`.
        Event::Presence(t) => {
            let _ = app.emit("chat:presence:x0x", t);
        }
        _ => {}
    }
}

fn log_pump(msg: &str) {
    eprintln!("[fetchit][chat] {msg}");
}
