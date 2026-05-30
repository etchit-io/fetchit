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
            lan_direct_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                lan_direct_enabled,
            )),
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
    spawn_relay_inbound(app.clone(), state.clone());
    spawn_lan_inbound(app.clone(), state.clone());
    spawn_lan_mdns(state.clone());
    spawn_relay_presence(app.clone(), state.clone());
    spawn_presence(app.clone(), state.clone());
    spawn_unified(app, state);
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
fn spawn_lan_mdns(state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let (Some(lan), Some(bound)) = (
                client.lan_transport_arc().cloned(),
                client.lan_bound_addr(),
            ) else {
                // LAN-direct isn't wired this round (toggle off or
                // builder path skipped). Wait and re-check on the
                // next rebuild.
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };

            let aid_hex = lan.local_agent_id().0.clone();
            let table = lan.peer_table().clone();

            let Some(_daemon) = start_lan_mdns_daemon(&aid_hex, bound.port(), table.clone())
            else {
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };

            // Hold the daemon alive until the cached client is replaced
            // (toggle flip or invalidate). `Arc::ptr_eq` on the
            // transport handle is the cheapest identity check we have.
            let lan_for_check = lan.clone();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let same = match state.client.lock().await.as_ref() {
                    Some(c) => c
                        .lan_transport_arc()
                        .is_some_and(|t| Arc::ptr_eq(t, &lan_for_check)),
                    None => false,
                };
                if !same {
                    log_pump("[lan-mdns] client invalidated; tearing down");
                    break;
                }
            }
            // _daemon drops here -> mdns-sd's daemon thread exits.
        }
    });
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
