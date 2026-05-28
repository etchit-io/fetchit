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
    ) -> Result<Self, String> {
        let url = Url::parse(relay_url).map_err(|e| format!("invalid relay url: {e}"))?;
        Ok(Self {
            client: Arc::new(Mutex::new(None)),
            relay_url: url,
            data_dir,
            passphrase: Arc::new(Mutex::new(passphrase)),
        })
    }

    async fn get(&self) -> Result<Client, String> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let passphrase = self.passphrase.lock().await.clone();
        let mut builder = Client::builder()
            .relay_url(self.relay_url.clone())
            .data_dir(self.data_dir.clone());
        if let Some(p) = passphrase {
            builder = builder.passphrase(p);
        }
        let c = builder.build().await.map_err(|e| e.to_string())?;
        *guard = Some(c.clone());
        Ok(c)
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
    let uri = card.to_share_uri().map_err(|e| e.to_string())?;
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
    spawn_presence(app.clone(), state.clone());
    spawn_unified(app, state);
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
                handle_inbound(&app, identity.as_ref(), registry.as_ref(), env).await;
            }
            log_pump("[relay] inbound closed; reconnecting");
            state.invalidate().await;
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

async fn handle_inbound(
    app: &AppHandle,
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
            Ok(InboundDispatch::WelcomeIgnored) => {
                // Stale or duplicate welcome — no UI signal.
            }
            Ok(InboundDispatch::Message {
                group_id_hex: _,
                sender_agent_id_hex,
                payload,
            }) => {
                let dm = DirectMessage {
                    from: AgentId(sender_agent_id_hex),
                    to: None,
                    body: payload.body.clone(),
                    sender_name: payload.sender_name.clone(),
                    timestamp_ms: Some(payload.ts_ms),
                    // The v2 conversation layer doesn't carry a per-message
                    // transport id at this seam; the relay's `dedupe_key`
                    // isn't propagated end-to-end yet, and the conversation
                    // payload itself doesn't include one. Leave `None`
                    // until that wiring lands.
                    message_id: None,
                    verified: Some(true),
                };
                let _ = app.emit("chat:dm", &dm);
                let _ = app.emit("chat:event", &Event::DirectMessage(dm));
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
        Event::Presence(t) => {
            let _ = app.emit("chat:presence", t);
        }
        _ => {}
    }
}

fn log_pump(msg: &str) {
    eprintln!("[fetchit][chat] {msg}");
}
