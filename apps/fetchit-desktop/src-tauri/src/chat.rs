//! Tauri bridge for the chat surface — x0xd (identity / contacts /
//! presence / groups) + fetchit relay (DM transport).
//!
//! Lazily builds a [`fetchit_chat::Client`] on first use, configured
//! with the relay URL from settings, exposes a typed command surface
//! to the frontend, and runs background pumps that forward inbound
//! events (relay deliveries, x0xd SSE) to Tauri events
//! (`chat:event`, `chat:presence`, `chat:dm`).

use fetchit_chat::contacts::TrustLevel;
use fetchit_chat::groups::{GroupId, GroupInvite};
use fetchit_chat::identity::{AgentCard, AgentId};
use fetchit_chat::messages::decode_direct_message;
use fetchit_chat::{Client, Event};
use serde::Serialize;
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
}

impl ChatState {
    /// Build a fresh `ChatState` bound to the supplied relay URL.
    ///
    /// # Errors
    /// Returns the parse error if `relay_url` is not a valid URL.
    pub fn new(relay_url: &str) -> Result<Self, String> {
        let url = Url::parse(relay_url).map_err(|e| format!("invalid relay url: {e}"))?;
        Ok(Self {
            client: Arc::new(Mutex::new(None)),
            relay_url: url,
        })
    }

    async fn get(&self) -> Result<Client, String> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let c = Client::builder()
            .relay_url(self.relay_url.clone())
            .build()
            .await
            .map_err(|e| e.to_string())?;
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
    state
        .get()
        .await?
        .identity()
        .import_uri(&uri)
        .await
        .map_err(|e| e.to_string())
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

/// Spawn the background event pumps:
///
/// - **Relay inbound** — drains the relay transport's inbound channel
///   and emits each delivery as a `chat:dm` event.
/// - **x0xd presence SSE** — keeps presence + contact / group state
///   in sync; unchanged by the relay migration.
/// - **x0xd unified SSE** — catch-all for events the relay isn't
///   responsible for (gossip, contacts, groups).
///
/// Each pump owns its own task; reconnections invalidate the cached
/// `Client` so the next iteration re-handshakes with x0xd + relay.
pub fn spawn_event_pump(app: AppHandle, state: ChatState) {
    spawn_relay_dms(app.clone(), state.clone());
    spawn_presence(app.clone(), state.clone());
    spawn_unified(app, state);
}

fn spawn_relay_dms(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
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
                match decode_direct_message(env) {
                    Ok(dm) => emit(&app, &Event::DirectMessage(dm)),
                    Err(e) => log_pump(&format!("[relay] decode: {e}")),
                }
            }
            log_pump("[relay] inbound closed; reconnecting");
            state.invalidate().await;
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
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
