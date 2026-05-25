//! Tauri bridge for the x0xd gossip-daemon client.
//!
//! Lazily builds a [`fetchit_chat::Client`] on first use, exposes a
//! typed command surface to the frontend, and runs a background pump
//! that forwards the daemon's SSE events to Tauri events
//! (`chat:event`, `chat:presence`, `chat:dm`).

use fetchit_chat::contacts::TrustLevel;
use fetchit_chat::groups::{GroupId, GroupInvite};
use fetchit_chat::identity::{AgentCard, AgentId};
use fetchit_chat::{Client, Event};
use serde::Serialize;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// Tauri-managed handle to the lazily-built chat client.
#[derive(Clone, Default)]
pub struct ChatState {
    client: Arc<Mutex<Option<Client>>>,
}

impl ChatState {
    async fn get(&self) -> Result<Client, String> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let c = Client::auto().await.map_err(|e| e.to_string())?;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Force the next call to rebuild — used after a daemon restart
    /// invalidates the discovered port/token.
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
    state.get().await?.health().await.map_err(|e| e.to_string())?;
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
    let card = AgentCard::from_share_uri(&uri).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .identity()
        .import(&card)
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

/// Spawn the background SSE event pump. Reconnects with backoff on
/// disconnect or daemon-not-running. Emits Tauri events:
///
/// - `chat:event` — every event with the typed variant tag
/// - `chat:dm` — DMs only, body shape: [`fetchit_chat::messages::DirectMessage`]
/// - `chat:presence` — presence transitions only
pub fn spawn_event_pump(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let client = match state.get().await {
                Ok(c) => c,
                Err(e) => {
                    log_pump(&format!("daemon not reachable: {e}"));
                    state.invalidate().await;
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
            };
            let mut stream = match client.events().await {
                Ok(s) => s,
                Err(e) => {
                    log_pump(&format!("event stream open failed: {e}"));
                    state.invalidate().await;
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
            };
            log_pump("event stream open");
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => emit(&app, &ev),
                    Err(e) => {
                        log_pump(&format!("event stream error: {e}"));
                        break;
                    }
                }
            }
            log_pump("event stream ended; reconnecting");
            state.invalidate().await;
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
