//! Tauri bridge for the chat surface — x0xd (identity / contacts /
//! presence / groups) + fetchit relay (DM transport).
//!
//! Lazily builds a [`fetchit_chat::Client`] on first use, configured
//! with the relay URL from settings, exposes a typed command surface
//! to the frontend, and runs background pumps that forward inbound
//! events (relay deliveries, x0xd SSE) to Tauri events
//! (`chat:event`, `chat:presence`, `chat:dm`, `chat:conversation`,
//! `chat:warn`).

use crate::settings::resolve_chat_enabled;
use crate::state::AppState;
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

/// Specific error string returned by every gated chat command when
/// the M0.2 feature flag resolves to off. Pinned as a constant so the
/// frontend (and the unit test below) can rely on the exact text.
pub const CHAT_FEATURE_DISABLED_ERR: &str = "chat feature disabled";

/// Resolve the M0.2 chat feature flag from the live `AppState`
/// settings + env override. The chat UI is hidden when off, but the
/// IPC surface stays registered with Tauri's `invoke_handler`. Each
/// `chat_*` command calls this at the top so a caller reaching
/// `__TAURI_INTERNALS__.invoke` (`DevTools`, malicious renderer code,
/// extension surface) cannot drive the chat stack while the user-
/// facing toggle is off.
///
/// The check re-resolves per call so a runtime flip via Settings →
/// Advanced or a `FETCHIT_CHAT_ENABLED` env change takes effect on
/// the very next IPC, matching the existing
/// [`crate::chat_feature_enabled`] command's behaviour.
fn ensure_chat_enabled(app_state: &AppState) -> Result<(), String> {
    let enabled = app_state
        .settings
        .lock()
        .map_or_else(|_| cfg!(debug_assertions), |s| resolve_chat_enabled(&s));
    if enabled {
        Ok(())
    } else {
        Err(CHAT_FEATURE_DISABLED_ERR.to_owned())
    }
}

const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// Tauri-managed handle to the lazily-built chat client.
#[derive(Clone)]
pub struct ChatState {
    client: Arc<Mutex<Option<Client>>>,
    /// Mutable relay URL — switched at runtime by `set_relay_url` when
    /// the user picks a different region in Settings. Reads are
    /// infrequent (only on client rebuild), so a plain `std::sync::Mutex`
    /// is fine; never held across an `.await` point.
    relay_url: Arc<std::sync::Mutex<Url>>,
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
    /// Base URL for the locally-managed x0xd instance, set when the
    /// supervisor picks the bundled binary and binds it to a known port.
    /// `None` when using an installed x0xd (discovery falls through to
    /// `discover_local()` in `fetchit_chat::Client::builder().build()`).
    x0xd_base_url: Option<String>,
}

impl ChatState {
    /// Build a fresh `ChatState` bound to the supplied relay URL +
    /// chat data dir. `passphrase` is an optional Argon2id passphrase
    /// for headless installs without a working keystore. `x0xd_base_url`
    /// pins the daemon URL when the supervisor manages the bundled x0xd;
    /// `None` falls through to `discover_local()` on the first `get()`.
    ///
    /// # Errors
    /// Returns the parse error if `relay_url` is not a valid URL.
    pub fn new(
        relay_url: &str,
        data_dir: PathBuf,
        passphrase: Option<String>,
        lan_direct_enabled: bool,
        x0xd_base_url: Option<String>,
    ) -> Result<Self, String> {
        // Go through the same validation path as `set_relay_url` so a
        // hand-edited `settings.json` with a loopback or reserved
        // host can't sneak past the SSRF guard. The
        // FETCHIT_ALLOW_LOCAL_RELAY env bypass still applies for dev
        // testing.
        let url = validate_relay_url(relay_url)?;
        Ok(Self {
            client: Arc::new(Mutex::new(None)),
            relay_url: Arc::new(std::sync::Mutex::new(url)),
            data_dir,
            passphrase: Arc::new(Mutex::new(passphrase)),
            lan_direct_enabled: Arc::new(std::sync::atomic::AtomicBool::new(lan_direct_enabled)),
            x0xd_base_url,
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
        let relay_url = self
            .relay_url
            .lock()
            .map_err(|e| format!("relay_url lock poisoned: {e}"))?
            .clone();
        let mut builder = Client::builder()
            .relay_url(relay_url)
            .data_dir(self.data_dir.clone())
            .enable_lan_direct(lan);
        if let Some(p) = passphrase {
            builder = builder.passphrase(p);
        }
        if let Some(ref base) = self.x0xd_base_url {
            builder = builder.base_url(base.clone());
        }
        let c = builder.build().await.map_err(|e| e.to_string())?;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Snapshot the current relay URL. Used by the pair-share command
    /// to assemble the v3 share URI from the same relay the chat
    /// client is talking to. Lock is held for a clone-and-drop only.
    #[must_use]
    pub fn relay_url(&self) -> Url {
        self.relay_url
            .lock()
            .map_or_else(|p| p.into_inner().clone(), |g| g.clone())
    }

    /// Swap the relay URL and force a client rebuild so the next chat
    /// call connects to the new region. Delegates to
    /// [`validate_relay_url`] for the parse + scheme + path checks.
    ///
    /// # Errors
    /// Returns an error if the URL is malformed, uses an unsupported
    /// scheme (anything other than `http`/`https`), or has a non-root
    /// path component.
    pub async fn set_relay_url(&self, url: &str) -> Result<(), String> {
        let parsed = validate_relay_url(url)?;
        match self.relay_url.lock() {
            Ok(mut g) => *g = parsed,
            Err(p) => *p.into_inner() = parsed,
        }
        self.invalidate().await;
        Ok(())
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<NearbyPeer>, String> {
    ensure_chat_enabled(&app_state)?;
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
pub async fn chat_health(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<bool, String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<fetchit_chat::identity::AgentIdentity, String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    display_name: String,
) -> Result<CardWithUri, String> {
    ensure_chat_enabled(&app_state)?;
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

/// M3 Phase E2: regenerate the v2 extended share card with a fresh
/// list of advertised relays in its `fetchit_rendezvous_hints` slot.
///
/// The frontend Settings → Network → Advanced panel drives this
/// after the user edits + saves the list. Validation (non-empty,
/// `wss://` only, <= 8 entries, <= 256 chars per entry) happens
/// inside [`fetchit_chat::Client::regenerate_card_with_relays`] via
/// `RendezvousHintsV1::from_value`; a rejection surfaces as a
/// `String` error the frontend renders verbatim.
#[tauri::command]
pub async fn chat_regenerate_card_with_relays(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    relays: Vec<String>,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
    state
        .get()
        .await?
        .regenerate_card_with_relays(relays)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_import_card(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    uri: String,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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

/// Result of a successful `chat_pair_accept` — the imported peer's
/// `agent_id` so the frontend can navigate to the new DM, plus a
/// `cross_relay` hint when the offerer's published relay differs
/// from the local user's so the UI can warn the user that messages
/// won't deliver until one of them switches regions.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairAccepted {
    /// 64-hex lowercase `agent_id` of the imported contact.
    pub agent_id_hex: String,
    /// Offerer's relay URL as embedded in their v3 share URI. The
    /// frontend uses this to render a "they're on a different relay"
    /// hint when it differs from the local user's `relay_url`
    /// setting.
    pub offerer_relay_url: String,
    /// True when the offerer's relay URL differs from the local
    /// user's. Until cross-relay federation lands, messages between
    /// two peers on different relays silently fail — surfacing this
    /// at pair time is the only chance to head the failure off.
    pub cross_relay: bool,
}

/// Accept a v3 share URI (`fetchit://share/v3/...`) the user pasted
/// or scanned. Parses, fetches the offerer's profile-index record
/// from the relay in the URI, verifies the ML-DSA-65 signature,
/// and persists a [`fetchit_chat::messages::StoredContactCard`] so
/// the chat path can immediately DM the new peer.
///
/// `display_name` is left empty until phase 4 (Autonomi fetch of
/// the full `ProfileManifest`) lands; the UI falls back to the
/// `agent_id` prefix label until then.
#[tauri::command]
pub async fn chat_pair_accept(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    uri: String,
) -> Result<PairAccepted, String> {
    ensure_chat_enabled(&app_state)?;
    let client = state.get().await?;
    let layout = client
        .layout()
        .ok_or_else(|| "chat layout not available (REST-only client)".to_string())?;
    let http = reqwest::Client::new();
    // Re-parse the URI here so we can inspect the offerer's relay
    // BEFORE the heavy work; pair_accept re-parses internally
    // anyway, so this is cheap.
    let offerer_uri = fetchit_chat::profile::from_v3_share_uri(&uri).map_err(|e| e.to_string())?;
    let offerer_relay_url = offerer_uri.relay.as_str().to_owned();
    let outcome = fetchit_chat::pair::pair_accept(&uri, &http, layout)
        .await
        .map_err(|e| e.to_string())?;
    // Best-effort dual-write to x0xd's /agent/card/import so the
    // daemon-backed contact list (`chat_contacts`) surfaces the new
    // peer. Failure here MUST NOT block the send path — the v3
    // KEM/DSA keys already live in StoreLayout, which is what the
    // encrypted-DM transport reads. Closes #155 for the v3 path.
    match fetchit_chat::pair::record_to_legacy_share_uri(&outcome.record) {
        Ok(legacy_uri) => {
            if let Err(e) = client.identity().import_uri(&legacy_uri).await {
                eprintln!("[fetchit][chat] x0xd contact import (best-effort): {e}");
            }
        }
        Err(e) => eprintln!("[fetchit][chat] build legacy share URI: {e}"),
    }
    // Cross-relay detection — normalise both sides via Url so trailing
    // slashes and case differences don't false-positive.
    let our_relay = state.relay_url();
    let cross_relay = !urls_same_origin(&our_relay, &offerer_uri.relay);
    Ok(PairAccepted {
        agent_id_hex: outcome.agent_id_hex,
        offerer_relay_url,
        cross_relay,
    })
}

/// True when two relay URLs point at the same origin — that is, same
/// scheme, host, and port. Trailing-slash differences and
/// case-insensitive host comparisons are normalised by `url::Url`.
/// Returns `false` when either side has no host (only possible for a
/// malformed URL that previously slipped past validation).
fn urls_same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Build the local user's v3 share URI by self-looking-up their
/// profile-index record on the relay.
///
/// Returns an error when the local user hasn't published a profile
/// yet — the relay has no record under their `agent_id`. Once
/// etch>it's Profile-tab has run a publish, this command succeeds
/// and the frontend renders the result as a QR code.
#[tauri::command]
pub async fn chat_pair_share(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<String, String> {
    ensure_chat_enabled(&app_state)?;
    let client = state.get().await?;
    let me = client.identity().me().await.map_err(|e| e.to_string())?;
    // Build the relay's profile-index URL from the client's
    // configured relay. The chat ClientBuilder stores it on the
    // state, not on the Client surface; re-read from the source of
    // truth here.
    let relay = state.relay_url();
    let http = reqwest::Client::new();
    let url = relay
        .join(&format!("v1/profile/{}", me.agent_id.0))
        .map_err(|e| format!("build relay URL: {e}"))?;
    let resp = http
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("relay fetch: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Err(
            "Publish your profile first — open the Profile tab in etch>it and click Publish."
                .to_string(),
        );
    }
    if !resp.status().is_success() {
        return Err(format!("relay returned {}", resp.status()));
    }
    let record: fetchit_chat::pair::ProfileIndexRecord =
        resp.json().await.map_err(|e| format!("relay JSON: {e}"))?;
    let parsed_relay = relay.clone();
    fetchit_chat::profile::to_v3_share_uri(&record.agent_id, &record.profile_addr, &parsed_relay)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_contacts(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<fetchit_chat::contacts::Contact>, String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    agent_id: String,
    level: TrustLevel,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    agent_id: String,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    to: String,
    body: String,
    sender_name: Option<String>,
) -> Result<Option<String>, String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    agent_id: String,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<fetchit_chat::presence::OnlineAgent>, String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
) -> Result<Vec<fetchit_chat::groups::Group>, String> {
    ensure_chat_enabled(&app_state)?;
    state
        .get()
        .await?
        .groups()
        .list()
        .await
        .map_err(|e| e.to_string())
}

/// Which group-creation surface the dialog routed through.
///
/// `PrivateSecure` is the default user-facing path — it calls
/// `groups::create_private`, producing a PQ-encrypted x0x MLS room with
/// `Hidden` visibility. `PublicOpen` preserves the legacy plaintext-on-relay
/// path for opt-in public rooms.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateGroupPreset {
    /// PQ-encrypted via x0x MLS; routes to `groups::create_private`.
    PrivateSecure,
    /// Plaintext on relay; routes to the legacy `groups::create`.
    PublicOpen,
}

#[tauri::command]
pub async fn chat_group_create(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    name: String,
    display_name: Option<String>,
    preset: CreateGroupPreset,
) -> Result<fetchit_chat::groups::Group, String> {
    ensure_chat_enabled(&app_state)?;
    let chat = state.get().await?;
    match preset {
        CreateGroupPreset::PrivateSecure => {
            chat.groups()
                .create_private(&name, display_name.as_deref())
                .await
        }
        CreateGroupPreset::PublicOpen => chat.groups().create(&name, display_name.as_deref()).await,
    }
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_invite(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    group_id: String,
) -> Result<String, String> {
    ensure_chat_enabled(&app_state)?;
    let gid = GroupId::parse(&group_id).map_err(|e| e.to_string())?;
    let invite = state
        .get()
        .await?
        .groups()
        .invite(&gid)
        .await
        .map_err(|e| e.to_string())?;
    Ok(invite.0)
}

#[tauri::command]
pub async fn chat_group_join(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    invite: String,
    display_name: Option<String>,
) -> Result<fetchit_chat::groups::Group, String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    group_id: String,
    body: String,
) -> Result<Option<String>, String> {
    ensure_chat_enabled(&app_state)?;
    let gid = GroupId::parse(&group_id).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .groups()
        .send(&gid, &body)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_leave(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    group_id: String,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
    let gid = GroupId::parse(&group_id).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .groups()
        .leave(&gid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn chat_group_messages(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    group_id: String,
) -> Result<Vec<fetchit_chat::groups::GroupMessage>, String> {
    ensure_chat_enabled(&app_state)?;
    let gid = GroupId::parse(&group_id).map_err(|e| e.to_string())?;
    state
        .get()
        .await?
        .groups()
        .history(&gid)
        .await
        .map_err(|e| e.to_string())
}

/// Enrol (or update) the Argon2id passphrase used to unlock the chat
/// at-rest vault on headless Linux installs without a working Secret
/// Service. Forces the next call to `state.get()` to rebuild the
/// `Client` so the new passphrase takes effect.
#[tauri::command]
pub async fn chat_set_passphrase(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    passphrase: String,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    agent_ids: Vec<String>,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
    let parsed = parse_relay_agent_ids(&agent_ids)?;
    let client = state.get().await?;
    client
        .watch_relay_presence(&parsed)
        .map_err(|e| e.to_string())
}

/// Drop the relay-level presence subscription for `agent_ids` (hex).
#[tauri::command]
pub async fn chat_unwatch_presence(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    agent_ids: Vec<String>,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    group_id_hex: String,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
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
    spawn_relay_conn_state(app.clone(), state.clone());
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
    // When the bundled supervisor is managing a private x0xd instance, skip
    // the legacy path-based poller. Running both would race over `x0x start`
    // against a process the new supervisor already owns on a managed port.
    if crate::BUNDLED_SUPERVISOR_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
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

/// Find the `x0x` CLI binary. Walks the PATH env var directly (no
/// shell-out to `which`, which doesn't exist on Windows) and falls
/// back to a short list of well-known install locations so the
/// supervisor works even when PATH is missing the user's local bin
/// dir — a common case when fetch>it is launched from a desktop
/// launcher rather than a shell that has sourced `~/.bashrc`.
///
/// On Windows the executable carries a `.exe` suffix; both the PATH
/// walk and the candidate list account for that.
///
/// Behaviour divergence from `which`: `path.is_file()` does NOT
/// check the Unix executable bit. A non-executable `x0x` on PATH
/// would be returned here, then fail on spawn with `EACCES` — the
/// supervisor catches that and logs it. Acceptable trade-off: a
/// non-executable binary on PATH means a broken install, and the
/// spawn error surfaces a useful diagnostic instead of silently
/// skipping a misnamed file the user thought was the real binary.
fn locate_x0x_binary() -> Option<std::path::PathBuf> {
    let exe_name = if cfg!(windows) { "x0x.exe" } else { "x0x" };

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if cfg!(windows) {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(std::path::PathBuf::from(local).join("Programs/x0x/x0x.exe"));
        }
        if let Some(home) = std::env::var_os("USERPROFILE") {
            candidates.push(std::path::PathBuf::from(home).join(".local/bin/x0x.exe"));
        }
    } else {
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(std::path::PathBuf::from(home).join(".local/bin/x0x"));
        }
        candidates.push(std::path::PathBuf::from("/usr/local/bin/x0x"));
        candidates.push(std::path::PathBuf::from("/opt/x0x/bin/x0x"));
    }
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

/// Pump the relay-client's connection-state watch into a Tauri event
/// so the frontend can surface a transient "lost connection" notice
/// when the supervisor hits its reconnect cap and stops trying.
/// Only emits the terminal `PermanentlyDisconnected` transition —
/// transient Disconnected / Connecting noise stays in-process so the
/// notice stack isn't spammed during normal flaky-network operation.
fn spawn_relay_conn_state(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let Some(mut rx) = client.relay_connection_state() else {
                // REST-only / no relay configured — nothing to pump.
                tokio::time::sleep(RECONNECT_BACKOFF * 6).await;
                continue;
            };
            loop {
                let snapshot = if let fetchit_chat::RelayConnState::PermanentlyDisconnected {
                    reason,
                    attempts,
                } = rx.borrow().clone()
                {
                    Some((reason, attempts))
                } else {
                    None
                };
                if let Some((reason, attempts)) = snapshot {
                    let _ = app.emit(
                        "chat:relay-status",
                        serde_json::json!({
                            "kind": "permanently_disconnected",
                            "reason": reason,
                            "attempts": attempts,
                        }),
                    );
                    // Break the inner loop and fall through to the
                    // outer loop so the next ChatState::invalidate()
                    // (from any path — settings change, daemon
                    // watcher, manual reconnect) rebuilds the chat
                    // client and re-arms this pump against the new
                    // supervisor's watch receiver. Returning here
                    // would orphan all future terminal transitions.
                    break;
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
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
            Ok(InboundDispatch::WelcomeIgnored | InboundDispatch::ReplayDetected { .. }) => {
                // Stale or duplicate welcome, or spec §7 replay drop —
                // observers' problem, not the user's. Silent.
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

/// Opt-in env var that bypasses the loopback / link-local host
/// guard. Mirrors the precedent set by `FETCHIT_LIVE_ADDR` in
/// fetchit-net — devs running a local relay during testing can set
/// this; production builds simply never see it. The check is
/// per-call so flipping the env var without restarting takes effect
/// on the next `set_relay_url`.
const ALLOW_LOCAL_RELAY_ENV: &str = "FETCHIT_ALLOW_LOCAL_RELAY";

fn validate_relay_url(url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid relay url: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("relay url must use http or https, got {other}")),
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(format!(
            "relay url must be a base URL with no path (got {path:?})"
        ));
    }
    if std::env::var(ALLOW_LOCAL_RELAY_ENV).is_err() {
        reject_local_or_reserved(&parsed)?;
    }
    Ok(parsed)
}

/// SSRF guard — reject relay URLs whose host resolves to a loopback,
/// unspecified, link-local, multicast, or broadcast address, or the
/// literal `localhost` domain. Without this guard, a user-entered
/// custom relay could point chat traffic at the in-process media
/// server or any other internal service.
///
/// IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`) are unwrapped
/// before classification so the IPv6 disguise doesn't bypass the
/// IPv4 ruleset. Numeric "dotless" hosts like `127.1` are caught
/// because the url crate parses them as `Host::Ipv4` after RFC 3986
/// normalisation.
fn reject_local_or_reserved(parsed: &Url) -> Result<(), String> {
    let host = parsed.host().ok_or_else(|| {
        "relay url must not point at a local or reserved address (host is missing)".to_owned()
    })?;
    let blocked = || {
        "relay url must not point at a local or reserved address \
         (set FETCHIT_ALLOW_LOCAL_RELAY for dev testing)"
            .to_owned()
    };
    match host {
        url::Host::Ipv4(addr) => {
            if addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_broadcast()
                || addr.is_link_local()
                || addr.is_multicast()
            {
                return Err(blocked());
            }
        }
        url::Host::Ipv6(addr) => {
            if let Some(v4) = ipv6_to_ipv4_mapped(addr) {
                if v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_link_local()
                    || v4.is_multicast()
                {
                    return Err(blocked());
                }
            }
            if addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_multicast()
                || is_ipv6_link_local(addr)
            {
                return Err(blocked());
            }
        }
        url::Host::Domain(name) => {
            let lc = name.to_ascii_lowercase();
            if lc == "localhost" || lc.ends_with(".localhost") {
                return Err(blocked());
            }
        }
    }
    Ok(())
}

/// Stable manual check for IPv6 link-local (`fe80::/10`). The
/// `is_unicast_link_local` method is nightly-only as of Rust 1.78.
fn is_ipv6_link_local(addr: std::net::Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Stable shim for `Ipv6Addr::to_ipv4_mapped`. We re-implement it
/// here so the crate's stable-channel build doesn't need the nightly
/// `ipv6_to_ipv4_mapped` feature.
fn ipv6_to_ipv4_mapped(addr: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = addr.segments();
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
        let octets = addr.octets();
        Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::validate_relay_url;

    #[test]
    fn accepts_http_with_port_no_path() {
        let p = validate_relay_url("http://relay.example:8088").unwrap();
        assert_eq!(p.scheme(), "http");
    }

    #[test]
    fn accepts_https_with_trailing_slash() {
        let p = validate_relay_url("https://relay.example:8443/").unwrap();
        assert_eq!(p.scheme(), "https");
        assert_eq!(p.path(), "/");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let err = validate_relay_url("file:///etc/passwd").unwrap_err();
        assert!(err.contains("http or https"), "{err}");
    }

    #[test]
    fn rejects_javascript_scheme() {
        let err = validate_relay_url("javascript:alert(1)").unwrap_err();
        assert!(err.contains("http or https"), "{err}");
    }

    #[test]
    fn rejects_url_with_non_root_path() {
        let err = validate_relay_url("http://relay.example:8088/prefix/").unwrap_err();
        assert!(err.contains("no path"), "{err}");
    }

    #[test]
    fn rejects_url_with_v1_profile_path() {
        // The exact path `chat_pair_share` would later `Url::join` would
        // collide with — this would silently produce the wrong URL if
        // we let it through.
        let err = validate_relay_url("http://relay.example:8088/v1/profile/abc").unwrap_err();
        assert!(err.contains("no path"), "{err}");
    }

    #[test]
    fn rejects_malformed_url() {
        let err = validate_relay_url("not a url").unwrap_err();
        assert!(err.contains("invalid relay url"), "{err}");
    }

    // The local/reserved-host guard tests must run serially because
    // they touch the process-global env var. The `#[serial]` attr
    // from the `serial_test` crate would be the idiomatic answer;
    // since we don't have that dep pulled in, we keep all env
    // mutation inside a single guard helper that always sets+unsets.
    // Serialise env-touching tests — the relay-url loopback guard
    // reads a process-global env var, so parallel test runs would
    // race. Acquiring this mutex pins one validator at a time.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_local_relay_env<F: FnOnce() -> R, R>(allowed: bool, f: F) -> R {
        let _guard = ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = super::ALLOW_LOCAL_RELAY_ENV;
        let prev = std::env::var_os(key);
        if allowed {
            std::env::set_var(key, "1");
        } else {
            std::env::remove_var(key);
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        out
    }

    #[test]
    fn rejects_ipv4_loopback_127_0_0_1() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://127.0.0.1:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv4_loopback_127_99_0_1() {
        // Full /8 is loopback, not just 127.0.0.1.
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://127.99.0.1:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv4_unspecified() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://0.0.0.0:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv4_link_local() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://169.254.0.1:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv4_multicast() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://224.0.0.1:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv6_loopback() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://[::1]:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv6_unspecified() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://[::]:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv6_link_local() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://[fe80::1]:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv6_multicast() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://[ff02::1]:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_loopback() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://[::ffff:127.0.0.1]:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_localhost_lowercase() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://localhost:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_localhost_mixed_case() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://LocalHost:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn rejects_dotted_localhost_suffix() {
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://my.relay.localhost:8088").unwrap_err();
            assert!(err.contains("local or reserved"), "{err}");
        });
    }

    #[test]
    fn accepts_public_ipv4_relay() {
        with_local_relay_env(false, || {
            // Matches the shipped NYC relay address — must stay
            // accepted or the shipped default breaks on every install.
            let p = validate_relay_url("http://67.207.94.66:8088").unwrap();
            assert_eq!(p.scheme(), "http");
        });
    }

    #[test]
    fn accepts_public_domain_relay() {
        with_local_relay_env(false, || {
            assert!(validate_relay_url("https://relay.example.com:8443").is_ok());
        });
    }

    #[test]
    fn env_bypass_allows_loopback() {
        with_local_relay_env(true, || {
            assert!(validate_relay_url("http://127.0.0.1:8088").is_ok());
            assert!(validate_relay_url("http://localhost:8088").is_ok());
            assert!(validate_relay_url("http://[::1]:8088").is_ok());
        });
    }

    #[test]
    fn urls_same_origin_normalises_trailing_slash_and_case() {
        let a = url::Url::parse("http://relay.example:8088").unwrap();
        let b = url::Url::parse("http://relay.example:8088/").unwrap();
        assert!(super::urls_same_origin(&a, &b));
        let c = url::Url::parse("http://RELAY.example:8088/").unwrap();
        assert!(super::urls_same_origin(&a, &c));
    }

    #[test]
    fn urls_same_origin_distinguishes_by_host_port_scheme() {
        let nyc = url::Url::parse("http://67.207.94.66:8088").unwrap();
        let fra = url::Url::parse("http://159.89.11.217:8088").unwrap();
        let nyc_https = url::Url::parse("https://67.207.94.66:8088").unwrap();
        let nyc_alt_port = url::Url::parse("http://67.207.94.66:9999").unwrap();
        assert!(!super::urls_same_origin(&nyc, &fra));
        assert!(!super::urls_same_origin(&nyc, &nyc_https));
        assert!(!super::urls_same_origin(&nyc, &nyc_alt_port));
    }

    #[test]
    fn locate_x0x_binary_finds_executable_in_path() {
        // Drop a stub binary into a tempdir, set PATH to just that
        // dir, confirm locate_x0x_binary picks it up — exercises the
        // direct PATH walk that replaced the `which` shell-out.
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let exe_name = if cfg!(windows) { "x0x.exe" } else { "x0x" };
        let path = dir.path().join(exe_name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"stub").unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }

        let _guard = ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());
        let found = super::locate_x0x_binary();
        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let found = found.expect("PATH walk should have located the stub");
        assert_eq!(found.file_name().unwrap(), exe_name);
    }

    #[test]
    fn error_message_mentions_env_bypass() {
        // Power users discover the dev-mode bypass via the error
        // text; pin the substring so we don't drop it on a future
        // copy-tweak.
        with_local_relay_env(false, || {
            let err = validate_relay_url("http://127.0.0.1:8088").unwrap_err();
            assert!(err.contains("FETCHIT_ALLOW_LOCAL_RELAY"), "{err}");
        });
    }

    /// Build a minimal `AppState` carrying a `Settings` with the
    /// chat-enabled flag set as requested. Used by the M0.2 gate tests
    /// below; the disk-cache + settings-path arguments are placeholders
    /// — the gate only ever reads `state.settings`.
    fn make_app_state(chat_enabled: bool) -> super::AppState {
        use crate::disk_cache::{DiskCache, Policy};
        use crate::settings::Settings;
        let tmp = tempfile::tempdir().expect("tempdir");
        let disk = std::sync::Arc::new(DiskCache::new(tmp.path().join("disk"), Policy::default()));
        let s = Settings {
            chat_enabled,
            ..Settings::default()
        };
        super::AppState::new(disk, s, tmp.path().join("settings.json"))
    }

    /// Pin the M0.2 gate: when the chat feature flag is off, the
    /// helper every `chat_*` Tauri command calls at the top returns
    /// the canonical disabled error so callers reaching the IPC
    /// surface directly (`DevTools`, malicious renderer code, extension)
    /// cannot drive the chat stack while the user-facing toggle is
    /// off. Serialised against the env-touching guard tests above so
    /// a concurrent `FETCHIT_CHAT_ENABLED=1` set never races us.
    #[test]
    fn ensure_chat_enabled_rejects_when_flag_off() {
        let _guard = ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = crate::settings::CHAT_ENABLED_ENV;
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        let app_state = make_app_state(false);
        let err = super::ensure_chat_enabled(&app_state).unwrap_err();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        assert_eq!(err, super::CHAT_FEATURE_DISABLED_ERR);
    }

    #[test]
    fn ensure_chat_enabled_passes_when_flag_on() {
        let _guard = ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = crate::settings::CHAT_ENABLED_ENV;
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        let app_state = make_app_state(true);
        let result = super::ensure_chat_enabled(&app_state);
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }
}
