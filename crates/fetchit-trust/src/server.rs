//! Top-level [`Server`] type — axum routes + shared state.

use crate::config::ServerConfig;
use crate::error::TrustError;
use crate::signer::IssuerSigner;
use crate::storage::Storage;
use crate::types::{
    DenylistEntry, DenylistResponse, EntryKind, Health, Report, ReportKind, TargetIdentity,
};
use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{header::ETAG, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::info;

/// Shared state passed to every axum handler.
pub struct ServerState {
    /// Operating config.
    pub config: ServerConfig,
    /// File-backed report + denylist storage.
    pub storage: Arc<Storage>,
    /// ML-DSA-65 issuer that signs denylist responses.
    pub signer: Arc<IssuerSigner>,
}

/// Runtime entry-point for one trust-service node.
pub struct Server {
    state: Arc<ServerState>,
}

impl Server {
    /// Construct a new server, loading or generating the issuer keypair.
    ///
    /// # Errors
    /// Returns any IO / keygen failure encountered during setup.
    pub fn new(config: ServerConfig) -> Result<Self, TrustError> {
        // The admin API (deny/revoke/list) is UNAUTHENTICATED; its only
        // gate is that it binds loopback + is never reverse-proxied, so
        // reachability means shell access to the host. Enforce that
        // invariant in code, not just docs: refuse to start if
        // admin_bind is non-loopback (a misconfigured
        // FETCHIT_TRUST_ADMIN_BIND would otherwise expose deny/revoke to
        // the internet). Mirrors the relay-server's internal_bind guard.
        if !config.admin_bind.ip().is_loopback() {
            return Err(TrustError::Config(format!(
                "admin_bind must be a loopback address (the admin API is unauthenticated); got {}",
                config.admin_bind
            )));
        }
        std::fs::create_dir_all(&config.data_dir)?;
        let storage = Arc::new(Storage::open(config.data_dir.join("trust-snapshot.json"))?);
        let signer = Arc::new(IssuerSigner::load_or_generate(
            &config.data_dir,
            &config.issuer_key_id,
        )?);
        let state = ServerState {
            config,
            storage,
            signer,
        };
        Ok(Self {
            state: Arc::new(state),
        })
    }

    /// Build the axum router and return both it and the shared state.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/health", get(health))
            .route("/v1/report", post(submit_report))
            .route("/v1/denylist", get(denylist_by_kind))
            .route("/v1/denylist/xornames", get(denylist_xornames))
            .route("/v1/denylist/agent_ids", get(denylist_agent_ids))
            .route("/v1/denylist/etag", get(denylist_etag))
            .route("/v1/issuer/public_key", get(issuer_public_key))
            .with_state(self.state.clone())
    }

    /// Loopback-only admin router: `POST /admin/deny`, `POST
    /// /admin/revoke`, `GET /admin/list`.
    ///
    /// Served on `config.admin_bind` (a loopback address) and NEVER
    /// forwarded by the public reverse proxy, so the moderator
    /// credential is shell access to the trust host. A later revision
    /// can require an ML-DSA admin signature on these routes + bind
    /// publicly to support remote moderators without host access; the
    /// handlers are the on-ramp for that.
    pub fn admin_router(&self) -> Router {
        Router::new()
            .route("/admin/deny", post(admin_deny))
            .route("/admin/revoke", post(admin_revoke))
            .route("/admin/list", get(admin_list))
            .with_state(self.state.clone())
    }

    /// Bind and serve forever: the public API on `config.bind` and the
    /// loopback admin API on `config.admin_bind`, concurrently.
    ///
    /// # Errors
    /// Returns any IO error from binding or serving either listener.
    pub async fn run(self) -> Result<()> {
        let public_listener = TcpListener::bind(self.state.config.bind).await?;
        let admin_listener = TcpListener::bind(self.state.config.admin_bind).await?;
        info!(
            public=%self.state.config.bind,
            admin=%self.state.config.admin_bind,
            "fetchit-trust listening",
        );
        let public = self.router();
        let admin = self.admin_router();
        let serve_public = async move { axum::serve(public_listener, public).await };
        let serve_admin = async move { axum::serve(admin_listener, admin).await };
        tokio::try_join!(serve_public, serve_admin)?;
        Ok(())
    }

    /// Borrow the shared state (useful for tests).
    #[must_use]
    pub fn state(&self) -> &Arc<ServerState> {
        &self.state
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ReportSubmit {
    target: TargetIdentity,
    kind: ReportKind,
    reason: String,
    #[serde(default)]
    attached_excerpt: Option<String>,
    #[serde(default)]
    reporter_agent_id_hex: Option<String>,
}

use crate::types::DenylistToSign;

async fn health(State(state): State<Arc<ServerState>>) -> Json<Health> {
    Json(Health {
        ok: true,
        version: format!("fetchit-trust/{}", env!("CARGO_PKG_VERSION")),
        queued_reports: state.storage.reports_len().unwrap_or(0),
        denylisted_xornames: state.storage.xornames_len().unwrap_or(0),
        denylisted_agents: state.storage.agents_len().unwrap_or(0),
    })
}

async fn submit_report(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<ReportSubmit>,
) -> Result<StatusCode, (StatusCode, String)> {
    let report = Report {
        reporter_agent_id_hex: body.reporter_agent_id_hex,
        target: body.target,
        kind: body.kind,
        reason: body.reason,
        attached_excerpt: body.attached_excerpt,
        timestamp_ms: now_ms(),
    };
    state
        .storage
        .enqueue_report(report)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::ACCEPTED)
}

/// Query string for the canonical `GET /v1/denylist?kind=<kind>` route.
/// `kind` deserializes from the `snake_case` [`EntryKind`] discriminant
/// (`xor_name` / `agent_id` / `relay_url` / `actor_url`) — the exact
/// values `fetchit-trust-client::DenylistConsumer` emits. An unknown
/// value fails the extractor with a 400 before any handler logic runs.
#[derive(Debug, Deserialize)]
struct KindQuery {
    kind: EntryKind,
}

/// Canonical denylist route consumed by `fetchit-trust-client` and the
/// fetch>it desktop / reader clients: `GET /v1/denylist?kind=<kind>`.
/// Dispatches all four kinds through the same signed-response path as
/// the legacy `/denylist/xornames` route; kinds with no entries return
/// a validly-signed empty list.
async fn denylist_by_kind(
    State(state): State<Arc<ServerState>>,
    Query(q): Query<KindQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    signed_denylist(&state, q.kind)
}

async fn denylist_xornames(
    State(state): State<Arc<ServerState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    signed_denylist(&state, EntryKind::XorName)
}

async fn denylist_agent_ids(
    State(state): State<Arc<ServerState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    signed_denylist(&state, EntryKind::AgentId)
}

fn signed_denylist(
    state: &Arc<ServerState>,
    kind: EntryKind,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let entries: Vec<DenylistEntry> = state
        .storage
        .denylist_for(kind)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let etag = state
        .storage
        .etag()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let generated_at_ms = now_ms();
    let to_sign = DenylistToSign {
        etag: etag.as_str(),
        generated_at_ms,
        kind,
        entries: &entries,
    };
    let sign_bytes = postcard::to_allocvec(&to_sign)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sig = state
        .signer
        .sign(&sign_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let body = DenylistResponse {
        etag: etag.clone(),
        generated_at_ms,
        kind,
        entries,
        issuer_signature_hex: hex::encode(sig),
        issuer_key_id: state.signer.key_id.clone(),
    };
    Ok(([(ETAG, etag)], Json(body)))
}

async fn denylist_etag(
    State(state): State<Arc<ServerState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let etag = state
        .storage
        .etag()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(([(ETAG, etag.clone())], etag))
}

#[derive(Debug, Serialize)]
struct IssuerKeyResponse {
    key_id: String,
    public_key_hex: String,
}

async fn issuer_public_key(State(state): State<Arc<ServerState>>) -> Json<IssuerKeyResponse> {
    Json(IssuerKeyResponse {
        key_id: state.signer.key_id.clone(),
        public_key_hex: hex::encode(state.signer.public_key_bytes()),
    })
}

/// Body of `POST /admin/deny`. `value` is validated + canonicalized
/// through [`TargetIdentity::try_new`] so a denylist entry always
/// matches the canonical form consumers gate against (hex lowercased,
/// URLs fragment/userinfo-stripped) — the same contract the M4 actor
/// gate relies on.
#[derive(Debug, Deserialize)]
struct AdminDenyRequest {
    kind: EntryKind,
    value: String,
    reason: ReportKind,
}

/// Body of `POST /admin/revoke`.
#[derive(Debug, Deserialize)]
struct AdminRevokeRequest {
    kind: EntryKind,
    value: String,
}

async fn admin_deny(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<AdminDenyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let target = TargetIdentity::try_new(req.kind, req.value)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .storage
        .deny(DenylistEntry {
            target: target.clone(),
            added_at_ms: now_ms(),
            reason: req.reason,
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    info!(action = "deny", kind = ?target.kind, value = %target.value, reason = ?req.reason, "trust admin");
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_revoke(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<AdminRevokeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let target = TargetIdentity::try_new(req.kind, req.value)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .storage
        .allow(&target)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    info!(action = "revoke", kind = ?target.kind, value = %target.value, "trust admin");
    Ok(StatusCode::NO_CONTENT)
}

/// Full moderation view: every denylist entry (all kinds) + the queued
/// report backlog.
#[derive(Serialize)]
struct AdminListResponse {
    denylist: Vec<DenylistEntry>,
    queued_reports: Vec<Report>,
}

async fn admin_list(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<AdminListResponse>, (StatusCode, String)> {
    let mut denylist = Vec::new();
    for kind in [
        EntryKind::XorName,
        EntryKind::AgentId,
        EntryKind::RelayUrl,
        EntryKind::ActorUrl,
    ] {
        denylist.extend(
            state
                .storage
                .denylist_for(kind)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        );
    }
    let queued_reports = state
        .storage
        .list_reports()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminListResponse {
        denylist,
        queued_reports,
    }))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}
