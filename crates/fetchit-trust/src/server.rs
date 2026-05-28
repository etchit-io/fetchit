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
    extract::State,
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
            .route("/v1/denylist/xornames", get(denylist_xornames))
            .route("/v1/denylist/agent_ids", get(denylist_agent_ids))
            .route("/v1/denylist/etag", get(denylist_etag))
            .route("/v1/issuer/public_key", get(issuer_public_key))
            .with_state(self.state.clone())
    }

    /// Bind and serve forever.
    ///
    /// # Errors
    /// Returns any IO error from binding or serving.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.state.config.bind).await?;
        info!(bind=%self.state.config.bind, "fetchit-trust listening");
        axum::serve(listener, self.router()).await?;
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

#[derive(Serialize)]
struct DenylistToSign<'a> {
    etag: &'a str,
    generated_at_ms: u64,
    kind: EntryKind,
    entries: &'a [DenylistEntry],
}

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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}
