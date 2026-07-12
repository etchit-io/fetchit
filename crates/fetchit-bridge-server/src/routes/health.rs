//! Health + metrics endpoints.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::server::BridgeState;

/// `/health` response body.
#[derive(Serialize)]
pub struct Health {
    /// Always `true` while serving.
    pub ok: bool,
    /// Build identifier.
    pub version: String,
}

/// `GET /health` — liveness + version.
pub async fn health(State(state): State<Arc<BridgeState>>) -> Json<Health> {
    Json(Health {
        ok: true,
        version: state.config.server_version.clone(),
    })
}

/// `GET /metrics` — Prometheus text exposition.
pub async fn metrics(State(state): State<Arc<BridgeState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render_prometheus(),
    )
}
