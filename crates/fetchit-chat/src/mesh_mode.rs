//! Runtime mesh-mode flip for the embedded/attached x0xd.
//!
//! The Android shell used to flip mesh mode by tearing down and re-serving
//! the in-process daemon. saorsa-gossip-pubsub spawns unstructured tasks
//! with no shutdown API, so a torn-down instance could leave its
//! anti-entropy loop hot-failing ("node not initialized", ~1000/sec) —
//! starving the app and burning battery/data until process death. The
//! replacement: the daemon serves once and stays up; mesh mode flips via
//! `POST /mesh/join` (bootstrap dial phases) and `POST /mesh/quiesce`
//! (disconnect every mesh peer). Nothing is torn down, so no task can be
//! orphaned.

use crate::error::Result;
use crate::http::Http;

/// POST the daemon's mesh-mode endpoint for the requested mode.
///
/// `active = true` → `/mesh/join` (returns as soon as dialing is scheduled);
/// `false` → `/mesh/quiesce` (awaits the disconnect sweep — fast). Both are
/// safe to re-assert: a join while joined re-dials the seed set (bounded),
/// a quiesce while quiet disconnects zero peers. Callers treat any error as
/// retryable — the Android `MeshPolicy` re-asserts on a backoff until the
/// mode sticks.
pub(crate) async fn set_mesh_mode(http: &Http, active: bool) -> Result<()> {
    let path = if active {
        "/mesh/join"
    } else {
        "/mesh/quiesce"
    };
    let _resp: serde_json::Value = http.post_json(path, &serde_json::json!({})).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn server_with(endpoint: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn join_posts_mesh_join() {
        let server = server_with("/mesh/join").await;
        let http = Http::new(server.uri(), "tok".to_owned()).expect("http");
        set_mesh_mode(&http, true).await.expect("join must succeed");
    }

    #[tokio::test]
    async fn quiesce_posts_mesh_quiesce() {
        let server = server_with("/mesh/quiesce").await;
        let http = Http::new(server.uri(), "tok".to_owned()).expect("http");
        set_mesh_mode(&http, false)
            .await
            .expect("quiesce must succeed");
    }

    #[tokio::test]
    async fn daemon_rejection_surfaces_as_error() {
        // A 500 must surface (callers retry on a backoff); swallowing it
        // would let the phone believe the mesh is off while it still burns
        // mobile data.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mesh/quiesce"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let http = Http::new(server.uri(), "tok".to_owned()).expect("http");
        let err = set_mesh_mode(&http, false).await;
        assert!(err.is_err(), "500 must not read as success");
    }
}
