//! `WebFinger` responder: maps an `acct:` handle to the actor URL.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::server::BridgeState;

/// The `?resource=` query parameter received by the `WebFinger` endpoint.
#[derive(Deserialize)]
pub struct WebFingerQuery {
    resource: String,
}

#[derive(Serialize)]
struct Jrd {
    subject: String,
    links: Vec<JrdLink>,
}

#[derive(Serialize)]
struct JrdLink {
    rel: String,
    #[serde(rename = "type")]
    link_type: String,
    href: String,
}

/// `GET /.well-known/webfinger?resource=acct:<handle>@<domain>`.
///
/// Resolves a local handle to its actor URL when `<domain>` matches the
/// bridge's configured domain and the actor is registered.
pub async fn webfinger(
    State(state): State<Arc<BridgeState>>,
    Query(q): Query<WebFingerQuery>,
) -> impl IntoResponse {
    state.metrics.inc_webfinger();
    let Some((handle, domain)) = parse_acct(&q.resource) else {
        return (
            StatusCode::BAD_REQUEST,
            "resource must be acct:<handle>@<domain>",
        )
            .into_response();
    };
    if !domain.eq_ignore_ascii_case(&state.config.domain) {
        return (StatusCode::NOT_FOUND, "unknown domain").into_response();
    }
    match state.store.actor_by_handle(&handle).await {
        Ok(Some(rec)) => {
            let jrd = Jrd {
                // Canonical subject: echo the configured domain, not the
                // client's casing -- the request domain passed only a
                // case-insensitive match, and RFC 7033 wants the canonical
                // form (strict resolvers byte-compare `subject`). The handle
                // is already canonical: the store lookup is an exact match.
                subject: format!("acct:{handle}@{}", state.config.domain),
                links: vec![JrdLink {
                    rel: "self".to_owned(),
                    link_type: "application/activity+json".to_owned(),
                    href: rec.actor_url,
                }],
            };
            let body = serde_json::to_string(&jrd).unwrap_or_default();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/jrd+json")],
                body,
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such actor").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webfinger lookup failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// Parse `acct:<handle>@<domain>` into `(handle, domain)`.
fn parse_acct(resource: &str) -> Option<(String, String)> {
    let rest = resource.strip_prefix("acct:")?;
    let (handle, domain) = rest.split_once('@')?;
    if handle.is_empty() || domain.is_empty() {
        return None;
    }
    Some((handle.to_owned(), domain.to_owned()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::parse_acct;

    #[test]
    fn parses_valid_acct() {
        assert_eq!(
            parse_acct("acct:alice@etchit.io"),
            Some(("alice".to_owned(), "etchit.io".to_owned()))
        );
    }

    #[test]
    fn rejects_missing_acct_prefix() {
        assert!(parse_acct("alice@etchit.io").is_none());
    }

    #[test]
    fn rejects_empty_handle_or_domain() {
        assert!(parse_acct("acct:@etchit.io").is_none());
        assert!(parse_acct("acct:alice@").is_none());
        assert!(parse_acct("acct:@").is_none());
    }

    #[test]
    fn splits_on_first_at() {
        assert_eq!(
            parse_acct("acct:user@host@extra"),
            Some(("user".to_owned(), "host@extra".to_owned()))
        );
    }
}
