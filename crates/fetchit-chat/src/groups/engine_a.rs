//! Detecting a daemon that lacks the fork's engine-A apply endpoints.
//!
//! Stock x0xd (v0.34.3) has no `POST /groups/:id/apply-metadata-event` or
//! `POST /groups/:id/join-result/:member` — those are fork additions, and
//! the daemon serves no capability registry to ask. The only signal is the
//! call itself: a route that does not exist answers `404` with an EMPTY
//! (router-level) body, while the fork's handlers answer their 4xx with
//! the daemon's JSON error shape (`{"error": ...}`).
//!
//! That distinction is load-bearing for warm recovery:
//! [`super::epoch_recovery::log_applier`] must classify a RECORD-level 404
//! ("group not found" for this specific record) as skip-past-poison, but an
//! ENDPOINT-level 404 as "this daemon has no engine-A at all" — skipping on
//! the latter would silently drain the whole group-log unapplied while
//! looking successful. The bias is chosen by failure asymmetry: when a 404
//! carries no JSON error body we treat it as a missing route (engine-A
//! unsupported) and fall back to cold recovery — the safe, visible side —
//! never as a poison record.

/// True when `e` is an HTTP 404 whose body does NOT carry the daemon's
/// JSON error shape — i.e. the route itself is missing (stock daemon),
/// not a handler rejecting this particular record.
pub(crate) fn route_miss_404(e: &x0xd_client::X0xdError) -> bool {
    match e {
        x0xd_client::X0xdError::ApplyRejected {
            status: 404,
            detail,
        } => !detail.contains("\"error\""),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_bare_router_404_is_a_route_miss() {
        // Stock axum answers an unknown route with 404 and an empty body.
        let e = x0xd_client::X0xdError::ApplyRejected {
            status: 404,
            detail: "POST /groups/abc/apply-metadata-event: ".into(),
        };
        assert!(route_miss_404(&e));
    }

    #[test]
    fn a_handler_404_with_the_daemon_error_shape_is_not() {
        // The fork handler's "group not found" is a RECORD fault the warm
        // loop must skip past, never a capability signal.
        let e = x0xd_client::X0xdError::ApplyRejected {
            status: 404,
            detail: "POST /groups/abc/apply-metadata-event: {\"error\":\"group not found\",\"ok\":false}".into(),
        };
        assert!(!route_miss_404(&e));
    }

    #[test]
    fn other_statuses_and_variants_are_not_route_misses() {
        let e = x0xd_client::X0xdError::ApplyRejected {
            status: 500,
            detail: String::new(),
        };
        assert!(!route_miss_404(&e));
        assert!(!route_miss_404(&x0xd_client::X0xdError::Rejected(
            "returned 404".into()
        )));
    }
}
