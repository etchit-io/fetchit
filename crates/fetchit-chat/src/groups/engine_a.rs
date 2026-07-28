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

/// True when `e` is the engine-A apply endpoints' 409 `{"applied": false}`:
/// the daemon's applier declined without a handler error, which for a
/// bridged join event means REPLAY — the event (or its result) was already
/// converged past, e.g. a re-bridged `member_joined` for a member the owner
/// already admitted. Distinct from the daemon's error-shaped 409s
/// (`{"error": "group is withdrawn"}`), which are real refusals.
///
/// The body is ambiguous between an idempotent replay and a genuine decline
/// (a commit that failed verification also answers `applied: false`), so
/// call sites must react with actions that are safe under BOTH readings —
/// re-serving an already-staged result, or leaving durable pending-join
/// intent in place — never by recording convergence.
pub(crate) fn apply_conflict_409(e: &x0xd_client::X0xdError) -> bool {
    match e {
        x0xd_client::X0xdError::ApplyRejected {
            status: 409,
            detail,
        } => detail.contains("\"applied\""),
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

    #[test]
    fn a_handler_409_applied_false_is_an_apply_conflict() {
        // The engine-A apply endpoints answer an applier decline with
        // 409 {"applied": false} — for a bridged member_joined that is the
        // replay signal (member already admitted) the owner reply path must
        // NOT treat as a dispatch failure.
        let e = x0xd_client::X0xdError::ApplyRejected {
            status: 409,
            detail: "POST /groups/abc/apply-metadata-event: {\"applied\":false}".into(),
        };
        assert!(apply_conflict_409(&e));
    }

    #[test]
    fn error_shaped_409s_and_other_errors_are_not_apply_conflicts() {
        // "group is withdrawn" is the daemon's error-shaped 409 — a real
        // refusal, never the applier's idempotent decline.
        let withdrawn = x0xd_client::X0xdError::ApplyRejected {
            status: 409,
            detail: "POST /groups/abc/join: {\"ok\":false,\"error\":\"group is withdrawn\"}".into(),
        };
        assert!(!apply_conflict_409(&withdrawn));
        let not_conflict = x0xd_client::X0xdError::ApplyRejected {
            status: 404,
            detail: "{\"applied\":false}".into(),
        };
        assert!(!apply_conflict_409(&not_conflict));
        assert!(!apply_conflict_409(&x0xd_client::X0xdError::Rejected(
            "returned 409".into()
        )));
    }
}
