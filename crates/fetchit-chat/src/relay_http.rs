//! SSRF guard for relay-bound dials.
//!
//! Reachability V1 introduced the first chat path that issues HTTP
//! requests to relay URLs supplied by contacts (a contact's
//! `advertised_relays` in a signed pair / forwarding record, or a
//! scanned pair-URI). A malicious-but-paired contact can advertise
//! `http://127.0.0.1:<port>`, `http://169.254.169.254` (cloud
//! metadata), `http://[::1]`, RFC1918, or ULA space as their relay; the
//! client would then dial it. This module is the shared gate every
//! relay-bound dial calls before connecting, reusing the canonical
//! [`fetchit_fedi::ssrf`] private-IP primitives rather than growing a
//! parallel implementation.
//!
//! Foundation piece: every item here is consumed by the dial-site
//! wiring that lands in a follow-up task, so the whole module is
//! `dead_code` until then. The `allow` is module-scoped rather than
//! per-item because all of the surface is wired in one follow-up.
#![allow(dead_code)]

use thiserror::Error;

/// Opt-in env var that bypasses the relay SSRF host guard for dev /
/// integration testing. The contract string the desktop crate and any
/// ops tooling key on; kept byte-identical to the desktop precedent in
/// `apps/fetchit-desktop/src-tauri/src/chat.rs`.
pub(crate) const ALLOW_LOCAL_RELAY_ENV: &str = "FETCHIT_ALLOW_LOCAL_RELAY";

/// Whether localhost / private relay hosts are permitted for this dial.
///
/// True in debug builds, or whenever [`ALLOW_LOCAL_RELAY_ENV`] is set.
/// The `debug_assertions` arm keeps dev and test builds working against
/// localhost relays: the headless chat-peer used in the live mission,
/// the desktop `tauri dev` build, and `cargo test` all run debug and
/// must reach a local relay. Shipped release builds have
/// `debug_assertions` off, so the guard is enforced. Evaluated per call
/// so flipping the env var without recompiling takes effect on the next
/// dial.
pub(crate) fn local_relays_allowed() -> bool {
    cfg!(debug_assertions) || std::env::var(ALLOW_LOCAL_RELAY_ENV).is_ok()
}

/// Reasons [`guard_relay_url`] rejects a relay URL before dialing it.
#[derive(Debug, Error)]
pub(crate) enum RelayGuardError {
    /// The relay URL has no host component to validate.
    #[error("relay url has no host")]
    MissingHost,

    /// The host is, or resolves to, private / non-routable IP space.
    #[error("relay host is private or non-routable: {0}")]
    PrivateHost(String),

    /// DNS resolution of the host failed.
    #[error("relay host resolution failed: {0}")]
    Resolve(String),
}

/// Gate a relay URL before any relay-bound dial connects to it.
///
/// Thin wrapper over [`guard_relay_url_with`] that resolves the dev /
/// test carve-out via [`local_relays_allowed`] at call time.
///
/// # Errors
/// - [`RelayGuardError::MissingHost`] when the URL has no host.
/// - [`RelayGuardError::PrivateHost`] when the host is, or resolves to,
///   private / non-routable space.
/// - [`RelayGuardError::Resolve`] when DNS resolution fails.
pub(crate) async fn guard_relay_url(relay: &url::Url) -> Result<(), RelayGuardError> {
    guard_relay_url_with(relay, local_relays_allowed()).await
}

/// Build-profile-independent core of [`guard_relay_url`].
///
/// Split out so tests can pin both the strict (`allow_local = false`)
/// and the carve-out (`allow_local = true`) policy regardless of
/// `debug_assertions`, mirroring the desktop precedent's
/// `validate_relay_url_with`.
///
/// When `allow_local` is true the function returns `Ok(())` immediately
/// without resolving or inspecting the host (the dev / test carve-out).
async fn guard_relay_url_with(relay: &url::Url, allow_local: bool) -> Result<(), RelayGuardError> {
    if allow_local {
        return Ok(());
    }
    let host = relay.host().ok_or(RelayGuardError::MissingHost)?;
    match host {
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
            match fetchit_fedi::ssrf::private_ip_reason(&host) {
                Some(reason) => Err(RelayGuardError::PrivateHost(reason)),
                None => Ok(()),
            }
        }
        url::Host::Domain(name) => {
            let port = relay.port_or_known_default().unwrap_or(443);
            // v1 limitation: this resolves-then-connects, leaving a
            // DNS-rebind TOCTOU window; full address pinning is deferred
            // per the plan, so the validated addrs are intentionally
            // discarded here.
            match fetchit_fedi::ssrf::resolve_and_pin_host(name, port).await {
                Ok(_addrs) => Ok(()),
                Err(fetchit_fedi::ssrf::SsrfError::PrivateAddress { host }) => {
                    Err(RelayGuardError::PrivateHost(host))
                }
                Err(fetchit_fedi::ssrf::SsrfError::Resolve(e)) => Err(RelayGuardError::Resolve(e)),
            }
        }
    }
}

/// Build a [`reqwest::Client`] for relay-bound requests.
///
/// Drop-in replacement for [`reqwest::Client::new`] with redirect
/// following disabled: a relay that answers a guarded request with a
/// `302 -> http://169.254.169.254` (or any other private target) must
/// not be able to bypass the URL-only host check by redirecting the
/// client onward. The `unwrap_or_else` fallback is lint-clean (it is
/// not `.unwrap()`); `reqwest`'s builder only errors on TLS-backend
/// initialization, the same condition under which `Client::new()` is
/// the fallback `reqwest` itself uses.
pub(crate) fn guarded_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use url::Url;

    #[tokio::test]
    async fn guard_with_allow_local_true_accepts_loopback_literal() {
        let url = Url::parse("http://127.0.0.1:8080/").unwrap();
        assert!(guard_relay_url_with(&url, true).await.is_ok());
    }

    #[tokio::test]
    async fn guard_strict_rejects_ipv4_loopback() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::PrivateHost(_)));
    }

    #[tokio::test]
    async fn guard_strict_rejects_rfc1918() {
        let url = Url::parse("http://10.0.0.1/").unwrap();
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::PrivateHost(_)));
    }

    #[tokio::test]
    async fn guard_strict_rejects_aws_metadata() {
        let url = Url::parse("http://169.254.169.254/").unwrap();
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::PrivateHost(_)));
    }

    #[tokio::test]
    async fn guard_strict_rejects_ipv6_loopback() {
        let url = Url::parse("http://[::1]/").unwrap();
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::PrivateHost(_)));
    }

    #[tokio::test]
    async fn guard_strict_rejects_ipv6_unique_local() {
        let url = Url::parse("http://[fc00::1]/").unwrap();
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::PrivateHost(_)));
    }

    #[tokio::test]
    async fn guard_strict_accepts_public_ipv4_literal() {
        let url = Url::parse("https://1.1.1.1/").unwrap();
        assert!(guard_relay_url_with(&url, false).await.is_ok());
    }

    #[tokio::test]
    async fn guard_strict_rejects_localhost_domain() {
        // `localhost` resolves to loopback (127.0.0.1 and/or ::1), so the
        // domain arm's resolve_and_pin_host trips with PrivateHost. Real
        // DNS on `localhost` is hermetic.
        let url = Url::parse("http://localhost/").unwrap();
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::PrivateHost(_)));
    }

    #[tokio::test]
    async fn guard_strict_missing_host_errors() {
        // `mailto:` URLs parse but carry no host; verified inline before
        // asserting the guard maps that to MissingHost.
        let url = Url::parse("mailto:relay@example.com").unwrap();
        assert!(url.host().is_none(), "test url must have no host");
        let err = guard_relay_url_with(&url, false).await.unwrap_err();
        assert!(matches!(err, RelayGuardError::MissingHost));
    }

    #[test]
    fn local_relays_allowed_true_under_debug_assertions() {
        // Documents the test-build posture and guards against a silent
        // flip: cargo test runs debug, so the carve-out is active.
        assert!(local_relays_allowed());
    }

    #[test]
    fn allow_local_env_constant_matches_desktop() {
        assert_eq!(ALLOW_LOCAL_RELAY_ENV, "FETCHIT_ALLOW_LOCAL_RELAY");
    }

    #[test]
    fn guarded_client_builds_without_panicking() {
        // Smoke only. reqwest does not expose the redirect policy for
        // introspection; the redirect-none behavior is covered by an
        // integration-style test in the dial-site wiring task.
        let _c = guarded_client();
    }
}
