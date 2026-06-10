//! Typed error surface for x0xd-client.

use std::path::PathBuf;
use thiserror::Error;

/// Why [`discover_local`](crate::discover_local) or
/// [`discover_in`](crate::discover_in) failed.
///
/// Callers branch on the variant to distinguish "x0xd has never run on
/// this box" from "x0xd is installed but not currently running" from
/// "the daemon files are corrupt".
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The parent data directory does not exist — x0xd has never been
    /// installed or has been wiped.
    #[error("x0xd not installed: {0} is missing")]
    NotInstalled(PathBuf),

    /// The data directory exists but the named file (`api.port` or
    /// `api-token`) is absent — x0xd is installed but not running.
    #[error("x0xd not running: {0} missing")]
    NotRunning(&'static str),

    /// The filesystem rejected a read with `PermissionDenied`.
    #[error("permission denied reading {path}: {source}")]
    PermissionDenied {
        /// The file or directory that was being read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// File content was unreadable or unparsable (empty `api.port`,
    /// non-UTF-8 token, etc.).
    #[error("x0xd metadata malformed: {0}")]
    Malformed(String),

    /// `api.port` / `api-token` exist but nothing answered at the
    /// recorded address — almost always a stale `api.port` left behind
    /// by a daemon that died without cleaning up. Returned by the
    /// liveness-verified discovery paths only.
    #[error(
        "x0xd not running: {base_url} unreachable (stale api.port from a dead daemon?): {detail}"
    )]
    Unreachable {
        /// The base URL the on-disk metadata pointed at.
        base_url: String,
        /// Transport-level failure, full cause chain.
        detail: String,
    },

    /// Other I/O failure — disk error, etc.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Why an [`X0xdSigner`](crate::X0xdSigner) call failed.
///
/// Distinct from [`DiscoveryError`] because the daemon is *running* by
/// the time we talk to its HTTP API — these are transport / protocol
/// faults, not "is it there?" questions.
#[derive(Debug, Error)]
pub enum X0xdError {
    /// HTTP transport error. The message carries the full `source()`
    /// chain via [`render_reqwest_chain`], because reqwest's own
    /// Display stops at "error sending request for url (...)" and hides
    /// the transport cause — connection refused, DNS, a dropped tokio
    /// runtime — which is exactly what tells a dead daemon apart from a
    /// client-side fault.
    #[error("http: {}", render_reqwest_chain(.0))]
    Http(#[from] reqwest::Error),

    /// URL was malformed.
    #[error("url: {0}")]
    Url(#[from] url::ParseError),

    /// x0xd accepted the bearer token but returned a non-OK body, an
    /// unexpected algorithm tag, or refused to sign.
    #[error("x0xd rejected: {0}")]
    Rejected(String),

    /// Caller-supplied input failed local validation before any HTTP
    /// round-trip — malformed group id, non-hex characters, wrong
    /// length, etc. Distinct from `Rejected` (daemon-side refusal) so
    /// callers can branch on "the bytes never left this process".
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Render a reqwest error together with its full `source()` chain.
///
/// reqwest's `Display` reports only the top frame (e.g. `error sending
/// request for url (http://127.0.0.1:12700/health)`), which is the same
/// string whether the daemon is down, the address is wrong, or the
/// connection was reset. Appending each `source()` frame surfaces the
/// concrete transport cause (`Connection refused (os error 111)`, a DNS
/// failure, a dropped runtime) so an operator can tell those apart from
/// one log line. Loopback clients are built with `.no_proxy()`, so an
/// ambient proxy is never a hidden link in this chain.
pub(crate) fn render_reqwest_chain(e: &reqwest::Error) -> String {
    use std::error::Error;
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A refused loopback connect must render with its underlying cause
    /// appended, not just reqwest's generic top frame — and `.no_proxy()`
    /// must keep the request on the direct loopback path.
    #[tokio::test]
    async fn http_error_renders_full_source_chain() {
        // 127.0.0.1:1 is reserved and never bound, so connect is refused
        // immediately and deterministically (no external network).
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let err: X0xdError = client
            .get("http://127.0.0.1:1/health")
            .send()
            .await
            .expect_err("connect to a reserved port must fail")
            .into();
        let rendered = err.to_string();
        assert!(rendered.starts_with("http: "), "got {rendered:?}");
        // The chain renderer appends at least one cause frame beyond the
        // bare reqwest message (which has no ": " separator of its own).
        let after_prefix = rendered.trim_start_matches("http: ");
        assert!(
            after_prefix.contains(": "),
            "expected an appended source frame, got {rendered:?}"
        );
    }
}
