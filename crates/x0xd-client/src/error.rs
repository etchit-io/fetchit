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
    /// HTTP transport error.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// URL was malformed.
    #[error("url: {0}")]
    Url(#[from] url::ParseError),

    /// x0xd accepted the bearer token but returned a non-OK body, an
    /// unexpected algorithm tag, or refused to sign.
    #[error("x0xd rejected: {0}")]
    Rejected(String),
}
