//! Bridge configuration loaded from the environment.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::BridgeError;

/// Handles that are blocked from open registration via `POST /actors`
/// regardless of attestation validity. Anyone can mint a valid ML-DSA
/// attestation, so without this gate an attacker could squat brand or
/// operator handles (e.g. "admin", "etchit") on this domain. Extend at
/// runtime via the `FETCHIT_BRIDGE_RESERVED_HANDLES` env var.
const DEFAULT_RESERVED_HANDLES: &[&str] = &[
    "etchit",
    "fetchit",
    "admin",
    "administrator",
    "root",
    "support",
    "help",
    "abuse",
    "security",
    "postmaster",
    "webmaster",
    "hostmaster",
    "info",
    "contact",
    "mod",
    "moderator",
    "official",
    "system",
    "bridge",
    "api",
    "www",
    "noreply",
    "no-reply",
];

/// Operating parameters for a bridge node.
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// The fediverse domain this bridge is authoritative for
    /// (the `<domain>` in `acct:<handle>@<domain>`).
    pub domain: String,
    /// Path to the `SQLite` database file.
    pub db_path: PathBuf,
    /// Build identifier advertised at `/health`.
    pub server_version: String,
    /// Handles blocked from open registration regardless of attestation
    /// validity. Seeded from `DEFAULT_RESERVED_HANDLES` and extended via
    /// the `FETCHIT_BRIDGE_RESERVED_HANDLES` env var.
    pub reserved_handles: HashSet<String>,
    /// Burst capacity for the per-IP registration limiter. `0` disables it.
    pub register_burst: u32,
    /// Sustained registration rate per IP, in requests per minute (the token
    /// refill rate). Paired with `register_burst`.
    pub register_per_min: u32,
    /// Number of trusted reverse proxies in front of the bridge. `0`
    /// (default) uses the socket peer IP and ignores `X-Forwarded-For` -- the
    /// secure default for a directly-exposed bridge. Set to the real proxy
    /// count at deploy (behind a TLS terminator / CDN) so the limiter keys on
    /// the real client IP rather than the proxy's.
    pub trusted_proxy_hops: usize,
}

/// Does `domain` look like it carries a port? A fediverse domain must be
/// a bare host: the registration gate string-compares it against an actor
/// URL's host (which never includes a port), so any `:` here would 403
/// every registration. Detected at load so the operator gets a warning
/// rather than a silent reject on every request.
fn domain_has_port(domain: &str) -> bool {
    domain.contains(':')
}

/// A trusted-proxy-hop count above this warns at load: real proxy chains are
/// 1-3, and a value above the true chain length is the spoofable case.
const MAX_SANE_PROXY_HOPS: usize = 4;

/// Whether a trusted-proxy-hop count is suspiciously high (likely a misconfig,
/// and the spoofable case). Warned about at load.
fn proxy_hops_suspicious(hops: usize) -> bool {
    hops > MAX_SANE_PROXY_HOPS
}

/// Parse an environment variable into `T`, falling back to `default` when the
/// variable is unset or unparseable.
fn parse_env_or<T: FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

impl BridgeConfig {
    /// Returns the built-in reserved-handle set derived from
    /// `DEFAULT_RESERVED_HANDLES`. This is the baseline used by
    /// [`from_env`](Self::from_env); callers constructing `BridgeConfig`
    /// literals in tests should call this to populate the field.
    #[must_use]
    pub fn default_reserved_handles() -> HashSet<String> {
        DEFAULT_RESERVED_HANDLES
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// Load from the environment, falling back to defaults.
    ///
    /// Variables: `FETCHIT_BRIDGE_BIND` (default `127.0.0.1:8089`),
    /// `FETCHIT_BRIDGE_DOMAIN` (default `etchit.io`),
    /// `FETCHIT_BRIDGE_DB` (default `./bridge.sqlite`),
    /// `FETCHIT_BRIDGE_RESERVED_HANDLES` (comma-separated extra handles to
    /// block in addition to the built-in list),
    /// `FETCHIT_BRIDGE_REGISTER_BURST` (default `10`),
    /// `FETCHIT_BRIDGE_REGISTER_PER_MIN` (default `10`),
    /// `FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS` (default `0`).
    ///
    /// # Errors
    /// Returns [`BridgeError::Config`] if `FETCHIT_BRIDGE_BIND` is not a
    /// valid socket address.
    pub fn from_env() -> Result<Self, BridgeError> {
        let bind_raw =
            std::env::var("FETCHIT_BRIDGE_BIND").unwrap_or_else(|_| "127.0.0.1:8089".to_owned());
        let bind = SocketAddr::from_str(&bind_raw)
            .map_err(|e| BridgeError::Config(format!("bad FETCHIT_BRIDGE_BIND: {e}")))?;
        let domain =
            std::env::var("FETCHIT_BRIDGE_DOMAIN").unwrap_or_else(|_| "etchit.io".to_owned());
        if domain_has_port(&domain) {
            tracing::warn!(
                "FETCHIT_BRIDGE_DOMAIN ({}) looks like it carries a port; it must \
                 be the bare host (e.g. etchit.io). The registration gate compares \
                 it against an actor URL host, which never includes a port, so a \
                 port here rejects every registration.",
                domain
            );
        }
        let db_path =
            std::env::var("FETCHIT_BRIDGE_DB").unwrap_or_else(|_| "./bridge.sqlite".to_owned());
        let mut reserved_handles = Self::default_reserved_handles();
        if let Ok(extra) = std::env::var("FETCHIT_BRIDGE_RESERVED_HANDLES") {
            reserved_handles.extend(
                extra
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        }
        // Registration limiter: secure-by-default -- enabled with a modest
        // rate, trusting no proxy header until explicitly configured.
        let register_burst = parse_env_or("FETCHIT_BRIDGE_REGISTER_BURST", 10u32);
        let register_per_min = parse_env_or("FETCHIT_BRIDGE_REGISTER_PER_MIN", 10u32);
        let trusted_proxy_hops = parse_env_or("FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS", 0usize);
        if proxy_hops_suspicious(trusted_proxy_hops) {
            tracing::warn!(
                "FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS ({trusted_proxy_hops}) is unusually \
                 high; real proxy chains are 1-3. A value above the actual hop count \
                 lets a client spoof X-Forwarded-For to forge its rate-limit key unless \
                 the origin is firewalled to the trusted edge."
            );
        }
        Ok(Self {
            bind,
            domain,
            db_path: PathBuf::from(db_path),
            server_version: concat!("fetchit-bridge-server/", env!("CARGO_PKG_VERSION")).to_owned(),
            reserved_handles,
            register_burst,
            register_per_min,
            trusted_proxy_hops,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::{domain_has_port, proxy_hops_suspicious, BridgeConfig};

    #[test]
    fn bare_host_has_no_port() {
        assert!(!domain_has_port("etchit.io"));
        assert!(!domain_has_port("bridge.etchit.io"));
    }

    #[test]
    fn high_proxy_hop_count_is_flagged() {
        assert!(!proxy_hops_suspicious(0));
        assert!(!proxy_hops_suspicious(2));
        assert!(!proxy_hops_suspicious(4));
        assert!(proxy_hops_suspicious(5));
    }

    #[test]
    fn ported_host_is_detected() {
        assert!(domain_has_port("etchit.io:443"));
        assert!(domain_has_port("etchit.io:8443"));
        assert!(domain_has_port("bridge-origin.etchit.io:8089"));
    }

    #[test]
    fn default_reserved_handles_contains_brand_and_operator_handles() {
        let handles = BridgeConfig::default_reserved_handles();
        assert!(handles.contains("etchit"), "etchit must be reserved");
        assert!(handles.contains("admin"), "admin must be reserved");
        assert!(!handles.contains("alice"), "alice must NOT be reserved");
    }
}
