//! Service configuration loaded from environment.

use crate::error::TrustError;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Operating parameters for one trust-service node.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Public HTTP bind address (served behind the TLS reverse proxy).
    pub bind: SocketAddr,
    /// Loopback-only admin bind address for the deny / revoke / list
    /// surface. MUST stay a loopback address: the reverse proxy never
    /// forwards to it, so reachability is gated by shell access to the
    /// host. Defaults to `127.0.0.1:8091`.
    pub admin_bind: SocketAddr,
    /// Working directory holding the snapshot file + issuer key.
    pub data_dir: PathBuf,
    /// Stable identifier for the active issuer key.
    pub issuer_key_id: String,
}

/// Default loopback admin bind (`127.0.0.1:8091`).
fn default_admin_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8091))
}

impl ServerConfig {
    /// Build a config with explicit values; the admin surface defaults
    /// to `127.0.0.1:8091` (override with [`Self::with_admin_bind`]).
    #[must_use]
    pub fn new(bind: SocketAddr, data_dir: PathBuf, issuer_key_id: impl Into<String>) -> Self {
        Self {
            bind,
            admin_bind: default_admin_bind(),
            data_dir,
            issuer_key_id: issuer_key_id.into(),
        }
    }

    /// Override the loopback admin bind address.
    #[must_use]
    pub fn with_admin_bind(mut self, admin_bind: SocketAddr) -> Self {
        self.admin_bind = admin_bind;
        self
    }

    /// Load from environment, falling back to defaults.
    ///
    /// Recognised variables: `FETCHIT_TRUST_BIND` (default
    /// `127.0.0.1:8090`), `FETCHIT_TRUST_ADMIN_BIND` (default
    /// `127.0.0.1:8091`, MUST be loopback), `FETCHIT_TRUST_DATA`
    /// (default `./fetchit-trust-data`), `FETCHIT_TRUST_ISSUER` (default
    /// `issuer-v1`).
    ///
    /// # Errors
    /// Returns `TrustError::Config` if `FETCHIT_TRUST_BIND` or
    /// `FETCHIT_TRUST_ADMIN_BIND` is malformed.
    pub fn from_env() -> Result<Self, TrustError> {
        let bind_raw =
            std::env::var("FETCHIT_TRUST_BIND").unwrap_or_else(|_| "127.0.0.1:8090".to_owned());
        let bind = SocketAddr::from_str(&bind_raw)
            .map_err(|e| TrustError::Config(format!("bad bind address: {e}")))?;
        let admin_bind = match std::env::var("FETCHIT_TRUST_ADMIN_BIND") {
            Ok(raw) => SocketAddr::from_str(&raw)
                .map_err(|e| TrustError::Config(format!("bad admin bind address: {e}")))?,
            Err(_) => default_admin_bind(),
        };
        let data_dir = PathBuf::from(
            std::env::var("FETCHIT_TRUST_DATA").unwrap_or_else(|_| "fetchit-trust-data".to_owned()),
        );
        let issuer_key_id =
            std::env::var("FETCHIT_TRUST_ISSUER").unwrap_or_else(|_| "issuer-v1".to_owned());
        Ok(Self::new(bind, data_dir, issuer_key_id).with_admin_bind(admin_bind))
    }
}
