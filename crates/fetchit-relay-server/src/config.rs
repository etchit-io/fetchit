//! Server configuration loaded from environment / CLI.

use crate::error::ServerError;
use fetchit_relay_proto::Region;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

/// Operating parameters for one relay node.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Address the HTTP / WebSocket server binds to.
    pub bind: SocketAddr,
    /// Geographic region tag advertised in `Ready` frames.
    pub region: Region,
    /// Build identifier advertised in `Ready` frames.
    pub server_version: String,
    /// Cap on per-envelope encoded byte length at the default service profile.
    pub max_envelope_bytes: u32,
    /// How long undelivered envelopes sit in the transit buffer.
    pub transit_ttl: Duration,
    /// Per-recipient transit buffer capacity (envelope count).
    pub transit_per_recipient: usize,
    /// Global cap on bytes the transit buffer may hold across all
    /// recipients. The per-recipient envelope count alone allows
    /// `cap_per_recipient × max_envelope_bytes × N` worst-case RAM —
    /// this caps the total so a fanned-out attacker can't push the
    /// process toward OOM.
    pub transit_total_bytes_cap: usize,
    /// How long group-log records are retained before the sweeper
    /// evicts them. Retention is serve-to-many: fetches never delete a
    /// record, only this window (or the caps below) bounds the log.
    pub group_log_window: Duration,
    /// Per-group record cap on the group log. An append past it evicts
    /// the group's OLDEST record — the newest records are the ones
    /// members need to catch up.
    pub group_log_per_group_cap: usize,
    /// Global cap on bytes the group log may hold across all groups.
    /// Appends past it are rejected (typed error → `Throttle` on the
    /// wire), bounding worst-case RAM/disk like the transit byte cap.
    pub group_log_total_bytes_cap: usize,
    /// Lifetime of an issued auth challenge before it must be redeemed.
    pub challenge_ttl: Duration,
    /// Lifetime of a minted bearer token for the WebSocket upgrade.
    pub bearer_ttl: Duration,
    /// Trust anchors: issuer key id → ML-DSA-65 public key bytes.
    pub issuer_keys: HashMap<String, Vec<u8>>,
    /// Loopback-only listener for sensitive metrics (`/v1/metrics/internal`).
    ///
    /// Defaults to `127.0.0.1:9088`. Set to `None` to disable the
    /// internal channel entirely. Any non-loopback address is rejected
    /// when the config is loaded from environment or when the server
    /// starts — the kernel-level loopback bind is the security boundary,
    /// not a request-time check.
    pub internal_bind: Option<SocketAddr>,
    /// Path of the durable `SQLite` transit store. `None` (the default)
    /// keeps the in-RAM buffer: undelivered envelopes are lost on
    /// restart. `Some` makes buffered envelopes survive a process
    /// restart (still ciphertext-only — the store is as blind as the
    /// RAM buffer).
    pub transit_db_path: Option<std::path::PathBuf>,
}

impl ServerConfig {
    /// Defaults suitable for one-node dev or single-region production.
    #[must_use]
    pub fn defaults(bind: SocketAddr, region: Region) -> Self {
        Self {
            bind,
            region,
            server_version: format!(
                "fetchit-relay-server/{}-{}",
                env!("CARGO_PKG_VERSION"),
                env!("FETCHIT_RELAY_GIT_SHORT"),
            ),
            max_envelope_bytes: fetchit_relay_proto::DEFAULT_MAX_ENVELOPE_BYTES,
            transit_ttl: Duration::from_secs(15 * 60),
            transit_per_recipient: 256,
            transit_total_bytes_cap: 1 << 30,
            group_log_window: Duration::from_secs(30 * 24 * 60 * 60),
            group_log_per_group_cap: 4096,
            group_log_total_bytes_cap: 1 << 30,
            challenge_ttl: Duration::from_secs(60),
            bearer_ttl: Duration::from_secs(15 * 60),
            issuer_keys: HashMap::new(),
            internal_bind: Some(SocketAddr::from(([127, 0, 0, 1], 9088))),
            transit_db_path: None,
        }
    }

    /// Load from environment variables, falling back to defaults.
    ///
    /// Recognised variables: `FETCHIT_RELAY_BIND` (default `127.0.0.1:8088`),
    /// `FETCHIT_RELAY_REGION` (default `nyc`),
    /// `FETCHIT_RELAY_INTERNAL_BIND` (default `127.0.0.1:9088`; literal
    /// `none` / `disabled` / empty turns the internal channel off; any
    /// non-loopback address is rejected),
    /// `FETCHIT_RELAY_TRANSIT_DB` (default unset = in-RAM transit buffer;
    /// a path enables the durable `SQLite` store; literal `none` /
    /// `disabled` / empty keeps RAM).
    ///
    /// # Errors
    /// Returns `ServerError::Config` if any variable is malformed.
    pub fn from_env() -> Result<Self, ServerError> {
        let bind_raw =
            std::env::var("FETCHIT_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8088".to_owned());
        let bind = SocketAddr::from_str(&bind_raw)
            .map_err(|e| ServerError::Config(format!("bad bind address: {e}")))?;
        let region_raw = std::env::var("FETCHIT_RELAY_REGION").unwrap_or_else(|_| "nyc".to_owned());
        let region = Region::from_str(&region_raw).unwrap_or(Region::Nyc);
        let mut cfg = Self::defaults(bind, region);
        if let Ok(raw) = std::env::var("FETCHIT_RELAY_INTERNAL_BIND") {
            cfg.internal_bind = parse_internal_bind(&raw)?;
        }
        if let Ok(raw) = std::env::var("FETCHIT_RELAY_TRANSIT_DB") {
            cfg.transit_db_path = parse_transit_db(&raw);
        }
        Ok(cfg)
    }
}

/// Parse the `FETCHIT_RELAY_TRANSIT_DB` override. An empty string or
/// the literals `none` / `disabled` (case-insensitive) keep the in-RAM
/// buffer; anything else is taken as the `SQLite` store path.
fn parse_transit_db(raw: &str) -> Option<std::path::PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("disabled")
    {
        return None;
    }
    Some(std::path::PathBuf::from(trimmed))
}

/// Parse the `FETCHIT_RELAY_INTERNAL_BIND` override, enforcing the
/// loopback-only invariant. Accepts an empty string or the literals
/// `none` / `disabled` (case-insensitive) to turn the endpoint off.
///
/// # Errors
/// Returns `ServerError::Config` if the value is not parseable as a
/// socket address, or if the address is not loopback.
pub fn parse_internal_bind(raw: &str) -> Result<Option<SocketAddr>, ServerError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("disabled")
    {
        return Ok(None);
    }
    let addr = SocketAddr::from_str(trimmed)
        .map_err(|e| ServerError::Config(format!("bad internal bind address {trimmed:?}: {e}")))?;
    if !addr.ip().is_loopback() {
        return Err(ServerError::Config(format!(
            "FETCHIT_RELAY_INTERNAL_BIND must be loopback (127.0.0.0/8 or ::1), got {addr}"
        )));
    }
    Ok(Some(addr))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{parse_internal_bind, parse_transit_db, Region, ServerConfig};
    use std::net::SocketAddr;

    #[test]
    fn parse_transit_db_takes_a_path_and_off_literals_keep_ram() {
        assert_eq!(
            parse_transit_db("/var/lib/fetchit-relay/transit.db"),
            Some(std::path::PathBuf::from(
                "/var/lib/fetchit-relay/transit.db"
            ))
        );
        assert_eq!(parse_transit_db(""), None);
        assert_eq!(parse_transit_db("  "), None);
        assert_eq!(parse_transit_db("none"), None);
        assert_eq!(parse_transit_db("Disabled"), None);
    }

    #[test]
    fn transit_db_defaults_to_ram() {
        let cfg = ServerConfig::defaults(SocketAddr::from(([127, 0, 0, 1], 0)), Region::Nyc);
        assert!(cfg.transit_db_path.is_none());
    }

    #[test]
    fn server_version_carries_semver_and_git_short() {
        let cfg = ServerConfig::defaults(SocketAddr::from(([127, 0, 0, 1], 0)), Region::Nyc);
        let prefix = format!("fetchit-relay-server/{}-", env!("CARGO_PKG_VERSION"));
        assert!(
            cfg.server_version.starts_with(&prefix),
            "expected version to start with {prefix:?}, got {:?}",
            cfg.server_version
        );
        let suffix = cfg.server_version.strip_prefix(&prefix).unwrap();
        assert!(
            suffix == "unknown"
                || (suffix.len() == 7 && suffix.chars().all(|c| c.is_ascii_hexdigit())),
            "expected 7-hex-char short SHA or \"unknown\", got {suffix:?}"
        );
    }

    #[test]
    fn internal_bind_defaults_to_loopback() {
        let cfg = ServerConfig::defaults(SocketAddr::from(([127, 0, 0, 1], 0)), Region::Nyc);
        let addr = cfg.internal_bind.expect("internal_bind defaulted on");
        assert!(
            addr.ip().is_loopback(),
            "default internal bind must be loopback"
        );
        assert_eq!(addr.port(), 9088);
    }

    #[test]
    fn parse_internal_bind_accepts_ipv4_loopback() {
        let parsed = parse_internal_bind("127.0.0.1:9088").unwrap().unwrap();
        assert_eq!(parsed, SocketAddr::from(([127, 0, 0, 1], 9088)));
    }

    #[test]
    fn parse_internal_bind_accepts_ipv6_loopback() {
        let parsed = parse_internal_bind("[::1]:9088").unwrap().unwrap();
        assert!(parsed.ip().is_loopback());
    }

    #[test]
    fn parse_internal_bind_disable_keywords_return_none() {
        for raw in ["", "none", "NONE", "disabled", " DISABLED "] {
            assert!(
                parse_internal_bind(raw).unwrap().is_none(),
                "expected disable for {raw:?}"
            );
        }
    }

    #[test]
    fn parse_internal_bind_rejects_non_loopback() {
        let err = parse_internal_bind("10.0.0.1:9088").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("loopback"),
            "expected loopback rejection, got {msg:?}"
        );
    }

    #[test]
    fn parse_internal_bind_rejects_garbage() {
        assert!(parse_internal_bind("not-a-socket").is_err());
    }
}
