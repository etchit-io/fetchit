//! Bootstrap peers for the Autonomi production network and a small
//! parser that turns an `ip:port` shorthand (or a full multiaddr)
//! into the [`MultiAddr`] form `ant-core` expects.

use std::net::SocketAddr;

use ant_core::data::MultiAddr;

/// Bootstrap peers for the Autonomi production network, in `ip:port`
/// shorthand.
///
/// **Source of truth:** `WithAutonomi/ant-node` →
/// `config/bootstrap_peers.toml` (the same list `ant-node` loads when
/// no `--bootstrap` is given, and the same one vendored into
/// `ant-client/resources/` and `ant-sdk/antd/resources/`). This array
/// must stay a verbatim copy of that file. When upstream rotates the
/// list, update these entries to match — we don't `include_str!` it
/// because that file lives in a separate repo.
///
/// Last synced: 2026-05-11 (matches `ant-node@main`).
///
/// Pass these (or a user-supplied override) to
/// [`AutonomiClient::connect`](crate::AutonomiClient::connect); each
/// entry is parsed via [`parse_bootstrap_peer`].
pub const DEFAULT_PEERS: &[&str] = &[
    "207.148.94.42:10000",
    "45.77.50.10:10000",
    "66.135.23.83:10000",
    "149.248.9.2:10000",
    "49.12.119.240:10000",
    "5.161.25.133:10000",
    "18.228.202.183:10000",
];

/// Parse one bootstrap-peer string into a [`MultiAddr`].
///
/// An `ip:port` shorthand (e.g. `203.0.113.4:10000`) is turned into a
/// QUIC multiaddr via `ant-core`'s own [`MultiAddr::quic`] constructor
/// — so we get exactly the multiaddr shape the linked `ant-core`
/// expects (whether that's `/quic` or `/quic-v1` is its decision, not
/// ours). Anything that isn't a bare socket address is parsed directly
/// as a multiaddr. Surrounding whitespace is trimmed.
///
/// # Errors
///
/// Returns a human-readable message if the input is neither a valid
/// `ip:port` socket address nor a parseable multiaddr.
pub fn parse_bootstrap_peer(raw: &str) -> Result<MultiAddr, String> {
    let raw = raw.trim();
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Ok(MultiAddr::quic(sa));
    }
    raw.parse::<MultiAddr>()
        .map_err(|e| format!("invalid bootstrap peer {raw:?}: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn parses_ip_port_shorthand() {
        assert!(parse_bootstrap_peer("203.0.113.4:10000").is_ok());
        // surrounding whitespace is trimmed
        assert!(parse_bootstrap_peer("  203.0.113.4:10000  ").is_ok());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_bootstrap_peer("not-an-address").is_err());
        assert!(parse_bootstrap_peer("").is_err());
        assert!(parse_bootstrap_peer("missing-port:").is_err());
        assert!(parse_bootstrap_peer(":missing-host").is_err());
    }

    #[test]
    fn default_peer_list_is_non_empty_and_parses() {
        assert!(!DEFAULT_PEERS.is_empty());
        for p in DEFAULT_PEERS {
            parse_bootstrap_peer(p).unwrap_or_else(|e| panic!("default peer {p:?}: {e}"));
        }
    }
}
