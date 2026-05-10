//! Bootstrap peer addresses for the Autonomi production network and a
//! small normalizer that turns `ip:port` shorthand into a QUIC
//! multiaddr.

/// Bootstrap peers for the Autonomi production network, in `ip:port`
/// shorthand. Mirrors the list shipped by etchit-android — keeping
/// fetch>it on the same set means both clients reach the same network
/// without a divergent peer story.
///
/// Pass these (or a user-supplied override) to
/// [`AutonomiClient::connect`](crate::AutonomiClient::connect) after
/// running each through [`normalize_multiaddr`] — the network expects
/// QUIC multiaddrs.
pub const DEFAULT_PEERS: &[&str] = &[
    "207.148.94.42:10000",
    "45.77.50.10:10000",
    "66.135.23.83:10000",
    "149.248.9.2:10000",
    "49.12.119.240:10000",
    "5.161.25.133:10000",
    "18.228.202.183:10000",
];

/// Upgrade an `ip:port` shorthand to a `/ip4/<ip>/udp/<port>/quic`
/// multiaddr.
///
/// Inputs that already start with `/` are passed through unchanged.
/// Inputs that don't split cleanly into `host:port` are also passed
/// through — `ant-core`'s `MultiAddr::parse` will reject them at
/// connect time with a clear error, so we don't duplicate validation.
#[must_use]
pub fn normalize_multiaddr(addr: &str) -> String {
    if addr.starts_with('/') {
        return addr.to_owned();
    }
    let mut parts = addr.splitn(2, ':');
    if let (Some(host), Some(port)) = (parts.next(), parts.next()) {
        if !host.is_empty() && !port.is_empty() {
            return format!("/ip4/{host}/udp/{port}/quic");
        }
    }
    addr.to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn normalises_ip_port_shorthand() {
        assert_eq!(
            normalize_multiaddr("1.2.3.4:10000"),
            "/ip4/1.2.3.4/udp/10000/quic"
        );
    }

    #[test]
    fn passes_through_existing_multiaddr() {
        let addr = "/ip4/1.2.3.4/udp/10000/quic-v1/p2p/12D3KooW...";
        assert_eq!(normalize_multiaddr(addr), addr);
    }

    #[test]
    fn passes_through_malformed_input() {
        assert_eq!(normalize_multiaddr("not-an-address"), "not-an-address");
        assert_eq!(normalize_multiaddr(":missing-host"), ":missing-host");
        assert_eq!(normalize_multiaddr("missing-port:"), "missing-port:");
    }

    #[test]
    fn default_peer_list_is_non_empty_and_normalisable() {
        assert!(!DEFAULT_PEERS.is_empty());
        for p in DEFAULT_PEERS {
            let normalised = normalize_multiaddr(p);
            assert!(normalised.starts_with("/ip4/"), "got {normalised}");
            assert!(normalised.contains("/udp/"), "got {normalised}");
            assert!(normalised.ends_with("/quic"), "got {normalised}");
        }
    }
}
