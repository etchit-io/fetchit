//! SSRF gate primitives shared by every fetch-from-remote path.
//!
//! Lifted out of [`crate::webfinger`] (M4 SEC-3 / V-2 fold) so
//! non-fediverse callers — Reachability V1's contact-supplied relay
//! dials in `fetchit-chat` (plan T13) — reuse the one canonical
//! private-IP detection instead of growing a parallel implementation.
//! The fediverse callers ([`crate::webfinger`], [`crate::actor`])
//! consume these same functions; an IP-class extension lands here once.
//!
//! The intended call pattern for any client that dials a
//! remotely-supplied URL:
//!
//! 1. Pre-flight: [`private_ip_reason`] on the parsed URL host —
//!    rejects IP literals (`http://127.0.0.1`, `http://[::1]`) before
//!    any socket opens.
//! 2. Resolve + pin: [`resolve_and_pin_host`] on hostname URLs — DNS
//!    resolution with every returned address validated, returning the
//!    addresses for `reqwest::ClientBuilder::resolve_to_addrs` (or a
//!    direct pinned-`SocketAddr` connect for non-reqwest dials) so the
//!    connect-time lookup can't TTL=0 rebind to a private IP.
//! 3. Post-flight: [`private_ip_reason`] on the response's final URL
//!    host — backstop for any redirect that slipped past
//!    `redirect::Policy::none()`.
//!
//! Dev carve-outs (e.g. allowing localhost relays in integration
//! environments) belong at the **call site**, never here — these
//! primitives stay unconditional so every caller keeps its gate.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use thiserror::Error;

/// Errors from [`resolve_and_pin_host`].
#[derive(Debug, Error)]
pub enum SsrfError {
    /// DNS resolution failed or returned no addresses.
    #[error("resolve: {0}")]
    Resolve(String),

    /// The host is, or resolves to, private / non-routable IP space.
    #[error("host {host} is in private / non-routable IP space")]
    PrivateAddress {
        /// Description of the host + IP class that triggered the gate.
        host: String,
    },
}

/// IPv4 private / non-routable classes. Shared by the direct-IPv4 and
/// IPv4-mapped-IPv6 arms of both [`is_private_ip_addr`] and
/// [`private_ip_reason`] so a class extension lands in exactly one
/// place. Covers RFC1918 private, loopback, link-local (the cloud
/// metadata service), multicast, broadcast, unspecified, and CGNAT
/// `100.64.0.0/10` (RFC 6598 — V-7 fold: carrier shared space is
/// dialable from inside ISP networks the same way RFC1918 is on a LAN).
fn is_private_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
}

/// Inspect a resolved [`IpAddr`] and return a description if it points
/// at private / non-routable space.
///
/// Twin of [`private_ip_reason`] for the post-`lookup_host` path —
/// where `private_ip_reason` checks an IP literal embedded in a URL,
/// this checks the IPs a DNS resolver actually returns for a hostname.
/// Both twins share `is_private_v4` for the IPv4 classes, so only
/// the IPv6-specific prefixes are mirrored by hand.
#[must_use]
pub fn is_private_ip_addr(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            if is_private_v4(v4) {
                Some(format!("private/non-routable IPv4 {v4}"))
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return Some(format!("non-routable IPv6 {v6}"));
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                if is_private_v4(v4) {
                    return Some(format!("IPv4-mapped private IPv6 {v6}"));
                }
            }
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return Some(format!("unique-local IPv6 {v6}"));
            }
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Some(format!("link-local IPv6 {v6}"));
            }
            None
        }
    }
}

/// Inspect a parsed [`url::Host`] and return a description string if it
/// points at private / non-routable IP space.
///
/// Pre-request gate against IP-literal URLs and post-response gate
/// against redirect targets. Domain hosts return `None` — hostname
/// validation is [`resolve_and_pin_host`]'s job, after DNS.
#[must_use]
pub fn private_ip_reason(host: &url::Host<&str>) -> Option<String> {
    match host {
        url::Host::Ipv4(ip) => {
            if is_private_v4(*ip) {
                Some(format!("private/non-routable IPv4 {ip}"))
            } else {
                None
            }
        }
        url::Host::Ipv6(ip) => {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                return Some(format!("non-routable IPv6 {ip}"));
            }
            if let Some(v4) = ip.to_ipv4_mapped() {
                if is_private_v4(v4) {
                    return Some(format!("IPv4-mapped private IPv6 {ip}"));
                }
            }
            // Unique-local fc00::/7
            if (ip.segments()[0] & 0xfe00) == 0xfc00 {
                return Some(format!("unique-local IPv6 {ip}"));
            }
            // Link-local fe80::/10
            if (ip.segments()[0] & 0xffc0) == 0xfe80 {
                return Some(format!("link-local IPv6 {ip}"));
            }
            None
        }
        url::Host::Domain(_) => None,
    }
}

/// Resolve `host:port` via `tokio::net::lookup_host` and validate every
/// returned address against [`is_private_ip_addr`].
///
/// Any private/non-routable address in the resolved set trips the gate
/// (partial-results-safe). Empty resolution surfaces as
/// [`SsrfError::Resolve`]. On success returns the validated addresses
/// so the caller can pin them — via
/// `reqwest::ClientBuilder::resolve_to_addrs` for HTTP, or by
/// connecting the TCP socket to a returned [`SocketAddr`] directly for
/// non-reqwest dials (passing the hostname only for SNI / TLS
/// verification). Without pinning, a TTL=0 DNS-rebinding host passes
/// this check and then resolves private at connect time.
///
/// # Errors
/// - [`SsrfError::Resolve`] when the lookup fails or returns nothing.
/// - [`SsrfError::PrivateAddress`] when any resolved address is
///   private / non-routable.
pub async fn resolve_and_pin_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, SsrfError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| SsrfError::Resolve(format!("lookup_host({host}): {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(SsrfError::Resolve(format!(
            "lookup_host({host}): empty result"
        )));
    }
    for addr in &addrs {
        if let Some(reason) = is_private_ip_addr(addr.ip()) {
            return Err(SsrfError::PrivateAddress { host: reason });
        }
    }
    Ok(addrs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use url::Url;

    // ----- is_private_ip_addr: post-DNS twin -----

    #[test]
    fn is_private_ip_addr_flags_v4_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_some());
    }

    #[test]
    fn is_private_ip_addr_flags_v4_rfc1918() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_some());
    }

    #[test]
    fn is_private_ip_addr_flags_v4_aws_metadata() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_some());
    }

    #[test]
    fn is_private_ip_addr_flags_v6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_some());
    }

    #[test]
    fn is_private_ip_addr_allows_v4_public() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_none());
    }

    // ----- V-7 fold: CGNAT 100.64.0.0/10 (RFC 6598) -----

    #[test]
    fn is_private_ip_addr_flags_v4_cgnat() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let reason = is_private_ip_addr(ip).expect("CGNAT 100.64/10 must flag");
        assert!(reason.contains("100.64.0.1"), "reason = {reason}");
    }

    #[test]
    fn is_private_ip_addr_flags_v4_cgnat_top_of_range() {
        // 100.127.255.255 is the last address inside 100.64.0.0/10 —
        // pins the /10 mask, not just the canonical 100.64 prefix.
        let ip: IpAddr = "100.127.255.255".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_some());
    }

    #[test]
    fn is_private_ip_addr_allows_v4_just_below_cgnat() {
        // 100.63.255.255 sits one address below the /10. Public.
        let ip: IpAddr = "100.63.255.255".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_none());
    }

    #[test]
    fn is_private_ip_addr_allows_v4_just_above_cgnat() {
        // 100.128.0.0 sits one address past the /10. Public.
        let ip: IpAddr = "100.128.0.0".parse().unwrap();
        assert!(is_private_ip_addr(ip).is_none());
    }

    #[test]
    fn private_ip_reason_flags_ipv4_mapped_cgnat() {
        // ::ffff:100.64.0.1 — the IPv4-mapped arm shares is_private_v4,
        // so the CGNAT class must flag through the v6 twin too.
        let url = Url::parse("https://[::ffff:6440:0001]/").unwrap();
        let host = url.host().unwrap();
        let reason = private_ip_reason(&host).expect("IPv4-mapped CGNAT must flag");
        assert!(reason.contains("IPv4-mapped"), "reason = {reason}");
    }

    // ----- private_ip_reason: URL-literal twin -----

    #[test]
    fn private_ip_reason_flags_ipv6_loopback() {
        let url = Url::parse("https://[::1]/").unwrap();
        let host = url.host().unwrap();
        assert!(private_ip_reason(&host).is_some());
    }

    #[test]
    fn private_ip_reason_flags_ipv6_unique_local() {
        let url = Url::parse("https://[fc00::1]/").unwrap();
        let host = url.host().unwrap();
        let reason = private_ip_reason(&host).expect("unique-local fc00::/7 must flag");
        assert!(reason.contains("unique-local"), "reason = {reason}");
    }

    #[test]
    fn private_ip_reason_flags_ipv4_mapped_ipv6() {
        // ::ffff:192.168.1.1 — IPv4-mapped IPv6 of an RFC1918 address.
        let url = Url::parse("https://[::ffff:c0a8:0101]/").unwrap();
        let host = url.host().unwrap();
        let reason = private_ip_reason(&host).expect("IPv4-mapped private must flag");
        assert!(reason.contains("IPv4-mapped"), "reason = {reason}");
    }

    #[test]
    fn private_ip_reason_flags_ipv6_link_local() {
        // fe80::/10 — IPv6 link-local. Reachable on the local segment
        // without routing; SSRF target equivalent to IPv4 169.254/16.
        let url = Url::parse("https://[fe80::1]/").unwrap();
        let host = url.host().unwrap();
        let reason = private_ip_reason(&host).expect("fe80::/10 must flag");
        assert!(reason.contains("link-local"), "reason = {reason}");
    }

    #[test]
    fn private_ip_reason_flags_ipv6_link_local_high_in_range() {
        // febf:: is the top of the fe80::/10 prefix (segments[0] = 0xfebf
        // still passes the 0xffc0 mask comparison). Pins the mask, not
        // just the canonical fe80:: prefix.
        let url = Url::parse("https://[febf::1]/").unwrap();
        let host = url.host().unwrap();
        assert!(private_ip_reason(&host).is_some());
    }

    #[test]
    fn private_ip_reason_flags_ipv4_cgnat_literal() {
        let url = Url::parse("http://100.64.0.1/").unwrap();
        let host = url.host().unwrap();
        assert!(private_ip_reason(&host).is_some());
    }

    #[test]
    fn private_ip_reason_allows_public_ipv4() {
        let url = Url::parse("https://1.1.1.1/").unwrap();
        let host = url.host().unwrap();
        assert!(private_ip_reason(&host).is_none());
    }

    #[test]
    fn private_ip_reason_allows_domain() {
        let url = Url::parse("https://mastodon.example/").unwrap();
        let host = url.host().unwrap();
        assert!(private_ip_reason(&host).is_none());
    }

    // ----- resolve_and_pin_host: DNS-resolution gate -----

    #[tokio::test]
    async fn resolve_and_pin_host_rejects_localhost() {
        // `localhost` resolves to 127.0.0.1 (and possibly ::1). Either
        // way every resolved address is private/non-routable, so the
        // gate trips with PrivateAddress. Pins the post-lookup_host
        // validation V-2 added; without it, `https://evil.example/`
        // DNS-rebinding to a private IP would slip past the IP-literal
        // pre-flight and hit the network.
        let err = resolve_and_pin_host("localhost", 80).await.unwrap_err();
        assert!(matches!(err, SsrfError::PrivateAddress { .. }));
    }
}
