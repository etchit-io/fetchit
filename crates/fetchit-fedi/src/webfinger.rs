//! `WebFinger` client + handle resolution.
//!
//! Resolves `@user@instance` to an `ActivityPub` actor URL, then to the
//! actor's inbox/outbox URLs. Used by [`crate::transport`] before every
//! outbound POST and by `Client::subscribe_actor` per the Follow flow
//! in plan Stage 5.3.

use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Hard cap on `WebFinger` response body size before JRD parse. JRDs are
/// typically 200-800 bytes; 64KB is comfortably above any benign instance
/// while shutting the door on parse-cost / memory inflation attacks.
const MAX_JRD_BODY_BYTES: usize = 64 * 1024;

/// Per-call request timeout for `WebFinger` resolution. The caller's
/// `reqwest::Client` may carry its own timeout; this is the floor that
/// applies regardless.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors surfaceable from the `WebFinger` resolution flow. The variant
/// set is bounded so Stage 5.2's per-mention gate can render the right
/// UI string + the relay-server inbox can emit a bounded-cardinality
/// failure counter.
#[derive(Debug, Error)]
pub enum WebFingerError {
    /// Mention string does not match `@user@instance` shape.
    #[error("malformed handle: {0}")]
    MalformedHandle(String),

    /// Mention parses structurally but the instance part is rejected
    /// before any network call (empty / missing dot / non-ASCII per
    /// the conservative gate we enforce).
    #[error("instance domain invalid: {0}")]
    InvalidInstance(String),

    /// Underlying HTTPS GET reached the instance but the instance
    /// returned a non-2xx. `status` is the response code, `body` is
    /// the first 256 bytes of the body for ops diagnostics.
    #[error("HTTP {status}: {body}")]
    Http {
        /// HTTP status code from the `WebFinger` response.
        status: u16,
        /// First 256 bytes of the response body (for ops diagnostics).
        body: String,
    },

    /// `reqwest`-side error (DNS, connect, TLS, body read). String form
    /// to avoid leaking the underlying error type into the public API.
    #[error("transport: {0}")]
    Transport(String),

    /// Response body wasn't valid JRD or the parsed JRD lacked required
    /// fields.
    #[error("JRD parse: {0}")]
    JrdParse(String),

    /// JRD parsed cleanly but didn't contain a `rel: "self"` link with
    /// `type: application/activity+json`. The conventional shape; an
    /// instance that doesn't follow it cannot be resolved to an actor.
    #[error("no actor link in JRD")]
    NoActorLink,

    /// SEC-1: response body exceeded the 64KB cap before JRD parse.
    /// A hostile or misconfigured instance attempting to inflate parse
    /// cost or exhaust memory; resolver fails fast on the first chunk
    /// that crosses the limit.
    #[error("response body exceeded {max_bytes} byte cap")]
    BodyTooLarge {
        /// Hard cap that triggered the rejection.
        max_bytes: usize,
    },

    /// SEC-3: instance host (passed-in or reached via redirect) is an IP
    /// literal in private / loopback / link-local space. Closes the SSRF
    /// surface against cloud-metadata services (e.g. `169.254.169.254`),
    /// loopback (`127.0.0.0/8`, `::1`), RFC1918 private space, and
    /// IPv6 unique-local.
    #[error("instance host {host} resolves to private / non-routable IP space")]
    PrivateInstance {
        /// Description of the host + IP class that triggered the gate.
        host: String,
    },
}

/// Result of parsing an `@user@instance` mention into the two halves
/// needed for `WebFinger` resolution.
///
/// `instance` is lowercased at parse time so resolution + denylist
/// matching stay case-insensitive without each caller re-normalising.
/// `local` is preserved verbatim because some instances treat the
/// local-part as case-sensitive at the protocol layer (e.g. Pleroma).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHandle {
    /// Local-part of the handle (`alice` in `@alice@mastodon.example`).
    /// Preserved verbatim; some instances treat this as case-sensitive.
    pub local: String,
    /// Instance domain (`mastodon.example`). Lowercased at parse time so
    /// resolution + denylist matching stay case-insensitive.
    pub instance: String,
}

/// Parse an `@user@instance.tld` mention into its halves.
///
/// Conservative shape gate: requires exactly two `@`s, both halves
/// non-empty, instance contains a `.`. Stricter checks (real TLD list,
/// IDNA) happen at resolution time when `reqwest` does its own URL
/// parse + DNS lookup.
///
/// # Errors
/// - [`WebFingerError::MalformedHandle`] when the structural shape
///   fails (missing leading `@`, missing instance `@`, empty parts).
/// - [`WebFingerError::InvalidInstance`] when the instance side
///   passes structural shape but fails the dot / non-empty check.
pub fn parse_mention(handle: &str) -> Result<ParsedHandle, WebFingerError> {
    let stripped = handle
        .strip_prefix('@')
        .ok_or_else(|| WebFingerError::MalformedHandle(format!("missing leading '@': {handle}")))?;
    let mut parts = stripped.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let instance = parts.next().ok_or_else(|| {
        WebFingerError::MalformedHandle(format!("missing '@<instance>': {handle}"))
    })?;
    if local.is_empty() {
        return Err(WebFingerError::MalformedHandle(format!(
            "empty local part: {handle}"
        )));
    }
    if instance.is_empty() {
        return Err(WebFingerError::InvalidInstance(format!(
            "empty instance: {handle}"
        )));
    }
    if !instance.contains('.') {
        return Err(WebFingerError::InvalidInstance(format!(
            "instance has no dot: {handle}"
        )));
    }
    if instance.contains('@') || instance.contains('/') {
        return Err(WebFingerError::InvalidInstance(format!(
            "instance contains reserved char: {handle}"
        )));
    }
    Ok(ParsedHandle {
        local: local.to_owned(),
        instance: instance.to_ascii_lowercase(),
    })
}

/// Minimal JRD ([RFC 7033 §4.4]) shape we consume.
///
/// We deliberately decode only the `links` field. Other top-level
/// fields (`subject`, `aliases`, `properties`) are forward-compat
/// ignored — a future expansion that needs them can add a new field
/// here without touching parsing for the current Stage 5.2 callers.
///
/// [RFC 7033 §4.4]: https://datatracker.ietf.org/doc/html/rfc7033#section-4.4
#[derive(Debug, Deserialize)]
struct Jrd {
    links: Vec<JrdLink>,
}

#[derive(Debug, Deserialize)]
struct JrdLink {
    rel: String,
    #[serde(rename = "type")]
    link_type: Option<String>,
    href: Option<String>,
}

/// Inspect a parsed `url::Host` and return a description string if it
/// points at private / non-routable IP space. SSRF gate primitive used
/// by [`resolve_handle`] both pre-request (against the instance) and
/// post-response (against the final URL, in case caller's client
/// followed a redirect).
fn private_ip_reason(host: &url::Host<&str>) -> Option<String> {
    match host {
        url::Host::Ipv4(ip) => {
            if ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
            {
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
                if v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                {
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

/// Resolve `handle` to its canonical `ActivityPub` actor URL via
/// `WebFinger`.
///
/// Issues a single HTTPS GET to
/// `https://<instance>/.well-known/webfinger?resource=acct:<local>@<instance>`
/// per RFC 7033 §4.1 and returns the `href` of the first link with
/// `rel = "self"` and `type = "application/activity+json"` (the
/// Mastodon-interop shape).
///
/// # Hardening (caller-configured)
///
/// The `http` client passed in **MUST** be built with
/// `redirect::Policy::none()` (or `limited(1)` at most). A redirect
/// from a hostile instance can target cloud-metadata services
/// (e.g. `169.254.169.254`) or loopback addresses; the post-flight
/// IP filter (SEC-3) catches the response, but the request itself
/// still fires — disable redirects to stop the request altogether.
///
/// # Hardening enforced in code
///
/// - **SEC-1**: response body hard-capped at 64KB before JRD parse;
///   surfaces [`WebFingerError::BodyTooLarge`].
/// - **SEC-2**: per-call request timeout of 10s; client-level timeouts
///   on the passed `http` apply on top, this is the floor.
/// - **SEC-3**: pre-flight rejects instance hosts that are IP literals
///   in private / loopback / link-local space; post-flight rejects
///   responses whose final URL targets the same set. Both surface
///   [`WebFingerError::PrivateInstance`].
///
/// # Errors
/// Surfaces every [`WebFingerError`] variant — the inner `reqwest`
/// errors are mapped into [`WebFingerError::Transport`] rather than
/// propagated raw so the public surface stays bounded.
pub async fn resolve_handle(
    http: &reqwest::Client,
    handle: &ParsedHandle,
) -> Result<Url, WebFingerError> {
    let resource = format!("acct:{}@{}", handle.local, handle.instance);
    let encoded_resource: String =
        url::form_urlencoded::byte_serialize(resource.as_bytes()).collect();
    let endpoint = format!(
        "https://{}/.well-known/webfinger?resource={}",
        handle.instance, encoded_resource
    );

    // SEC-3 pre-flight: parse_mention only requires a dot, so an IPv4
    // literal like 192.168.1.1 slips through. Reject before any socket
    // opens.
    let pre_url =
        Url::parse(&endpoint).map_err(|e| WebFingerError::InvalidInstance(e.to_string()))?;
    if let Some(host) = pre_url.host() {
        if let Some(reason) = private_ip_reason(&host) {
            return Err(WebFingerError::PrivateInstance { host: reason });
        }
    }

    resolve_handle_at_endpoint(http, &endpoint, RESOLVE_TIMEOUT).await
}

/// Internal: HTTP-fetch + JRD parse + actor link extraction. Factored
/// out so wiremock-backed tests can exercise the body cap + timeout +
/// post-flight IP filter via `http://` without faking TLS.
async fn resolve_handle_at_endpoint(
    http: &reqwest::Client,
    endpoint: &str,
    timeout: Duration,
) -> Result<Url, WebFingerError> {
    let mut resp = http
        .get(endpoint)
        .header("Accept", "application/jrd+json, application/json")
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| WebFingerError::Transport(e.to_string()))?;

    // SEC-3 post-flight: if the response URL host differs from the
    // request URL host the caller's client followed a redirect; the
    // post-flight IP filter then catches an SSRF redirect targeting
    // private space. If hosts match no redirect happened, so the
    // public `resolve_handle` pre-flight already gated the host (and
    // tests calling this helper directly own that responsibility).
    let req_host = Url::parse(endpoint)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    let resp_host = resp.url().host_str().map(str::to_owned);
    if req_host != resp_host {
        if let Some(host) = resp.url().host() {
            if let Some(reason) = private_ip_reason(&host) {
                return Err(WebFingerError::PrivateInstance { host: reason });
            }
        }
    }

    let status = resp.status();
    if !status.is_success() {
        let body_full = resp
            .text()
            .await
            .map_err(|e| WebFingerError::Transport(e.to_string()))?;
        let body = body_full.chars().take(256).collect();
        return Err(WebFingerError::Http {
            status: status.as_u16(),
            body,
        });
    }

    // SEC-1 pre-check: if the response declares Content-Length > 64KB,
    // reject before any body bytes land. Reqwest would otherwise
    // pre-allocate against the declared length and consume that memory
    // before the per-chunk cap fires. Hostile instance with a truthful
    // (but oversized) header hits this branch; the streaming check
    // still catches chunked/zero-length-declared bodies that exceed.
    if let Some(len) = resp.content_length() {
        if len > MAX_JRD_BODY_BYTES as u64 {
            return Err(WebFingerError::BodyTooLarge {
                max_bytes: MAX_JRD_BODY_BYTES,
            });
        }
    }

    // SEC-1: stream body chunks with a running size cap. Fails fast on
    // the first chunk that crosses 64KB rather than waiting for the
    // full body to land. Backstop for responses without Content-Length
    // (chunked transfer-encoding) or with a truthful small length but
    // an overrunning body.
    let mut body: Vec<u8> = Vec::with_capacity(1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| WebFingerError::Transport(e.to_string()))?
    {
        if body.len() + chunk.len() > MAX_JRD_BODY_BYTES {
            return Err(WebFingerError::BodyTooLarge {
                max_bytes: MAX_JRD_BODY_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }

    let jrd: Jrd =
        serde_json::from_slice(&body).map_err(|e| WebFingerError::JrdParse(e.to_string()))?;

    for link in &jrd.links {
        if link.rel == "self" && link.link_type.as_deref() == Some("application/activity+json") {
            if let Some(href) = &link.href {
                return Url::parse(href).map_err(|e| WebFingerError::JrdParse(e.to_string()));
            }
        }
    }
    Err(WebFingerError::NoActorLink)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_mention_well_formed() {
        let p = parse_mention("@alice@mastodon.example").unwrap();
        assert_eq!(p.local, "alice");
        assert_eq!(p.instance, "mastodon.example");
    }

    #[test]
    fn parse_mention_lowercases_instance() {
        let p = parse_mention("@Bob@Mastodon.Example").unwrap();
        assert_eq!(p.local, "Bob");
        assert_eq!(p.instance, "mastodon.example");
    }

    #[test]
    fn parse_mention_rejects_missing_leading_at() {
        assert!(matches!(
            parse_mention("alice@mastodon.example"),
            Err(WebFingerError::MalformedHandle(_))
        ));
    }

    #[test]
    fn parse_mention_rejects_missing_instance_at() {
        assert!(matches!(
            parse_mention("@alice"),
            Err(WebFingerError::MalformedHandle(_))
        ));
    }

    #[test]
    fn parse_mention_rejects_empty_local() {
        assert!(matches!(
            parse_mention("@@mastodon.example"),
            Err(WebFingerError::MalformedHandle(_))
        ));
    }

    #[test]
    fn parse_mention_rejects_empty_instance() {
        assert!(matches!(
            parse_mention("@alice@"),
            Err(WebFingerError::InvalidInstance(_))
        ));
    }

    #[test]
    fn parse_mention_rejects_instance_without_dot() {
        assert!(matches!(
            parse_mention("@alice@localhost"),
            Err(WebFingerError::InvalidInstance(_))
        ));
    }

    #[test]
    fn parse_mention_rejects_instance_with_slash() {
        assert!(matches!(
            parse_mention("@alice@mastodon.example/users/alice"),
            Err(WebFingerError::InvalidInstance(_))
        ));
    }

    #[test]
    fn parse_mention_rejects_three_at_signs() {
        // splitn(2, '@') leaves the third @ inside the instance, which
        // then fails the "no slash / no @" gate.
        assert!(parse_mention("@alice@evil@example.com").is_err());
    }

    fn jrd_body_for(href: &str) -> String {
        format!(
            r#"{{"subject":"acct:alice@mastodon.example","links":[{{"rel":"self","type":"application/activity+json","href":"{href}"}}]}}"#
        )
    }

    /// Direct exercise of [`resolve_handle_at_endpoint`] against
    /// wiremock — the public [`resolve_handle`] hardcodes `https://`
    /// and can't be hit by a plain-HTTP mock. This closes Alice's T-1
    /// (happy-path test didn't actually call into the resolver).
    #[tokio::test]
    async fn resolve_handle_at_endpoint_happy_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(jrd_body_for("https://mastodon.example/users/alice")),
            )
            .mount(&server)
            .await;

        let endpoint = format!(
            "{}/.well-known/webfinger?resource=acct:alice@x",
            server.uri()
        );
        let client = reqwest::Client::new();
        let actor = resolve_handle_at_endpoint(&client, &endpoint, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(actor.as_str(), "https://mastodon.example/users/alice");
    }

    #[test]
    fn jrd_parse_rejects_missing_links() {
        let body = r#"{"subject":"acct:alice@x.example"}"#;
        assert!(serde_json::from_str::<Jrd>(body).is_err());
    }

    #[test]
    fn jrd_parse_handles_link_without_type_or_href() {
        let body = r#"{"links":[{"rel":"http://webfinger.net/rel/profile-page"}]}"#;
        let jrd: Jrd = serde_json::from_str(body).unwrap();
        assert_eq!(jrd.links.len(), 1);
        assert!(jrd.links[0].link_type.is_none());
        assert!(jrd.links[0].href.is_none());
    }

    // ----- SEC-1: body cap -----

    #[tokio::test]
    async fn resolve_handle_at_endpoint_caps_oversized_body() {
        let server = MockServer::start().await;
        // Build a >64KB body that's still structurally JSON so we
        // assert the cap fires before parse, not as a JRD parse error.
        let big = "x".repeat(70 * 1024);
        let body = format!(r#"{{"subject":"acct:alice@x.example","filler":"{big}","links":[]}}"#);
        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let endpoint = format!(
            "{}/.well-known/webfinger?resource=acct:alice@x",
            server.uri()
        );
        let client = reqwest::Client::new();
        let err = resolve_handle_at_endpoint(&client, &endpoint, Duration::from_secs(5))
            .await
            .unwrap_err();
        match err {
            WebFingerError::BodyTooLarge { max_bytes } => {
                assert_eq!(max_bytes, MAX_JRD_BODY_BYTES);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    // ----- SEC-2: per-call timeout -----

    #[tokio::test]
    async fn resolve_handle_at_endpoint_enforces_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(jrd_body_for("https://x.example/users/alice"))
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;

        let endpoint = format!(
            "{}/.well-known/webfinger?resource=acct:alice@x",
            server.uri()
        );
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let err = resolve_handle_at_endpoint(&client, &endpoint, Duration::from_millis(200))
            .await
            .unwrap_err();
        let elapsed = start.elapsed();
        // Must surface as Transport (reqwest's timeout error wraps in)
        // and must fire well inside the 2s mock delay.
        assert!(
            matches!(err, WebFingerError::Transport(_)),
            "expected Transport(timeout), got {err:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1500),
            "timeout did not fire promptly: elapsed={elapsed:?}"
        );
    }

    // ----- SEC-3: SSRF / private-IP gate -----

    #[tokio::test]
    async fn resolve_handle_rejects_private_ipv4_instance() {
        let handle = ParsedHandle {
            local: "alice".to_owned(),
            instance: "192.168.1.1".to_owned(),
        };
        let err = resolve_handle(&reqwest::Client::new(), &handle)
            .await
            .unwrap_err();
        match err {
            WebFingerError::PrivateInstance { host } => {
                assert!(host.contains("192.168.1.1"), "host = {host}");
            }
            other => panic!("expected PrivateInstance, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_handle_rejects_loopback_ipv4_instance() {
        let handle = ParsedHandle {
            local: "alice".to_owned(),
            instance: "127.0.0.1".to_owned(),
        };
        let err = resolve_handle(&reqwest::Client::new(), &handle)
            .await
            .unwrap_err();
        assert!(matches!(err, WebFingerError::PrivateInstance { .. }));
    }

    #[tokio::test]
    async fn resolve_handle_rejects_link_local_aws_metadata_instance() {
        // 169.254.169.254 is the AWS / GCP / Azure metadata service.
        // The canonical SSRF target the doc-MUST + IP filter exists to
        // block.
        let handle = ParsedHandle {
            local: "alice".to_owned(),
            instance: "169.254.169.254".to_owned(),
        };
        let err = resolve_handle(&reqwest::Client::new(), &handle)
            .await
            .unwrap_err();
        assert!(matches!(err, WebFingerError::PrivateInstance { .. }));
    }

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

    // ----- V-1: IPv6 link-local fe80::/10 -----

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

    // ----- V-3: post-flight IP filter catches redirect target -----

    #[tokio::test]
    async fn resolve_handle_at_endpoint_post_flight_catches_redirect_to_private_ip() {
        let server = MockServer::start().await;
        // Configure a 302 redirecting to the AWS / GCP / Azure metadata
        // service. Reqwest's default redirect policy follows up to 10
        // redirects — V-3's reason-for-being. The post-flight IP filter
        // (resolve_handle_at_endpoint, after the redirect lands) MUST
        // fail closed.
        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://169.254.169.254/latest/meta-data/"),
            )
            .mount(&server)
            .await;

        let endpoint = format!(
            "{}/.well-known/webfinger?resource=acct:alice@x",
            server.uri()
        );
        let client = reqwest::Client::new();
        let err = resolve_handle_at_endpoint(&client, &endpoint, Duration::from_secs(3))
            .await
            .unwrap_err();
        // Either PrivateInstance (post-flight fires because 169.254
        // actually responded) OR Transport (169.254 unreachable in the
        // test env — typical for CI / local). The failure mode this test
        // refuses to accept is `Ok(Url)` containing a parsed actor URL
        // from the metadata service, which would prove the post-flight
        // gate is open.
        match err {
            WebFingerError::PrivateInstance { host } => {
                assert!(host.contains("169.254"), "host = {host}");
            }
            WebFingerError::Transport(_) => {
                // 169.254 unreachable — SSRF surface still closed: no
                // JRD was parsed, no actor URL surfaced.
            }
            other => panic!("expected PrivateInstance or Transport, got {other:?}"),
        }
    }

    // ----- V-6: parse_mention rejects bracketed IPv6 instance -----

    #[test]
    fn parse_mention_rejects_bracketed_ipv6_instance() {
        // `[fe80::1]` has no `.` so it fails the structural instance gate
        // before resolve_handle's SSRF pre-flight ever runs. Pinning the
        // current behavior so a future relaxation of parse_mention's
        // "has a dot" check (e.g. for sub-domain handling) doesn't open
        // an IPv6-literal bypass.
        assert!(matches!(
            parse_mention("@alice@[fe80::1]"),
            Err(WebFingerError::InvalidInstance(_))
        ));
    }
}
