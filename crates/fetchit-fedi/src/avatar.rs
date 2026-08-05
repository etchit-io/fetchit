//! Actor avatar (`icon`) extraction and SSRF-guarded image fetch.
//!
//! Avatar URLs are **attacker-controlled**: they come out of an
//! arbitrary remote actor document. Extraction is therefore liberal
//! (Mastodon emits `icon` as an `Image` object, other implementations
//! emit an array or a bare string) while the fetch is strict:
//!
//! - https only — an `http://` or `file://` icon is rejected before any
//!   socket opens;
//! - the same resolver-pinned, redirect-disabled client
//!   [`crate::actor::fetch_actor`] builds (`pinned_no_redirect_client`),
//!   so the private / loopback / link-local / CGNAT gate in
//!   [`crate::ssrf`] runs on the literal host AND on every address DNS
//!   returns, with the addresses pinned so a TTL=0 rebind can't land
//!   elsewhere at connect time;
//! - `redirect::Policy::none()` means there are **zero** redirect hops
//!   to re-check: a 3xx surfaces as [`FetchAvatarError::Http`] rather
//!   than being followed. The post-flight host re-check is kept as a
//!   backstop anyway, mirroring the actor JSON-LD fetch;
//! - a hard [`MAX_AVATAR_BYTES`] body cap, pre-checked against
//!   `Content-Length` and enforced again by a streaming accumulator;
//! - a `Content-Type` allowlist ([`ALLOWED_AVATAR_CONTENT_TYPES`]).
//!
//! This module deliberately does **not** decode the image. Handing
//! attacker bytes to a Rust image parser would add a memory-safety
//! surface for no gain — the shells decode with the platform decoder
//! (Android `BitmapFactory`), which is the sandbox we actually want.

use crate::actor::{pinned_no_redirect_client, FetchActorError};
use serde_json::Value;
use std::time::Duration;

/// Hard cap on an avatar response body. Profile pictures are served at
/// a few tens of KB; 512 KiB is generous and still bounds the memory a
/// hostile instance can make us hold per fetch.
pub const MAX_AVATAR_BYTES: usize = 512 * 1024;

/// Per-call connect + request timeout for [`fetch_avatar`].
pub const AVATAR_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// `Content-Type` allowlist. Anything else — including a missing
/// header — is rejected, so a hostile instance cannot use the avatar
/// slot to hand a shell an SVG (script surface) or an HTML page.
pub const ALLOWED_AVATAR_CONTENT_TYPES: [&str; 4] =
    ["image/jpeg", "image/png", "image/webp", "image/gif"];

/// `Content-Type` allowlist for an avatar the USER uploads to our own
/// bridge. Narrower than [`ALLOWED_AVATAR_CONTENT_TYPES`], which governs
/// what we accept FROM a remote instance: GIF is dropped because our
/// shells re-encode to a still image before upload, so a GIF here could
/// only arrive from a hand-rolled client.
///
/// One definition shared by the bridge (verify side) and the chat client
/// (pre-flight side), so the two ends cannot drift.
pub const UPLOADABLE_AVATAR_CONTENT_TYPES: [&str; 3] = ["image/jpeg", "image/png", "image/webp"];

/// Whether `bytes` open with the file-format magic that `content_type`
/// claims. Signature inspection only — nothing is decoded.
///
/// Uploads land on a domain we serve, so a declared-but-false content
/// type would let a registered user park arbitrary bytes (an HTML
/// phishing page, a binary) under `etchit.io`. `nosniff` plus a strict
/// stored `Content-Type` already stops a browser rendering them; this
/// check stops them being stored at all.
///
/// Unknown content types answer `false` — the caller has already applied
/// [`UPLOADABLE_AVATAR_CONTENT_TYPES`], so reaching here with anything
/// else is a bug, and failing closed is the right shape for one.
#[must_use]
pub fn magic_matches_content_type(content_type: &str, bytes: &[u8]) -> bool {
    match content_type {
        // SOI marker. The third byte is the first segment's marker
        // introducer, which is 0xFF for every JPEG variant.
        "image/jpeg" => bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        // RIFF container with a WEBP form type at offset 8.
        "image/webp" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP",
        _ => false,
    }
}

/// Recursion bound for [`icon_url_from_actor_doc`]. Actor bodies are
/// already capped at [`crate::actor::MAX_ACTOR_BODY_BYTES`] and serde
/// caps nesting depth, but the walk states its own bound rather than
/// inheriting someone else's.
const MAX_ICON_DEPTH: u8 = 8;

/// Errors surfaceable from [`fetch_avatar`]. Bounded variant set so
/// callers can emit a bounded-cardinality failure counter.
#[derive(Debug, thiserror::Error)]
pub enum FetchAvatarError {
    /// The icon URL is not `https`. Rejected before any socket opens.
    #[error("avatar url scheme {scheme:?} is not https")]
    NotHttps {
        /// The scheme that was served.
        scheme: String,
    },

    /// The icon host is, or resolves to, private / non-routable IP
    /// space (or a post-flight host change landed there).
    #[error("avatar host {host} resolves to private / non-routable IP space")]
    PrivateInstance {
        /// Description of the host + IP class that triggered the gate.
        host: String,
    },

    /// The response body exceeded [`MAX_AVATAR_BYTES`].
    #[error("avatar body exceeded {max_bytes} byte cap")]
    BodyTooLarge {
        /// The cap that triggered the rejection.
        max_bytes: usize,
    },

    /// The `Content-Type` was absent or outside
    /// [`ALLOWED_AVATAR_CONTENT_TYPES`].
    #[error("avatar content-type {content_type:?} is not an allowed image type")]
    ContentType {
        /// The served content type (empty when the header was absent).
        content_type: String,
    },

    /// `reqwest`-side error (DNS, connect, TLS, body read, timeout).
    #[error("transport: {0}")]
    Transport(String),

    /// The host answered with a non-2xx status. A 3xx lands here too:
    /// the client follows no redirects.
    #[error("HTTP {status}")]
    Http {
        /// HTTP status code from the icon URL response.
        status: u16,
    },
}

/// A fetched avatar: the raw bytes plus the caching metadata worth
/// persisting beside them. Never decoded in Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedAvatar {
    /// Raw image bytes exactly as served.
    pub bytes: Vec<u8>,
    /// Normalised (lowercased, parameter-stripped) content type, always
    /// one of [`ALLOWED_AVATAR_CONTENT_TYPES`].
    pub content_type: String,
    /// `ETag` as served, when the host supplied one.
    pub etag: Option<String>,
}

/// Pull the avatar URL out of an `ActivityPub` actor document's `icon`.
///
/// Liberal in what it accepts, because implementations differ:
///
/// - `"icon": {"type": "Image", "url": "https://…"}` (Mastodon),
/// - `"icon": [{…}, {…}]` (first usable entry wins),
/// - `"icon": "https://…"` (bare string),
/// - `"icon": {"url": {"href": "https://…"}}` (JSON-LD `Link` object),
/// - `"icon": {"url": ["https://…", …]}`.
///
/// Returns the URL **as served** — no scheme or host validation
/// happens here. [`fetch_avatar`] is the gate.
#[must_use]
pub fn icon_url_from_actor_doc(doc: &Value) -> Option<String> {
    url_from_icon_value(doc.get("icon")?, 0)
}

fn url_from_icon_value(v: &Value, depth: u8) -> Option<String> {
    if depth > MAX_ICON_DEPTH {
        return None;
    }
    match v {
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_owned())
            }
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| url_from_icon_value(item, depth + 1)),
        Value::Object(map) => map
            .get("url")
            .and_then(|u| url_from_icon_value(u, depth + 1))
            .or_else(|| {
                map.get("href")
                    .and_then(|h| url_from_icon_value(h, depth + 1))
            }),
        _ => None,
    }
}

/// Pull the `mediaType` an actor document declares beside its `icon`
/// URL, when it declares one.
///
/// Companion to [`icon_url_from_actor_doc`] and equally liberal: the
/// object shape and the first entry of an array shape both work. The
/// value is advisory — the served `Content-Type` is what
/// [`fetch_avatar`] gates on — so a missing or nonsense `mediaType`
/// costs nothing.
#[must_use]
pub fn icon_media_type_from_actor_doc(doc: &Value) -> Option<String> {
    media_type_from_icon_value(doc.get("icon")?, 0)
}

fn media_type_from_icon_value(v: &Value, depth: u8) -> Option<String> {
    if depth > MAX_ICON_DEPTH {
        return None;
    }
    match v {
        Value::Array(items) => items
            .iter()
            .find_map(|item| media_type_from_icon_value(item, depth + 1)),
        Value::Object(map) => map
            .get("mediaType")
            .and_then(Value::as_str)
            .map(normalize_content_type)
            .filter(|s| !s.is_empty()),
        _ => None,
    }
}

/// Normalise a `Content-Type` header value: drop parameters, trim,
/// lowercase. `"Image/PNG; charset=binary"` becomes `"image/png"`.
#[must_use]
pub fn normalize_content_type(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Fetch an avatar image from an attacker-supplied `icon` URL.
///
/// # Errors
/// Every [`FetchAvatarError`] variant. `reqwest`-side failures land as
/// [`FetchAvatarError::Transport`].
pub async fn fetch_avatar(icon_url: &url::Url) -> Result<FetchedAvatar, FetchAvatarError> {
    // https-only, checked before the SSRF machinery so `file:` /
    // `data:` / plain-http icons never reach a resolver at all.
    if icon_url.scheme() != "https" {
        return Err(FetchAvatarError::NotHttps {
            scheme: icon_url.scheme().to_owned(),
        });
    }
    let client = pinned_no_redirect_client(icon_url, AVATAR_FETCH_TIMEOUT)
        .await
        .map_err(map_client_error)?;
    fetch_avatar_at_url(&client, icon_url, AVATAR_FETCH_TIMEOUT).await
}

fn map_client_error(e: FetchActorError) -> FetchAvatarError {
    match e {
        FetchActorError::PrivateInstance { host } => FetchAvatarError::PrivateInstance { host },
        other => FetchAvatarError::Transport(other.to_string()),
    }
}

/// Internal: GET + post-flight host check + content-type allowlist +
/// body cap. Factored out so wiremock-backed tests can exercise the
/// caps over `http://127.0.0.1` without tripping the https + loopback
/// pre-flight that lives in the public [`fetch_avatar`].
async fn fetch_avatar_at_url(
    http: &reqwest::Client,
    icon_url: &url::Url,
    timeout: Duration,
) -> Result<FetchedAvatar, FetchAvatarError> {
    let mut resp = http
        .get(icon_url.as_str())
        .header("Accept", "image/*")
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| FetchAvatarError::Transport(e.to_string()))?;

    // Backstop only: the client follows no redirects, so a host change
    // here would mean reqwest changed behaviour under us.
    if icon_url.host_str() != resp.url().host_str() {
        if let Some(host) = resp.url().host() {
            if let Some(reason) = crate::ssrf::private_ip_reason(&host) {
                return Err(FetchAvatarError::PrivateInstance { host: reason });
            }
        }
    }

    let status = resp.status();
    if !status.is_success() {
        return Err(FetchAvatarError::Http {
            status: status.as_u16(),
        });
    }

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(normalize_content_type)
        .unwrap_or_default();
    if !ALLOWED_AVATAR_CONTENT_TYPES.contains(&content_type.as_str()) {
        return Err(FetchAvatarError::ContentType { content_type });
    }

    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Cheap pre-check on the advertised length…
    if let Some(len) = resp.content_length() {
        if len > MAX_AVATAR_BYTES as u64 {
            return Err(FetchAvatarError::BodyTooLarge {
                max_bytes: MAX_AVATAR_BYTES,
            });
        }
    }
    // …and the accumulator that actually holds the line for chunked
    // transfer or a dishonest Content-Length.
    let mut bytes: Vec<u8> = Vec::with_capacity(8192);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FetchAvatarError::Transport(e.to_string()))?
    {
        if bytes.len() + chunk.len() > MAX_AVATAR_BYTES {
            return Err(FetchAvatarError::BodyTooLarge {
                max_bytes: MAX_AVATAR_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(FetchedAvatar {
        bytes,
        content_type,
        etag,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ----- icon extraction shapes -----

    #[test]
    fn mastodon_image_object_shape() {
        let doc = json!({
            "id": "https://fosstodon.org/users/happyborg",
            "icon": { "type": "Image", "mediaType": "image/png",
                      "url": "https://cdn.example/a.png" }
        });
        assert_eq!(
            icon_url_from_actor_doc(&doc).as_deref(),
            Some("https://cdn.example/a.png")
        );
    }

    #[test]
    fn icon_array_takes_first_usable_entry() {
        let doc = json!({
            "icon": [
                { "type": "Image" },
                { "type": "Image", "url": "https://cdn.example/b.png" },
                { "type": "Image", "url": "https://cdn.example/c.png" }
            ]
        });
        assert_eq!(
            icon_url_from_actor_doc(&doc).as_deref(),
            Some("https://cdn.example/b.png")
        );
    }

    #[test]
    fn bare_string_icon_is_accepted() {
        let doc = json!({ "icon": "https://cdn.example/d.png" });
        assert_eq!(
            icon_url_from_actor_doc(&doc).as_deref(),
            Some("https://cdn.example/d.png")
        );
    }

    #[test]
    fn json_ld_link_object_href_is_accepted() {
        let doc = json!({ "icon": { "url": { "type": "Link",
                                             "href": "https://cdn.example/e.png" } } });
        assert_eq!(
            icon_url_from_actor_doc(&doc).as_deref(),
            Some("https://cdn.example/e.png")
        );
    }

    #[test]
    fn url_array_inside_icon_object_is_accepted() {
        let doc = json!({ "icon": { "url": ["https://cdn.example/f.png",
                                            "https://cdn.example/g.png"] } });
        assert_eq!(
            icon_url_from_actor_doc(&doc).as_deref(),
            Some("https://cdn.example/f.png")
        );
    }

    #[test]
    fn missing_or_unusable_icon_is_none() {
        assert!(icon_url_from_actor_doc(&json!({})).is_none());
        assert!(icon_url_from_actor_doc(&json!({ "icon": null })).is_none());
        assert!(icon_url_from_actor_doc(&json!({ "icon": 7 })).is_none());
        assert!(icon_url_from_actor_doc(&json!({ "icon": "   " })).is_none());
        assert!(icon_url_from_actor_doc(&json!({ "icon": { "type": "Image" } })).is_none());
        assert!(icon_url_from_actor_doc(&json!({ "icon": [] })).is_none());
    }

    #[test]
    fn deeply_nested_icon_terminates() {
        // Pathological nesting must bottom out at MAX_ICON_DEPTH rather
        // than recursing on attacker-chosen depth.
        let mut v = json!("https://cdn.example/deep.png");
        for _ in 0..64 {
            v = json!({ "url": v });
        }
        assert!(icon_url_from_actor_doc(&json!({ "icon": v })).is_none());
    }

    // ----- media type beside the icon -----

    #[test]
    fn icon_media_type_is_read_from_object_and_array_shapes() {
        let obj = json!({ "icon": { "type": "Image", "mediaType": "Image/JPEG",
                                    "url": "https://cdn.example/a.jpg" } });
        assert_eq!(
            icon_media_type_from_actor_doc(&obj).as_deref(),
            Some("image/jpeg")
        );
        let arr = json!({ "icon": [{ "mediaType": "image/png",
                                     "url": "https://cdn.example/a.png" }] });
        assert_eq!(
            icon_media_type_from_actor_doc(&arr).as_deref(),
            Some("image/png")
        );
    }

    #[test]
    fn absent_or_empty_icon_media_type_is_none() {
        assert!(icon_media_type_from_actor_doc(&json!({})).is_none());
        assert!(
            icon_media_type_from_actor_doc(&json!({ "icon": "https://cdn.example/a.png" }))
                .is_none()
        );
        assert!(
            icon_media_type_from_actor_doc(&json!({ "icon": { "mediaType": "  " } })).is_none()
        );
    }

    // ----- upload magic-byte gate -----

    #[test]
    fn upload_allowlist_excludes_gif_and_is_a_subset() {
        assert!(!UPLOADABLE_AVATAR_CONTENT_TYPES.contains(&"image/gif"));
        for ct in UPLOADABLE_AVATAR_CONTENT_TYPES {
            assert!(
                ALLOWED_AVATAR_CONTENT_TYPES.contains(&ct),
                "{ct} must also be fetchable"
            );
        }
    }

    #[test]
    fn magic_matches_the_declared_type() {
        assert!(magic_matches_content_type(
            "image/jpeg",
            &[0xFF, 0xD8, 0xFF, 0xE0, 0x00]
        ));
        assert!(magic_matches_content_type(
            "image/png",
            b"\x89PNG\r\n\x1a\nrest"
        ));
        assert!(magic_matches_content_type(
            "image/webp",
            b"RIFF\x24\x00\x00\x00WEBPVP8 "
        ));
    }

    #[test]
    fn magic_rejects_mislabelled_or_truncated_bytes() {
        // The whole point: a page or a script claiming to be an image
        // must not become a file we host under our own domain.
        assert!(!magic_matches_content_type(
            "image/png",
            b"<!doctype html><script>"
        ));
        assert!(!magic_matches_content_type(
            "image/jpeg",
            b"\x89PNG\r\n\x1a\n"
        ));
        assert!(!magic_matches_content_type("image/webp", b"RIFF\x00\x00"));
        assert!(!magic_matches_content_type("image/png", b""));
        // A type outside the upload allowlist fails closed.
        assert!(!magic_matches_content_type("image/gif", b"GIF89a"));
        assert!(!magic_matches_content_type(
            "image/svg+xml",
            b"<svg xmlns=\"\">"
        ));
    }

    // ----- content-type normalisation -----

    #[test]
    fn content_type_parameters_are_stripped_and_lowercased() {
        assert_eq!(
            normalize_content_type("Image/PNG; charset=binary"),
            "image/png"
        );
        assert_eq!(normalize_content_type("  image/jpeg  "), "image/jpeg");
        assert_eq!(normalize_content_type(""), "");
    }

    // ----- SSRF gate: rejected URLs never reach the wire -----

    #[tokio::test]
    async fn loopback_icon_url_is_rejected_without_issuing_a_request() {
        // The mock server is live on 127.0.0.1; the pre-flight must
        // reject before a socket opens, so it records zero requests.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 16]))
            .mount(&server)
            .await;
        let port = server.address().port();
        let url: url::Url = format!("https://127.0.0.1:{port}/avatar.png")
            .parse()
            .unwrap();

        let err = fetch_avatar(&url).await.unwrap_err();
        assert!(
            matches!(err, FetchAvatarError::PrivateInstance { .. }),
            "expected PrivateInstance, got {err:?}"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "SSRF-rejected URL must never be fetched",
        );
    }

    #[tokio::test]
    async fn private_ipv4_icon_url_is_rejected() {
        let url: url::Url = "https://192.168.1.1/a.png".parse().unwrap();
        assert!(matches!(
            fetch_avatar(&url).await.unwrap_err(),
            FetchAvatarError::PrivateInstance { .. }
        ));
    }

    #[tokio::test]
    async fn cloud_metadata_icon_url_is_rejected() {
        let url: url::Url = "https://169.254.169.254/a.png".parse().unwrap();
        assert!(matches!(
            fetch_avatar(&url).await.unwrap_err(),
            FetchAvatarError::PrivateInstance { .. }
        ));
    }

    #[tokio::test]
    async fn non_https_icon_url_is_rejected() {
        for raw in [
            "http://cdn.example/a.png",
            "file:///etc/passwd",
            "ftp://cdn.example/a.png",
        ] {
            let url: url::Url = raw.parse().unwrap();
            match fetch_avatar(&url).await.unwrap_err() {
                FetchAvatarError::NotHttps { scheme } => {
                    assert_ne!(scheme, "https");
                }
                other => panic!("expected NotHttps for {raw}, got {other:?}"),
            }
        }
    }

    // ----- caps + allowlist over wiremock -----

    async fn serve(ct: Option<&str>, body: Vec<u8>) -> (MockServer, url::Url) {
        let server = MockServer::start().await;
        let mut tmpl = ResponseTemplate::new(200).set_body_bytes(body);
        if let Some(ct) = ct {
            tmpl = tmpl.insert_header("content-type", ct);
        }
        Mock::given(method("GET"))
            .and(path("/avatar"))
            .respond_with(tmpl)
            .mount(&server)
            .await;
        let url = format!("{}/avatar", server.uri()).parse().unwrap();
        (server, url)
    }

    #[tokio::test]
    async fn allowed_content_type_returns_bytes() {
        let (_s, url) = serve(Some("image/png; charset=binary"), vec![0x89, 0x50, 0x4e]).await;
        let got = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .expect("happy path");
        assert_eq!(got.bytes, vec![0x89, 0x50, 0x4e]);
        assert_eq!(got.content_type, "image/png");
    }

    #[tokio::test]
    async fn every_allowlisted_type_is_accepted() {
        for ct in ALLOWED_AVATAR_CONTENT_TYPES {
            let (_s, url) = serve(Some(ct), vec![1, 2, 3]).await;
            let got = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
                .await
                .unwrap_or_else(|e| panic!("{ct} must be accepted: {e}"));
            assert_eq!(got.content_type, ct);
        }
    }

    #[tokio::test]
    async fn disallowed_content_types_are_rejected() {
        for ct in ["text/html", "image/svg+xml", "application/octet-stream"] {
            let (_s, url) = serve(Some(ct), vec![1, 2, 3]).await;
            let err = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
                .await
                .unwrap_err();
            match err {
                FetchAvatarError::ContentType { content_type } => assert_eq!(content_type, ct),
                other => panic!("expected ContentType for {ct}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn missing_content_type_is_rejected() {
        let (_s, url) = serve(None, vec![1, 2, 3]).await;
        let err = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchAvatarError::ContentType { .. }));
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let (_s, url) = serve(Some("image/png"), vec![0u8; MAX_AVATAR_BYTES + 1]).await;
        let err = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        match err {
            FetchAvatarError::BodyTooLarge { max_bytes } => {
                assert_eq!(max_bytes, MAX_AVATAR_BYTES);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn body_exactly_at_the_cap_is_accepted() {
        let (_s, url) = serve(Some("image/jpeg"), vec![7u8; MAX_AVATAR_BYTES]).await;
        let got = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .expect("the cap is inclusive");
        assert_eq!(got.bytes.len(), MAX_AVATAR_BYTES);
    }

    #[tokio::test]
    async fn non_2xx_surfaces_http() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/avatar"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let url: url::Url = format!("{}/avatar", server.uri()).parse().unwrap();
        let err = fetch_avatar_at_url(&reqwest::Client::new(), &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchAvatarError::Http { status: 404 }));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        // The production client is redirect::Policy::none(), so a 3xx is
        // a terminal non-2xx: there is no second hop to SSRF-check.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/avatar"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "http://127.0.0.1/secret"),
            )
            .mount(&server)
            .await;
        let url: url::Url = format!("{}/avatar", server.uri()).parse().unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let err = fetch_avatar_at_url(&client, &url, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchAvatarError::Http { status: 302 }));
    }
}
