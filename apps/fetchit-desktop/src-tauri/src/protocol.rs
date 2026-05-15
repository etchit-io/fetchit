//! `fetchit://<64-hex>` custom URI scheme — serves Autonomi bytes to the
//! WebView so `<img>`, `<audio>`, `<video>`, `<iframe>`, and the EPUB/PDF
//! readers can stream content without round-tripping IPC for every load.
//!
//! Mirrors `HtmlView.shouldInterceptRequest` from the Android app: the WebView
//! never reaches the public internet for these URIs — the handler resolves the
//! address against the in-process cache (or fetches over Autonomi on miss).

use crate::state::{default_peers, ensure_client, AppState};
use bytes::Bytes;
use fetchit_core::{Address, NetworkClient};
use tauri::http::{header, Request, Response, StatusCode};
use tauri::{AppHandle, Manager, Runtime, UriSchemeContext, UriSchemeResponder};

// Dev-only diagnostic line on the daemon's stderr. Compiles out of release.
macro_rules! diag {
    ($($t:tt)+) => {
        if cfg!(debug_assertions) {
            eprintln!($($t)+);
        }
    };
}

/// Entry point matched by [`tauri::Builder::register_asynchronous_uri_scheme_protocol`].
/// Registered twice in `lib.rs` — once each for `fetchit://` and `autonomi://`.
pub fn handle<R: Runtime>(
    ctx: UriSchemeContext<'_, R>,
    request: Request<Vec<u8>>,
    responder: UriSchemeResponder,
) {
    let app = ctx.app_handle().clone();
    tauri::async_runtime::spawn(async move {
        responder.respond(serve(app, request).await);
    });
}

async fn serve<R: Runtime>(app: AppHandle<R>, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    let uri = request.uri();
    let scheme = uri.scheme_str().unwrap_or("?");
    let host = uri.host().unwrap_or("");
    let path = uri.path();
    let range_str = request
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    diag!("[fetchit] req scheme={scheme} host={host} path={path} range={range_str}");

    let Some(addr) = extract_addr(host, path) else {
        diag!("[fetchit] err bad-address scheme={scheme} host={host} path={path}");
        return error(StatusCode::BAD_REQUEST, "fetchit:// requires a 64-hex address");
    };

    let state = app.state::<AppState>();
    let bytes = match state.cached_bytes(&addr) {
        Some(b) => {
            diag!("[fetchit] cache-hit {} bytes", b.len());
            b
        }
        None => {
            diag!("[fetchit] cache-miss → network");
            match fetch_into_cache(&state, addr).await {
                Ok(b) => {
                    diag!("[fetchit] fetched {} bytes", b.len());
                    b
                }
                Err(msg) => {
                    diag!("[fetchit] err fetch-failed: {msg}");
                    return error(StatusCode::BAD_GATEWAY, &msg);
                }
            }
        }
    };
    let range = request.headers().get(header::RANGE).and_then(|v| v.to_str().ok());
    let resp = build(&bytes, range);
    diag!(
        "[fetchit] resp status={} mime={} bytes={}",
        resp.status(),
        sniff_mime(&bytes),
        bytes.len()
    );
    resp
}

async fn fetch_into_cache(state: &AppState, addr: Address) -> Result<Bytes, String> {
    let client = ensure_client(state, &default_peers()).await?;
    let bytes = client.fetch(&addr).await.map_err(|e| e.to_string())?;
    state.cache_bytes(&addr, bytes.clone());
    Ok(bytes)
}

// The address can arrive in either the host or the first path segment. Path
// wins when both look like addresses: when the iframe's `<base href>` is
// `fetchit://<spa>/` and the page references `<img src="<image>">`, the
// resolved URL is `fetchit://<spa>/<image>` — the *image* is the resource
// the WebView is requesting, the SPA address is just the base context.
// Linux WebKitGTK also rewrites custom schemes to
// `http://<scheme>.localhost/<rest>`, which lands the address in the path.
fn extract_addr(host: &str, path: &str) -> Option<Address> {
    for cand in [path.trim_start_matches('/'), host] {
        let head = cand.split(['/', '?', '#']).next().unwrap_or("");
        if head.len() == 64 && head.bytes().all(|b| b.is_ascii_hexdigit()) {
            return head.parse().ok();
        }
    }
    None
}

fn sniff_mime(bytes: &[u8]) -> &'static str {
    infer::get(bytes).map_or("application/octet-stream", |k| k.mime_type())
}

fn build(bytes: &Bytes, range: Option<&str>) -> Response<Vec<u8>> {
    let total = bytes.len();
    let mime = sniff_mime(bytes);
    // The WebView probes media with `Range: bytes=0-1445`. If the file starts
    // with a big ID3 tag (or other container header), 1446 bytes contains no
    // audio frames and WebKitGTK bails with MEDIA_ERR_SRC_NOT_SUPPORTED
    // without issuing a follow-up Range — playback is dead. We always have
    // the full bytes cached, so for any 0-prefixed probe we serve the WHOLE
    // file with a plain 200 OK (HTTP allows ignoring Range and returning the
    // full body). Non-zero starts (real seeks) still get a proper 206 slice.
    if let Some((start, end)) = range.and_then(|h| parse_range(h, total)) {
        if start == 0 {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CONTENT_LENGTH, total)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(bytes.to_vec())
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR));
        }
        let len = end - start + 1;
        let slice = bytes.slice(start..=end);
        return Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, len)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{total}"))
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(slice.to_vec())
            .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR));
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, total)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(bytes.to_vec())
        .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
}

fn parse_range(header: &str, total: usize) -> Option<(usize, usize)> {
    let spec = header.strip_prefix("bytes=")?;
    let (s, e) = spec.split_once('-')?;
    let start: usize = s.parse().ok()?;
    let end: usize = if e.is_empty() {
        total.checked_sub(1)?
    } else {
        e.parse().ok()?
    };
    if start > end || end >= total {
        return None;
    }
    Some((start, end))
}

fn error(status: StatusCode, msg: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(msg.as_bytes().to_vec())
        .unwrap_or_else(|_| empty(status))
}

fn empty(status: StatusCode) -> Response<Vec<u8>> {
    let mut r = Response::new(Vec::new());
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn expected_addr() -> Address {
        A.parse().expect("valid 64-hex test fixture")
    }

    #[test]
    fn extract_addr_from_host() {
        assert_eq!(extract_addr(A, "/"), Some(expected_addr()));
    }

    #[test]
    fn extract_addr_from_path_only() {
        assert_eq!(
            extract_addr("fetchit.localhost", &format!("/{A}")),
            Some(expected_addr())
        );
    }

    #[test]
    fn extract_addr_ignores_extra_path_segments() {
        assert_eq!(
            extract_addr("fetchit.localhost", &format!("/{A}/nested/asset.png")),
            Some(expected_addr())
        );
    }

    #[test]
    fn extract_addr_prefers_path_when_both_are_addresses() {
        // <img src="<image>"> with <base href="fetchit://<spa>/"> resolves to
        // fetchit://<spa>/<image>; the image is the actual resource.
        const SPA: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(extract_addr(SPA, &format!("/{A}")), Some(expected_addr()));
    }

    #[test]
    fn extract_addr_falls_back_to_host_when_path_has_no_address() {
        // <img src="some/relative/asset.png"> with fetchit://<addr>/ as base
        // resolves to fetchit://<addr>/some/relative/asset.png — no address in
        // the path; the host is the only meaningful target.
        assert_eq!(
            extract_addr(A, "/some/relative/asset.png"),
            Some(expected_addr())
        );
    }

    #[test]
    fn extract_addr_rejects_non_hex_chars() {
        let bad = "z".repeat(64);
        assert!(extract_addr(&bad, "/").is_none());
    }

    #[test]
    fn extract_addr_rejects_wrong_length() {
        assert!(extract_addr("abcd", "/").is_none());
        assert!(extract_addr(&"a".repeat(63), "/").is_none());
        assert!(extract_addr(&"a".repeat(65), "/").is_none());
    }

    #[test]
    fn extract_addr_returns_none_when_both_empty() {
        assert!(extract_addr("", "/").is_none());
        assert!(extract_addr("", "").is_none());
    }

    #[test]
    fn parse_range_full_explicit() {
        assert_eq!(parse_range("bytes=0-99", 100), Some((0, 99)));
    }

    #[test]
    fn parse_range_open_ended_means_to_end() {
        assert_eq!(parse_range("bytes=50-", 100), Some((50, 99)));
    }

    #[test]
    fn parse_range_first_byte_only() {
        assert_eq!(parse_range("bytes=0-0", 100), Some((0, 0)));
    }

    #[test]
    fn parse_range_rejects_wrong_prefix() {
        assert!(parse_range("items=0-99", 100).is_none());
        assert!(parse_range("0-99", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_missing_dash() {
        assert!(parse_range("bytes=50", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_end_past_total() {
        assert!(parse_range("bytes=0-100", 100).is_none());
        assert!(parse_range("bytes=0-9999", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_start_after_end() {
        assert!(parse_range("bytes=99-0", 100).is_none());
    }

    #[test]
    fn parse_range_rejects_open_ended_on_empty() {
        assert!(parse_range("bytes=0-", 0).is_none());
    }

    #[test]
    fn parse_range_rejects_non_numeric() {
        assert!(parse_range("bytes=abc-def", 100).is_none());
        assert!(parse_range("bytes=0-xyz", 100).is_none());
    }

    #[test]
    fn sniff_mime_falls_back_for_empty() {
        assert_eq!(sniff_mime(&[]), "application/octet-stream");
    }

    #[test]
    fn sniff_mime_identifies_png_magic() {
        let png = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0];
        assert_eq!(sniff_mime(&png), "image/png");
    }
}
