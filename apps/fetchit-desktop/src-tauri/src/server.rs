//! Tiny localhost HTTP server for serving Autonomi bytes to the WebView's
//! `<audio>` / `<video>` elements at `http://127.0.0.1:<port>/<addr>`.
//!
//! Why this exists: WebKitGTK's media pipeline accepts only a small allowlist
//! of URL schemes for `<video src>` (http, https, file, blob). Our custom
//! `fetchit://` / `autonomi://` schemes resolve via Tauri's protocol handler
//! for `fetch()` and `<img>` requests, but the video pipeline ignores them
//! and fires `MEDIA_ERR_SRC_NOT_SUPPORTED`. The Android `HtmlView` mirror of
//! this — `shouldInterceptRequest` against `https://aut.local/<addr>` — has
//! no desktop equivalent; we get the same outcome by giving the WebView a
//! standard `http://` URL pointing at a tiny local server.
//!
//! The server is bound to `127.0.0.1:0` (random free port). Same cache and
//! `AutonomiClient` as the protocol handler — fetch-on-miss reuses the
//! bytes a `fetch_and_render` may already have downloaded.

use crate::state::AppState;
use bytes::Bytes;
use fetchit_core::{Address, NetworkClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

macro_rules! diag {
    ($($t:tt)+) => {
        if cfg!(debug_assertions) {
            eprintln!($($t)+);
        }
    };
}

/// Spawn the server on a random free port. Returns the bound port.
pub async fn spawn(state: AppState) -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    diag!("[media-srv] listening on http://127.0.0.1:{port}");
    tokio::spawn(async move {
        loop {
            let stream = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    diag!("[media-srv] accept error: {e}");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = serve(stream, state).await {
                    diag!("[media-srv] serve error: {e}");
                }
            });
        }
    });
    Ok(port)
}

async fn serve(mut stream: TcpStream, state: AppState) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 32 * 1024 {
            return reply_simple(&mut stream, 431, "Request Header Fields Too Large", "").await;
        }
    }

    let request = String::from_utf8_lossy(&buf);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("");

    if !matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return reply_simple(&mut stream, 405, "Method Not Allowed", "").await;
    }
    if method == "OPTIONS" {
        return reply_cors_preflight(&mut stream).await;
    }

    let mut range: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = strip_header_ci(line, "range") {
            range = Some(rest.to_string());
        }
    }

    let addr_part = raw_path
        .trim_start_matches('/')
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if addr_part.len() != 64 || !addr_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        diag!("[media-srv] err bad-address path={raw_path}");
        return reply_simple(&mut stream, 400, "Bad Request", "address must be 64-hex").await;
    }
    let Ok(addr) = addr_part.parse::<Address>() else {
        return reply_simple(&mut stream, 400, "Bad Request", "invalid address").await;
    };

    diag!(
        "[media-srv] req method={method} addr={}… range={}",
        &addr_part[..10],
        range.as_deref().unwrap_or("")
    );

    let bytes = match state.cached_bytes(&addr) {
        Some(b) => {
            diag!("[media-srv] cache-hit {} bytes", b.len());
            b
        }
        None => match fetch_into_cache(&state, addr).await {
            Ok(b) => {
                diag!("[media-srv] fetched {} bytes", b.len());
                b
            }
            Err(msg) => {
                diag!("[media-srv] fetch-failed: {msg}");
                return reply_simple(&mut stream, 502, "Bad Gateway", &msg).await;
            }
        },
    };

    let mime = sniff_mime(&bytes);
    let total = bytes.len();

    if method == "HEAD" {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if let Some((start, end)) = range.as_deref().and_then(|h| parse_range(h, total)) {
        let len = end - start + 1;
        let slice = bytes.slice(start..=end);
        let resp = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Type: {mime}\r\nContent-Length: {len}\r\nContent-Range: bytes {start}-{end}/{total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.write_all(&slice).await?;
        diag!("[media-srv] resp 206 bytes={len}/{total} mime={mime}");
    } else {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.write_all(&bytes).await?;
        diag!("[media-srv] resp 200 bytes={total} mime={mime}");
    }
    Ok(())
}

async fn fetch_into_cache(state: &AppState, addr: Address) -> Result<Bytes, String> {
    let client = crate::state::ensure_client(state, &state.effective_peers()).await?;
    let bytes = client.fetch(&addr).await.map_err(|e| e.to_string())?;
    state.cache_bytes(&addr, bytes.clone());
    Ok(bytes)
}

async fn reply_simple(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream.write_all(resp.as_bytes()).await
}

async fn reply_cors_preflight(stream: &mut TcpStream) -> std::io::Result<()> {
    let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, HEAD, OPTIONS\r\nAccess-Control-Allow-Headers: Range\r\nAccess-Control-Max-Age: 86400\r\nConnection: close\r\n\r\n";
    stream.write_all(resp.as_bytes()).await
}

fn strip_header_ci<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (head, rest) = line.split_once(':')?;
    if head.trim().eq_ignore_ascii_case(name) {
        Some(rest.trim())
    } else {
        None
    }
}

fn sniff_mime(bytes: &[u8]) -> &'static str {
    infer::get(bytes).map_or("application/octet-stream", |k| k.mime_type())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_full_explicit() {
        assert_eq!(parse_range("bytes=0-99", 100), Some((0, 99)));
    }

    #[test]
    fn parse_range_open_end() {
        assert_eq!(parse_range("bytes=50-", 100), Some((50, 99)));
    }

    #[test]
    fn parse_range_rejects_bad_input() {
        assert!(parse_range("items=0-99", 100).is_none());
        assert!(parse_range("bytes=50", 100).is_none());
        assert!(parse_range("bytes=0-100", 100).is_none());
        assert!(parse_range("bytes=99-0", 100).is_none());
    }

    #[test]
    fn strip_header_ci_matches_any_case() {
        assert_eq!(strip_header_ci("Range: bytes=0-99", "range"), Some("bytes=0-99"));
        assert_eq!(strip_header_ci("RANGE: bytes=0-99", "range"), Some("bytes=0-99"));
        assert_eq!(strip_header_ci("Other: x", "range"), None);
    }
}
