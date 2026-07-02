//! Tiny localhost HTTP server for serving Autonomi bytes to the `WebView`'s
//! `<audio>` / `<video>` elements at `http://127.0.0.1:<port>/<addr>`.
//!
//! Why this exists: `WebKitGTK`'s media pipeline accepts only a small allowlist
//! of URL schemes for `<video src>` (http, https, file, blob). Our custom
//! `fetchit://` / `autonomi://` schemes resolve via Tauri's protocol handler
//! for `fetch()` and `<img>` requests, but the video pipeline ignores them
//! and fires `MEDIA_ERR_SRC_NOT_SUPPORTED`. The Android `HtmlView` mirror of
//! this — `shouldInterceptRequest` against `https://aut.local/<addr>` — has
//! no desktop equivalent; we get the same outcome by giving the `WebView` a
//! standard `http://` URL pointing at a tiny local server.
//!
//! The server is bound to `127.0.0.1:0` (random free port). On a cache miss
//! it calls `AppState::get_or_start_stream`, which either joins an existing
//! progressive download or starts a new feeder task and returns the shared
//! `Arc<StreamingMedia>`. Each connection holds an `InterestGuard` for its
//! lifetime; when the last guard drops the feeder stops early.

use crate::state::AppState;
use crate::streaming_media::await_offset;
use bytes::Bytes;
use fetchit_core::Address;
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

    // Fast path: fully cached -> serve the complete buffer as before.
    if let Some(bytes) = state.cached_bytes(&addr) {
        diag!("[media-srv] cache-hit {} bytes", bytes.len());
        return serve_complete(&mut stream, method, range.as_deref(), &bytes).await;
    }

    // Progressive path. `get_or_start_stream` returns the stream and an
    // `InterestGuard` registered before the feeder can run, so the feeder
    // never sees interest == 0 between spawn and this connection taking hold.
    let (sm, _guard) = match state.get_or_start_stream(addr).await {
        Ok(pair) => pair,
        Err(msg) => {
            diag!("[media-srv] stream-failed: {msg}");
            return reply_simple(&mut stream, 502, "Bad Gateway", &msg).await;
        }
    };
    serve_progressive(&mut stream, method, range.as_deref(), &sm).await
}

/// Serve a fully-buffered response for a cache hit. Mirrors the original
/// complete-buffer HEAD / 206 / 200 response block verbatim so the fast
/// path is behavior-equivalent before and after the streaming rewrite.
async fn serve_complete(
    stream: &mut TcpStream,
    method: &str,
    range: Option<&str>,
    bytes: &Bytes,
) -> std::io::Result<()> {
    let mime = sniff_mime(bytes);
    let total = bytes.len();

    if method == "HEAD" {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if let Some((start, end)) = range.and_then(|h| parse_range(h, total)) {
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
        stream.write_all(bytes).await?;
        diag!("[media-srv] resp 200 bytes={total} mime={mime}");
    }
    Ok(())
}

/// Stream a response body progressively from a [`crate::streaming_media::StreamingMedia`]
/// instance. Sniffs the MIME type from the first arriving bytes, sends headers with
/// a real `Content-Length`, then delivers body chunks as the watermark advances.
/// Supports `Range` requests (206) and HEAD probes. On a TCP write error the
/// connection is dropped cleanly.
async fn serve_progressive(
    stream: &mut TcpStream,
    method: &str,
    range: Option<&str>,
    sm: &std::sync::Arc<crate::streaming_media::StreamingMedia>,
) -> std::io::Result<()> {
    let total = sm.total();
    let mut rx = sm.subscribe();

    // Sniff MIME from the first bytes: wait for a small prefix, then read it.
    // Use the actual available count returned by await_offset to clamp the
    // read; the feeder may end with fewer bytes than the sniff window (early
    // network failure or 0-byte content), and slicing past the buffer panics.
    let sniff_end = total.min(4096).saturating_sub(1);
    let avail = await_offset(&mut rx, sniff_end + 1).await.unwrap_or(0);
    let head = if avail == 0 {
        Bytes::new()
    } else {
        sm.read_range(0, avail.min(sniff_end + 1) - 1).await.unwrap_or_default()
    };
    let mime = sniff_mime(&head);

    if method == "HEAD" {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        );
        return stream.write_all(resp.as_bytes()).await;
    }

    let total_usize = usize::try_from(total).unwrap_or(usize::MAX);
    let parsed = range.and_then(|h| parse_range(h, total_usize));
    let is_partial = parsed.is_some();
    let (start, end) = match parsed {
        Some((s, e)) => (s as u64, e as u64),
        None => (0, total.saturating_sub(1)),
    };

    let header = if is_partial {
        let len = end - start + 1;
        format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Type: {mime}\r\nContent-Length: {len}\r\nContent-Range: bytes {start}-{end}/{total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        )
    };
    if stream.write_all(header.as_bytes()).await.is_err() {
        return Ok(()); // client gone
    }

    // Stream the body in windows as the watermark advances.
    let mut pos = start;
    while pos <= end {
        let want = (pos + 64 * 1024).min(end + 1); // 64 KiB windows
        let Ok(available) = await_offset(&mut rx, want).await else {
            break; // feeder failed; drop the connection
        };
        let ready_end = available.min(end + 1);
        if ready_end <= pos {
            break; // EOF before the requested end
        }
        let Ok(slice) = sm.read_range(pos, ready_end - 1).await else {
            break;
        };
        if stream.write_all(&slice).await.is_err() {
            break; // client disconnected mid-stream
        }
        pos = ready_end;
    }
    Ok(())
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_test_state() -> (AppState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let disk = std::sync::Arc::new(crate::disk_cache::DiskCache::new(
            tmp.path().join("disk"),
            crate::disk_cache::Policy::default(),
        ));
        let state = AppState::new(
            disk,
            crate::settings::Settings::default(),
            tmp.path().join("settings.json"),
        );
        (state, tmp)
    }

    /// Progressive streaming: a stream pre-seeded via `insert_stream_for_test`
    /// is fed incrementally after the request is in flight, and the server
    /// delivers all bytes with the correct `Content-Length` header.
    #[tokio::test]
    async fn serve_streams_body_as_it_arrives() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (state, _tmp) = make_test_state();
        let addr: Address = "cd".repeat(32).parse().unwrap();
        let sm = std::sync::Arc::new(crate::streaming_media::StreamingMedia::new(
            6,
            crate::streaming_media::StreamBacking::Memory(std::sync::Mutex::new(Vec::new())),
        ));
        state.insert_stream_for_test(addr, sm.clone());
        let port = super::spawn(state).await.unwrap();

        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        conn.write_all(
            format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "cd".repeat(32)).as_bytes(),
        )
        .await
        .unwrap();
        // feed after the request is in flight
        sm.push(b"abc").await.unwrap();
        sm.push(b"def").await.unwrap();
        sm.finish();

        let mut resp = Vec::new();
        conn.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("Content-Length: 6"), "expected Content-Length: 6 in {text}");
        assert!(text.contains("Accept-Ranges: bytes"), "expected Accept-Ranges in {text}");
        assert!(resp.ends_with(b"abcdef"), "expected body abcdef, got tail {:?}", &resp[resp.len().saturating_sub(10)..]);
    }

    /// Regression: a Memory-backed progressive stream whose feeder ends with
    /// fewer bytes than the 4096-byte MIME sniff window must not panic when
    /// `serve_progressive` reads back the sniff head.
    #[tokio::test]
    async fn serve_progressive_short_body_no_panic() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (state, _tmp) = make_test_state();
        let addr: Address = "ef".repeat(32).parse().unwrap();
        // total > 4096 so the sniff window is 4095 bytes; feeder sends only 50.
        let sm = std::sync::Arc::new(crate::streaming_media::StreamingMedia::new(
            10_000,
            crate::streaming_media::StreamBacking::Memory(std::sync::Mutex::new(Vec::new())),
        ));
        state.insert_stream_for_test(addr, sm.clone());
        let port = super::spawn(state).await.unwrap();

        let mut conn =
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        conn.write_all(
            format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "ef".repeat(32)).as_bytes(),
        )
        .await
        .unwrap();

        // Push far fewer bytes than the sniff window, then signal failure.
        sm.push(&[0xFFu8; 50]).await.unwrap();
        sm.fail("simulated early network failure".into());

        let mut resp = Vec::new();
        conn.read_to_end(&mut resp).await.unwrap();
        // Any non-empty HTTP response means no panic.
        assert!(!resp.is_empty());
    }

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
        assert_eq!(
            strip_header_ci("Range: bytes=0-99", "range"),
            Some("bytes=0-99")
        );
        assert_eq!(
            strip_header_ci("RANGE: bytes=0-99", "range"),
            Some("bytes=0-99")
        );
        assert_eq!(strip_header_ci("Other: x", "range"), None);
    }
}
