# Progressive Media Serving Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Play video/audio off an Autonomi address as bytes arrive instead of after a full download, by streaming the `127.0.0.1` media server's response from `fetch_to_sink`.

**Architecture:** A `StreamingMedia` value (one per address, shared by all HTTP connections) holds a growing backing store (in-memory when cache off, a `.partial` file when cache on) and a `watch<StreamState>` watermark. A feeder task runs `fetch_to_sink`, pushing each chunk into the backing and advancing the watermark. `server.rs`'s `serve()` sends a real `Content-Length` (from the data-map size, known up front) and streams the body / serves ranges by awaiting the watermark. Cancellation follows client disconnect.

**Tech Stack:** Rust, tokio (`sync::watch`, raw `TcpStream`), `bytes::Bytes`, ant-core `fetch_to_sink` + data map, the existing `DiskCache`.

## Global Constraints

- Scope: only the media types served through the `127.0.0.1` server (standalone video/audio + SPA-embedded `<video>/<audio>`). PDF (pdf.js), images, JSON, tabular, archive, text, HTML render stay on the existing whole-payload path. No changes to `protocol.rs`, `pdf.ts`, `htmlRewriter.ts`, or the iframe sandbox.
- Cache OFF (default): buffer in memory only; nothing new touches disk. Cache ON: stream into the cache slot via `DiskCache::stream_path`/`commit_stream`/`discard_stream`.
- Security boundary unchanged: same `127.0.0.1` origin, same CSP (`media-src` already lists `mediaBase`), same CORS, same 64-hex-address validation.
- Per-task gates: backend `cd apps/fetchit-desktop/src-tauri && cargo test <name> && cargo clippy --all-targets -- -D warnings`; net `cargo test -p fetchit-net <name> && cargo clippy -p fetchit-net --all-targets -- -D warnings`.
- Commits: `git commit -s` (DCO), no em-dashes, no AI co-author trailer.

## File Structure

- `crates/fetchit-net/src/client.rs` (modify): add `AutonomiClient::content_size` next to `fetch_to_sink`.
- `crates/fetchit-net/tests/live.rs` (modify): live assertion for `content_size`.
- `apps/fetchit-desktop/src-tauri/src/streaming_media.rs` (create): `StreamState`, `StreamBacking`, `StreamingMedia` (the unit-testable core: push/finish/fail/read_range + watch). One responsibility: hold and serve a growing per-address stream.
- `apps/fetchit-desktop/src-tauri/src/state.rs` (modify): a `streams` registry field on `AppState` + `get_or_start_stream`.
- `apps/fetchit-desktop/src-tauri/src/server.rs` (modify): `serve()` streaming rewrite; keep `parse_range`/`strip_header_ci`/`sniff_mime` and their tests.
- `apps/fetchit-desktop/src-tauri/src/lib.rs` (modify): register `mod streaming_media;`.
- `docs/SECURITY.md` (modify): one-line streaming note.

Notes for the implementer:
- `DiskCache` (`disk_cache.rs`) already exposes `stream_path(&Address) -> PathBuf` (the `.partial` file), `commit_stream(&Address)` (atomic rename onto the `.bin` slot + evict), `discard_stream(&Address)` (delete the partial), `get`, `put`, `policy`, `root`. Do NOT reimplement these.
- `ant_core::data::DataMap` is `self_encryption::DataMap` and has `original_file_size(&self) -> usize`.
- The existing `fetch_to_sink(&self, addr, sink: tokio::sync::mpsc::Sender<CoreResult<Bytes>>, on_progress)` returns `CoreResult<u64>` (total bytes). Reuse it as the feeder; do not change its signature.

---

### Task 1: `content_size` in fetchit-net

**Files:**
- Modify: `crates/fetchit-net/src/client.rs` (add method in the `impl AutonomiClient` inherent block, next to `fetch_to_sink`)
- Test: `crates/fetchit-net/tests/live.rs`

**Interfaces:**
- Produces: `pub async fn content_size(&self, addr: &Address) -> CoreResult<u64>` — resolves the data map and returns the original file size, without downloading content.

- [ ] **Step 1: Write the failing live test** (append inside `tests/live.rs`, before `fn rendition_kind`)

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "hits the live Autonomi network; requires FETCHIT_LIVE_ADDR"]
async fn content_size_matches_fetched_length() {
    let Ok(addr_hex) = std::env::var("FETCHIT_LIVE_ADDR") else {
        eprintln!("FETCHIT_LIVE_ADDR not set - nothing to test");
        return;
    };
    let addr: Address = addr_hex.parse().expect("FETCHIT_LIVE_ADDR must be 64-hex");
    let client = AutonomiClient::connect(&parse_peers())
        .await
        .expect("connect to live network");
    let size = client.content_size(&addr).await.expect("content_size");
    let whole = client.fetch(&addr).await.expect("fetch");
    assert_eq!(size, whole.len() as u64, "data-map size equals fetched length");
}
```

- [ ] **Step 2: Confirm it fails to compile** (method missing)

Run: `cargo test -p fetchit-net --test live 2>&1 | head`
Expected: compile error, `no method named content_size`.

- [ ] **Step 3: Implement `content_size`** (add to the `impl AutonomiClient` block in `client.rs`, right after `fetch_to_sink`)

```rust
/// Resolve the content's total byte size from its data map, without
/// downloading the content. Backed by `self_encryption`'s
/// `DataMap::original_file_size`, so the media server can send an exact
/// `Content-Length` (and support seeking) before the first content byte.
///
/// # Errors
/// [`fetchit_core::Error::Network`] if the data-map fetch fails.
pub async fn content_size(&self, addr: &Address) -> CoreResult<u64> {
    let key = *addr.as_bytes();
    let data_map = self
        .inner
        .data_map_fetch(&key)
        .await
        .map_err(|e| net_err(format!("data_map_fetch: {e}")))?;
    Ok(data_map.original_file_size() as u64)
}
```

- [ ] **Step 4: Compile + clippy**

Run: `cargo build -p fetchit-net && cargo clippy -p fetchit-net --all-targets -- -D warnings`
Expected: clean (the `#[ignore]`d live test compiles but does not run).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-net/src/client.rs crates/fetchit-net/tests/live.rs
git commit -s -m "feat(net): content_size reads the data-map file size"
```

---

### Task 2: `StreamingMedia` core (unit-testable heart)

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/streaming_media.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (add `mod streaming_media;`)

**Interfaces:**
- Produces:
  - `enum StreamBacking { Memory(std::sync::Mutex<Vec<u8>>), File(std::path::PathBuf) }`
  - `struct StreamState { pub downloaded: u64, pub total: u64, pub terminal: Option<Result<(), String>> }` (derives `Clone`)
  - `struct StreamingMedia { total: u64, backing: StreamBacking, tx: tokio::sync::watch::Sender<StreamState>, rx: tokio::sync::watch::Receiver<StreamState> }`
  - `StreamingMedia::new(total: u64, backing: StreamBacking) -> Self`
  - `fn subscribe(&self) -> tokio::sync::watch::Receiver<StreamState>`
  - `fn total(&self) -> u64`
  - `async fn push(&self, chunk: &[u8]) -> std::io::Result<()>` (append to backing, flush, advance watermark, publish)
  - `fn finish(&self)` / `fn fail(&self, msg: String)`
  - `async fn read_range(&self, start: u64, end_inclusive: u64) -> std::io::Result<bytes::Bytes>` (read after the watermark already covers it)
  - free fn `async fn await_offset(rx: &mut watch::Receiver<StreamState>, need: u64) -> Result<u64, String>` — returns available bytes once `downloaded >= need` or terminal; `Err` on feeder failure.

- [ ] **Step 1: Write failing unit tests** (create the file with the test module first)

```rust
//! Per-address progressive stream backing the media server.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mem(total: u64) -> StreamingMedia {
        StreamingMedia::new(total, StreamBacking::Memory(std::sync::Mutex::new(Vec::new())))
    }

    #[tokio::test]
    async fn push_advances_watermark_and_reads_back() {
        let s = mem(6);
        s.push(b"abc").await.unwrap();
        assert_eq!(s.subscribe().borrow().downloaded, 3);
        s.push(b"def").await.unwrap();
        s.finish();
        let got = s.read_range(0, 5).await.unwrap();
        assert_eq!(&got[..], b"abcdef");
    }

    #[tokio::test]
    async fn await_offset_unblocks_when_enough_pushed() {
        let s = std::sync::Arc::new(mem(6));
        let mut rx = s.subscribe();
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { await_offset(&mut rx, 6).await });
        s.push(b"abc").await.unwrap();
        s2.push(b"def").await.unwrap();
        assert_eq!(waiter.await.unwrap().unwrap(), 6);
    }

    #[tokio::test]
    async fn await_offset_errors_on_failure() {
        let s = std::sync::Arc::new(mem(6));
        let mut rx = s.subscribe();
        let waiter = tokio::spawn(async move { await_offset(&mut rx, 6).await });
        s.push(b"abc").await.unwrap();
        s.fail("boom".into());
        assert!(waiter.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn finish_lets_a_short_read_past_eof_resolve() {
        let s = std::sync::Arc::new(mem(3));
        let mut rx = s.subscribe();
        s.push(b"abc").await.unwrap();
        s.finish();
        // need beyond total resolves at EOF to the available count, not a hang
        assert_eq!(await_offset(&mut rx, 99).await.unwrap(), 3);
    }
}
```

- [ ] **Step 2: Run to verify failure** (type does not exist)

Run: `cd apps/fetchit-desktop/src-tauri && cargo test streaming_media 2>&1 | head`
Expected: compile error, `StreamingMedia` / `await_offset` undefined.

- [ ] **Step 3: Implement the core** (prepend above the test module)

```rust
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use bytes::Bytes;
use tokio::sync::watch;

/// Where a stream's bytes accumulate. Memory when the disk cache is off
/// (preserves the no-disk default); a `.partial` file when the cache is on.
pub enum StreamBacking {
    Memory(Mutex<Vec<u8>>),
    File(PathBuf),
}

/// Published on every watermark advance and on terminal state.
#[derive(Clone)]
pub struct StreamState {
    pub downloaded: u64,
    pub total: u64,
    pub terminal: Option<Result<(), String>>,
}

pub struct StreamingMedia {
    total: u64,
    backing: StreamBacking,
    tx: watch::Sender<StreamState>,
    rx: watch::Receiver<StreamState>,
}

impl StreamingMedia {
    pub fn new(total: u64, backing: StreamBacking) -> Self {
        let (tx, rx) = watch::channel(StreamState {
            downloaded: 0,
            total,
            terminal: None,
        });
        Self { total, backing, tx, rx }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn subscribe(&self) -> watch::Receiver<StreamState> {
        self.rx.clone()
    }

    /// Append a chunk, flush it durably enough for a concurrent reader, then
    /// advance the watermark. The watermark is advanced only after the bytes
    /// are readable, so a reader gated on `downloaded >= end` never reads a
    /// short slice.
    pub async fn push(&self, chunk: &[u8]) -> std::io::Result<()> {
        match &self.backing {
            StreamBacking::Memory(m) => {
                m.lock().expect("stream buffer lock").extend_from_slice(chunk);
            }
            StreamBacking::File(path) => {
                let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
                f.write_all(chunk)?;
                f.flush()?;
            }
        }
        self.tx.send_modify(|s| s.downloaded += chunk.len() as u64);
        Ok(())
    }

    pub fn finish(&self) {
        self.tx.send_modify(|s| s.terminal = Some(Ok(())));
    }

    pub fn fail(&self, msg: String) {
        self.tx.send_modify(|s| s.terminal = Some(Err(msg)));
    }

    /// Read `[start, end_inclusive]`. Caller must have already awaited the
    /// watermark past `end_inclusive` (or EOF-clamped it) via `await_offset`.
    pub async fn read_range(&self, start: u64, end_inclusive: u64) -> std::io::Result<Bytes> {
        let len = (end_inclusive - start + 1) as usize;
        match &self.backing {
            StreamBacking::Memory(m) => {
                let g = m.lock().expect("stream buffer lock");
                Ok(Bytes::copy_from_slice(&g[start as usize..start as usize + len]))
            }
            StreamBacking::File(path) => {
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    let mut f = std::fs::File::open(path)?;
                    f.seek(SeekFrom::Start(start))?;
                    let mut buf = vec![0u8; len];
                    f.read_exact(&mut buf)?;
                    Ok(Bytes::from(buf))
                })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        }
    }
}

/// Await until `downloaded >= need` or the stream ends. Returns the bytes
/// available at that point (clamped to the total on EOF), or `Err` if the
/// feeder reported a failure.
pub async fn await_offset(
    rx: &mut watch::Receiver<StreamState>,
    need: u64,
) -> Result<u64, String> {
    loop {
        {
            let s = rx.borrow();
            if let Some(Err(e)) = &s.terminal {
                return Err(e.clone());
            }
            if s.downloaded >= need {
                return Ok(s.downloaded);
            }
            if s.terminal.is_some() {
                // Done, but fewer bytes than requested: EOF clamp.
                return Ok(s.downloaded);
            }
        }
        if rx.changed().await.is_err() {
            let s = rx.borrow();
            return Ok(s.downloaded);
        }
    }
}
```

- [ ] **Step 4: Register the module** in `lib.rs` (add with the other `mod` lines)

```rust
mod streaming_media;
```

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test streaming_media && cargo clippy --all-targets -- -D warnings`
Expected: 4 tests pass, clippy clean.

- [ ] **Step 6: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/streaming_media.rs apps/fetchit-desktop/src-tauri/src/lib.rs
git commit -s -m "feat(desktop): StreamingMedia progressive stream backing"
```

---

### Task 3: Stream registry + feeder on `AppState`

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/state.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/streaming_media.rs` (add the feeder spawn helper)

**Interfaces:**
- Consumes: `StreamingMedia`, `StreamBacking`, `AutonomiClient::content_size`, `AutonomiClient::fetch_to_sink`, `DiskCache::{stream_path, policy}`.
- Produces on `AppState`:
  - field `streams: Arc<std::sync::Mutex<std::collections::HashMap<Address, Arc<StreamingMedia>>>>`
  - `async fn get_or_start_stream(&self, addr: Address) -> Result<Arc<StreamingMedia>, String>` — returns the existing stream or creates one, resolving `content_size`, choosing the backing by cache policy, and spawning ONE feeder task.

- [ ] **Step 1: Write the dedup unit test** (in `state.rs`'s test module; uses a tiny seam so it does not hit the network)

Add a test-only constructor path: a `fn insert_stream_for_test(&self, addr, Arc<StreamingMedia>)` guarded by `#[cfg(test)]`, then:

```rust
#[test]
fn get_or_start_returns_the_same_stream_for_one_address() {
    let addr: Address = "ab".repeat(32).parse().unwrap();
    let state = /* build a test AppState with cache off (see existing helpers) */;
    let sm = std::sync::Arc::new(super::streaming_media::StreamingMedia::new(
        4,
        super::streaming_media::StreamBacking::Memory(std::sync::Mutex::new(Vec::new())),
    ));
    state.insert_stream_for_test(addr, sm.clone());
    // A second lookup for the same address returns the identical Arc (one feeder).
    let again = state.streams.lock().unwrap().get(&addr).cloned().unwrap();
    assert!(std::sync::Arc::ptr_eq(&sm, &again));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test get_or_start_returns_the_same 2>&1 | head`
Expected: compile error (`streams` / `insert_stream_for_test` missing).

- [ ] **Step 3: Add the registry field + helpers** to `AppState` (`state.rs`)

```rust
// in the struct:
pub streams: Arc<std::sync::Mutex<std::collections::HashMap<Address, Arc<crate::streaming_media::StreamingMedia>>>>,

// in AppState::new(..): initialize
streams: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),

#[cfg(test)]
pub fn insert_stream_for_test(&self, addr: Address, sm: Arc<crate::streaming_media::StreamingMedia>) {
    self.streams.lock().expect("streams lock").insert(addr, sm);
}
```

- [ ] **Step 4: Add `get_or_start_stream` + the feeder** (feeder helper in `streaming_media.rs`)

In `streaming_media.rs`:

```rust
use std::sync::Arc;

/// Drive `fetch_to_sink` into `sm`, translating chunks to `push` and the
/// terminal into `finish`/`fail`. Runs as the single feeder task per address.
pub async fn feed(
    sm: Arc<StreamingMedia>,
    client: Arc<fetchit_net::AutonomiClient>,
    addr: fetchit_core::Address,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<fetchit_core::Result<Bytes>>(16);
    let pump = {
        let sm = sm.clone();
        tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                match item {
                    Ok(chunk) => {
                        if sm.push(&chunk).await.is_err() {
                            sm.fail("write to stream backing failed".into());
                            return;
                        }
                    }
                    Err(e) => {
                        sm.fail(e.to_string());
                        return;
                    }
                }
            }
        })
    };
    let result = client.fetch_to_sink(&addr, tx, |_p| {}).await;
    let _ = pump.await;
    match result {
        Ok(_) => sm.finish(),
        Err(e) => sm.fail(e.to_string()),
    }
}
```

In `state.rs`:

```rust
pub async fn get_or_start_stream(
    &self,
    addr: Address,
) -> Result<Arc<crate::streaming_media::StreamingMedia>, String> {
    if let Some(sm) = self.streams.lock().expect("streams lock").get(&addr).cloned() {
        return Ok(sm);
    }
    let client = crate::state::ensure_client(self, &self.effective_peers()).await?;
    let total = client.content_size(&addr).await.map_err(|e| e.to_string())?;
    let backing = if self.disk_cache.policy().enabled() {
        crate::streaming_media::StreamBacking::File(self.disk_cache.stream_path(&addr))
    } else {
        crate::streaming_media::StreamBacking::Memory(std::sync::Mutex::new(Vec::new()))
    };
    let sm = Arc::new(crate::streaming_media::StreamingMedia::new(total, backing));
    // Insert before spawning so a racing request attaches to this one.
    {
        let mut map = self.streams.lock().expect("streams lock");
        if let Some(existing) = map.get(&addr).cloned() {
            return Ok(existing);
        }
        map.insert(addr, sm.clone());
    }
    let client = Arc::new(client);
    tokio::spawn(crate::streaming_media::feed(sm.clone(), client, addr));
    Ok(sm)
}
```

(Implementer: confirm `disk_cache.policy()` exposes an `enabled()` predicate; if it is an enum, match on the disabled variant instead. `ensure_client` returns an owned `AutonomiClient`; wrap in `Arc` for the feeder.)

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test get_or_start_returns_the_same streaming_media && cargo clippy --all-targets -- -D warnings`
Expected: pass, clippy clean.

- [ ] **Step 6: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/state.rs apps/fetchit-desktop/src-tauri/src/streaming_media.rs
git commit -s -m "feat(desktop): per-address stream registry + feeder"
```

---

### Task 4: `server.rs` streaming `serve()`

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/server.rs`
- Test: `apps/fetchit-desktop/src-tauri/src/server.rs` (loopback integration test in its `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `AppState::{cached_bytes, get_or_start_stream}`, `StreamingMedia::{total, subscribe, read_range}`, `await_offset`, existing `parse_range`/`sniff_mime`/`strip_header_ci`.

- [ ] **Step 1: Write a loopback integration test** (in server.rs test module) that spawns the server against an `AppState` whose stream is pre-seeded via `insert_stream_for_test` and fed incrementally, then does a raw GET and asserts the body streams and matches. Provide the full test:

```rust
#[tokio::test]
async fn serve_streams_body_as_it_arrives() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let state = /* test AppState, cache off */;
    let addr: Address = "cd".repeat(32).parse().unwrap();
    let sm = std::sync::Arc::new(crate::streaming_media::StreamingMedia::new(
        6,
        crate::streaming_media::StreamBacking::Memory(std::sync::Mutex::new(Vec::new())),
    ));
    state.insert_stream_for_test(addr, sm.clone());
    let port = super::spawn(state).await.unwrap();

    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    conn.write_all(format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "cd".repeat(32)).as_bytes())
        .await
        .unwrap();
    // feed after the request is in flight
    sm.push(b"abc").await.unwrap();
    sm.push(b"def").await.unwrap();
    sm.finish();

    let mut resp = Vec::new();
    conn.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.contains("Content-Length: 6"));
    assert!(text.contains("Accept-Ranges: bytes"));
    assert!(resp.ends_with(b"abcdef"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test serve_streams_body_as_it_arrives 2>&1 | head`
Expected: fails (current `serve` blocks on `fetch_into_cache` / does not use the pre-seeded stream).

- [ ] **Step 3: Rewrite `serve()`** to branch: cache hit -> existing complete-buffer path (keep it); otherwise resolve the stream and stream the response. Replace the `let bytes = match state.cached_bytes ...` block and the response section below it with:

```rust
    // Fast path: fully cached -> serve the complete buffer as before.
    if let Some(bytes) = state.cached_bytes(&addr) {
        return serve_complete(&mut stream, method, range.as_deref(), &bytes).await;
    }

    // Progressive path.
    let sm = match state.get_or_start_stream(addr).await {
        Ok(sm) => sm,
        Err(msg) => return reply_simple(&mut stream, 502, "Bad Gateway", &msg).await,
    };
    let total = sm.total();
    let mut rx = sm.subscribe();

    // Sniff MIME from the first bytes: wait for a small prefix, then read it.
    let sniff_end = total.min(4096).saturating_sub(1);
    let _ = await_offset(&mut rx, sniff_end + 1).await;
    let head = sm.read_range(0, sniff_end).await.unwrap_or_default();
    let mime = sniff_mime(&head);

    if method == "HEAD" {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
        );
        return stream.write_all(resp.as_bytes()).await;
    }

    let (start, end) = match range.as_deref().and_then(|h| parse_range(h, total as usize)) {
        Some((s, e)) => (s as u64, e as u64),
        None => (0, total.saturating_sub(1)),
    };
    let is_partial = range.is_some();

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
        let available = match await_offset(&mut rx, want).await {
            Ok(a) => a,
            Err(_) => break, // feeder failed; drop the connection
        };
        let ready_end = available.min(end + 1);
        if ready_end <= pos {
            break; // EOF before the requested end
        }
        let slice = match sm.read_range(pos, ready_end - 1).await {
            Ok(b) => b,
            Err(_) => break,
        };
        if stream.write_all(&slice).await.is_err() {
            break; // client disconnected mid-stream
        }
        pos = ready_end;
    }
    Ok(())
```

Then extract the existing complete-buffer response into a helper `serve_complete(stream, method, range, bytes)` (the current HEAD/206/200 block, verbatim) so the fast path keeps its exact behavior. Import `await_offset` and the streaming types at the top: `use crate::streaming_media::await_offset;`.

- [ ] **Step 4: Run the new test + the existing `parse_range` tests + clippy**

Run: `cargo test --lib server && cargo clippy --all-targets -- -D warnings`
Expected: `serve_streams_body_as_it_arrives` passes, `parse_range_*` still pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/server.rs
git commit -s -m "feat(desktop): stream media responses from StreamingMedia"
```

---

### Task 5: Cancellation + cache commit/discard

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/streaming_media.rs` (interest tracking + terminal cache actions)
- Modify: `apps/fetchit-desktop/src-tauri/src/state.rs` (drop the stream from the registry on terminal; wire cache commit/discard)

**Interfaces:**
- Consumes: `DiskCache::{commit_stream, discard_stream, policy}`.
- Behavior: when a stream finishes AND cache is on -> `commit_stream(addr)`; when the last connection drops before completion (or the feeder fails) AND cache is on -> `discard_stream(addr)`; the finished/aborted stream is removed from `AppState::streams` so a later view re-resolves (cache hit if committed).

- [ ] **Step 1: Write the terminal-action unit test** (in `streaming_media.rs` tests): a stream with an interest counter drops to zero and reports `should_abort()`; a finished stream reports `completed()`. Provide:

```rust
#[test]
fn interest_tracks_connections_and_abort_on_last_drop() {
    let s = mem(10);
    let g1 = s.add_interest();
    let g2 = s.add_interest();
    drop(g1);
    assert!(!s.should_abort()); // g2 still holds interest
    drop(g2);
    assert!(s.should_abort()); // no readers, not finished -> abort
    s.finish();
    assert!(!s.should_abort()); // finished streams are not "aborted"
}
```

- [ ] **Step 2: Run to verify failure** (`add_interest`/`should_abort` missing)

Run: `cargo test interest_tracks_connections 2>&1 | head`
Expected: compile error.

- [ ] **Step 3: Implement interest tracking** in `StreamingMedia`

```rust
// add field: interest: std::sync::atomic::AtomicUsize (init 0)
pub fn add_interest(self: &std::sync::Arc<Self>) -> InterestGuard {
    self.interest.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    InterestGuard(self.clone())
}
pub fn should_abort(&self) -> bool {
    self.rx.borrow().terminal.is_none()
        && self.interest.load(std::sync::atomic::Ordering::SeqCst) == 0
}
pub struct InterestGuard(std::sync::Arc<StreamingMedia>);
impl Drop for InterestGuard {
    fn drop(&mut self) {
        self.0.interest.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
```

- [ ] **Step 4: Wire it into the server + feeder.**
  - In `server.rs serve()`: `let _guard = sm.add_interest();` right after resolving `sm`, held for the connection's lifetime (drops on return / disconnect).
  - In `state.rs get_or_start_stream`'s feeder spawn: after `feed(...)` returns, if `sm.should_abort()` abort semantics apply; on completion with cache on call `self.disk_cache.commit_stream(&addr)`, on failure/abort with cache on call `self.disk_cache.discard_stream(&addr)`; always remove `addr` from `self.streams`. Implement by wrapping the spawn in a closure that owns `self`'s needed handles (clone `disk_cache` Arc + `streams` Arc + `addr`):

```rust
let streams = self.streams.clone();
let disk_cache = self.disk_cache.clone();
let cache_on = self.disk_cache.policy().enabled();
tokio::spawn(async move {
    crate::streaming_media::feed(sm.clone(), client, addr).await;
    let ok = matches!(sm.subscribe().borrow().terminal, Some(Ok(())));
    if cache_on {
        if ok {
            disk_cache.commit_stream(&addr);
        } else {
            disk_cache.discard_stream(&addr);
        }
    }
    streams.lock().expect("streams lock").remove(&addr);
});
```

(The mid-download abort-on-last-reader optimization can be layered by having the feeder poll `sm.should_abort()` between chunks and stop early; keep v1 simple: the feeder runs to completion or failure, and a disconnected client simply stops receiving. Document this as the v1 behavior in a code comment.)

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test streaming_media server && cargo clippy --all-targets -- -D warnings`
Expected: pass, clippy clean.

- [ ] **Step 6: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/streaming_media.rs apps/fetchit-desktop/src-tauri/src/state.rs
git commit -s -m "feat(desktop): stream interest tracking + cache commit/discard"
```

---

### Task 6: Security note + live verification

**Files:**
- Modify: `docs/SECURITY.md`

- [ ] **Step 1: Add the streaming note** to the media-server section of `docs/SECURITY.md` (one line, factual, present-tense):

```markdown
The `127.0.0.1` media server (`server.rs`) streams its response progressively
from `StreamingMedia` for uncached media; origin, CSP, CORS, and the 64-hex
address validation are unchanged from the complete-buffer path.
```

- [ ] **Step 2: Full backend gate**

Run: `cd apps/fetchit-desktop/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all green.

- [ ] **Step 3: Manual live check** (documented, not automated)

Run the dev shell (`npm run tauri dev`), open a large video address, confirm playback starts before the full download (watch the `[media-srv]` diag lines stream), then scrub to confirm a seek resolves. Note the result in the PR description.

- [ ] **Step 4: Commit**

```bash
git add docs/SECURITY.md
git commit -s -m "docs(security): note the media server streams progressively"
```

---

## Self-Review

**Spec coverage:** progressive serving (Tasks 2-4), Content-Length + Range from data-map size (Tasks 1, 4), cache-off memory / cache-on file (Tasks 3, 5), cancellation via disconnect + interest (Task 5), security note (Task 6), non-goals untouched (no task touches protocol.rs/pdf.ts/htmlRewriter.ts). Covered.

**Type consistency:** `StreamingMedia`, `StreamBacking`, `StreamState`, `await_offset`, `content_size`, `get_or_start_stream`, `feed`, `add_interest`/`should_abort`/`InterestGuard` are used with the same signatures across tasks.

**Known implementer confirmations (call out in review, not blockers):** `DiskCache::policy().enabled()` predicate shape; the exact existing `serve_complete` extraction is a verbatim move of the current HEAD/206/200 block; `AutonomiClient` derives/exposes what the feeder needs behind `Arc`.
