# Progressive Media Serving: Design Spec

Date: 2026-07-02
Status: design approved; pending spec review, then implementation plan.

## Goal

Play video and audio off an Autonomi address as soon as the first bytes arrive,
instead of waiting for the whole file to download. Turn the streaming primitive
already landed in `fetchit-net` (`AutonomiClient::fetch_to_sink`, streams
decrypted chunks to a channel as they arrive) into a user-visible speed win: the
desktop media server serves the growing stream progressively, with real seek
support, instead of blocking on a complete download.

## Current state (verified)

- `apps/fetchit-desktop/src-tauri/src/server.rs` is a raw-TCP HTTP server bound
  to `127.0.0.1:0`. Its `serve()` maps `GET /<64-hex>` to media bytes. It already
  parses `Range` and answers `206 Partial Content` / `200 OK` with
  `Accept-Ranges: bytes` and permissive CORS, but only over a fully-materialized
  buffer.
- The blocking point is `fetch_into_cache()` -> `client.fetch(&addr)`: it
  downloads the entire file into memory, caches it, and only then does `serve()`
  compute `total = bytes.len()` and answer. Large media therefore incurs a full
  download and full residency before the first frame plays.
- `video.ts` and `audio.ts` set `src = mediaUrlOf(addr)` (the `127.0.0.1` server).
  `<video>/<audio>` embedded in rendered HTML SPAs also resolve through the same
  media base (allowed by the CSP `media-src` in `htmlRewriter.ts`). `pdf.ts`
  renders via pdf.js from full bytes and does not use the media server.
- The on-disk cache is opt-in: `state.cache_bytes()` -> `disk_cache.put()` is a
  no-op when the policy is disabled. So today, cache-off means nothing touches
  disk and the whole payload lives in memory.
- Cancellation exists as tab-scoped, generation-tagged `CancellationToken`s in
  `state.rs` (`register_fetch`), but the media server's fetch is not wired into
  it. An abandoned `<video>` does not currently stop its download.
- `self_encryption::DataMap::original_file_size()` exposes the original byte size
  of the content. The total is therefore knowable from the data map before any
  content chunk is downloaded.

## Scope

### In scope

- Progressive serving of the media types that flow through the `127.0.0.1`
  server: standalone video and audio renditions, and `<video>/<audio>` inside
  rendered SPAs.
- Real `Content-Length` and progressive `Range`/seek, using the data-map size.
- Cache-aware buffering (in-memory when cache off, cache-file when cache on).
- Cancellation on client disconnect.

### Non-goals (v1)

- PDF (pdf.js renders from full bytes, a different model), images, JSON, tabular,
  archive, text, HTML render: all stay on the existing whole-payload path.
- Backward-seek beyond what the buffer already holds triggers no re-fetch beyond
  the normal sequential download (ant-core streams sequentially; a far-forward
  seek blocks until the download reaches that offset).
- No HLS / adaptive bitrate / multi-file manifest handling.

## Architecture

Three units, each independently testable.

### 1. `StreamingMedia`: shared per-address stream state

A new type owned by `AppState`, keyed by `Address`, tracking one in-flight
progressive download that any number of concurrent HTTP connections read from.

Fields (conceptual):

- `total: u64` resolved from the data map before the first content chunk.
- `downloaded: watermark` (bytes available so far), updated as chunks land.
- backing store: an in-memory growing buffer when the cache is off; a cache-slot
  file handle when the cache is on.
- `done: bool` / terminal error.
- a `tokio::sync::Notify` (or `watch`) to wake connections waiting for the
  watermark to advance.
- an interest count / abort handle for the feeder task.

Exactly one feeder task per address runs `fetch_to_sink`, appends each chunk to
the store, advances `downloaded`, and notifies waiters. A second concurrent
request for the same address attaches to the existing `StreamingMedia` instead
of starting a second download.

### 2. `server.rs` `serve()` rewrite

Replace the "materialize then serve" body with:

1. Fully cached address -> serve from cache as today (fast path, unchanged).
2. Otherwise get-or-create the `StreamingMedia` for the address (starts the
   feeder task on first request).
3. Emit response headers immediately using `total` (from the data map):
   `Content-Length`, `Accept-Ranges: bytes`, `Content-Type`, CORS, and for a
   range request the `206` + `Content-Range` line.
4. Stream the body:
   - `200` (no range): loop writing newly-available bytes to the TCP stream,
     awaiting the `Notify` between writes, until EOF.
   - `206` `[start,end]`: await `downloaded >= end` (or EOF), then write the
     slice. Sequential playback keeps this near-instant; a far-forward seek
     blocks only until the sequential download reaches `end`.
5. `HEAD`: headers only, with `total` (works because the size is known up front).

MIME sniffing needs the leading bytes; wait for the watermark to cover the sniff
window (the existing `SNIFF`-style prefix, a few KB) before writing headers, then
proceed. This is the only place headers wait, and only for a few KB.

### 3. `fetchit-net`: total size up front

`fetch_to_sink` currently returns `total` only on completion. Surface the size at
the start so `server.rs` can send `Content-Length` before the first content byte.
Preferred approach: resolve the data map once, report `original_file_size()`
early (a `oneshot`, or a companion `content_size(addr)` that returns the data-map
size), then stream, so the data map is not fetched twice. Confirm during planning
whether `ant_core::data::DataMap` re-exports `original_file_size()`; if not, add
the minimal accessor on the fetch>it side from the resolved data map.

## Data flow

```
GET /<addr> (+ optional Range)
  -> server.rs serve()
     -> cache hit? -> serve complete bytes (unchanged)
     -> else StreamingMedia::get_or_start(addr)
            -> feeder task: fetch_to_sink(addr, sink) ; report total early
               -> per chunk: append to store, advance watermark, Notify
     -> write headers (Content-Length = total, Accept-Ranges)
     -> body loop: write available bytes, await Notify, until range/EOF satisfied
     -> on write error (client gone): drop interest; abort feeder if last + no cache
```

## Range / seek and Content-Length

- `Content-Length` and `Content-Range` are always exact because `total` comes
  from the data map, not from a completed download. Players get a seekable
  timeline on the first response.
- Range satisfaction is watermark-gated: `await downloaded >= end`. EOF clamps
  `end` to `total - 1` (existing `parse_range` semantics preserved).
- Sequential reads (normal playback) resolve as bytes arrive. A far-forward seek
  blocks until the sequential download passes the seek target. This is the
  accepted v1 behavior; ant-core does not expose offset-start downloads.

## Cache interaction

- Cache ON: the single feeder task writes each chunk into the cache slot as it
  streams; connections serve from the growing file. On completion the slot is a
  normal cache entry, so a re-view is an instant cache hit. A cancelled /
  incomplete stream must not leave a partial file that later reads as complete
  (write to a temp path, promote to the cache key only on successful completion).
- Cache OFF: in-memory growing buffer only; nothing touches disk (preserves the
  current privacy behavior and the current memory profile, which is already
  whole-file-in-memory). Buffer is dropped when the last connection closes.

## Cancellation

The streaming response is the cancellation signal. When the WebView tears down
the media element (navigate away, tab close, re-navigation), the TCP connection
drops and `write_all` returns an error. On that error the connection drops its
interest in the `StreamingMedia`. When the last interested connection is gone and
the stream is not being persisted to the cache, the feeder task is aborted so the
download stops. This also closes the current gap where the media server's fetch
was never cancellable. It composes with, and does not replace, the existing
tab-scoped `CancellationToken` chain used by the protocol/fetch path.

## Security

No change to the security boundary. Same `127.0.0.1` synthetic origin, same
`media-src`/`connect-src` CSP (already lists `mediaBase`), same permissive CORS
for the local media element, same strict 64-hex-address validation before any
fetch. Progressive serving changes when bytes are written, not what origin,
headers, or validation apply; the sandboxed iframe and `htmlRewriter.ts` are
untouched. `docs/SECURITY.md` gets a one-line note that the media server streams
its response so the load-bearing-files list stays accurate.

## Error handling

- Data-map resolution failure (bad address, network) -> `502` before any body, as
  today.
- Mid-stream chunk failure -> the feeder records a terminal error; waiting
  connections observe it and close the response (the player surfaces a media
  error). A partial cache file is discarded, never promoted.
- Client disconnect mid-stream -> not an error; drop interest, maybe abort feeder.
- Range not satisfiable (start >= total) -> `416`, computed up front from `total`.

## Testing

- Unit tests on `StreamingMedia` fed synthetic chunks:
  - a range whose `end` exceeds the current watermark blocks, then completes when
    fed enough;
  - a range past EOF clamps to `total - 1`;
  - two connections for one address share a single feeder (one download);
  - dropping the last connection aborts the feeder when not caching;
  - a terminal feeder error propagates to waiting readers.
- Keep the existing `parse_range` unit tests.
- Cache-on completion promotes a temp file to the cache key; an aborted stream
  leaves no promoted entry.
- Manual live check: progressive playback against a known large video address
  (time-to-first-frame drops from full-download to first-chunk), plus a seek.

## Files touched

- `crates/fetchit-net/src/client.rs`: surface data-map size early (small
  addition next to `fetch_to_sink`).
- `apps/fetchit-desktop/src-tauri/src/server.rs`: `serve()` rewrite + streaming
  body.
- `apps/fetchit-desktop/src-tauri/src/state.rs`: `StreamingMedia` registry on
  `AppState` (new small module preferred over growing `state.rs`).
- `docs/SECURITY.md`: one-line streaming note.

## Open items to resolve in the plan

- Exact mechanism to report the data-map size early (oneshot vs companion call)
  and whether `ant_core::data::DataMap` exposes `original_file_size()`.
- Concurrency primitive for the watermark wait (`Notify` vs `watch<u64>`);
  `watch<u64>` carrying the watermark is likely cleanest for range gating.
- Temp-file-then-promote details for the cache-on path (naming, fsync, cleanup on
  crash).
