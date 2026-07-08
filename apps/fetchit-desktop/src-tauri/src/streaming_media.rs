//! Per-address progressive stream backing the media server.
//!
//! [`StreamingMedia`] accumulates a download in a growing buffer while
//! exposing a [`watch`]-based watermark so the HTTP range server in
//! `server.rs` can serve byte ranges as soon as they land, without waiting
//! for the full download to complete.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::watch;

/// Where a stream's bytes accumulate. Memory when the disk cache is off
/// (preserves the no-disk default); a `.partial` file when the cache is on.
pub enum StreamBacking {
    /// In-memory accumulation buffer.
    Memory(Mutex<Vec<u8>>),
    /// Append-only file for cache-enabled sessions. Never constructed under
    /// the `e2e` feature (that build forces in-memory backing), but still
    /// matched in the read paths, so silence the dead-variant lint there.
    #[cfg_attr(feature = "e2e", allow(dead_code))]
    File(PathBuf),
}

/// Published on every watermark advance and on terminal state.
#[derive(Clone)]
pub struct StreamState {
    /// Bytes durably written so far (monotonically increasing).
    pub downloaded: u64,
    /// Set to `Some(Ok(()))` on clean EOF, `Some(Err(msg))` on feeder failure.
    pub terminal: Option<Result<(), String>>,
}

/// Per-address progressive download state shared between the network feeder
/// and the HTTP range-request server.
pub struct StreamingMedia {
    total: u64,
    backing: StreamBacking,
    tx: watch::Sender<StreamState>,
    rx: watch::Receiver<StreamState>,
    /// Count of active HTTP connections consuming this stream. When this
    /// drops to zero and the stream is not yet terminal, the feeder pump
    /// should stop via [`StreamingMedia::should_abort`].
    interest: AtomicUsize,
}

/// RAII guard that holds one unit of interest in a stream.
///
/// Obtained from [`StreamingMedia::add_interest`]; held for the lifetime
/// of an HTTP connection. Dropping the guard decrements the interest
/// counter, which may trigger feeder abort if it reaches zero while the
/// stream is still in progress.
pub struct InterestGuard(Arc<StreamingMedia>);

impl Drop for InterestGuard {
    fn drop(&mut self) {
        self.0.interest.fetch_sub(1, Ordering::SeqCst);
    }
}

impl StreamingMedia {
    /// Create a new stream with the given total size and backing store.
    pub fn new(total: u64, backing: StreamBacking) -> Self {
        let (tx, rx) = watch::channel(StreamState {
            downloaded: 0,
            terminal: None,
        });
        Self {
            total,
            backing,
            tx,
            rx,
            interest: AtomicUsize::new(0),
        }
    }

    /// Expected total byte count.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Clone the watch receiver so a caller can await watermark advances.
    pub fn subscribe(&self) -> watch::Receiver<StreamState> {
        self.rx.clone()
    }

    /// Register a connection's interest in this stream and return a guard.
    /// Dropping the guard decrements the interest counter.
    pub fn add_interest(self: &Arc<Self>) -> InterestGuard {
        self.interest.fetch_add(1, Ordering::SeqCst);
        InterestGuard(self.clone())
    }

    /// True when no connection holds interest and the stream has not yet
    /// reached a terminal state. The feeder pump checks this after each
    /// chunk push and stops early to free network resources.
    pub fn should_abort(&self) -> bool {
        self.rx.borrow().terminal.is_none() && self.interest.load(Ordering::SeqCst) == 0
    }

    /// Append a chunk, flush it durably enough for a concurrent reader, then
    /// advance the watermark. The watermark is advanced only after the bytes
    /// are readable, so a reader gated on `downloaded >= end` never reads a
    /// short slice.
    ///
    /// The signature is `async` for uniformity with call sites in `feed`;
    /// the file-backed path uses synchronous I/O in this call.
    #[allow(clippy::unused_async)]
    pub async fn push(&self, chunk: &[u8]) -> std::io::Result<()> {
        match &self.backing {
            StreamBacking::Memory(m) => {
                m.lock()
                    .map_err(|e| std::io::Error::other(e.to_string()))?
                    .extend_from_slice(chunk);
            }
            StreamBacking::File(path) => {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                f.write_all(chunk)?;
                f.flush()?;
            }
        }
        self.tx.send_modify(|s| s.downloaded += chunk.len() as u64);
        Ok(())
    }

    /// Signal clean EOF. Unblocks any `await_offset` waiters.
    ///
    /// No-op if a terminal state is already set (first writer wins), so
    /// a pump that aborts early via [`Self::fail`] is not overwritten by
    /// the feeder's final `finish` call.
    pub fn finish(&self) {
        self.tx.send_modify(|s| {
            if s.terminal.is_none() {
                s.terminal = Some(Ok(()));
            }
        });
    }

    /// Signal a feeder error. Any pending `await_offset` call returns `Err`.
    ///
    /// No-op if a terminal state is already set (first writer wins).
    pub fn fail(&self, msg: String) {
        self.tx.send_modify(|s| {
            if s.terminal.is_none() {
                s.terminal = Some(Err(msg));
            }
        });
    }

    /// Read `[start, end_inclusive]`. Caller must have already awaited the
    /// watermark past `end_inclusive` (or EOF-clamped it) via [`await_offset`].
    ///
    /// # Errors
    /// Returns an `io::Error` if the backing store cannot be read or if the
    /// byte-range arithmetic overflows `usize` (would require a >4 GB single
    /// range on a 32-bit target).
    pub async fn read_range(&self, start: u64, end_inclusive: u64) -> std::io::Result<Bytes> {
        let len = usize::try_from(end_inclusive - start + 1)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let start_usize =
            usize::try_from(start).map_err(|e| std::io::Error::other(e.to_string()))?;
        match &self.backing {
            StreamBacking::Memory(m) => {
                let g = m.lock().map_err(|e| std::io::Error::other(e.to_string()))?;
                Ok(Bytes::copy_from_slice(&g[start_usize..start_usize + len]))
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
/// available at that point (clamped to EOF), or `Err` if the feeder reported
/// a failure.
pub async fn await_offset(rx: &mut watch::Receiver<StreamState>, need: u64) -> Result<u64, String> {
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

/// Drive `fetch_to_sink` into `sm`, translating chunks to [`StreamingMedia::push`]
/// and the terminal result into [`StreamingMedia::finish`] or [`StreamingMedia::fail`].
/// Runs as the single feeder task per address; the registry in [`crate::state::AppState`]
/// ensures only one instance is spawned.
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
                        // Stop downloading if no connection is watching.
                        // Setting fail before dropping rx ensures the
                        // terminal is marked before fetch_to_sink unwinds,
                        // so state.rs always sees a non-Ok terminal and
                        // calls discard_stream rather than commit_stream.
                        if sm.should_abort() {
                            sm.fail("download cancelled: no active readers".into());
                            return; // dropping rx causes fetch_to_sink to get SendError
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mem(total: u64) -> StreamingMedia {
        StreamingMedia::new(
            total,
            StreamBacking::Memory(std::sync::Mutex::new(Vec::new())),
        )
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

    #[test]
    fn interest_tracks_connections_and_abort_on_last_drop() {
        let s = Arc::new(mem(10));
        let g1 = s.add_interest();
        let g2 = s.add_interest();
        drop(g1);
        assert!(!s.should_abort()); // g2 still holds interest
        drop(g2);
        assert!(s.should_abort()); // no readers, not finished -> abort
        s.finish();
        assert!(!s.should_abort()); // finished streams are not "aborted"
    }
}
