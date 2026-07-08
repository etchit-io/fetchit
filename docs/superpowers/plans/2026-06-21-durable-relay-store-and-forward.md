# Durable Blind Relay Store-and-Forward (R2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the relay's 15-minute RAM-only transit buffer with a persistent, SQLite-backed, per-recipient store that survives restart, retains for ~7 days, and deletes only on confirmed delivery — so the relay's acceptance Ack stops being a lie.

**Architecture:** Introduce a `TransitStore` trait; keep the existing in-RAM `TransitBuffer` as the test/fallback impl behind it, and add a `SqliteTransitStore` for production. Reconnect drain becomes a **non-destructive read**; entries are deleted only when the client returns a new transport-level `TransitAck` frame (or the 7-day TTL sweeps them). The relay continues to store only opaque `TransitEnvelope` ciphertext — it stays blind.

**Tech Stack:** Rust, `fetchit-relay-server` + `fetchit-relay-proto` + `fetchit-relay-client`, `rusqlite`/SQLite (already a relay-server dependency via the registry store), `postcard` wire, `tokio`.

## Global Constraints

- **Relay stays BLIND.** The store persists only `TransitEnvelope` (ciphertext + routing metadata), never plaintext. No app-layer at-rest encryption is added — the payload is already E2EE ciphertext; disk-at-rest is the operator's full-disk-encryption responsibility (consistent with x0xd ADR-0015). A test asserts the persisted bytes round-trip to the opaque envelope.
- **Workspace lints:** `unsafe_code = forbid`, `clippy::pedantic -D warnings`, `missing_docs = warn`; no `unwrap()`/`expect()`/`panic!` outside `#[cfg(test)]` modules (which open with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`). Every public item carries rustdoc.
- **Commits:** DCO sign-off (`git commit -s`). No em-dashes and no AI-coauthor trailer on commit messages.
- **Build:** `fetchit-relay-server`, `-proto`, `-client` are root-workspace members — `cargo test -p <crate>` from repo root.
- **v1 scope:** single home-relay durability (the sender fans to each member's home relay, which holds that member's durable copy). Cross-relay federation is explicitly v1.x and out of scope.

## Design decisions (RESOLVED with Bob 2026-06-21 cross-review)

1. **Storage engine = SQLite (`rusqlite`).** Already a `fetchit-relay-server` dependency (the self-serve registry store, `registry/store_sqlite.rs`), so **zero new dependency**; battle-tested durability, transactional delete-on-ack, indexed per-recipient read + TTL sweep. Sled (maturity) and a hand-rolled append-log (custom compaction bugs) were rejected. Isolated behind the `TransitStore` trait; the RAM `TransitBuffer` stays as the test impl.
2. **Retention = 7 days**, and the per-recipient cap stays a **config knob** (`transit_per_recipient`) with a **cap-rejection counter** so a full queue is never a silent drop (the sender already gets a `Throttle`; past-cap groups recover via the R1 re-Welcome). TTL is the backstop; delete-on-ack is the primary reclaim path.
3. **Delete trigger = a transport-level relay ack** (`ClientFrame::TransitAck { acked_ids }`, keyed by `transit_seq`), **NOT** the e2e `DeliveryReceipt` — the receipt is sealed, so keying delete on it would force the relay to read sealed content and break blind-relay. Reconnect read is **non-destructive**; re-delivery on a missed ack is harmless (client dedups via `NonceDedup`).
4. **Stable transit id reuses `Deliver.transit_seq`** (no `Deliver` wire-struct change). `TransitAck` is **appended** to `ClientFrame`; an old server that can't decode it hits the existing `from_bytes` error arm in `run_io_loop` and ignores the frame (forward-compatible).
5. **Single home-relay durable copy for v1** (federation = v1.x): the sender already fans to each member's HOME relay via `resolve_hints_for_recipient`, so the durable copy lands where that recipient drains.

## File structure

- `crates/fetchit-relay-server/src/transit.rs` — MODIFY. Add the `TransitStore` trait + `StoredEntry`; make `Entry.enqueued_at` wall-clock `u64` ms (serializable); refactor `TransitBuffer` (RAM) to implement the trait (assign stable ids, non-destructive `read_all`, `delete`).
- `crates/fetchit-relay-server/src/transit_sqlite.rs` — CREATE. `SqliteTransitStore` (rusqlite-backed) implementing `TransitStore`; opens/creates the SQLite file, survives reopen.
- `crates/fetchit-relay-proto/src/frame.rs` — MODIFY. Append `ClientFrame::TransitAck`; rustdoc `Deliver.transit_seq` as the stable transit id (0 = direct/non-durable).
- `crates/fetchit-relay-server/src/ws.rs` — MODIFY. Reconnect uses `read_all` (non-destructive) and stamps each `Deliver.transit_seq` with the stored id; handle `ClientFrame::TransitAck` → `store.delete`.
- `crates/fetchit-relay-server/src/config.rs` — MODIFY. `transit_ttl` 15 min → 7 days; add `transit_store_path: Option<PathBuf>` (+ `from_env`).
- `crates/fetchit-relay-server/src/metrics.rs` — MODIFY. Add a `transit_cap_rejected` counter.
- `crates/fetchit-relay-server/src/server.rs` — MODIFY. Construct `SqliteTransitStore` when `transit_store_path` is set (else RAM `TransitBuffer`); `ServerState.transit` becomes `Arc<dyn TransitStore>`.
- `crates/fetchit-relay-server/src/error.rs` — MODIFY. Add `ServerError::TransitStore(String)`.
- `crates/fetchit-relay-client/src/client.rs` — MODIFY. On an inbound `Deliver` with `transit_seq != 0`, send `ClientFrame::TransitAck` after the message is surfaced.

---

### Task 1: `TransitStore` trait + serializable `Entry` + RAM impl

Make the buffer's interface durability-shaped (stable ids, non-destructive read, explicit delete) and time-serializable, keeping the RAM impl green for tests.

**Files:**
- Modify: `crates/fetchit-relay-server/src/transit.rs`
- Modify: `crates/fetchit-relay-server/src/error.rs`

**Interfaces:**
- Produces: `trait TransitStore`, `struct StoredEntry { id: u64, envelope: TransitEnvelope, enqueued_at_ms: u64 }`, `TransitBuffer: TransitStore`.
- Consumes: `fetchit_relay_proto::{AgentId, TransitEnvelope}`.

- [ ] **Step 1: Add the error variant.** In `error.rs`, add to `ServerError`:

```rust
    /// A durable transit-store backend operation failed (open, read,
    /// write, or delete). Carries a human-readable cause; never payload.
    #[error("transit store backend error: {0}")]
    TransitStore(String),
```

- [ ] **Step 2: Write the failing test** (append to the `tests` module in `transit.rs`):

```rust
    #[test]
    fn read_all_is_non_destructive_and_delete_removes_by_id() {
        let b = TransitBuffer::new(Duration::from_secs(60), 10, usize::MAX);
        let to = AgentId::from_bytes([9u8; 32]);
        let id1 = b.enqueue(to, env_for(1)).unwrap();
        let id2 = b.enqueue(to, env_for(2)).unwrap();
        assert_ne!(id1, id2, "ids are unique");

        let first = b.read_all(&to);
        assert_eq!(first.len(), 2);
        let second = b.read_all(&to);
        assert_eq!(second.len(), 2, "read_all is non-destructive");

        b.delete(&to, &[id1]);
        let after = b.read_all(&to);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, id2);
    }
```

- [ ] **Step 3: Run it, expect failure.** Run: `cargo test -p fetchit-relay-server transit:: -- read_all_is_non_destructive`. Expected: FAIL (no `read_all`/`delete`/`enqueue`-returns-id).

- [ ] **Step 4: Implement.** In `transit.rs`:
  - Change `Entry` to `{ pub envelope: TransitEnvelope, pub enqueued_at_ms: u64 }` (drop `Instant`).
  - Add `pub struct StoredEntry { pub id: u64, pub envelope: TransitEnvelope, pub enqueued_at_ms: u64 }`.
  - Add the trait:

```rust
/// A per-recipient durable (or in-memory) store of undelivered,
/// opaque transit envelopes. Implementations MUST persist only the
/// ciphertext `TransitEnvelope` and never inspect its payload.
pub trait TransitStore: Send + Sync {
    /// Enqueue `envelope` for `to`, returning a store-stable id used
    /// later by [`TransitStore::delete`]. Ids are never reused.
    ///
    /// # Errors
    /// [`ServerError::TransitBufferFull`] on a cap breach;
    /// [`ServerError::TransitStore`] on a backend failure.
    fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<u64, ServerError>;
    /// Read every currently-stored entry for `to` WITHOUT removing it
    /// (delivery is confirmed separately via [`TransitStore::delete`]).
    fn read_all(&self, to: &AgentId) -> Vec<StoredEntry>;
    /// Delete the listed ids for `to` (called on a client delivery-ack).
    fn delete(&self, to: &AgentId, ids: &[u64]);
    /// Evict every entry older than the configured TTL; returns the count.
    fn sweep_expired(&self) -> usize;
    /// Total envelopes stored across all recipients.
    fn len(&self) -> usize;
    /// True if nothing is stored.
    fn is_empty(&self) -> bool { self.len() == 0 }
    /// Total accounted bytes across all recipients.
    fn total_bytes(&self) -> usize;
}
```

  - Give `TransitBuffer` a `next_id: AtomicU64` (start at 1; `0` is reserved for "direct/non-durable") and change its map to `DashMap<AgentId, VecDeque<(u64, Entry)>>`. Implement `TransitStore` for it: `enqueue` assigns `next_id.fetch_add(1)`, pushes `(id, Entry{envelope, enqueued_at_ms: now_ms()})`; `read_all` clones to `StoredEntry`s; `delete` retains entries whose id is not in `ids` (decrementing `total_bytes`); `sweep_expired` compares `now_ms().saturating_sub(e.enqueued_at_ms) >= ttl_ms`. Store `ttl_ms: u64` (from the `Duration`). Add a private `fn now_ms() -> u64` (SystemTime since epoch, saturating).

- [ ] **Step 5: Update the existing tests** in `transit.rs` that called `drain` / built `Entry { enqueued_at: Instant::now() }`: replace `drain(&to)` with `read_all` + `delete`, and `Entry` construction with `enqueued_at_ms: 1`. Keep the cap and byte-budget tests (they assert `enqueue`/`sweep_expired`/`total_bytes`).

- [ ] **Step 6: Run.** Run: `cargo test -p fetchit-relay-server transit::` (PASS), then `cargo clippy -p fetchit-relay-server --all-targets -- -D warnings` (clean).

- [ ] **Step 7: Commit.**

```bash
git add crates/fetchit-relay-server/src/transit.rs crates/fetchit-relay-server/src/error.rs
git commit -s -m "feat(relay): TransitStore trait with stable ids and non-destructive read"
```

---

### Task 2: SQLite-backed `SqliteTransitStore` (the durability core)

The persistent implementation. Its headline test is restart survival. `rusqlite` is already a relay-server dependency (the registry store) — no new dependency.

**Files:**
- Create: `crates/fetchit-relay-server/src/transit_sqlite.rs`
- Modify: `crates/fetchit-relay-server/src/lib.rs` (add `mod transit_sqlite; pub use transit_sqlite::SqliteTransitStore;`)

**Interfaces:**
- Consumes: `crate::transit::{TransitStore, StoredEntry}`, `ServerError`.
- Produces: `SqliteTransitStore::open(path, ttl, cap_per_recipient, max_total_bytes) -> Result<Self, ServerError>` implementing `TransitStore`.

- [ ] **Step 1: Confirm the dependency.** Verify `rusqlite` is in `crates/fetchit-relay-server/Cargo.toml` (it backs `registry/store_sqlite.rs`). If it is feature-gated behind `fediverse-inbox`/registry, move it to an always-on dependency. No version change; no root `Cargo.toml` dep addition.

- [ ] **Step 2: Write the failing restart test.** Create `transit_sqlite.rs` with only the test module first:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::transit::TransitStore;
    use fetchit_relay_proto::{AgentId, EnvelopeKind, MachineId, TransitEnvelope, WIRE_VERSION};
    use std::time::Duration;

    fn env() -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION, kind: EnvelopeKind::Dm, group_id: None, tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1; 32]), sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1, epoch: 0, ciphertext: vec![7u8; 32], nonce: vec![], kem_ciphertext: vec![], sender_signature: vec![],
        }
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.db");
        let to = AgentId::from_bytes([9u8; 32]);
        let id = {
            let s = SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
            let id = s.enqueue(to, env()).unwrap();
            assert_eq!(s.read_all(&to).len(), 1);
            id
        }; // store dropped == process restart
        let reopened = SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
        let after = reopened.read_all(&to);
        assert_eq!(after.len(), 1, "entry survived reopen");
        assert_eq!(after[0].id, id);
        assert_eq!(after[0].envelope.ciphertext, vec![7u8; 32], "ciphertext intact");
    }

    #[test]
    fn delete_then_reopen_stays_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let to = AgentId::from_bytes([4u8; 32]);
        let s = SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
        let id = s.enqueue(to, env()).unwrap();
        s.delete(&to, &[id]);
        drop(s);
        let s2 = SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
        assert!(s2.read_all(&to).is_empty());
    }

    #[test]
    fn ttl_sweep_removes_old() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let to = AgentId::from_bytes([5u8; 32]);
        // ttl 0 => everything already expired.
        let s = SqliteTransitStore::open(&path, Duration::from_millis(0), 256, 1 << 30).unwrap();
        s.enqueue(to, env()).unwrap();
        assert_eq!(s.sweep_expired(), 1);
        assert!(s.read_all(&to).is_empty());
    }
}
```

- [ ] **Step 3: Run it, expect failure.** Run: `cargo test -p fetchit-relay-server transit_sqlite:: -- survives_reopen`. Expected: FAIL (`SqliteTransitStore` undefined).

- [ ] **Step 4: Implement `SqliteTransitStore`.** Above the test module (`AgentId::as_bytes()` returns the recipient byte slice; bind it once and pass as a BLOB param):

```rust
//! SQLite-backed durable transit store (rusqlite). Persists opaque
//! `TransitEnvelope` ciphertext per recipient so undelivered messages
//! survive a relay restart and a multi-day offline window. SQLite is
//! already a relay-server dependency (the self-serve registry store),
//! so durability is added with no new dependency. The relay never
//! inspects the payload (stays blind); disk-at-rest is operator FDE.

use crate::error::ServerError;
use crate::transit::{StoredEntry, TransitStore};
use fetchit_relay_proto::{AgentId, TransitEnvelope};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

const FIXED_OVERHEAD: usize = 128;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

fn row_size(env: &TransitEnvelope) -> usize {
    FIXED_OVERHEAD
        .saturating_add(env.ciphertext.len())
        .saturating_add(env.nonce.len())
        .saturating_add(env.kem_ciphertext.len())
        .saturating_add(env.sender_signature.len())
}

/// Durable per-recipient transit store backed by a single SQLite file.
/// `rusqlite::Connection` is `!Sync`, so it is wrapped in a `Mutex`;
/// transit traffic is modest and SQLite serializes writes anyway.
pub struct SqliteTransitStore {
    conn: Mutex<Connection>,
    ttl_ms: u64,
    cap_per_recipient: usize,
    max_total_bytes: usize,
}

impl SqliteTransitStore {
    /// Open (or create) the store at `path`.
    ///
    /// # Errors
    /// [`ServerError::TransitStore`] if the DB cannot be opened or the
    /// schema cannot be created.
    pub fn open(
        path: &Path,
        ttl: Duration,
        cap_per_recipient: usize,
        max_total_bytes: usize,
    ) -> Result<Self, ServerError> {
        let conn = Connection::open(path).map_err(|e| ServerError::TransitStore(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 recipient BLOB NOT NULL,
                 enqueued_at_ms INTEGER NOT NULL,
                 envelope BLOB NOT NULL
             )",
            [],
        )
        .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transit_recipient ON transit(recipient, id)",
            [],
        )
        .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            ttl_ms: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
            cap_per_recipient,
            max_total_bytes,
        })
    }
}

impl TransitStore for SqliteTransitStore {
    fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<u64, ServerError> {
        let bytes =
            postcard::to_allocvec(&envelope).map_err(|e| ServerError::TransitStore(e.to_string()))?;
        let size = row_size(&envelope);
        let rid = to.as_bytes();
        let conn = self
            .conn
            .lock()
            .map_err(|_| ServerError::TransitStore("transit mutex poisoned".into()))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM transit WHERE recipient = ?1",
                params![rid],
                |r| r.get(0),
            )
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= self.cap_per_recipient {
            return Err(ServerError::TransitBufferFull);
        }
        let total: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(envelope)), 0) FROM transit",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        if usize::try_from(total).unwrap_or(usize::MAX).saturating_add(size) > self.max_total_bytes {
            return Err(ServerError::TransitBufferFull);
        }
        conn.execute(
            "INSERT INTO transit (recipient, enqueued_at_ms, envelope) VALUES (?1, ?2, ?3)",
            params![rid, i64::try_from(now_ms()).unwrap_or(i64::MAX), bytes],
        )
        .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        Ok(u64::try_from(conn.last_insert_rowid()).unwrap_or(0))
    }

    fn read_all(&self, to: &AgentId) -> Vec<StoredEntry> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, enqueued_at_ms, envelope FROM transit WHERE recipient = ?1 ORDER BY id",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![to.as_bytes()], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
        });
        let Ok(rows) = rows else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (id, at, env_bytes) in rows.flatten() {
            if let Ok(envelope) = postcard::from_bytes::<TransitEnvelope>(&env_bytes) {
                out.push(StoredEntry {
                    id: u64::try_from(id).unwrap_or(0),
                    envelope,
                    enqueued_at_ms: u64::try_from(at).unwrap_or(0),
                });
            }
        }
        out
    }

    fn delete(&self, to: &AgentId, ids: &[u64]) {
        let Ok(conn) = self.conn.lock() else {
            return;
        };
        for id in ids {
            let _ = conn.execute(
                "DELETE FROM transit WHERE recipient = ?1 AND id = ?2",
                params![to.as_bytes(), i64::try_from(*id).unwrap_or(i64::MAX)],
            );
        }
    }

    fn sweep_expired(&self) -> usize {
        let cutoff = now_ms().saturating_sub(self.ttl_ms);
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.execute(
            "DELETE FROM transit WHERE enqueued_at_ms <= ?1",
            params![i64::try_from(cutoff).unwrap_or(i64::MAX)],
        )
        .unwrap_or(0)
    }

    fn len(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.query_row("SELECT COUNT(*) FROM transit", [], |r| r.get::<_, i64>(0))
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
            .unwrap_or(0)
    }

    fn total_bytes(&self) -> usize {
        let count = self.len();
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        let raw: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(envelope)), 0) FROM transit",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        usize::try_from(raw)
            .unwrap_or(0)
            .saturating_add(count.saturating_mul(FIXED_OVERHEAD))
    }
}
```

  Note on `sweep_expired`: `<= cutoff` (with `cutoff = now - ttl`) so a `ttl = 0` makes everything immediately expired (the `ttl_sweep_removes_old` test). `Connection::execute` returns rows-affected as the evicted count.

- [ ] **Step 5: Wire the module.** In `lib.rs` add `mod transit_sqlite;` and `pub use transit_sqlite::SqliteTransitStore;`. Ensure `tempfile` is in `[dev-dependencies]`.

- [ ] **Step 6: Run.** Run: `cargo test -p fetchit-relay-server transit_sqlite::` (PASS: `survives_reopen`, `delete_then_reopen_stays_deleted`, `ttl_sweep_removes_old`), then `cargo clippy -p fetchit-relay-server --all-targets -- -D warnings` (clean).

- [ ] **Step 7: Commit.**

```bash
git add crates/fetchit-relay-server/src/transit_sqlite.rs crates/fetchit-relay-server/src/lib.rs crates/fetchit-relay-server/Cargo.toml
git commit -s -m "feat(relay): SQLite-backed durable transit store surviving restart"
```

---

### Task 3: `TransitAck` wire frame

The client-to-relay, transport-level delivery confirmation (NOT the sealed e2e receipt) that lets the relay reclaim delivered entries while staying blind.

**Files:**
- Modify: `crates/fetchit-relay-proto/src/frame.rs`

**Interfaces:**
- Produces: `ClientFrame::TransitAck { acked_ids: Vec<u64> }`; documented contract that `Deliver.transit_seq` is the durable transit id (0 = direct/non-durable).

- [ ] **Step 1: Write the failing test** (in the `frame.rs` tests module):

```rust
    #[test]
    fn transit_ack_roundtrips() {
        let f = ClientFrame::TransitAck(TransitAck { acked_ids: vec![1, 2, 9] });
        let bytes = postcard::to_allocvec(&f).unwrap();
        let back: ClientFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(f, back);
    }
```

- [ ] **Step 2: Run it, expect failure.** Run: `cargo test -p fetchit-relay-proto frame:: -- transit_ack`. Expected: FAIL (`TransitAck` undefined).

- [ ] **Step 3: Implement.** In `frame.rs`, add the struct and **append** the variant to `ClientFrame` (append keeps existing discriminants stable):

```rust
/// Client confirmation that the listed durable transit ids were
/// delivered and may be reclaimed by the relay. Transport-level and
/// blind: ids echo [`Deliver::transit_seq`] from durable replays (a
/// `0` is never sent). This is NOT the sealed e2e `DeliveryReceipt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitAck {
    /// The `Deliver::transit_seq` values the client has accepted.
    pub acked_ids: Vec<u64>,
}
```

Add `TransitAck(TransitAck)` as the last variant of `enum ClientFrame`. Update the `Deliver.transit_seq` rustdoc to: "Durable-store id of this entry when replayed from the transit store (echo it in [`TransitAck`] to confirm delivery); `0` for a direct push that needs no ack."

- [ ] **Step 4: Run.** Run: `cargo test -p fetchit-relay-proto frame::` (PASS), then `cargo clippy -p fetchit-relay-proto --all-targets -- -D warnings` (clean).

- [ ] **Step 5: Commit.**

```bash
git add crates/fetchit-relay-proto/src/frame.rs
git commit -s -m "feat(relay-proto): add transport-level TransitAck client frame"
```

---

### Task 4: Server — non-destructive replay + ack-driven delete

Switch the reconnect path to non-destructive read, stamp ids into `Deliver`, and reclaim on `TransitAck`.

**Files:**
- Modify: `crates/fetchit-relay-server/src/ws.rs`

**Interfaces:**
- Consumes: `TransitStore::{read_all, delete}`, `StoredEntry`, `ClientFrame::TransitAck`.

- [ ] **Step 1: Write the failing test** (ws.rs tests module — uses a RAM `TransitBuffer` behind the trait; add a `sample_env()` helper if absent):

```rust
    #[test]
    fn replay_uses_stored_id_and_is_non_destructive() {
        let store = TransitBuffer::new(Duration::from_secs(60), 10, usize::MAX);
        let to = AgentId::from_bytes([5u8; 32]);
        let id = store.enqueue(to, sample_env()).unwrap();
        let entries = store.read_all(&to);
        let (tx, mut rx) = mpsc::channel::<ServerFrame>(8);
        let out = replay_transit_entries(entries, &tx, now_ms());
        assert_eq!(out.delivered, 1);
        match rx.try_recv() {
            Ok(ServerFrame::Deliver(d)) => assert_eq!(d.transit_seq, id, "Deliver carries the durable id"),
            other => panic!("expected a Deliver, got {other:?}"),
        }
        assert_eq!(store.read_all(&to).len(), 1, "replay did not delete");
    }
```

- [ ] **Step 2: Run it, expect failure.** Run: `cargo test -p fetchit-relay-server ws:: -- replay_uses_stored_id`. Expected: FAIL (`replay_transit_entries` undefined).

- [ ] **Step 3: Implement.** In `ws.rs`:
  - Add a `StoredEntry`-based replay that preserves the id:

```rust
fn replay_transit_entries(
    entries: Vec<crate::transit::StoredEntry>,
    tx: &mpsc::Sender<ServerFrame>,
    delivered_at_ms: u64,
) -> ReplayOutcome {
    let mut delivered = 0usize;
    let mut undelivered = Vec::new();
    let mut iter = entries.into_iter();
    while let Some(entry) = iter.next() {
        let frame = ServerFrame::Deliver(Deliver {
            envelope: entry.envelope,
            transit_seq: entry.id,
            delivered_at_ms,
        });
        match tx.try_send(frame) {
            Ok(()) => delivered += 1,
            Err(e) => {
                let rejected = match e {
                    mpsc::error::TrySendError::Full(f) | mpsc::error::TrySendError::Closed(f) => f,
                };
                if let ServerFrame::Deliver(d) = rejected { undelivered.push(d.envelope); }
                for remaining in iter { undelivered.push(remaining.envelope); }
                break;
            }
        }
    }
    ReplayOutcome { delivered, undelivered }
}
```

  - In connection setup (currently `ws.rs:124-136`), replace `drain` + re-enqueue with a non-destructive read; do NOT re-enqueue (entries stay until acked):

```rust
    let pending = state.transit.read_all(&auth.agent_id);
    let ReplayOutcome { delivered, undelivered: _ } =
        replay_transit_entries(pending, &tx, now_ms());
    for _ in 0..delivered {
        state.metrics.envelope_delivered();
    }
    // Entries are NOT removed here; they are reclaimed on TransitAck or
    // by the TTL sweep, so a mid-delivery disconnect or relay restart
    // cannot lose them. Re-delivery on the next reconnect is deduped
    // client-side (NonceDedup).
```

  - In `handle_client_frame`, add the arm:

```rust
        ClientFrame::TransitAck(TransitAck { acked_ids }) => {
            state.transit.delete(&auth.agent_id, &acked_ids);
            true
        }
```

  (Import `TransitAck` from `fetchit_relay_proto` alongside the other frame types.)
  - Grep `replay_transit(` and `state.transit.drain(`; the legacy `replay_transit(Vec<Entry>, ..)` and `drain` are now unused — delete them and the now-stale `drain`-based test.

- [ ] **Step 4: Run.** Run: `cargo test -p fetchit-relay-server ws::`, then `cargo test -p fetchit-relay-server`, then `cargo clippy -p fetchit-relay-server --all-targets -- -D warnings`. Expected: green/clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/fetchit-relay-server/src/ws.rs
git commit -s -m "feat(relay): non-destructive replay with ack-driven transit reclaim"
```

---

### Task 5: Config + metrics + server wiring (7-day TTL, disk path, cap counter, trait object)

Make `ServerState.transit` a trait object, default to SQLite when a path is configured, bump retention, and count cap rejections.

**Files:**
- Modify: `crates/fetchit-relay-server/src/config.rs`
- Modify: `crates/fetchit-relay-server/src/metrics.rs`
- Modify: `crates/fetchit-relay-server/src/server.rs`
- Modify: `crates/fetchit-relay-server/src/ws.rs` (bump the new counter on cap rejection)

**Interfaces:**
- Consumes: `SqliteTransitStore`, `TransitBuffer`, `TransitStore`.
- Produces: `ServerState.transit: Arc<dyn TransitStore>`; `ServerConfig.transit_store_path: Option<PathBuf>`; `Metrics::transit_cap_rejected()`.

- [ ] **Step 1: Write the failing config test** (config.rs tests):

```rust
    #[test]
    fn transit_ttl_default_is_seven_days() {
        let c = ServerConfig::defaults();
        assert_eq!(c.transit_ttl, Duration::from_secs(7 * 24 * 60 * 60));
    }
```

- [ ] **Step 2: Run it, expect failure.** Run: `cargo test -p fetchit-relay-server config:: -- transit_ttl_default_is_seven_days`. Expected: FAIL (still 15 min).

- [ ] **Step 3: Implement config.** In `config.rs`: set `transit_ttl: Duration::from_secs(7 * 24 * 60 * 60)` in `defaults()`; add field `pub transit_store_path: Option<PathBuf>` (default `None`); in `from_env`, parse `FETCHIT_RELAY_TRANSIT_DB` into it (`std::env::var(..).ok().map(PathBuf::from)`). The per-recipient cap knob `transit_per_recipient` already exists; leave it.

- [ ] **Step 4: Add the cap counter.** In `metrics.rs`, add a `transit_cap_rejected` atomic counter mirroring the existing counter pattern (a `fn transit_cap_rejected(&self)` incrementer + exposure in the metrics render). In `ws.rs`, in the `state.transit.enqueue(to, envelope).is_err()` branch (the cap-rejection path that already sends `Throttle`), call `state.metrics.transit_cap_rejected()` so a full queue is a counted event, never a silent drop.

- [ ] **Step 5: Implement server wiring.** In `server.rs`:
  - Change `ServerState.transit` type to `Arc<dyn crate::transit::TransitStore>`.
  - Open the store fallibly in `run()` (which already returns `Result`) so no `panic!`/`unwrap` is introduced; thread the built `Arc<dyn TransitStore>` into `router()` (add a parameter or build state in `run()`). When `transit_store_path` is `Some`, build `SqliteTransitStore::open(path, transit_ttl, transit_per_recipient, transit_total_bytes_cap)?` wrapped in `Arc`; else `Arc::new(TransitBuffer::new(..))`. Both coerce to `Arc<dyn TransitStore>`.
  - The sweeper (`server.rs:319`) already calls `state.transit.sweep_expired()` / `.len()` — both on the trait, unchanged.

- [ ] **Step 6: Add a wiring test** (server.rs tests): build a `ServerConfig` with `transit_store_path: Some(tempdir path)`, construct the state via the production path, enqueue via `state.transit`, drop, rebuild from the same path, assert `read_all` still returns the entry (end-to-end persistence through real construction).

- [ ] **Step 7: Run.** Run: `cargo test -p fetchit-relay-server`, then `cargo clippy -p fetchit-relay-server --all-targets -- -D warnings`. Expected: green/clean.

- [ ] **Step 8: Commit.**

```bash
git add crates/fetchit-relay-server/src/config.rs crates/fetchit-relay-server/src/metrics.rs crates/fetchit-relay-server/src/server.rs crates/fetchit-relay-server/src/ws.rs
git commit -s -m "feat(relay): 7-day retention, SQLite transit when configured, cap-rejection counter"
```

---

### Task 6: Client — send `TransitAck` on durable deliveries

Close the loop so delivered entries are reclaimed.

**Files:**
- Modify: `crates/fetchit-relay-client/src/client.rs`

**Interfaces:**
- Consumes: inbound `ServerFrame::Deliver { transit_seq }`, outbound `ClientFrame::TransitAck`.

- [ ] **Step 1: Write the failing test.** In `client.rs` tests, drive the inbound handler with a `Deliver { transit_seq: 7, .. }` and assert the client emits `ClientFrame::TransitAck { acked_ids: vec![7] }`; and that `Deliver { transit_seq: 0, .. }` (direct push) emits NO ack. If inbound handling is inline in the read loop, extract `fn ack_for_deliver(d: &Deliver) -> Option<ClientFrame>` (below) so it is unit-testable, and call it from the loop.

- [ ] **Step 2: Run it, expect failure.** Run: `cargo test -p fetchit-relay-client -- transit_ack`. Expected: FAIL.

- [ ] **Step 3: Implement.**

```rust
/// Build the durable-delivery ack for an inbound `Deliver`, if one is
/// owed. `transit_seq == 0` is a direct push that needs no ack.
fn ack_for_deliver(d: &fetchit_relay_proto::Deliver) -> Option<fetchit_relay_proto::ClientFrame> {
    if d.transit_seq == 0 {
        None
    } else {
        Some(fetchit_relay_proto::ClientFrame::TransitAck(
            fetchit_relay_proto::TransitAck { acked_ids: vec![d.transit_seq] },
        ))
    }
}
```

Call it in the inbound loop after the message is surfaced to the consumer (so the ack means "the app has it"), sending the returned frame on the existing outbound channel. One-id-per-ack is correct; batching is a later optimization.

- [ ] **Step 4: Run.** Run: `cargo test -p fetchit-relay-client`, then `cargo clippy -p fetchit-relay-client --all-targets -- -D warnings`. Expected: green/clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/fetchit-relay-client/src/client.rs
git commit -s -m "feat(relay-client): ack durable transit deliveries so the relay can reclaim"
```

---

### Task 7: Workspace gate + docs

Prove the tree is green and keep the docs honest (docs-track-code).

**Files:**
- Modify: `crates/fetchit-relay-server/src/transit.rs` (module doc), `docs/CAPABILITIES.md`.

- [ ] **Step 1: Update docs.** Fix the `transit.rs` module doc (currently "RAM-only ... Never writes to disk") to describe the trait + the SQLite durable impl + the ack/TTL reclaim. Add a `docs/CAPABILITIES.md` entry under the chat/relay section: "Durable blind relay store-and-forward (`SqliteTransitStore`, 7-day retention, delete-on-ack) — `crates/fetchit-relay-server/src/transit_sqlite.rs`", anchored + stamped per `check-arch-stamps.sh`.

- [ ] **Step 2: Full workspace gate.** From repo root: `cargo fmt --all`, then `cargo clippy --workspace --all-targets -- -D warnings`, then `cargo test --workspace`. Expected: all clean/green.

- [ ] **Step 3: Commit.**

```bash
git add -A
git commit -s -m "docs(relay): record durable transit store-and-forward in module docs and CAPABILITIES"
```

---

## Self-Review

**Spec coverage (against `2026-06-21-reliable-pq-delivery-design.md` R2):** persistent disk store (Task 2), survive restart (Task 2 `survives_reopen` + Task 5 wiring test), 7-day retention (Task 5), delete-on-confirmed-delivery / kill ack-then-drop (Tasks 3/4/6), cap-rejection counter / no silent drop (Task 5), relay stays blind (Global Constraints + Task 2 ciphertext assertion), single home-relay v1 (Global Constraints; cross-relay deferred). Covered.

**Placeholder scan:** no TBD/TODO; every code step has complete code. The fallible-`open` wiring (Task 5 Step 5) is stated concretely (build in `run()`, thread into state) rather than left vague, honoring the no-panic lint.

**Type consistency:** `TransitStore` (enqueue→`u64`, `read_all`→`Vec<StoredEntry>`, `delete(&AgentId, &[u64])`, `sweep_expired`, `len`, `total_bytes`) is used identically in Tasks 1, 2, 4, 5. `StoredEntry { id, envelope, enqueued_at_ms }`, `ClientFrame::TransitAck { acked_ids }`, and `Deliver.transit_seq` (the id; `0` = direct) are consistent across server (Task 4) and client (Task 6).

**Cross-review (Bob, resolved):** store engine = SQLite/`rusqlite` (already a dep, isolated behind the trait); `TransitAck` is the transport-level blind ack (not the sealed receipt); cap stays config + counted; single home-relay for v1. Open follow-up for Bob at review: confirm whether `transit_per_recipient` (currently 256) should rise given 7-day retention.
