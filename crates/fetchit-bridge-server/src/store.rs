//! Durable embedded store for the bridge node.
//!
//! The chat relays are RAM-only; the bridge is not — a lost follower
//! list silently stops delivery, which is worse than a relay restart.
//! Backed by a single-file `SQLite` database (`rusqlite`, bundled). All
//! access goes through [`Store`], which serialises queries behind a
//! mutex and runs them on the blocking pool so the async runtime is
//! never blocked.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::BridgeError;

/// One registered local actor the bridge serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRecord {
    /// Derived ML-DSA agent id (lowercase hex) — the unforgeable identity.
    pub agent_id: String,
    /// Local-part handle (`preferredUsername`), unique across actors.
    pub handle: String,
    /// Canonical actor URL (the JSON-LD `id`).
    pub actor_url: String,
    /// The canonical actor JSON-LD document, serialised.
    pub doc_json: String,
    /// Registration time, milliseconds since the Unix epoch.
    pub registered_ms: i64,
}

/// Result of a registration attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// A new actor row was inserted.
    Created,
    /// An existing actor (same agent id) was updated.
    Updated,
    /// The handle is already held by a different agent id.
    HandleTaken,
}

/// Durable bridge store.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
    /// Open (or create) the database at `path` and apply migrations.
    ///
    /// # Errors
    /// Returns [`BridgeError::Store`] if the database cannot be opened
    /// or the schema cannot be created.
    pub fn open(path: &Path) -> Result<Self, BridgeError> {
        let conn = Connection::open(path)?;
        Self::migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open a private in-memory database (tests). The single shared
    /// connection means clones see the same data.
    ///
    /// # Errors
    /// Returns [`BridgeError::Store`] if the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, BridgeError> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn migrate(conn: &Connection) -> Result<(), BridgeError> {
        // All four tables are created now to avoid migration churn;
        // milestone 1 uses only `actors`. followers/outbox/
        // pending_deliveries are populated by the Follow/fan-out plan.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS actors (
                 agent_id      TEXT PRIMARY KEY,
                 handle        TEXT NOT NULL UNIQUE,
                 actor_url     TEXT NOT NULL,
                 doc_json      TEXT NOT NULL,
                 registered_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS followers (
                 actor_id           TEXT NOT NULL,
                 follower_actor_url TEXT NOT NULL,
                 shared_inbox_url   TEXT NOT NULL,
                 since_ms           INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, follower_actor_url)
             );
             CREATE TABLE IF NOT EXISTS following (
                 actor_id           TEXT NOT NULL,
                 target_actor_url   TEXT NOT NULL,
                 target_inbox_url   TEXT NOT NULL,
                 state              TEXT NOT NULL
                                    CHECK (state IN ('pending','accepted')),
                 follow_activity_id TEXT NOT NULL UNIQUE,
                 created_ms         INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, target_actor_url)
             );
             CREATE TABLE IF NOT EXISTS outbox (
                 actor_id      TEXT NOT NULL,
                 created_ms    INTEGER NOT NULL,
                 activity_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS pending_deliveries (
                 id               INTEGER PRIMARY KEY AUTOINCREMENT,
                 actor_id         TEXT NOT NULL,
                 target_inbox     TEXT NOT NULL,
                 activity_json    TEXT NOT NULL,
                 attempts         INTEGER NOT NULL DEFAULT 0,
                 next_retry_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS inbox_messages (
                 id               INTEGER PRIMARY KEY AUTOINCREMENT,
                 actor_id         TEXT NOT NULL,
                 sender_actor_url TEXT NOT NULL,
                 note_id          TEXT NOT NULL,
                 text             TEXT NOT NULL,
                 published        TEXT NOT NULL,
                 created_ms       INTEGER NOT NULL,
                 UNIQUE (actor_id, note_id)
             );",
        )?;
        Ok(())
    }

    pub(crate) async fn with_conn<F, T>(&self, f: F) -> Result<T, BridgeError>
    where
        F: FnOnce(&Connection) -> Result<T, BridgeError> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|_| BridgeError::StoreLockPoisoned)?;
            f(&guard)
        })
        .await
        .map_err(|e| BridgeError::Store(format!("join: {e}")))?
    }

    /// Insert or update an actor. A handle already held by a *different*
    /// agent id is rejected ([`RegisterOutcome::HandleTaken`]); the same
    /// agent re-registering updates its row.
    ///
    /// # Errors
    /// Returns [`BridgeError::Store`] on a database failure.
    pub async fn register_actor(&self, rec: ActorRecord) -> Result<RegisterOutcome, BridgeError> {
        self.with_conn(move |c| {
            let existing: Option<String> = c
                .query_row(
                    "SELECT agent_id FROM actors WHERE handle = ?1",
                    params![rec.handle],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(other) = &existing {
                if other != &rec.agent_id {
                    return Ok(RegisterOutcome::HandleTaken);
                }
            }
            // Pre-read existence: the UPSERT below returns rows_changed=1
            // for BOTH an INSERT and an ON CONFLICT(agent_id) UPDATE, so its
            // return value cannot distinguish Created from Updated -- this
            // SELECT disambiguates the outcome.
            let is_update = c
                .query_row(
                    "SELECT 1 FROM actors WHERE agent_id = ?1",
                    params![rec.agent_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let inserted = c.execute(
                "INSERT INTO actors (agent_id, handle, actor_url, doc_json, registered_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(agent_id) DO UPDATE SET
                     handle = excluded.handle,
                     actor_url = excluded.actor_url,
                     doc_json = excluded.doc_json,
                     registered_ms = excluded.registered_ms",
                params![
                    rec.agent_id,
                    rec.handle,
                    rec.actor_url,
                    rec.doc_json,
                    rec.registered_ms
                ],
            );
            match inserted {
                Ok(_) => Ok(if is_update {
                    RegisterOutcome::Updated
                } else {
                    RegisterOutcome::Created
                }),
                // Defense-in-depth (cross-review P3): the SELECT-then-INSERT
                // above is serialised by the single connection mutex, so a
                // concurrent same-handle race cannot occur today and this
                // branch is unreachable until a future connection pool. The
                // mapping keeps the API correct (409 HandleTaken, not 500)
                // under that change.
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Ok(RegisterOutcome::HandleTaken)
                }
                Err(e) => Err(BridgeError::from(e)),
            }
        })
        .await
    }

    /// Fetch a registered actor by its handle.
    ///
    /// # Errors
    /// Returns [`BridgeError::Store`] on a database failure.
    pub async fn actor_by_handle(&self, handle: &str) -> Result<Option<ActorRecord>, BridgeError> {
        let handle = handle.to_owned();
        self.with_conn(move |c| {
            c.query_row(
                "SELECT agent_id, handle, actor_url, doc_json, registered_ms
                 FROM actors WHERE handle = ?1",
                params![handle],
                |row| {
                    Ok(ActorRecord {
                        agent_id: row.get(0)?,
                        handle: row.get(1)?,
                        actor_url: row.get(2)?,
                        doc_json: row.get(3)?,
                        registered_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(BridgeError::from)
        })
        .await
    }

    /// Store an inbound fediverse message for `actor_id`. Redeliveries
    /// (same `note_id`) are dropped — remote servers retry with backoff,
    /// so the unique key makes retries harmless. Returns whether a new
    /// row was created.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on the underlying `SQLite` failure.
    pub async fn inbox_insert(&self, msg: InboxMessage) -> Result<bool, BridgeError> {
        self.with_conn(move |c| {
            let n = c.execute(
                "INSERT OR IGNORE INTO inbox_messages
                     (actor_id, sender_actor_url, note_id, text, published, created_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    msg.actor_id,
                    msg.sender_actor_url,
                    msg.note_id,
                    msg.text,
                    msg.published,
                    msg.created_ms
                ],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Inbound messages for `actor_id` newer than `since_ms`, oldest
    /// first, capped at `limit`. The owner-only `messages` route serves
    /// this; clients advance a `since_ms` cursor from the last row.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on the underlying `SQLite` failure.
    pub async fn inbox_list(
        &self,
        actor_id: &str,
        since_ms: i64,
        limit: u32,
    ) -> Result<Vec<InboxMessage>, BridgeError> {
        let actor = actor_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT actor_id, sender_actor_url, note_id, text, published, created_ms
                 FROM inbox_messages
                 WHERE actor_id = ?1 AND created_ms > ?2
                 ORDER BY created_ms ASC, id ASC
                 LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(params![actor, since_ms, limit], |row| {
                    Ok(InboxMessage {
                        actor_id: row.get(0)?,
                        sender_actor_url: row.get(1)?,
                        note_id: row.get(2)?,
                        text: row.get(3)?,
                        published: row.get(4)?,
                        created_ms: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }
}

/// One inbound fediverse message as stored for its recipient. `text` is
/// the display-ready plain-text reduction — raw remote HTML is never
/// persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxMessage {
    /// Recipient's agent id (the registered actor).
    pub actor_id: String,
    /// Sender's canonical actor URL.
    pub sender_actor_url: String,
    /// The Note's `id` — the redelivery-dedup key.
    pub note_id: String,
    /// Plain-text body.
    pub text: String,
    /// ISO-8601 `published` stamp as served (may be empty).
    pub published: String,
    /// Bridge receive time (epoch ms) — the cursor axis.
    pub created_ms: i64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn rec(agent: &str, handle: &str) -> ActorRecord {
        ActorRecord {
            agent_id: agent.into(),
            handle: handle.into(),
            actor_url: format!("https://etchit.io/actors/{handle}"),
            doc_json: "{}".into(),
            registered_ms: 1,
        }
    }

    #[tokio::test]
    async fn register_then_fetch_round_trips() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(
            s.register_actor(rec("aa", "alice")).await.unwrap(),
            RegisterOutcome::Created
        );
        let got = s.actor_by_handle("alice").await.unwrap().unwrap();
        assert_eq!(got.agent_id, "aa");
        assert_eq!(got.actor_url, "https://etchit.io/actors/alice");
    }

    #[tokio::test]
    async fn same_agent_reregister_updates() {
        let s = Store::open_in_memory().unwrap();
        s.register_actor(rec("aa", "alice")).await.unwrap();
        assert_eq!(
            s.register_actor(rec("aa", "alice")).await.unwrap(),
            RegisterOutcome::Updated
        );
    }

    #[tokio::test]
    async fn handle_taken_by_other_agent_is_rejected() {
        let s = Store::open_in_memory().unwrap();
        s.register_actor(rec("aa", "alice")).await.unwrap();
        assert_eq!(
            s.register_actor(rec("bb", "alice")).await.unwrap(),
            RegisterOutcome::HandleTaken
        );
        assert_eq!(
            s.actor_by_handle("alice").await.unwrap().unwrap().agent_id,
            "aa"
        );
    }

    #[tokio::test]
    async fn unknown_handle_is_none() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.actor_by_handle("nobody").await.unwrap().is_none());
    }

    fn msg(actor: &str, note: &str, created_ms: i64) -> InboxMessage {
        InboxMessage {
            actor_id: actor.into(),
            sender_actor_url: "https://fosstodon.org/users/happyborg".into(),
            note_id: note.into(),
            text: "hello back".into(),
            published: "2026-07-13T13:00:00Z".into(),
            created_ms,
        }
    }

    #[tokio::test]
    async fn inbox_dedups_redeliveries_and_lists_by_cursor() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.inbox_insert(msg("aa", "n1", 100)).await.unwrap());
        // Remote servers retry deliveries; the same note must not double.
        assert!(!s.inbox_insert(msg("aa", "n1", 150)).await.unwrap());
        assert!(s.inbox_insert(msg("aa", "n2", 200)).await.unwrap());
        // Another recipient's inbox is disjoint.
        assert!(s.inbox_insert(msg("bb", "n1", 300)).await.unwrap());

        let all = s.inbox_list("aa", 0, 50).await.unwrap();
        assert_eq!(
            all.iter().map(|m| m.note_id.as_str()).collect::<Vec<_>>(),
            vec!["n1", "n2"]
        );
        // Cursor: strictly-newer only.
        let newer = s.inbox_list("aa", 100, 50).await.unwrap();
        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].note_id, "n2");
        assert!(s.inbox_list("aa", 200, 50).await.unwrap().is_empty());
    }
}
