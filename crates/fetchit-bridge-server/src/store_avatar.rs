//! Avatar half of the bridge [`Store`]: the bytes behind an actor's
//! `icon` URL.
//!
//! A profile picture belongs to the actor row, so it lives in two
//! nullable columns on `actors` rather than a table of its own — a
//! deleted actor cannot leave an orphaned image behind, and serving one
//! is a single keyed read.
//!
//! Bytes are stored **verbatim**. The bridge never decodes an image:
//! handing user bytes to a decoder on a server that also holds the
//! follower graph buys nothing and adds a memory-safety surface. The
//! upload route's job is the allowlist, the size cap, and the
//! signature check; this module's job is durability.

use rusqlite::{params, OptionalExtension};

use crate::error::BridgeError;
use crate::store::Store;

/// A stored avatar as served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAvatar {
    /// Image bytes exactly as uploaded.
    pub bytes: Vec<u8>,
    /// The `Content-Type` the uploader declared, already normalised and
    /// allowlist-checked at upload time.
    pub content_type: String,
}

impl Store {
    /// Replace `agent_id`'s avatar. Returns `false` when no such actor
    /// row exists.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn set_avatar(
        &self,
        agent_id: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<bool, BridgeError> {
        let (agent_id, ct) = (agent_id.to_owned(), content_type.to_owned());
        self.with_conn(move |c| {
            let n = c.execute(
                "UPDATE actors SET avatar = ?2, avatar_ct = ?3 WHERE agent_id = ?1",
                params![agent_id, bytes, ct],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Drop `agent_id`'s avatar. Returns whether one was actually
    /// cleared, so a repeat delete is a no-op rather than an error.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn clear_avatar(&self, agent_id: &str) -> Result<bool, BridgeError> {
        let agent_id = agent_id.to_owned();
        self.with_conn(move |c| {
            let n = c.execute(
                "UPDATE actors SET avatar = NULL, avatar_ct = NULL
                 WHERE agent_id = ?1 AND avatar IS NOT NULL",
                params![agent_id],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// The avatar published at `handle`'s actor, or `None` when the
    /// handle is unknown or has no picture set — the public GET serves
    /// 404 for both, so they need no distinction.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn avatar_by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<StoredAvatar>, BridgeError> {
        let handle = handle.to_owned();
        self.with_conn(move |c| {
            let row: Option<(Option<Vec<u8>>, Option<String>)> = c
                .query_row(
                    "SELECT avatar, avatar_ct FROM actors WHERE handle = ?1",
                    params![handle],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            Ok(match row {
                Some((Some(bytes), Some(content_type))) if !bytes.is_empty() => {
                    Some(StoredAvatar {
                        bytes,
                        content_type,
                    })
                }
                _ => None,
            })
        })
        .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::store::ActorRecord;

    async fn store_with_actor() -> Store {
        let s = Store::open_in_memory().unwrap();
        s.register_actor(ActorRecord {
            agent_id: "aa".into(),
            handle: "alice".into(),
            actor_url: "https://etchit.io/actors/alice".into(),
            doc_json: "{}".into(),
            registered_ms: 1,
        })
        .await
        .unwrap();
        s
    }

    #[tokio::test]
    async fn set_then_read_round_trips_bytes_and_type() {
        let s = store_with_actor().await;
        assert!(s.avatar_by_handle("alice").await.unwrap().is_none());

        assert!(s
            .set_avatar("aa", vec![1, 2, 3], "image/png")
            .await
            .unwrap());
        let got = s.avatar_by_handle("alice").await.unwrap().unwrap();
        assert_eq!(got.bytes, vec![1, 2, 3]);
        assert_eq!(got.content_type, "image/png");
    }

    #[tokio::test]
    async fn set_replaces_the_previous_picture() {
        let s = store_with_actor().await;
        s.set_avatar("aa", vec![1], "image/png").await.unwrap();
        s.set_avatar("aa", vec![9, 9], "image/jpeg").await.unwrap();
        let got = s.avatar_by_handle("alice").await.unwrap().unwrap();
        assert_eq!(got.bytes, vec![9, 9]);
        assert_eq!(got.content_type, "image/jpeg");
    }

    #[tokio::test]
    async fn clear_is_idempotent() {
        let s = store_with_actor().await;
        s.set_avatar("aa", vec![1], "image/png").await.unwrap();
        assert!(s.clear_avatar("aa").await.unwrap());
        assert!(s.avatar_by_handle("alice").await.unwrap().is_none());
        assert!(
            !s.clear_avatar("aa").await.unwrap(),
            "second clear is a no-op"
        );
    }

    #[tokio::test]
    async fn an_unknown_agent_or_handle_changes_nothing() {
        let s = store_with_actor().await;
        assert!(!s.set_avatar("bb", vec![1], "image/png").await.unwrap());
        assert!(!s.clear_avatar("bb").await.unwrap());
        assert!(s.avatar_by_handle("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn re_registration_keeps_the_avatar() {
        // A device re-asserts its actor document on every ensure pass;
        // that must not silently blank the user's profile picture.
        let s = store_with_actor().await;
        s.set_avatar("aa", vec![7, 7], "image/webp").await.unwrap();
        s.register_actor(ActorRecord {
            agent_id: "aa".into(),
            handle: "alice".into(),
            actor_url: "https://etchit.io/actors/alice".into(),
            doc_json: r#"{"updated":true}"#.into(),
            registered_ms: 2,
        })
        .await
        .unwrap();
        let got = s.avatar_by_handle("alice").await.unwrap().unwrap();
        assert_eq!(got.bytes, vec![7, 7]);
    }

    #[tokio::test]
    async fn an_old_database_without_the_avatar_columns_opens_and_upgrades() {
        // The production file predates these columns; opening it must
        // ALTER them in rather than fail or silently lose the table.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.sqlite");
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE actors (
                     agent_id      TEXT PRIMARY KEY,
                     handle        TEXT NOT NULL UNIQUE,
                     actor_url     TEXT NOT NULL,
                     doc_json      TEXT NOT NULL,
                     registered_ms INTEGER NOT NULL
                 );
                 INSERT INTO actors VALUES
                     ('aa', 'alice', 'https://etchit.io/actors/alice', '{}', 1);",
            )
            .unwrap();
        }

        let s = Store::open(&path).unwrap();
        assert_eq!(
            s.actor_by_handle("alice").await.unwrap().unwrap().agent_id,
            "aa",
            "the pre-existing row survives the upgrade"
        );
        assert!(s.avatar_by_handle("alice").await.unwrap().is_none());
        assert!(s.set_avatar("aa", vec![4], "image/png").await.unwrap());

        // And re-opening the upgraded file is a no-op, not a duplicate
        // ALTER (which SQLite would reject).
        let again = Store::open(&path).unwrap();
        assert_eq!(
            again
                .avatar_by_handle("alice")
                .await
                .unwrap()
                .unwrap()
                .bytes,
            vec![4]
        );
    }
}
