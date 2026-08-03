//! Follow-graph half of the bridge [`Store`] (M7 P1).
//!
//! Two directions, two tables:
//!
//! * `following` — actors WE follow. Rows are created `pending` when the
//!   signed `Follow` is enqueued and flip to `accepted` when the remote
//!   `Accept` arrives (matched on `follow_activity_id`, never on the
//!   sender's word alone — the inbox has already HTTP-signature-verified
//!   the `Accept` against the remote actor's key by the time it calls
//!   [`Store::follow_accepted`]).
//! * `followers` — actors following US. v1 policy is open follows: a
//!   verified inbound `Follow` is QUEUED (`follow_requests`), and the
//!   owner DEVICE — which holds the keys and the denylist consumer —
//!   gates on the denylist, signs the `Accept`, and confirms the
//!   follower. Manual approval is post-v1.
//!
//! Everything here is storage + state transitions; activity construction
//! and signing live in the routes/delivery layer.

use rusqlite::{params, OptionalExtension};

use crate::error::BridgeError;
use crate::store::Store;

/// Per-actor bound on queued inbound follow requests; beyond it the
/// oldest rows are evicted. Also the `LIMIT` on the owner's queue read.
const MAX_QUEUED_FOLLOW_REQUESTS: i64 = 200;

/// Outcome of [`Store::follow_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowOutcome {
    /// New `pending` row created — caller enqueues the `Follow` activity.
    Created,
    /// A `pending` row already exists — do not re-send the `Follow`.
    AlreadyPending,
    /// The follow is already `accepted` — nothing to do.
    AlreadyAccepted,
}

/// One row of the `following` table.
#[derive(Debug, Clone)]
pub struct FollowingRecord {
    /// Remote actor URL we follow (AP `id`).
    pub target_actor_url: String,
    /// Remote actor's inbox URL (delivery target for `Undo`).
    pub target_inbox_url: String,
    /// `pending` or `accepted`.
    pub state: FollowState,
    /// The `Follow` activity id we minted (matched by inbound `Accept`).
    pub follow_activity_id: String,
    /// Millisecond timestamp the follow was requested.
    pub created_ms: u64,
}

/// Follow lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowState {
    /// `Follow` sent, no `Accept` yet.
    Pending,
    /// Remote `Accept` verified and recorded.
    Accepted,
}

impl FollowState {
    fn parse(s: &str) -> Result<Self, BridgeError> {
        match s {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            other => Err(BridgeError::Store(format!("bad follow state: {other}"))),
        }
    }
}

impl Store {
    /// Record an outbound follow request as `pending`.
    ///
    /// Idempotent per `(actor_id, target)`: repeat calls report the
    /// existing state instead of duplicating rows, so a double-tap in the
    /// UI cannot spam the remote inbox with `Follow` activities.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn follow_request(
        &self,
        actor_id: &str,
        target_actor_url: &str,
        target_inbox_url: &str,
        follow_activity_id: &str,
        now_ms: u64,
    ) -> Result<FollowOutcome, BridgeError> {
        let (actor_id, target, inbox, fid) = (
            actor_id.to_owned(),
            target_actor_url.to_owned(),
            target_inbox_url.to_owned(),
            follow_activity_id.to_owned(),
        );
        self.with_conn(move |c| {
            let existing: Option<String> = c
                .query_row(
                    "SELECT state FROM following
                     WHERE actor_id = ?1 AND target_actor_url = ?2",
                    params![actor_id, target],
                    |row| row.get(0),
                )
                .optional()?;
            match existing.as_deref() {
                Some("accepted") => Ok(FollowOutcome::AlreadyAccepted),
                Some(_) => Ok(FollowOutcome::AlreadyPending),
                None => {
                    c.execute(
                        "INSERT INTO following (actor_id, target_actor_url,
                             target_inbox_url, state, follow_activity_id,
                             created_ms)
                         VALUES (?1, ?2, ?3, 'pending', ?4, ?5)",
                        params![
                            actor_id,
                            target,
                            inbox,
                            fid,
                            i64::try_from(now_ms).unwrap_or(i64::MAX)
                        ],
                    )?;
                    Ok(FollowOutcome::Created)
                }
            }
        })
        .await
    }

    /// Flip a pending follow to `accepted`, bound to the identity of the
    /// verified inbound `Accept`.
    ///
    /// The `follow_activity_id` alone is NOT an authorization: it rides
    /// the `Follow` we deliver to the target's inbox, so it is not secret,
    /// and any signature-verified actor could otherwise forge an `Accept`
    /// that flips a follow they were never party to. So the update also
    /// requires (a) `expected_target_actor_url` — the signature-verified
    /// sender of the `Accept` — to equal the actor the row actually
    /// follows, and (b) `expected_actor_id` — the recipient handle the
    /// `Accept` was delivered to — to own the row.
    ///
    /// Returns `false` when no pending row matches under those bindings
    /// (stale, forged, cross-account, or duplicate `Accept`) — callers
    /// treat that as a no-op, not an error.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn follow_accepted(
        &self,
        follow_activity_id: &str,
        expected_target_actor_url: &str,
        expected_actor_id: &str,
    ) -> Result<bool, BridgeError> {
        let (fid, target, actor) = (
            follow_activity_id.to_owned(),
            expected_target_actor_url.to_owned(),
            expected_actor_id.to_owned(),
        );
        self.with_conn(move |c| {
            let n = c.execute(
                "UPDATE following SET state = 'accepted'
                 WHERE follow_activity_id = ?1 AND state = 'pending'
                   AND target_actor_url = ?2 AND actor_id = ?3",
                params![fid, target, actor],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Drop a follow on a verified inbound `Reject`, bound to the
    /// signature-verified sender (`expected_target_actor_url`) so a
    /// third party cannot drop a follow they are not the target of.
    /// Returns `false` when nothing matched under that binding.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn follow_rejected(
        &self,
        follow_activity_id: &str,
        expected_target_actor_url: &str,
    ) -> Result<bool, BridgeError> {
        let (fid, target) = (
            follow_activity_id.to_owned(),
            expected_target_actor_url.to_owned(),
        );
        self.with_conn(move |c| {
            let n = c.execute(
                "DELETE FROM following
                 WHERE follow_activity_id = ?1 AND target_actor_url = ?2",
                params![fid, target],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Remove a follow locally and return the record (the caller mints
    /// `Undo(Follow)` from `follow_activity_id` and delivers it to
    /// `target_inbox_url`). `None` when we weren't following.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn unfollow(
        &self,
        actor_id: &str,
        target_actor_url: &str,
    ) -> Result<Option<FollowingRecord>, BridgeError> {
        let (actor_id, target) = (actor_id.to_owned(), target_actor_url.to_owned());
        self.with_conn(move |c| {
            let rec = c
                .query_row(
                    "SELECT target_actor_url, target_inbox_url, state,
                            follow_activity_id, created_ms
                     FROM following
                     WHERE actor_id = ?1 AND target_actor_url = ?2",
                    params![actor_id, target],
                    row_to_following,
                )
                .optional()?;
            if rec.is_some() {
                c.execute(
                    "DELETE FROM following
                     WHERE actor_id = ?1 AND target_actor_url = ?2",
                    params![actor_id, target],
                )?;
            }
            Ok(rec)
        })
        .await
    }

    /// Everyone `actor_id` follows, newest first.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn following_list(
        &self,
        actor_id: &str,
    ) -> Result<Vec<FollowingRecord>, BridgeError> {
        let actor_id = actor_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT target_actor_url, target_inbox_url, state,
                        follow_activity_id, created_ms
                 FROM following WHERE actor_id = ?1
                 ORDER BY created_ms DESC",
            )?;
            let rows = stmt.query_map(params![actor_id], row_to_following)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
        .await
    }

    /// Record an inbound (verified) follower. Idempotent: re-following
    /// refreshes nothing and reports `false`.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn add_follower(
        &self,
        actor_id: &str,
        follower_actor_url: &str,
        follower_inbox_url: &str,
        now_ms: u64,
    ) -> Result<bool, BridgeError> {
        let (actor_id, follower, inbox) = (
            actor_id.to_owned(),
            follower_actor_url.to_owned(),
            follower_inbox_url.to_owned(),
        );
        self.with_conn(move |c| {
            let n = c.execute(
                "INSERT OR IGNORE INTO followers
                     (actor_id, follower_actor_url, shared_inbox_url, since_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    actor_id,
                    follower,
                    inbox,
                    i64::try_from(now_ms).unwrap_or(i64::MAX)
                ],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Remove a follower on a verified `Undo(Follow)`. Returns `false`
    /// when nothing matched.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn remove_follower(
        &self,
        actor_id: &str,
        follower_actor_url: &str,
    ) -> Result<bool, BridgeError> {
        let (actor_id, follower) = (actor_id.to_owned(), follower_actor_url.to_owned());
        self.with_conn(move |c| {
            let n = c.execute(
                "DELETE FROM followers
                 WHERE actor_id = ?1 AND follower_actor_url = ?2",
                params![actor_id, follower],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Follower actor URLs for `actor_id`, newest first.
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn followers_list(&self, actor_id: &str) -> Result<Vec<String>, BridgeError> {
        let actor_id = actor_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT follower_actor_url FROM followers
                 WHERE actor_id = ?1 ORDER BY since_ms DESC",
            )?;
            let rows = stmt.query_map(params![actor_id], |row| row.get(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
        .await
    }

    /// Queue a verified inbound `Follow` for the owner device to answer.
    ///
    /// Upserts on `(actor_id, follower)`: a re-sent `Follow` (remote retry,
    /// or a re-follow after an unfollow) refreshes the stored activity id —
    /// the device's `Accept` must echo the follower's LATEST `Follow`, or
    /// Mastodon cannot correlate it. Queued even when the follower is
    /// already recorded: each inbound `Follow` deserves an `Accept`.
    ///
    /// The queue is bounded per actor at [`MAX_QUEUED_FOLLOW_REQUESTS`]:
    /// beyond it the OLDEST entries are evicted, so an attacker minting
    /// endless throwaway follower actors displaces only their own spam
    /// while the newest genuine requests survive (cross-review
    /// 2026-08-03 finding 1).
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn add_follow_request(
        &self,
        actor_id: &str,
        follower_actor_url: &str,
        follower_inbox_url: &str,
        follow_activity_id: &str,
        now_ms: u64,
    ) -> Result<(), BridgeError> {
        let (actor_id, follower, inbox, fid) = (
            actor_id.to_owned(),
            follower_actor_url.to_owned(),
            follower_inbox_url.to_owned(),
            follow_activity_id.to_owned(),
        );
        self.with_conn(move |c| {
            c.execute(
                "INSERT INTO follow_requests
                     (actor_id, follower_actor_url, follower_inbox_url,
                      follow_activity_id, received_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(actor_id, follower_actor_url) DO UPDATE SET
                     follower_inbox_url = excluded.follower_inbox_url,
                     follow_activity_id = excluded.follow_activity_id,
                     received_ms = excluded.received_ms",
                params![
                    actor_id,
                    follower,
                    inbox,
                    fid,
                    i64::try_from(now_ms).unwrap_or(i64::MAX)
                ],
            )?;
            c.execute(
                "DELETE FROM follow_requests
                 WHERE actor_id = ?1 AND follower_actor_url NOT IN (
                     SELECT follower_actor_url FROM follow_requests
                     WHERE actor_id = ?1
                     ORDER BY received_ms DESC
                     LIMIT ?2
                 )",
                params![actor_id, MAX_QUEUED_FOLLOW_REQUESTS],
            )?;
            Ok(())
        })
        .await
    }

    /// Pending inbound follow requests for `actor_id`, newest first,
    /// capped at [`MAX_QUEUED_FOLLOW_REQUESTS`] rows (mirrors
    /// `inbox_list`'s bounded reads — an owner fetch must never scale
    /// with attacker-controlled queue growth).
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn follow_requests_list(
        &self,
        actor_id: &str,
    ) -> Result<Vec<FollowRequestRecord>, BridgeError> {
        let actor_id = actor_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT follower_actor_url, follower_inbox_url,
                        follow_activity_id, received_ms
                 FROM follow_requests WHERE actor_id = ?1
                 ORDER BY received_ms DESC
                 LIMIT 200",
            )?;
            let rows = stmt.query_map(params![actor_id], |row| {
                let received: i64 = row.get(3)?;
                Ok(FollowRequestRecord {
                    follower_actor_url: row.get(0)?,
                    follower_inbox_url: row.get(1)?,
                    follow_activity_id: row.get(2)?,
                    received_ms: u64::try_from(received).unwrap_or(0),
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
        .await
    }

    /// Drop a queued follow request (the device confirmed its `Accept`, or
    /// the remote side retracted with `Undo(Follow)`). Returns `false`
    /// when nothing matched.
    ///
    /// When `follow_activity_id` is `Some`, only a row carrying exactly
    /// that id is consumed — a confirm answering an OLDER `Follow` then
    /// leaves a newer, re-sent request queued for its own `Accept`
    /// instead of silently dropping it (cross-review TOCTOU note).
    /// `None` removes regardless (the `Undo` path, and older clients).
    ///
    /// # Errors
    /// [`BridgeError::Store`] on a database failure.
    pub async fn remove_follow_request(
        &self,
        actor_id: &str,
        follower_actor_url: &str,
        follow_activity_id: Option<&str>,
    ) -> Result<bool, BridgeError> {
        let (actor_id, follower) = (actor_id.to_owned(), follower_actor_url.to_owned());
        let fid = follow_activity_id.map(str::to_owned);
        self.with_conn(move |c| {
            let n = c.execute(
                "DELETE FROM follow_requests
                 WHERE actor_id = ?1 AND follower_actor_url = ?2
                   AND (?3 IS NULL OR follow_activity_id = ?3)",
                params![actor_id, follower, fid],
            )?;
            Ok(n == 1)
        })
        .await
    }
}

/// One queued inbound follow request awaiting the device's `Accept`.
#[derive(Debug, Clone)]
pub struct FollowRequestRecord {
    /// The remote actor asking to follow us (AP `id`).
    pub follower_actor_url: String,
    /// Their inbox — where the device delivers its signed `Accept`.
    pub follower_inbox_url: String,
    /// The `Follow` activity id the `Accept` must echo.
    pub follow_activity_id: String,
    /// Millisecond timestamp the request arrived.
    pub received_ms: u64,
}

fn row_to_following(row: &rusqlite::Row<'_>) -> rusqlite::Result<FollowingRecord> {
    let state_raw: String = row.get(2)?;
    let state = FollowState::parse(&state_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(e.to_string())),
        )
    })?;
    let created: i64 = row.get(4)?;
    Ok(FollowingRecord {
        target_actor_url: row.get(0)?,
        target_inbox_url: row.get(1)?,
        state,
        follow_activity_id: row.get(3)?,
        created_ms: u64::try_from(created).unwrap_or(0),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const A: &str = "agent-a";
    const TGT: &str = "https://fosstodon.org/users/happyborg";
    const TGT_INBOX: &str = "https://fosstodon.org/users/happyborg/inbox";
    const FID: &str = "https://bridge.example/actors/josh/follows/1";

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[tokio::test]
    async fn follow_lifecycle_pending_to_accepted() {
        let s = store();
        assert_eq!(
            s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
                .await
                .unwrap(),
            FollowOutcome::Created
        );
        // duplicate request: no second Follow gets enqueued
        assert_eq!(
            s.follow_request(A, TGT, TGT_INBOX, "other-id", 2000)
                .await
                .unwrap(),
            FollowOutcome::AlreadyPending
        );
        let l = s.following_list(A).await.unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].state, FollowState::Pending);
        assert_eq!(l[0].follow_activity_id, FID);

        // verified Accept flips exactly the matching pending row
        assert!(s.follow_accepted(FID, TGT, A).await.unwrap());
        assert!(
            !s.follow_accepted(FID, TGT, A).await.unwrap(),
            "duplicate Accept is a no-op"
        );
        assert_eq!(
            s.following_list(A).await.unwrap()[0].state,
            FollowState::Accepted
        );
        assert_eq!(
            s.follow_request(A, TGT, TGT_INBOX, "third-id", 3000)
                .await
                .unwrap(),
            FollowOutcome::AlreadyAccepted
        );
    }

    #[tokio::test]
    async fn stale_or_forged_accept_matches_nothing() {
        let s = store();
        assert!(!s.follow_accepted("never-minted", TGT, A).await.unwrap());
        assert!(!s.follow_rejected("never-minted", TGT).await.unwrap());
    }

    #[tokio::test]
    async fn accept_from_wrong_sender_does_not_flip() {
        // An Accept whose signature-verified sender is NOT the actor we
        // followed must be a no-op even though it carries the right
        // follow_activity_id (which is not secret — it rides the Follow we
        // delivered). This is the forgeable-Accept authorization gap.
        let s = store();
        s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
            .await
            .unwrap();
        assert!(
            !s.follow_accepted(FID, "https://evil.test/users/mallory", A)
                .await
                .unwrap(),
            "Accept signed by a non-followee must not flip our follow"
        );
        assert_eq!(
            s.following_list(A).await.unwrap()[0].state,
            FollowState::Pending,
            "row stays pending after a forged Accept"
        );
        // The genuine followee still works.
        assert!(s.follow_accepted(FID, TGT, A).await.unwrap());
    }

    #[tokio::test]
    async fn accept_for_another_recipients_follow_does_not_flip() {
        // Even the correct followee cannot flip a follow that a DIFFERENT
        // local account owns: the recipient handle must own the row.
        let s = store();
        s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
            .await
            .unwrap();
        assert!(
            !s.follow_accepted(FID, TGT, "agent-b").await.unwrap(),
            "an Accept delivered to the wrong local actor must not flip"
        );
        assert!(s.follow_accepted(FID, TGT, A).await.unwrap());
    }

    #[tokio::test]
    async fn reject_from_wrong_sender_does_not_drop() {
        let s = store();
        s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
            .await
            .unwrap();
        assert!(
            !s.follow_rejected(FID, "https://evil.test/users/mallory")
                .await
                .unwrap(),
            "Reject signed by a non-followee must not drop our follow"
        );
        assert!(!s.following_list(A).await.unwrap().is_empty());
        assert!(s.follow_rejected(FID, TGT).await.unwrap());
    }

    #[tokio::test]
    async fn reject_drops_the_pending_row() {
        let s = store();
        s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
            .await
            .unwrap();
        assert!(s.follow_rejected(FID, TGT).await.unwrap());
        assert!(s.following_list(A).await.unwrap().is_empty());
        // re-follow after a reject starts a fresh pending row
        assert_eq!(
            s.follow_request(A, TGT, TGT_INBOX, "fid-2", 2000)
                .await
                .unwrap(),
            FollowOutcome::Created
        );
    }

    #[tokio::test]
    async fn unfollow_returns_record_for_the_undo() {
        let s = store();
        s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
            .await
            .unwrap();
        s.follow_accepted(FID, TGT, A).await.unwrap();
        let rec = s.unfollow(A, TGT).await.unwrap().expect("was following");
        assert_eq!(rec.follow_activity_id, FID);
        assert_eq!(rec.target_inbox_url, TGT_INBOX);
        assert!(s.following_list(A).await.unwrap().is_empty());
        assert!(
            s.unfollow(A, TGT).await.unwrap().is_none(),
            "second unfollow is None"
        );
    }

    #[tokio::test]
    async fn follower_add_is_idempotent_and_removable() {
        let s = store();
        assert!(s.add_follower(A, TGT, TGT_INBOX, 1000).await.unwrap());
        assert!(!s.add_follower(A, TGT, TGT_INBOX, 2000).await.unwrap());
        assert_eq!(s.followers_list(A).await.unwrap(), vec![TGT.to_owned()]);
        assert!(s.remove_follower(A, TGT).await.unwrap());
        assert!(!s.remove_follower(A, TGT).await.unwrap());
        assert!(s.followers_list(A).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn follow_graphs_are_per_actor() {
        let s = store();
        s.follow_request(A, TGT, TGT_INBOX, FID, 1000)
            .await
            .unwrap();
        assert!(s.following_list("agent-b").await.unwrap().is_empty());
        s.add_follower(A, TGT, TGT_INBOX, 1000).await.unwrap();
        assert!(s.followers_list("agent-b").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn follow_request_queue_upserts_and_consumes() {
        let s = store();
        s.add_follow_request(A, TGT, TGT_INBOX, "their-follow-1", 1000)
            .await
            .unwrap();
        // A re-sent Follow refreshes the stored activity id — the Accept
        // must echo the follower's LATEST Follow.
        s.add_follow_request(A, TGT, TGT_INBOX, "their-follow-2", 2000)
            .await
            .unwrap();
        let q = s.follow_requests_list(A).await.unwrap();
        assert_eq!(q.len(), 1, "upsert, not a duplicate row");
        assert_eq!(q[0].follow_activity_id, "their-follow-2");
        assert_eq!(q[0].follower_inbox_url, TGT_INBOX);

        assert!(s.remove_follow_request(A, TGT, None).await.unwrap());
        assert!(!s.remove_follow_request(A, TGT, None).await.unwrap());
        assert!(s.follow_requests_list(A).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn follow_request_queue_evicts_oldest_beyond_cap() {
        let s = store();
        for i in 0..205u32 {
            s.add_follow_request(
                A,
                &format!("https://spam.example/users/u{i}"),
                &format!("https://spam.example/users/u{i}/inbox"),
                &format!("https://spam.example/users/u{i}#follow/1"),
                u64::from(1000 + i),
            )
            .await
            .unwrap();
        }
        let q = s.follow_requests_list(A).await.unwrap();
        assert_eq!(q.len(), 200, "queue is bounded per actor");
        assert_eq!(
            q[0].follower_actor_url, "https://spam.example/users/u204",
            "newest survives"
        );
        assert!(
            !q.iter()
                .any(|r| r.follower_actor_url == "https://spam.example/users/u0"),
            "oldest evicted"
        );
    }

    #[tokio::test]
    async fn matched_remove_spares_a_newer_resent_follow() {
        // TOCTOU contract: a confirm answering an OLDER Follow must not
        // consume a NEWER re-sent request that still needs its own Accept.
        let s = store();
        s.add_follow_request(A, TGT, TGT_INBOX, "their-follow-1", 1000)
            .await
            .unwrap();
        s.add_follow_request(A, TGT, TGT_INBOX, "their-follow-2", 2000)
            .await
            .unwrap();
        assert!(
            !s.remove_follow_request(A, TGT, Some("their-follow-1"))
                .await
                .unwrap(),
            "stale-id confirm consumes nothing"
        );
        assert_eq!(s.follow_requests_list(A).await.unwrap().len(), 1);
        assert!(s
            .remove_follow_request(A, TGT, Some("their-follow-2"))
            .await
            .unwrap());
        assert!(s.follow_requests_list(A).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn follow_request_queue_is_per_actor() {
        let s = store();
        s.add_follow_request(A, TGT, TGT_INBOX, "their-follow-1", 1000)
            .await
            .unwrap();
        assert!(s.follow_requests_list("agent-b").await.unwrap().is_empty());
        assert!(
            !s.remove_follow_request("agent-b", TGT, None).await.unwrap(),
            "another actor cannot consume the queue entry"
        );
        assert_eq!(s.follow_requests_list(A).await.unwrap().len(), 1);
    }
}
