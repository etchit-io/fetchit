//! Per-`group_id` singleflight around the x0xd `/members` fetch on
//! the inbound bootstrap path.
//!
//! Context: `messages::Endpoint::receive_private_group_envelope` runs
//! a `verify_group_membership` check before
//! `mutate_in_place_or_init` lazy-bootstraps a fresh
//! `Conversation`. The membership probe lives OUTSIDE the per-group
//! mutex (the registry's `mutate_in_place_or_init` only takes the
//! mutex AFTER the check returns), so N concurrent inbound envelopes
//! for the same brand-new `group_id_hex` each fire their own
//! `/members` request against x0xd before any of them reach the
//! mutex. The wasted x0xd traffic is bounded (membership check only
//! runs on first-receive per group) but on a 5-member group joining
//! at the same epoch, that's still 4x extra HTTP round-trips for
//! zero correctness benefit.
//!
//! This module collapses concurrent membership probes for the same
//! `group_id_hex` into one upstream `/members` call. The leader runs
//! the fetch and gets its typed result back unchanged; waiters
//! receive an `Arc<Vec<AgentId>>` clone of the leader's roster, or a
//! stringified error mapped to [`ChatError::MessageTransport`] when
//! the leader's fetch failed. Sequential callers (one finishing
//! before the next starts) each fire their own fetch; the entry is
//! removed from the in-flight map as soon as the leader's result is
//! published. There is no TTL caching here, by design: stale
//! membership reads are worse than a fresh round-trip, and the
//! anti-DoS gate only runs once per group per process anyway.

use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex as AsyncMutex, Notify};

/// Cheap-cloneable result shape stored in [`Inflight::result`].
/// `Ok` carries an `Arc<Vec<AgentId>>` so waiters share the same
/// allocation; `Err` carries the leader's error message (variant
/// info collapsed to a string so the shared result is `Clone`).
type SharedRoster = std::result::Result<Arc<Vec<AgentId>>, String>;

/// In-flight membership probe shared between the leader and any
/// concurrent waiters.
#[derive(Clone)]
struct Inflight {
    /// Notified by the leader when [`Self::result`] has been
    /// populated. Uses `notify_waiters` so every concurrent waiter
    /// wakes on a single notify call.
    completion: Arc<Notify>,
    /// Final shared result. `None` while the leader is still
    /// fetching; `Some(_)` once published. Waiters surface the leader's
    /// stringified error as [`ChatError::MessageTransport`].
    result: Arc<std::sync::Mutex<Option<SharedRoster>>>,
}

/// Per-`group_id_hex` in-flight `/members` deduplicator. Shared
/// across `messages::Endpoint` instances via [`crate::ChatState`].
#[derive(Default)]
pub(crate) struct MembersSingleflight {
    inflight: AsyncMutex<HashMap<String, Inflight>>,
}

impl MembersSingleflight {
    /// Build a fresh empty deduplicator.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Run `fetch` exactly once per concurrent set of callers sharing
    /// the same `key`. The first caller to arrive on an empty key
    /// becomes the leader: it runs `fetch` and gets its result back
    /// verbatim. Concurrent callers wait on the leader's completion
    /// notify and receive a clone of the leader's roster (or
    /// [`ChatError::MessageTransport`] mapped from the leader's
    /// stringified error). Sequential callers (after the leader's
    /// entry is removed) each fire their own fetch.
    pub(crate) async fn fetch_or_wait<F, Fut>(&self, key: &str, fetch: F) -> Result<Vec<AgentId>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<AgentId>>>,
    {
        // Phase 1: claim leadership or pick up an existing in-flight
        // probe. The async mutex is held only across the HashMap
        // insertion / lookup, never across `await fetch()` (which
        // would serialize unrelated keys).
        let leader_slot = {
            let mut inflight = self.inflight.lock().await;
            if let Some(existing) = inflight.get(key) {
                let existing = existing.clone();
                drop(inflight);
                return wait_for_leader(existing).await;
            }
            let slot = Inflight {
                completion: Arc::new(Notify::new()),
                result: Arc::new(std::sync::Mutex::new(None)),
            };
            inflight.insert(key.to_owned(), slot.clone());
            slot
        };

        // Phase 2: run the fetch as the leader. Capture the result
        // for waiters BEFORE notifying, then return the typed result
        // to our own caller. Errors are stringified for sharing; the
        // leader's caller still sees the original ChatError.
        let result = fetch().await;
        publish_result(&leader_slot, &result);
        leader_slot.completion.notify_waiters();

        // Phase 3: remove the entry so the next round of concurrent
        // callers starts fresh against a real upstream fetch. The
        // shared result lives on through the `Arc`s held by waiters.
        let mut inflight = self.inflight.lock().await;
        inflight.remove(key);
        drop(inflight);

        result
    }
}

async fn wait_for_leader(existing: Inflight) -> Result<Vec<AgentId>> {
    existing.completion.notified().await;
    let Some(shared) = read_published(&existing) else {
        return Err(ChatError::MessageTransport(
            "singleflight leader dropped without setting a result".into(),
        ));
    };
    match shared {
        Ok(roster) => Ok((*roster).clone()),
        Err(msg) => Err(ChatError::MessageTransport(format!(
            "/members (singleflight): {msg}"
        ))),
    }
}

fn publish_result(slot: &Inflight, result: &Result<Vec<AgentId>>) {
    let shared = match result {
        Ok(v) => Ok(Arc::new(v.clone())),
        Err(e) => Err(e.to_string()),
    };
    let mut guard = slot
        .result
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(shared);
}

fn read_published(slot: &Inflight) -> Option<std::result::Result<Arc<Vec<AgentId>>, String>> {
    slot.result
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn aid(byte: u8) -> AgentId {
        AgentId::parse(hex::encode([byte; 32])).unwrap()
    }

    #[tokio::test]
    async fn single_caller_passes_through() {
        let sf = MembersSingleflight::new();
        let roster = sf
            .fetch_or_wait("gid-1", || async { Ok(vec![aid(0xaa), aid(0xbb)]) })
            .await
            .unwrap();
        assert_eq!(roster, vec![aid(0xaa), aid(0xbb)]);
    }

    #[tokio::test]
    async fn single_caller_propagates_error() {
        let sf = MembersSingleflight::new();
        let err = sf
            .fetch_or_wait("gid-1", || async {
                Err::<Vec<AgentId>, _>(ChatError::Invalid("boom".into()))
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ChatError::Invalid(ref m) if m == "boom"));
    }

    #[tokio::test]
    async fn concurrent_callers_same_key_collapse_to_one_fetch() {
        let sf = Arc::new(MembersSingleflight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());

        let mut handles = Vec::new();
        for _ in 0..8 {
            let sf = sf.clone();
            let calls = calls.clone();
            let release = release.clone();
            handles.push(tokio::spawn(async move {
                sf.fetch_or_wait("gid-1", || {
                    let calls = calls.clone();
                    let release = release.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        release.notified().await;
                        Ok(vec![aid(0xcc)])
                    }
                })
                .await
            }));
        }

        // Give the spawned tasks a chance to enter `fetch_or_wait`
        // and claim/wait on the leader slot before we release the
        // single in-flight fetch.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        release.notify_waiters();

        let results: Vec<_> = futures_util::future::join_all(handles).await;
        for result in results {
            let roster = result.unwrap().unwrap();
            assert_eq!(roster, vec![aid(0xcc)]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_callers_different_keys_run_independently() {
        let sf = Arc::new(MembersSingleflight::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for i in 0u8..4 {
            let sf = sf.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("gid-{i}");
                sf.fetch_or_wait(&key, || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(vec![aid(i)])
                    }
                })
                .await
            }));
        }
        for result in futures_util::future::join_all(handles).await {
            result.unwrap().unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn sequential_callers_each_run_their_own_fetch() {
        let sf = MembersSingleflight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let calls = calls.clone();
            sf.fetch_or_wait("gid-1", || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![aid(0xdd)])
            })
            .await
            .unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn waiters_receive_mapped_error_when_leader_fails() {
        let sf = Arc::new(MembersSingleflight::new());
        let release = Arc::new(Notify::new());

        let leader = {
            let sf = sf.clone();
            let release = release.clone();
            tokio::spawn(async move {
                sf.fetch_or_wait("gid-1", || async move {
                    release.notified().await;
                    Err::<Vec<AgentId>, _>(ChatError::Invalid("upstream 4xx".into()))
                })
                .await
            })
        };

        // Let the leader claim the slot.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let waiter = {
            let sf = sf.clone();
            tokio::spawn(async move {
                sf.fetch_or_wait("gid-1", || async {
                    unreachable!("waiter should not run its own fetch")
                })
                .await
            })
        };

        // Release the leader's fetch.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        release.notify_waiters();

        let leader_err = leader.await.unwrap().unwrap_err();
        let waiter_err = waiter.await.unwrap().unwrap_err();

        assert!(
            matches!(leader_err, ChatError::Invalid(ref m) if m == "upstream 4xx"),
            "leader: {leader_err:?}"
        );
        match waiter_err {
            ChatError::MessageTransport(msg) => {
                assert!(msg.contains("singleflight"), "msg: {msg}");
                assert!(msg.contains("upstream 4xx"), "msg: {msg}");
            }
            other => panic!("waiter: expected MessageTransport, got {other:?}"),
        }
    }
}
