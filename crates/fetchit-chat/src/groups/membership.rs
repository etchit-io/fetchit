//! Joiner-side x0xd membership-convergence polling.
//!
//! `POST /groups/join` returns OK before x0xd's local state slice
//! (the one `/secure/decrypt` reads against) has applied
//! `MemberAdded`. Owner-gossiped messages arriving inside that window
//! 403 with "not a member". Empirically observed on x0xd v0.21.3
//! across degraded NATs (~20s convergence window).
//!
//! [`wait_for_active_membership`] polls `GET /groups/<id>/members`
//! until the joiner appears in the active-filtered roster, then
//! returns. The closure-shaped fetcher keeps the poll loop unit-
//! testable without a live HTTP server.

use std::time::Duration;

use crate::error::{ChatError, Result};
use crate::identity::AgentId;

use super::GroupId;

/// Default wall-clock the joiner gets to converge before
/// [`wait_for_active_membership`] surfaces
/// [`ChatError::JoinerNotConverged`]. Sized to cover the
/// gossip-into-joiner saturation window observed on cross-NAT pairs.
pub const MEMBERSHIP_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default interval between `/groups/<id>/members` polls. Tight enough
/// that convergence is observable within a second of x0xd applying
/// `MemberAdded`, slow enough that the poll itself doesn't add
/// noticeable load.
pub const MEMBERSHIP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Resolve the joiner-side convergence wait, honouring the
/// `FETCHIT_MEMBERSHIP_WAIT_SECS` environment override and falling back
/// to [`MEMBERSHIP_WAIT_TIMEOUT`].
///
/// The override is an operations escape hatch for cross-NAT soak rigs
/// where the owner's `MemberAdded` gossip can take longer than the 60s
/// production default to saturate into the joiner's daemon. Production
/// leaves the variable unset, keeping the 60s ceiling so a genuinely
/// stuck join still fails fast.
#[must_use]
pub fn membership_wait_timeout() -> Duration {
    resolve_membership_wait(std::env::var("FETCHIT_MEMBERSHIP_WAIT_SECS").ok())
}

/// Pure core of [`membership_wait_timeout`]: parse an optional raw
/// seconds string, falling back to [`MEMBERSHIP_WAIT_TIMEOUT`] on absent
/// or unparseable input. Split out so the fallback is unit-testable
/// without mutating process environment.
fn resolve_membership_wait(raw: Option<String>) -> Duration {
    raw.and_then(|r| r.parse::<u64>().ok())
        .map_or(MEMBERSHIP_WAIT_TIMEOUT, Duration::from_secs)
}

/// Default native-first convergence window before
/// [`crate::Client::join_group_auto`] falls back to the engine-A relay
/// bridge. Deliberately shorter than [`MEMBERSHIP_WAIT_TIMEOUT`]: when the
/// warm-gossip path can reach the owner it converges in seconds, so a
/// shorter ceiling fails the cold/dual-NAT corner over to the bridge
/// promptly instead of blocking the full 60s on a mesh that will never
/// form for that pair.
pub const NATIVE_FIRST_WAIT: Duration = Duration::from_secs(15);

/// Resolve the native-first convergence wait, honouring the
/// `FETCHIT_NATIVE_FIRST_WAIT_SECS` environment override and falling back
/// to [`NATIVE_FIRST_WAIT`]. The override lets soak rigs widen or tighten
/// the warm-path window before the bridge fallback engages.
#[must_use]
pub fn native_first_wait() -> Duration {
    resolve_native_first_wait(std::env::var("FETCHIT_NATIVE_FIRST_WAIT_SECS").ok())
}

/// Pure core of [`native_first_wait`]: parse an optional raw seconds
/// string, falling back to [`NATIVE_FIRST_WAIT`] on absent or unparseable
/// input. Split out so the fallback is unit-testable without mutating
/// process environment.
fn resolve_native_first_wait(raw: Option<String>) -> Duration {
    raw.and_then(|r| r.parse::<u64>().ok())
        .map_or(NATIVE_FIRST_WAIT, Duration::from_secs)
}

/// Poll `members_fetcher` on `poll_interval` until `self_id` appears
/// in the returned roster, or `timeout` elapses.
///
/// Production callers use this via [`super::Endpoint::join`] so a
/// successful return guarantees a subsequent `/secure/decrypt` against
/// the same group won't 403 "not a member" for race reasons.
///
/// # Errors
/// - [`ChatError::JoinerNotConverged`] when the deadline is reached
///   and the fetcher succeeded but `self_id` never appeared.
/// - The last fetcher error, propagated verbatim, when every poll up
///   to the deadline errored.
pub async fn wait_for_active_membership<F, Fut>(
    group_id: &GroupId,
    self_id: &AgentId,
    timeout: Duration,
    poll_interval: Duration,
    mut members_fetcher: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<AgentId>>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let result = members_fetcher().await;
        if let Ok(members) = &result {
            if members.iter().any(|m| m == self_id) {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return match result {
                Ok(_) => Err(ChatError::JoinerNotConverged {
                    group_id: group_id.as_str().to_owned(),
                    waited_ms: timeout.as_millis(),
                }),
                Err(e) => Err(e),
            };
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn gid() -> GroupId {
        GroupId::parse("g-test").unwrap()
    }

    fn aid(prefix: char) -> AgentId {
        AgentId::parse(prefix.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn resolve_membership_wait_defaults_when_unset_or_unparseable() {
        assert_eq!(resolve_membership_wait(None), MEMBERSHIP_WAIT_TIMEOUT);
        assert_eq!(
            resolve_membership_wait(Some("not-a-number".to_owned())),
            MEMBERSHIP_WAIT_TIMEOUT
        );
    }

    #[test]
    fn resolve_membership_wait_honours_a_valid_override() {
        assert_eq!(
            resolve_membership_wait(Some("300".to_owned())),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn resolve_native_first_wait_defaults_and_honours_override() {
        assert_eq!(resolve_native_first_wait(None), NATIVE_FIRST_WAIT);
        assert_eq!(
            resolve_native_first_wait(Some("garbage".to_owned())),
            NATIVE_FIRST_WAIT
        );
        assert_eq!(
            resolve_native_first_wait(Some("5".to_owned())),
            Duration::from_secs(5)
        );
        // The native-first window must stay below the full membership
        // ceiling, else the bridge fallback never gets a chance to run.
        assert!(NATIVE_FIRST_WAIT < MEMBERSHIP_WAIT_TIMEOUT);
    }

    #[tokio::test]
    async fn returns_immediately_when_self_already_active() {
        let self_id = aid('a');
        let group_id = gid();
        let result = wait_for_active_membership(
            &group_id,
            &self_id,
            Duration::from_millis(500),
            Duration::from_millis(10),
            || async { Ok(vec![aid('a'), aid('b')]) },
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn converges_after_a_few_misses() {
        let self_id = aid('a');
        let group_id = gid();
        let polls = Mutex::new(0u32);
        let result = wait_for_active_membership(
            &group_id,
            &self_id,
            Duration::from_millis(500),
            Duration::from_millis(10),
            || {
                let n = {
                    let mut g = polls.lock().unwrap();
                    *g = g.saturating_add(1);
                    *g
                };
                async move {
                    if n < 3 {
                        Ok(vec![aid('b')])
                    } else {
                        Ok(vec![aid('a'), aid('b')])
                    }
                }
            },
        )
        .await;
        assert!(result.is_ok());
        assert!(*polls.lock().unwrap() >= 3);
    }

    #[tokio::test]
    async fn bails_with_joiner_not_converged_on_timeout_with_successful_polls() {
        let self_id = aid('a');
        let group_id = gid();
        let err = wait_for_active_membership(
            &group_id,
            &self_id,
            Duration::from_millis(60),
            Duration::from_millis(10),
            || async { Ok(vec![aid('b')]) },
        )
        .await
        .unwrap_err();
        match err {
            ChatError::JoinerNotConverged {
                group_id: g,
                waited_ms,
            } => {
                assert_eq!(g, "g-test");
                assert_eq!(waited_ms, 60);
            }
            other => panic!("expected JoinerNotConverged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn retries_through_transient_errors_then_succeeds() {
        let self_id = aid('a');
        let group_id = gid();
        let polls = Mutex::new(0u32);
        let result = wait_for_active_membership(
            &group_id,
            &self_id,
            Duration::from_millis(500),
            Duration::from_millis(10),
            || {
                let n = {
                    let mut g = polls.lock().unwrap();
                    *g = g.saturating_add(1);
                    *g
                };
                async move {
                    if n < 3 {
                        Err(ChatError::Invalid("transient".to_owned()))
                    } else {
                        Ok(vec![aid('a')])
                    }
                }
            },
        )
        .await;
        assert!(result.is_ok());
        assert!(*polls.lock().unwrap() >= 3);
    }

    #[tokio::test]
    async fn surfaces_last_error_when_polls_only_error() {
        let self_id = aid('a');
        let group_id = gid();
        let err = wait_for_active_membership(
            &group_id,
            &self_id,
            Duration::from_millis(60),
            Duration::from_millis(10),
            || async { Err(ChatError::Invalid("daemon down".to_owned())) },
        )
        .await
        .unwrap_err();
        match err {
            ChatError::Invalid(msg) => assert!(msg.contains("daemon down")),
            other => panic!("expected Invalid('daemon down'), got {other:?}"),
        }
    }
}
