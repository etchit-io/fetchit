//! Consumption of the signed `etchit-io` community denylist.
//!
//! The bridge is the binary that terminates real federation traffic —
//! `POST /actors/:handle/inbox` is where a remote server hands us a
//! stranger's activity — yet it verified HTTP signatures and audience
//! only. A moderated actor could keep delivering here forever.
//!
//! This module is the consumer side, wired exactly as the relay-server's
//! fediverse inbox wires it
//! (`crates/fetchit-relay-server/src/inbox/operator.rs`): reuse
//! [`fetchit_trust_client::DenylistConsumer`] as-is — hydrate its
//! on-disk cache synchronously so a cold offline boot still gates, then
//! detach its background poll loop — rather than re-implementing polling
//! or signature verification here.
//!
//! # Fail-open
//!
//! Every layer of this gate fails open by construction: no configured
//! service means no consumer, an empty (never-refreshed) index answers
//! `false`, and a failed poll leaves the previous snapshot in place. The
//! published manifest is the source of truth, and a trust-service
//! outage must never take federation down with it.

use std::sync::Arc;

use fetchit_trust_types::{DenylistQuery, EntryKind};

use crate::config::BridgeConfig;
use crate::error::BridgeError;

/// Build the denylist consumer for `config` and start its background
/// refresh, returning the query handle the inbox gate gets.
///
/// `Ok(None)` when [`BridgeConfig::denylist_url`] is `None` — the gate
/// is disabled and every signature-verified delivery is accepted.
///
/// Must be called from inside a Tokio runtime: the poll loop is spawned
/// here and detached (it holds its own `Arc` clone, so it lives for the
/// process). The on-disk cache is loaded synchronously first, so the
/// gate is already enforcing the last good snapshot by the time the
/// router is assembled.
///
/// The issuer key is the compiled-in
/// [`fetchit_trust_client::etchitio_pubkey`] — the same key every other
/// fetch>it consumer verifies against, so a manifest this bridge honours
/// is one a desktop client honours.
///
/// # Errors
/// [`BridgeError::Config`] when the production HTTP client cannot be
/// built.
pub fn install(config: &BridgeConfig) -> Result<Option<Arc<dyn DenylistQuery>>, BridgeError> {
    let Some(url) = config.denylist_url.clone() else {
        return Ok(None);
    };
    let consumer = Arc::new(fetchit_trust_client::DenylistConsumer::new(
        fetchit_trust_client::etchitio_pubkey(),
        url.clone(),
        config.denylist_cache.clone(),
    ));
    consumer.load_cache_blocking();
    let http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static> = Arc::new(
        fetchit_trust_client::ReqwestClient::new()
            .map_err(|e| BridgeError::Config(format!("denylist http client: {e}")))?,
    );
    // Detached exactly as the relay-server detaches it: the task owns an
    // Arc clone, so it outlives this call and ends with the process.
    let _poll = Arc::clone(&consumer).spawn_poll_loop(http);
    tracing::info!(denylist = %url, "inbound denylist gate active");
    let query: Arc<dyn DenylistQuery> = consumer;
    Ok(Some(query))
}

/// Is `actor_url` blocked by the wired denylist?
///
/// `None` (gate disabled) is always `false`. Otherwise the URL is
/// canonicalized with [`fetchit_trust_types::canonicalize_url_value`]
/// before the lookup, because the consumer index matches EXACT canonical
/// form: without this a moderated actor evades the gate by self-serving
/// its `id` with a trailing slash or a stray `?x` — the same evasion the
/// chat client's `check_actor_url_denylist` closes.
///
/// A URL that fails canonicalization counts as blocked. No legitimate
/// `ActivityPub` actor id carries userinfo, a query string, or a
/// fragment, and a gate against hostile senders must fail closed on
/// degenerate input rather than hand an unmatched value to an exact-match
/// index.
#[must_use]
pub fn is_blocked_actor(denylist: Option<&Arc<dyn DenylistQuery>>, actor_url: &str) -> bool {
    let Some(denylist) = denylist else {
        return false;
    };
    let Ok(canonical) = fetchit_trust_types::canonicalize_url_value(actor_url) else {
        tracing::warn!(
            actor = actor_url,
            "inbox: degenerate actor id, failing closed"
        );
        return true;
    };
    denylist.is_blocked(EntryKind::ActorUrl, &canonical)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct BlocksActors(Vec<String>);
    impl DenylistQuery for BlocksActors {
        fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
            matches!(kind, EntryKind::ActorUrl) && self.0.iter().any(|v| v == value)
        }
    }

    fn stub(blocked: &[&str]) -> Arc<dyn DenylistQuery> {
        Arc::new(BlocksActors(
            blocked.iter().map(|s| (*s).to_owned()).collect(),
        ))
    }

    #[test]
    fn no_denylist_configured_blocks_nothing() {
        assert!(!is_blocked_actor(
            None,
            "https://attacker.example/users/eve"
        ));
    }

    #[test]
    fn a_listed_actor_is_blocked() {
        let d = stub(&["https://attacker.example/users/eve"]);
        assert!(is_blocked_actor(
            Some(&d),
            "https://attacker.example/users/eve"
        ));
        assert!(!is_blocked_actor(
            Some(&d),
            "https://mastodon.example/users/alice"
        ));
    }

    #[test]
    fn trailing_slash_and_case_variants_cannot_evade() {
        let d = stub(&["https://attacker.example/users/eve"]);
        assert!(
            is_blocked_actor(Some(&d), "https://attacker.example/users/eve/"),
            "a trailing slash must not bypass the gate",
        );
    }

    #[test]
    fn degenerate_actor_ids_fail_closed() {
        let d = stub(&["https://attacker.example/users/eve"]);
        for degenerate in [
            "https://attacker.example/users/eve?x=1",
            "https://attacker.example/users/eve#main-key",
            "https://user@attacker.example/users/eve",
        ] {
            assert!(
                is_blocked_actor(Some(&d), degenerate),
                "{degenerate} must fail closed",
            );
        }
    }

    #[test]
    fn only_the_actor_url_kind_is_consulted() {
        // A relay-URL or agent-id entry must not bleed through as an
        // actor block — same security property the chat adapter pins.
        struct BlocksEverythingElse;
        impl DenylistQuery for BlocksEverythingElse {
            fn is_blocked(&self, kind: EntryKind, _value: &str) -> bool {
                !matches!(kind, EntryKind::ActorUrl)
            }
        }
        let d: Arc<dyn DenylistQuery> = Arc::new(BlocksEverythingElse);
        assert!(!is_blocked_actor(
            Some(&d),
            "https://mastodon.example/users/alice"
        ));
    }

    #[test]
    fn install_returns_none_when_the_gate_is_disabled() {
        let config = BridgeConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            domain: "etchit.io".into(),
            db_path: "unused".into(),
            server_version: "test".into(),
            reserved_handles: BridgeConfig::default_reserved_handles(),
            register_burst: 0,
            register_per_min: 0,
            trusted_proxy_hops: 0,
            denylist_url: None,
            denylist_cache: None,
        };
        // No runtime needed: the disabled path never spawns a poll loop.
        assert!(install(&config).unwrap().is_none());
    }
}
