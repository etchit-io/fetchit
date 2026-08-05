//! Prometheus metrics for the bridge.
//!
//! Label cardinality is deliberately tiny — only a static `version`
//! label, never per-actor or per-request identifiers.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Process-wide bridge counters.
#[derive(Debug)]
pub struct BridgeMetrics {
    started_at: Instant,
    version: String,
    actors_registered: AtomicU64,
    webfinger_requests: AtomicU64,
    actor_doc_requests: AtomicU64,
    inbox_denylisted: AtomicU64,
}

impl BridgeMetrics {
    /// Create a fresh metrics set tagged with `version`.
    #[must_use]
    pub fn new(version: String) -> Self {
        Self {
            started_at: Instant::now(),
            version,
            actors_registered: AtomicU64::new(0),
            webfinger_requests: AtomicU64::new(0),
            actor_doc_requests: AtomicU64::new(0),
            inbox_denylisted: AtomicU64::new(0),
        }
    }

    /// Increment the registered-actor counter.
    pub fn inc_actors_registered(&self) {
        self.actors_registered.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the WebFinger-request counter.
    pub fn inc_webfinger(&self) {
        self.webfinger_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the actor-document-request counter.
    pub fn inc_actor_doc(&self) {
        self.actor_doc_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the denylisted-inbound-delivery counter — one per
    /// activity dropped by the community denylist gate. Deliberately
    /// unlabelled: the actor URL goes to the log line, never to a
    /// Prometheus label, so a hostile sender cannot inflate metric
    /// cardinality.
    pub fn inc_inbox_denylisted(&self) {
        self.inbox_denylisted.fetch_add(1, Ordering::Relaxed);
    }

    /// Current denylisted-delivery count, for tests + ops assertions.
    #[must_use]
    pub fn inbox_denylisted_count(&self) -> u64 {
        self.inbox_denylisted.load(Ordering::Relaxed)
    }

    /// Render all counters in Prometheus text-exposition format.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let labels = format!(r#"version="{}""#, self.version);
        let mut out = String::new();
        let uptime = self.started_at.elapsed().as_secs();
        let _ = writeln!(
            out,
            "# HELP fetchit_bridge_uptime_seconds Seconds since process start"
        );
        let _ = writeln!(out, "# TYPE fetchit_bridge_uptime_seconds gauge");
        let _ = writeln!(out, "fetchit_bridge_uptime_seconds{{{labels}}} {uptime}");
        for (name, help, value) in [
            (
                "fetchit_bridge_actors_registered_total",
                "Actor registrations accepted",
                self.actors_registered.load(Ordering::Relaxed),
            ),
            (
                "fetchit_bridge_webfinger_requests_total",
                "WebFinger lookups served",
                self.webfinger_requests.load(Ordering::Relaxed),
            ),
            (
                "fetchit_bridge_actor_doc_requests_total",
                "Actor-document GETs served",
                self.actor_doc_requests.load(Ordering::Relaxed),
            ),
            (
                "fetchit_bridge_inbox_denylisted_total",
                "Inbound activities dropped by the community denylist",
                self.inbox_denylisted.load(Ordering::Relaxed),
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        }
        out
    }
}
