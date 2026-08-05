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
    inbox_signature_rejected: AtomicU64,
    inbox_forwarded_ignored: AtomicU64,
    inbox_actor_resolution_failed: AtomicU64,
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
            inbox_signature_rejected: AtomicU64::new(0),
            inbox_forwarded_ignored: AtomicU64::new(0),
            inbox_actor_resolution_failed: AtomicU64::new(0),
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

    /// Increment the inbound-signature-rejection counter (a 401 off the
    /// fediverse inbox).
    pub fn inc_inbox_signature_rejected(&self) {
        self.inbox_signature_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the forwarded-activity counter: authenticated
    /// delivery, but the signer is not the activity's author, so the
    /// object was dropped unread.
    ///
    /// Deliberately its own counter rather than a rejection: conflating
    /// the two is what hid the 2026-08 forwarding bug for weeks. After
    /// that fix `inbox_signature_rejected` should collapse toward zero
    /// while this one carries the volume.
    pub fn inc_inbox_forwarded_ignored(&self) {
        self.inbox_forwarded_ignored.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the same-host-actor-unresolvable counter: a delivery
    /// whose signer and claimed actor share a host, where the claimed
    /// actor could not be fetched to settle whether they are one
    /// account. Such a delivery is treated as forwarded.
    pub fn inc_inbox_actor_resolution_failed(&self) {
        self.inbox_actor_resolution_failed
            .fetch_add(1, Ordering::Relaxed);
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
                "fetchit_bridge_inbox_signature_rejected_total",
                "Inbound deliveries refused by the HTTP-Signature gate",
                self.inbox_signature_rejected.load(Ordering::Relaxed),
            ),
            (
                "fetchit_bridge_inbox_forwarded_ignored_total",
                "Authenticated deliveries whose signer is not the activity author",
                self.inbox_forwarded_ignored.load(Ordering::Relaxed),
            ),
            (
                "fetchit_bridge_inbox_actor_resolution_failed_total",
                "Same-host claimed actors that could not be resolved",
                self.inbox_actor_resolution_failed.load(Ordering::Relaxed),
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        }
        out
    }
}
