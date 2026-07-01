//! Allow-listed Prometheus metric surface.
//!
//! The complete metric set is documented in `private/metrics-policy.md`.
//! Every counter exposed here has a typed setter or incrementer — there
//! is no generic "label-set increment" API on purpose, so a developer
//! adding a forbidden dimension has to add a method and surface it in
//! code review.
//!
//! No metric label or value here may carry an agent id, tenant id,
//! group id, machine id, IP, country, ASN, or user agent.

use fetchit_relay_proto::Region;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Allow-listed aggregate counters for one relay process.
pub struct Metrics {
    /// Currently-connected agent count.
    connections_active: AtomicI64,
    /// Envelopes currently buffered across all recipients.
    transit_buffer_envelopes: AtomicI64,
    /// Send frames accepted into routing.
    envelopes_sent_total: AtomicU64,
    /// Deliver frames pushed to a connected recipient.
    envelopes_delivered_total: AtomicU64,
    /// Envelopes that went into transit because recipient was offline.
    envelopes_buffered_total: AtomicU64,
    /// Deposits answered with `Moved` because the recipient migrated
    /// away (no live session + live forwarding record) — the T7b
    /// departed signal. A rising rate is users changing home relays.
    envelopes_moved_total: AtomicU64,
    /// Envelopes the sweeper evicted past TTL without delivering — a
    /// proxy for "recipient never came back to THIS relay". A rising
    /// counter is the operator-visible signal that peers are routing
    /// to relays where their recipients don't live (the cross-relay
    /// federation gap). Per private/metrics-policy.md: no per-agent
    /// label — only the aggregate count.
    envelopes_dropped_ttl_total: AtomicU64,
    /// `/v1/auth/challenge` calls.
    auth_challenges_issued_total: AtomicU64,
    /// Successful `/v1/auth/verify`.
    auth_verify_ok_total: AtomicU64,
    /// Rejected `/v1/auth/verify`.
    auth_verify_failed_total: AtomicU64,
    /// Throttle for full recipient queue.
    throttles_per_recipient_total: AtomicU64,
    /// Throttle for sender rate cap.
    throttles_per_sender_total: AtomicU64,
    /// Throttle for over-size envelope.
    throttles_envelope_too_large_total: AtomicU64,
    /// Send-frame envelopes accepted at the wire-version gate with
    /// `envelope.version == 2` (pre-M2 sealed shape). This is the
    /// operator's burn-down signal for narrowing the gate to v3-only:
    /// when it stays at zero for a stable window, the transition
    /// window is safe to close. Per private/metrics-policy.md: no
    /// per-agent label — only the aggregate count.
    envelopes_accepted_legacy_v2_total: AtomicU64,
    /// Send-frame envelopes dropped at the wire-version gate because
    /// `envelope.version` was outside the accepted set (today: {2, 3}).
    /// A rising counter is the operator-visible signal that an old
    /// client (v1) or a future-version (v4+) is hitting the relay
    /// before its widening cutover has shipped. Per
    /// private/metrics-policy.md: aggregate count only.
    envelopes_dropped_version_gate_total: AtomicU64,
    /// Process start instant.
    started_at: Instant,
    /// Region this instance serves.
    region: Region,
    /// Build identifier reported in scrapes.
    version: String,
}

impl Metrics {
    /// Construct a fresh counter set bound to a region + version.
    #[must_use]
    pub fn new(region: Region, version: String) -> Self {
        Self {
            connections_active: AtomicI64::new(0),
            transit_buffer_envelopes: AtomicI64::new(0),
            envelopes_sent_total: AtomicU64::new(0),
            envelopes_delivered_total: AtomicU64::new(0),
            envelopes_buffered_total: AtomicU64::new(0),
            envelopes_moved_total: AtomicU64::new(0),
            envelopes_dropped_ttl_total: AtomicU64::new(0),
            auth_challenges_issued_total: AtomicU64::new(0),
            auth_verify_ok_total: AtomicU64::new(0),
            auth_verify_failed_total: AtomicU64::new(0),
            throttles_per_recipient_total: AtomicU64::new(0),
            throttles_per_sender_total: AtomicU64::new(0),
            throttles_envelope_too_large_total: AtomicU64::new(0),
            envelopes_accepted_legacy_v2_total: AtomicU64::new(0),
            envelopes_dropped_version_gate_total: AtomicU64::new(0),
            started_at: Instant::now(),
            region,
            version,
        }
    }

    /// Bump the active-connection count by one.
    pub fn connection_opened(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active-connection count by one.
    pub fn connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Update the transit-buffer gauge to a freshly-sampled value.
    pub fn set_transit_buffer_envelopes(&self, current: i64) {
        self.transit_buffer_envelopes
            .store(current, Ordering::Relaxed);
    }

    /// Bump the routed-envelopes counter.
    pub fn envelope_sent(&self) {
        self.envelopes_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the delivered-envelopes counter.
    pub fn envelope_delivered(&self) {
        self.envelopes_delivered_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the buffered-envelopes counter.
    pub fn envelope_buffered(&self) {
        self.envelopes_buffered_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the moved-deposits counter (T7b departed-recipient signal).
    pub fn envelope_moved(&self) {
        self.envelopes_moved_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the dropped-by-TTL counter by `count`. Called from the
    /// sweeper after `sweep_expired` evicts buffered envelopes that
    /// were never delivered.
    pub fn envelopes_dropped_ttl(&self, count: u64) {
        if count > 0 {
            self.envelopes_dropped_ttl_total
                .fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Bump the auth-challenge counter.
    pub fn auth_challenge_issued(&self) {
        self.auth_challenges_issued_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the auth-verify-ok counter.
    pub fn auth_verify_ok(&self) {
        self.auth_verify_ok_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the auth-verify-failed counter.
    pub fn auth_verify_failed(&self) {
        self.auth_verify_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the per-recipient-throttle counter.
    pub fn throttle_per_recipient(&self) {
        self.throttles_per_recipient_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the per-sender-throttle counter.
    pub fn throttle_per_sender(&self) {
        self.throttles_per_sender_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the envelope-too-large-throttle counter.
    pub fn throttle_envelope_too_large(&self) {
        self.throttles_envelope_too_large_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the legacy-v2 acceptance counter — called from the wire-
    /// version gate when an inbound send-frame envelope carries
    /// `version == 2`. The aggregate is the burn-down signal for the
    /// M2 transition: when it stays at zero across all live peers
    /// for a stable window, the relay's accepted-version set can be
    /// narrowed to v3-only.
    pub fn envelope_accepted_legacy_v2(&self) {
        self.envelopes_accepted_legacy_v2_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the version-gate drop counter — called when an inbound
    /// send-frame envelope's `version` falls outside the accepted
    /// set. A rising counter means either old clients have re-emerged
    /// (v1) or a future-version cutover started shipping early (v4+).
    pub fn envelope_dropped_version_gate(&self) {
        self.envelopes_dropped_version_gate_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Render every counter in Prometheus text-exposition format.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let labels = format!(
            r#"region="{}",version="{}""#,
            self.region.tag(),
            self.version
        );
        let mut out = String::new();
        let uptime = self.started_at.elapsed().as_secs();

        let _ = writeln!(
            out,
            "# HELP fetchit_relay_uptime_seconds Seconds since process start"
        );
        let _ = writeln!(out, "# TYPE fetchit_relay_uptime_seconds gauge");
        let _ = writeln!(out, "fetchit_relay_uptime_seconds{{{labels}}} {uptime}");

        let _ = writeln!(
            out,
            "# HELP fetchit_relay_connections_active Currently-connected agent count"
        );
        let _ = writeln!(out, "# TYPE fetchit_relay_connections_active gauge");
        let _ = writeln!(
            out,
            "fetchit_relay_connections_active{{{labels}}} {}",
            self.connections_active.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP fetchit_relay_transit_buffer_envelopes Envelopes currently in transit buffer"
        );
        let _ = writeln!(out, "# TYPE fetchit_relay_transit_buffer_envelopes gauge");
        let _ = writeln!(
            out,
            "fetchit_relay_transit_buffer_envelopes{{{labels}}} {}",
            self.transit_buffer_envelopes.load(Ordering::Relaxed)
        );

        for (name, help, value) in self.counter_snapshot() {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        }

        out
    }

    /// Snapshot every allow-listed counter into a name/help/value
    /// table. Split out of [`Self::render_prometheus`] so adding a
    /// counter doesn't push the render function over the workspace
    /// clippy too-many-lines budget.
    fn counter_snapshot(&self) -> [(&'static str, &'static str, u64); 13] {
        [
            (
                "fetchit_relay_envelopes_sent_total",
                "Send frames accepted into routing",
                self.envelopes_sent_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_envelopes_delivered_total",
                "Deliver frames pushed to a connected recipient",
                self.envelopes_delivered_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_envelopes_buffered_total",
                "Envelopes routed into the transit buffer (offline recipient)",
                self.envelopes_buffered_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_envelopes_moved_total",
                "Deposits answered with Moved (recipient migrated, live forwarding record)",
                self.envelopes_moved_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_envelopes_dropped_ttl_total",
                "Envelopes evicted by the sweeper without delivery — \
                 a proxy for recipients that never came back to this relay",
                self.envelopes_dropped_ttl_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_auth_challenges_issued_total",
                "/v1/auth/challenge calls",
                self.auth_challenges_issued_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_auth_verify_ok_total",
                "Successful /v1/auth/verify",
                self.auth_verify_ok_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_auth_verify_failed_total",
                "Rejected /v1/auth/verify",
                self.auth_verify_failed_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_throttles_per_recipient_total",
                "Throttles emitted because recipient queue was full",
                self.throttles_per_recipient_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_throttles_per_sender_total",
                "Throttles emitted because sender hit rate limit",
                self.throttles_per_sender_total.load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_throttles_envelope_too_large_total",
                "Throttles emitted because envelope exceeded size cap",
                self.throttles_envelope_too_large_total
                    .load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_envelopes_accepted_legacy_v2_total",
                "Send-frame envelopes accepted at the wire-version gate \
                 with version=2 — the M2 transition burn-down signal",
                self.envelopes_accepted_legacy_v2_total
                    .load(Ordering::Relaxed),
            ),
            (
                "fetchit_relay_envelopes_dropped_version_gate_total",
                "Send-frame envelopes dropped because envelope.version \
                 fell outside the accepted set",
                self.envelopes_dropped_version_gate_total
                    .load(Ordering::Relaxed),
            ),
        ]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_every_allow_listed_series() {
        let m = Metrics::new(Region::Nyc, "fetchit-relay/0.0.1-test".to_owned());
        m.connection_opened();
        m.envelope_sent();
        m.envelope_delivered();
        m.throttle_per_sender();

        let out = m.render_prometheus();
        for series in [
            "fetchit_relay_uptime_seconds",
            "fetchit_relay_connections_active",
            "fetchit_relay_transit_buffer_envelopes",
            "fetchit_relay_envelopes_sent_total",
            "fetchit_relay_envelopes_delivered_total",
            "fetchit_relay_envelopes_buffered_total",
            "fetchit_relay_envelopes_dropped_ttl_total",
            "fetchit_relay_auth_challenges_issued_total",
            "fetchit_relay_auth_verify_ok_total",
            "fetchit_relay_auth_verify_failed_total",
            "fetchit_relay_throttles_per_recipient_total",
            "fetchit_relay_throttles_per_sender_total",
            "fetchit_relay_throttles_envelope_too_large_total",
            "fetchit_relay_envelopes_accepted_legacy_v2_total",
            "fetchit_relay_envelopes_dropped_version_gate_total",
        ] {
            assert!(out.contains(series), "missing: {series}");
        }
    }

    #[test]
    fn legacy_v2_acceptance_counter_increments_independently() {
        // The burn-down counter must increment ONLY when called and
        // must render at the exact bump count. Independent of v3
        // routing (we don't track v3 explicitly — it's the dominant
        // case covered by envelopes_sent_total).
        let m = Metrics::new(Region::Nyc, "v2-test".to_owned());
        for _ in 0..7 {
            m.envelope_accepted_legacy_v2();
        }
        let out = m.render_prometheus();
        assert!(out.contains(
            "fetchit_relay_envelopes_accepted_legacy_v2_total{region=\"nyc\",version=\"v2-test\"} 7"
        ));
        // And the gate-drop counter must STAY at zero — these are
        // distinct surfaces.
        assert!(out.contains(
            "fetchit_relay_envelopes_dropped_version_gate_total{region=\"nyc\",version=\"v2-test\"} 0"
        ));
    }

    #[test]
    fn version_gate_drop_counter_increments_independently() {
        let m = Metrics::new(Region::Nyc, "gate-test".to_owned());
        for _ in 0..3 {
            m.envelope_dropped_version_gate();
        }
        let out = m.render_prometheus();
        assert!(out.contains(
            "fetchit_relay_envelopes_dropped_version_gate_total{region=\"nyc\",version=\"gate-test\"} 3"
        ));
        // Burn-down counter stays at zero — they're orthogonal.
        assert!(out.contains(
            "fetchit_relay_envelopes_accepted_legacy_v2_total{region=\"nyc\",version=\"gate-test\"} 0"
        ));
    }

    #[test]
    fn labels_are_only_region_and_version() {
        let m = Metrics::new(Region::Fra, "v1".to_owned());
        let out = m.render_prometheus();
        // Spot-check one labelled line, then assert no forbidden labels appear.
        assert!(out.contains(r#"region="fra""#));
        assert!(out.contains(r#"version="v1""#));
        for forbidden in [
            "agent_id=",
            "tenant_id=",
            "group_id=",
            "machine_id=",
            "source_ip=",
            "country=",
            "asn=",
            "user_agent=",
            "sender=",
            "recipient=",
            "peer=",
        ] {
            assert!(!out.contains(forbidden), "label leak: {forbidden}");
        }
    }

    #[test]
    fn counters_increment_independently() {
        let m = Metrics::new(Region::Nyc, "x".to_owned());
        for _ in 0..3 {
            m.envelope_sent();
        }
        m.envelope_delivered();
        let out = m.render_prometheus();
        assert!(out.contains("fetchit_relay_envelopes_sent_total{region=\"nyc\",version=\"x\"} 3"));
        assert!(
            out.contains("fetchit_relay_envelopes_delivered_total{region=\"nyc\",version=\"x\"} 1")
        );
    }
}
