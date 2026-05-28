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
            auth_challenges_issued_total: AtomicU64::new(0),
            auth_verify_ok_total: AtomicU64::new(0),
            auth_verify_failed_total: AtomicU64::new(0),
            throttles_per_recipient_total: AtomicU64::new(0),
            throttles_per_sender_total: AtomicU64::new(0),
            throttles_envelope_too_large_total: AtomicU64::new(0),
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

        let counters: [(&str, &str, u64); 9] = [
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
        ];

        for (name, help, value) in counters {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        }

        out
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
            "fetchit_relay_auth_challenges_issued_total",
            "fetchit_relay_auth_verify_ok_total",
            "fetchit_relay_auth_verify_failed_total",
            "fetchit_relay_throttles_per_recipient_total",
            "fetchit_relay_throttles_per_sender_total",
            "fetchit_relay_throttles_envelope_too_large_total",
        ] {
            assert!(out.contains(series), "missing: {series}");
        }
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
