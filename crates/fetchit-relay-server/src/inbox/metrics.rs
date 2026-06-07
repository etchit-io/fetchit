//! Prometheus-shaped counters for the fediverse inbox.
//!
//! Stage 3.2 — wires every gate decision in [`super::router`] to a
//! `fedi_inbox_*_total` counter. Cardinality is consciously bounded:
//! per-instance + per-static-label families use `DashMap` with
//! `&'static str` or short String keys, never unbounded actor URLs.
//!
//! Render via [`InboxMetrics::render_prometheus`]; Stage 3.3 splices
//! the output into the existing `/v1/metrics` endpoint when the
//! relay-server is built with `--features fediverse-inbox`.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use super::DropReason;

/// Atomic counter family backing the inbox Prom metrics.
///
/// Construct via [`Self::new`] (zero-valued) and share a single
/// `Arc<InboxMetrics>` across the axum router + ops-surface
/// endpoint. All counters are `AtomicU64::Relaxed` — fast enough
/// for the hot path, accurate to within a few in-flight requests
/// at scrape time.
#[derive(Debug, Default)]
pub struct InboxMetrics {
    accepted: AtomicU64,

    // Single-counter drop reasons (no label).
    dropped_body_too_large: AtomicU64,
    dropped_stale_request: AtomicU64,
    dropped_replay: AtomicU64,
    dropped_unsupported_algorithm: AtomicU64,
    dropped_denylisted: AtomicU64,
    dropped_webfinger_lookup_failed: AtomicU64,
    dropped_missing_keyid: AtomicU64,
    dropped_sink_rejected: AtomicU64,

    // Per-source-instance rate-limit hits. `instance` is `host[:port]`
    // — bounded by the unique sender set we receive from. Community
    // relays see 10s-100s of instances; not a cardinality risk.
    dropped_rate_limited: DashMap<String, AtomicU64>,

    // Per-`SignatureVerifyError::reason_label` — bounded to the 4
    // static-string slots in fetchit-fedi.
    dropped_sig_fail: DashMap<&'static str, AtomicU64>,

    // Per-header-name missing-header counter — bounded to the static
    // header-name strings the extractor uses.
    dropped_missing_header: DashMap<&'static str, AtomicU64>,
}

impl InboxMetrics {
    /// New zero-valued counter family. Wrap in `Arc<...>` and share
    /// across the router + ops surface.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful inbox accept (gate-all-pass + sink enqueue).
    pub fn record_accept(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a gate-driven drop. The variant of `reason` selects
    /// which counter increments.
    pub fn record_drop(&self, reason: &DropReason) {
        match reason {
            DropReason::BodyTooLarge => {
                self.dropped_body_too_large.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::StaleRequest => {
                self.dropped_stale_request.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::Replay => {
                self.dropped_replay.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::UnsupportedAlgorithm => {
                self.dropped_unsupported_algorithm
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::Denylisted(_) => {
                self.dropped_denylisted.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::WebFingerLookupFailed => {
                self.dropped_webfinger_lookup_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::MissingKeyId => {
                self.dropped_missing_keyid.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::SinkRejected => {
                self.dropped_sink_rejected.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::RateLimited(instance) => {
                self.dropped_rate_limited
                    .entry(instance.clone())
                    .or_default()
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::SigFail(reason_label) => {
                self.dropped_sig_fail
                    .entry(*reason_label)
                    .or_default()
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::MissingHeader(name) => {
                self.dropped_missing_header
                    .entry(*name)
                    .or_default()
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot value of `fedi_inbox_accepted_total`.
    #[must_use]
    pub fn accepted_total(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Snapshot of all drop counters for the named scalar reasons.
    /// Returned in declaration order. Useful for tests / ops dashboards
    /// that don't want to parse the Prom text.
    #[must_use]
    pub fn scalar_drops(&self) -> ScalarDropSnapshot {
        ScalarDropSnapshot {
            body_too_large: self.dropped_body_too_large.load(Ordering::Relaxed),
            stale_request: self.dropped_stale_request.load(Ordering::Relaxed),
            replay: self.dropped_replay.load(Ordering::Relaxed),
            unsupported_algorithm: self.dropped_unsupported_algorithm.load(Ordering::Relaxed),
            denylisted: self.dropped_denylisted.load(Ordering::Relaxed),
            webfinger_lookup_failed: self.dropped_webfinger_lookup_failed.load(Ordering::Relaxed),
            missing_keyid: self.dropped_missing_keyid.load(Ordering::Relaxed),
            sink_rejected: self.dropped_sink_rejected.load(Ordering::Relaxed),
        }
    }

    /// Snapshot of the per-source-instance rate-limit counter for
    /// `instance`. Returns 0 if no entry was recorded.
    #[must_use]
    pub fn rate_limited_count(&self, instance: &str) -> u64 {
        self.dropped_rate_limited
            .get(instance)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    /// Snapshot of the per-`reason_label` sig-fail counter.
    #[must_use]
    pub fn sig_fail_count(&self, reason_label: &str) -> u64 {
        self.dropped_sig_fail
            .get(reason_label)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    /// Snapshot of the per-header missing-header counter.
    #[must_use]
    pub fn missing_header_count(&self, name: &str) -> u64 {
        self.dropped_missing_header
            .get(name)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    /// Render the inbox counters in Prometheus text format. Splices
    /// into the existing `/v1/metrics` endpoint at Stage 3.3.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(1024);

        // Helper to emit a single-label counter line.
        let _ = writeln!(
            out,
            "# HELP fedi_inbox_accepted_total Inbound activities accepted past every gate."
        );
        let _ = writeln!(out, "# TYPE fedi_inbox_accepted_total counter");
        let _ = writeln!(
            out,
            "fedi_inbox_accepted_total {}",
            self.accepted.load(Ordering::Relaxed)
        );

        // Scalar drop reasons.
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_body_too_large_total",
            "Inbound activities rejected for body > max_body_bytes.",
            self.dropped_body_too_large.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_stale_request_total",
            "Inbound activities rejected for Date header outside skew window.",
            self.dropped_stale_request.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_replay_total",
            "Inbound activities rejected as replays of (Content-Digest, Date) pairs.",
            self.dropped_replay.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_unsupported_algorithm_total",
            "Inbound activities rejected for cavage algorithm != rsa-sha256.",
            self.dropped_unsupported_algorithm.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_denylisted_total",
            "Inbound activities rejected because the signing actor URL is denylisted.",
            self.dropped_denylisted.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_webfinger_lookup_failed_total",
            "Inbound activities rejected because the actor pubkey could not be resolved via WebFinger.",
            self.dropped_webfinger_lookup_failed.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_missing_keyid_total",
            "Inbound activities rejected because the keyId parameter could not be parsed.",
            self.dropped_missing_keyid.load(Ordering::Relaxed),
        );
        emit_scalar(
            &mut out,
            "fedi_inbox_dropped_sink_rejected_total",
            "Inbound activities accepted at every gate but rejected by the downstream sink (queue full / receiver disconnected).",
            self.dropped_sink_rejected.load(Ordering::Relaxed),
        );

        // Per-instance rate-limit counter.
        let _ = writeln!(
            out,
            "# HELP fedi_inbox_dropped_rate_limited_total Inbound activities rejected by the per-source-instance token bucket."
        );
        let _ = writeln!(out, "# TYPE fedi_inbox_dropped_rate_limited_total counter");
        for entry in &self.dropped_rate_limited {
            let _ = writeln!(
                out,
                "fedi_inbox_dropped_rate_limited_total{{instance=\"{}\"}} {}",
                escape_label(entry.key()),
                entry.value().load(Ordering::Relaxed)
            );
        }

        // Per-reason sig-fail counter.
        let _ = writeln!(
            out,
            "# HELP fedi_inbox_dropped_sig_fail_total HTTP Signature verification failures, sliced by reason label."
        );
        let _ = writeln!(out, "# TYPE fedi_inbox_dropped_sig_fail_total counter");
        for entry in &self.dropped_sig_fail {
            let _ = writeln!(
                out,
                "fedi_inbox_dropped_sig_fail_total{{reason=\"{}\"}} {}",
                escape_label(entry.key()),
                entry.value().load(Ordering::Relaxed)
            );
        }

        // Per-header missing-header counter.
        let _ = writeln!(
            out,
            "# HELP fedi_inbox_dropped_missing_header_total Inbound activities rejected for a missing required header."
        );
        let _ = writeln!(
            out,
            "# TYPE fedi_inbox_dropped_missing_header_total counter"
        );
        for entry in &self.dropped_missing_header {
            let _ = writeln!(
                out,
                "fedi_inbox_dropped_missing_header_total{{name=\"{}\"}} {}",
                escape_label(entry.key()),
                entry.value().load(Ordering::Relaxed)
            );
        }

        out
    }
}

/// Snapshot of every single-counter drop reason. Returned by
/// [`InboxMetrics::scalar_drops`] for test + ops-dashboard use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarDropSnapshot {
    /// `fedi_inbox_dropped_body_too_large_total`.
    pub body_too_large: u64,
    /// `fedi_inbox_dropped_stale_request_total`.
    pub stale_request: u64,
    /// `fedi_inbox_dropped_replay_total`.
    pub replay: u64,
    /// `fedi_inbox_dropped_unsupported_algorithm_total`.
    pub unsupported_algorithm: u64,
    /// `fedi_inbox_dropped_denylisted_total`.
    pub denylisted: u64,
    /// `fedi_inbox_dropped_webfinger_lookup_failed_total`.
    pub webfinger_lookup_failed: u64,
    /// `fedi_inbox_dropped_missing_keyid_total`.
    pub missing_keyid: u64,
    /// `fedi_inbox_dropped_sink_rejected_total`.
    pub sink_rejected: u64,
}

fn emit_scalar(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

/// Escape `"` and `\` in a Prometheus label value per the
/// exposition format. Keeps `instance="..."` etc. parseable when
/// the source string contains exotic chars.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn new_is_all_zero() {
        let m = InboxMetrics::new();
        assert_eq!(m.accepted_total(), 0);
        assert_eq!(m.scalar_drops(), ScalarDropSnapshot::default());
    }

    #[test]
    fn record_accept_increments_counter() {
        let m = InboxMetrics::new();
        m.record_accept();
        m.record_accept();
        assert_eq!(m.accepted_total(), 2);
    }

    #[test]
    fn record_drop_routes_each_variant_to_its_counter() {
        let m = InboxMetrics::new();
        m.record_drop(&DropReason::BodyTooLarge);
        m.record_drop(&DropReason::StaleRequest);
        m.record_drop(&DropReason::Replay);
        m.record_drop(&DropReason::UnsupportedAlgorithm);
        m.record_drop(&DropReason::Denylisted(
            "https://attacker.example/actors/eve".into(),
        ));
        m.record_drop(&DropReason::WebFingerLookupFailed);
        m.record_drop(&DropReason::MissingKeyId);
        m.record_drop(&DropReason::SinkRejected);

        let s = m.scalar_drops();
        assert_eq!(s.body_too_large, 1);
        assert_eq!(s.stale_request, 1);
        assert_eq!(s.replay, 1);
        assert_eq!(s.unsupported_algorithm, 1);
        assert_eq!(s.denylisted, 1);
        assert_eq!(s.webfinger_lookup_failed, 1);
        assert_eq!(s.missing_keyid, 1);
        assert_eq!(s.sink_rejected, 1);
    }

    #[test]
    fn record_drop_rate_limited_increments_per_instance() {
        let m = InboxMetrics::new();
        m.record_drop(&DropReason::RateLimited("a.example".into()));
        m.record_drop(&DropReason::RateLimited("a.example".into()));
        m.record_drop(&DropReason::RateLimited("b.example".into()));
        assert_eq!(m.rate_limited_count("a.example"), 2);
        assert_eq!(m.rate_limited_count("b.example"), 1);
        assert_eq!(m.rate_limited_count("c.example"), 0);
    }

    #[test]
    fn record_drop_sig_fail_increments_per_reason_label() {
        let m = InboxMetrics::new();
        m.record_drop(&DropReason::SigFail("digest_mismatch"));
        m.record_drop(&DropReason::SigFail("digest_mismatch"));
        m.record_drop(&DropReason::SigFail("verify_failed"));
        assert_eq!(m.sig_fail_count("digest_mismatch"), 2);
        assert_eq!(m.sig_fail_count("verify_failed"), 1);
        assert_eq!(m.sig_fail_count("header_malformed"), 0);
    }

    #[test]
    fn record_drop_missing_header_increments_per_name() {
        let m = InboxMetrics::new();
        m.record_drop(&DropReason::MissingHeader("host"));
        m.record_drop(&DropReason::MissingHeader("date"));
        m.record_drop(&DropReason::MissingHeader("date"));
        assert_eq!(m.missing_header_count("host"), 1);
        assert_eq!(m.missing_header_count("date"), 2);
        assert_eq!(m.missing_header_count("signature"), 0);
    }

    #[test]
    fn render_prometheus_emits_canonical_format() {
        let m = InboxMetrics::new();
        m.record_accept();
        m.record_drop(&DropReason::BodyTooLarge);
        m.record_drop(&DropReason::RateLimited("mastodon.example".into()));
        m.record_drop(&DropReason::SigFail("digest_mismatch"));
        m.record_drop(&DropReason::MissingHeader("host"));

        let prom = m.render_prometheus();
        // Spot-check key lines so the test isn't a giant byte-pin.
        assert!(prom.contains("fedi_inbox_accepted_total 1"));
        assert!(prom.contains("fedi_inbox_dropped_body_too_large_total 1"));
        assert!(
            prom.contains("fedi_inbox_dropped_rate_limited_total{instance=\"mastodon.example\"} 1")
        );
        assert!(prom.contains("fedi_inbox_dropped_sig_fail_total{reason=\"digest_mismatch\"} 1"));
        assert!(prom.contains("fedi_inbox_dropped_missing_header_total{name=\"host\"} 1"));
        // Each metric must have HELP + TYPE lines.
        assert!(prom.contains("# HELP fedi_inbox_accepted_total"));
        assert!(prom.contains("# TYPE fedi_inbox_accepted_total counter"));
    }

    #[test]
    fn render_prometheus_escapes_label_values() {
        let m = InboxMetrics::new();
        m.record_drop(&DropReason::RateLimited(r#"weird"\name"#.into()));
        let prom = m.render_prometheus();
        // Double-quotes and backslashes inside the label value get
        // backslash-escaped per the Prom exposition format.
        assert!(prom.contains(r#"instance="weird\"\\name""#), "got:\n{prom}");
    }

    #[test]
    fn render_prometheus_omits_empty_dynamic_families() {
        let m = InboxMetrics::new();
        m.record_accept();
        let prom = m.render_prometheus();
        // No rate-limit / sig-fail / missing-header entries recorded —
        // HELP + TYPE lines are still present (Prom convention) but
        // there are no value rows under them.
        let rl_help = prom
            .lines()
            .position(|l| l.starts_with("# HELP fedi_inbox_dropped_rate_limited_total"));
        assert!(rl_help.is_some());
        let rl_values = prom
            .lines()
            .filter(|l| l.starts_with("fedi_inbox_dropped_rate_limited_total{"))
            .count();
        assert_eq!(rl_values, 0);
    }
}
