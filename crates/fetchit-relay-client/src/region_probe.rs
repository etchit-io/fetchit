//! Probe a set of candidate relays and pick the lowest-RTT one, plus
//! the bootstrap relay table the chat layer connects through by default.

use crate::error::ClientError;
use fetchit_relay_proto::Region;
use std::time::{Duration, Instant};
use url::Url;

/// Bootstrap descriptor for one fetch>it relay.
///
/// Carries enough metadata for UI to surface a per-region list of
/// active relays, distinguish official from community-run relays, and
/// route per-relay denylist scoping when M3.1 community-scoped lists
/// land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    /// Base URL the client dials. Stored as a `&'static str` because
    /// `Url::parse` is not const; [`RelayDescriptor::url`] does the
    /// runtime parse, `assert_default_relays_parse` in tests proves
    /// every baked-in entry is well-formed.
    pub base_url: &'static str,
    /// Region tag the relay advertises (matches `Region::from_str`).
    pub region: Region,
    /// Display label for the operator running the relay. "fetch>it"
    /// for the official entries; community operator handles when
    /// those land.
    pub operator: &'static str,
    /// True for relays operated by the fetch>it project itself; false
    /// for community-run relays. UI may surface this so users see
    /// the trust posture of each relay in their default set.
    pub is_official: bool,
}

impl RelayDescriptor {
    /// Parse [`Self::base_url`] into a typed [`Url`].
    ///
    /// Panics only when a hardcoded entry is malformed, which is a
    /// build-time invariant — `assert_default_relays_parse` makes
    /// that a CI-caught error rather than a runtime surprise.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn url(&self) -> Url {
        self.base_url
            .parse()
            .expect("DEFAULT_RELAYS entry is a valid URL — see assert_default_relays_parse")
    }
}

/// Bootstrap relay set fetch>it ships with.
///
/// The federation core connects to every entry so a peer is
/// reachable through any one. Community-run entries get added here
/// as operators complete the onboarding checklist in
/// `docs/COMMUNITY-RELAY.md`.
///
/// Order is meaningful: index 0 is the "primary" relay reported back
/// to legacy single-`ConnState` consumers via
/// [`RelaySet::primary_connection_state`](crate::RelaySet::primary_connection_state).
pub const DEFAULT_RELAYS: &[RelayDescriptor] = &[
    RelayDescriptor {
        base_url: "http://67.207.94.66:8088",
        region: Region::Nyc,
        operator: "fetch>it",
        is_official: true,
    },
    RelayDescriptor {
        base_url: "http://159.89.11.217:8088",
        region: Region::Fra,
        operator: "fetch>it",
        is_official: true,
    },
];

/// Materialize every entry of [`DEFAULT_RELAYS`] as a typed [`Url`].
///
/// Convenience for callers building a
/// [`RelaySet::connect`](crate::RelaySet::connect) argument or a
/// [`RelayTransport::connect_multi`](https://docs.rs/fetchit-chat)
/// `Vec<Url>`.
///
/// Panics only when a hardcoded entry is malformed — see
/// [`RelayDescriptor::url`].
#[must_use]
pub fn default_relay_urls() -> Vec<Url> {
    DEFAULT_RELAYS.iter().map(RelayDescriptor::url).collect()
}

/// One probe result.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    /// HTTPS base URL of the probed relay.
    pub base: Url,
    /// RTT measured to the `/v1/health` endpoint.
    pub rtt: Duration,
    /// Region the relay advertised.
    pub region: Region,
}

/// Probe each candidate via its `/v1/health` endpoint and return all
/// successful results sorted by RTT, lowest first.
///
/// # Errors
/// Returns every probe failure aggregated into a single error string
/// only when *no* candidate responded; if at least one succeeds the
/// caller gets back the successes and silent partial failures.
pub async fn probe(candidates: &[Url], timeout: Duration) -> Result<Vec<ProbeResult>, ClientError> {
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let mut results: Vec<ProbeResult> = Vec::with_capacity(candidates.len());
    for base in candidates {
        let url = base.join("v1/health")?;
        let start = Instant::now();
        let Ok(resp) = client.get(url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        let Some(region_tag) = body.get("region").and_then(|v| v.as_str()) else {
            continue;
        };
        let region = region_tag
            .parse()
            .unwrap_or(Region::Other(region_tag.into()));
        results.push(ProbeResult {
            base: base.clone(),
            rtt: start.elapsed(),
            region,
        });
    }
    results.sort_by_key(|r| r.rtt);
    Ok(results)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build-time invariant: every `DEFAULT_RELAYS` entry must be a
    /// well-formed URL. `RelayDescriptor::url` and
    /// `default_relay_urls` rely on this — if a new entry slips in
    /// with a typo, this test (and CI) flags it before it can panic
    /// in production.
    #[test]
    fn assert_default_relays_parse() {
        for d in DEFAULT_RELAYS {
            let u: Url = d
                .base_url
                .parse()
                .unwrap_or_else(|e| panic!("DEFAULT_RELAYS {} parse error: {e}", d.base_url));
            assert_eq!(d.url(), u, "RelayDescriptor::url disagrees with parse");
        }
    }

    /// `default_relay_urls` returns one URL per `DEFAULT_RELAYS`
    /// entry in declaration order — the chat-layer connect path
    /// relies on this for "primary relay" semantics.
    #[test]
    fn default_relay_urls_preserves_order() {
        let urls = default_relay_urls();
        assert_eq!(urls.len(), DEFAULT_RELAYS.len());
        for (u, d) in urls.iter().zip(DEFAULT_RELAYS.iter()) {
            assert_eq!(u.as_str().trim_end_matches('/'), d.base_url);
        }
    }

    /// Sanity-check: every official entry carries a real region
    /// (Nyc/Sfo/Fra/Sgp), not the `Other` escape hatch. Community
    /// entries MAY use `Other` for unconventional regions, so we
    /// only enforce this on the official set.
    #[test]
    fn official_entries_use_known_regions() {
        for d in DEFAULT_RELAYS.iter().filter(|d| d.is_official) {
            assert!(
                matches!(
                    d.region,
                    Region::Nyc | Region::Sfo | Region::Fra | Region::Sgp
                ),
                "official relay {} uses non-canonical region {:?}",
                d.base_url,
                d.region,
            );
        }
    }
}
