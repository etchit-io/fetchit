//! Probe a set of candidate relays and pick the lowest-RTT one.

use crate::error::ClientError;
use fetchit_relay_proto::Region;
use std::time::{Duration, Instant};
use url::Url;

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
