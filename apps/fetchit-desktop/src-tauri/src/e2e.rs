//! Fixture content for the desktop E2E suite. Compiled only under the
//! `e2e` feature and absent from every release build. `fetch_and_render`
//! routes byte acquisition here instead of the network, so the
//! `WebdriverIO` specs drive the renderers with deterministic content.
//!
//! The fixture addresses are mirrored in the desktop E2E specs.

use bytes::Bytes;
use fetchit_core::Address;

// Fixture addresses — all-zero but for the final byte.
const TEXT_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const JSON_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const HTML_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const QUERY_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000004";

/// Resolve fixture bytes for a known E2E test address. Any other address
/// returns an error, exercising the app's fetch-failure path.
pub fn fixture_bytes(addr: &Address) -> Result<Bytes, String> {
    let payload: &'static [u8] = match addr.to_hex().as_str() {
        TEXT_ADDR => b"fetch>it desktop E2E text fixture.",
        JSON_ADDR => br#"{"e2e":true,"count":7}"#,
        HTML_ADDR => b"<!doctype html><title>E2E</title><h1>E2E fixture</h1>",
        // SPA that echoes its location.search into #q — exercises the
        // rewriter's query injection.
        QUERY_ADDR => {
            br#"<!doctype html><title>Q</title><body><pre id="q"></pre><script>document.getElementById('q').textContent='search='+location.search</script>"#
        }
        _ => return Err("no fixture for this address".to_string()),
    };
    Ok(Bytes::from_static(payload))
}
