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
// Hostile SPA: probes the rendered-content security boundary from inside
// the sandboxed iframe and writes "blocked" / "LEAK" into per-probe divs
// the `sandbox-enforce` spec reads. Exercises ENFORCEMENT (the sandbox +
// CSP + neuter actually deny), not just that the attributes are set.
const HOSTILE_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000005";

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
        // Hostile content: every probe must read "blocked". A "LEAK" means
        // the boundary failed to deny that capability. Inline scripts ARE
        // allowed by CSP (script-src 'unsafe-inline'); what must be denied
        // is egress, host-bridge access, storage, and the neutered APIs.
        HOSTILE_ADDR => {
            br#"<!doctype html><meta charset=utf-8><title>SBX</title><body>
<div id=p-tauri>x</div><div id=p-rtc>x</div><div id=p-geo>x</div>
<div id=p-beacon>x</div><div id=p-sw>x</div><div id=p-storage>x</div>
<div id=p-relock>x</div><div id=p-parent>x</div><div id=p-popup>x</div>
<div id=p-fetch>pending</div>
<script>
function s(i,v){document.getElementById(i).textContent=v}
// Host bridge: untrusted content must not reach the Tauri IPC.
s('p-tauri',(typeof window.__TAURI__=='undefined'&&typeof window.__TAURI_INTERNALS__=='undefined'&&typeof window.__TAURI_INVOKE__=='undefined')?'blocked':'LEAK')
// Neutered JS surface (rewriter NEUTER_SCRIPT).
s('p-rtc',typeof window.RTCPeerConnection=='undefined'?'blocked':'LEAK')
s('p-geo',navigator.geolocation===undefined?'blocked':'LEAK')
s('p-beacon',typeof navigator.sendBeacon=='undefined'?'blocked':'LEAK')
s('p-sw',navigator.serviceWorker===undefined?'blocked':'LEAK')
// DOM storage denied by the null-origin sandbox (no allow-same-origin).
try{localStorage.setItem('x','1');s('p-storage','LEAK')}catch(e){s('p-storage','blocked')}
// A neutered global cannot be restored (non-writable + non-configurable).
try{window.RTCPeerConnection=function(){}}catch(e){}
try{Object.defineProperty(window,'RTCPeerConnection',{value:function(){},writable:true,configurable:true})}catch(e){}
s('p-relock',typeof window.RTCPeerConnection=='undefined'?'blocked':'LEAK')
// Cross-origin host frame is opaque to the null-origin iframe.
try{var c=parent.document.cookie;s('p-parent','LEAK')}catch(e){s('p-parent','blocked')}
// No allow-popups -> window.open is denied.
try{var w=window.open('https://example.com');if(w){s('p-popup','LEAK');w.close()}else{s('p-popup','blocked')}}catch(e){s('p-popup','blocked')}
// Egress to a non-allowlisted origin: 'blocked' = the fetch REJECTED (a CSP
// connect-src denial OR a network failure -- both satisfy the no-egress
// property the spec asserts; distinguishing the two is unnecessary).
fetch('https://example.com/sbx').then(function(){s('p-fetch','LEAK')}).catch(function(){s('p-fetch','blocked')})
</script></body>"#
        }
        _ => return Err("no fixture for this address".to_string()),
    };
    Ok(Bytes::from_static(payload))
}
