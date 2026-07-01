//! Diagnostic probe: mints a v2 extended share URI against the local
//! x0xd and reports the size of every component so we can pin down
//! exactly where the byte bloat is.
//!
//! Run explicitly:
//!
//! ```text
//! cargo test -p fetchit-chat --test probe_share_uri_size -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_chat::Client;

#[tokio::test]
#[ignore = "requires a running x0xd daemon"]
async fn probe_extended_share_uri_sizes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = match Client::builder()
        .data_dir(dir.path().to_path_buf())
        .passphrase("probe-passphrase".to_owned())
        .build()
        .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("x0xd not reachable; skipping: {e}");
            return;
        }
    };

    let display_name = "ProbeUser";
    let base_card = client
        .identity()
        .card(display_name)
        .await
        .expect("base card");
    let base_card_json = serde_json::to_vec(&base_card).expect("base card to json");
    let base_card_str = std::str::from_utf8(&base_card_json).expect("utf-8");

    println!("=== base x0xd /agent/card JSON ===");
    println!("total bytes:                 {}", base_card_json.len());
    println!(
        "  addresses field bytes:     {}",
        serde_json::to_vec(&base_card.addresses)
            .expect("addresses")
            .len()
    );
    println!(
        "  extra (flattened) bytes:   {}",
        serde_json::to_vec(&base_card.extra).expect("extra").len()
    );

    // Top hits inside `extra`. The serde flatten will land all the
    // `dm_capabilities`, `pq_signing` etc. fields here.
    if let Some(obj) = base_card.extra.as_object() {
        let mut sized: Vec<(String, usize)> = obj
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::to_vec(v).expect("kv").len()))
            .collect();
        sized.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (k, n) in sized.iter().take(8) {
            println!("    extra[{k}] bytes: {n}");
        }
    }

    let uri = client
        .identity()
        .extended_share_uri(display_name)
        .await
        .expect("extended uri");
    println!();
    println!("=== full v2 extended URI ===");
    println!("URI total bytes:             {}", uri.len());

    // The URI is `x0x://agent/<URL_SAFE_NO_PAD base64>`. Decode it back
    // to JSON and report the per-field weights of the v2 extension.
    let prefix = "x0x://agent/";
    assert!(uri.starts_with(prefix));
    let b64 = &uri[prefix.len()..];
    println!("base64 body bytes:           {}", b64.len());
    let raw = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b64.as_bytes(),
    )
    .expect("b64 decode");
    println!("decoded body bytes:          {}", raw.len());
    let value = fetchit_chat::card::extended_card_from_uri(&uri).expect("decode");
    if let Some(obj) = value.as_object() {
        let mut sized: Vec<(String, usize)> = obj
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::to_vec(v).expect("kv").len()))
            .collect();
        sized.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        println!();
        println!("=== v2 JSON top fields by size ===");
        for (k, n) in sized.iter().take(10) {
            println!("  {k}: {n}");
        }
    }

    // Cross-check: a sample of the URI body itself.
    println!();
    println!("URI head: {}", &uri[..uri.len().min(160)]);
    let _ = base_card_str;
}
