//! Integration tests for disk cache persistence + offline boot.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use fetchit_trust::signer::IssuerSigner;
use fetchit_trust::types::{
    DenylistEntry, DenylistResponse, DenylistToSign, ReportKind, TargetIdentity,
};
use fetchit_trust::EntryKind;
use fetchit_trust_client::{DenylistConsumer, HttpClient, TrustError};
use std::collections::HashMap;
use std::sync::Mutex;

struct StubHttp {
    by_kind: Mutex<HashMap<String, Vec<u8>>>,
}

impl StubHttp {
    fn new() -> Self {
        Self {
            by_kind: Mutex::new(HashMap::new()),
        }
    }
    fn pre_bake(&self, kind_query: &str, body: Vec<u8>) {
        self.by_kind.lock().unwrap().insert(kind_query.into(), body);
    }
}

#[async_trait]
impl HttpClient for StubHttp {
    async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError> {
        let map = self.by_kind.lock().unwrap();
        for (kind_query, body) in map.iter() {
            if url.contains(kind_query) {
                return Ok(body.clone());
            }
        }
        Err(TrustError::Http(format!("stub: no body for {url}")))
    }
}

fn signed_relay_response(signer: &IssuerSigner, urls: &[&str]) -> DenylistResponse {
    let entries: Vec<DenylistEntry> = urls
        .iter()
        .map(|v| DenylistEntry {
            target: TargetIdentity::new(EntryKind::RelayUrl, *v),
            added_at_ms: 1_700_000_000_000,
            reason: ReportKind::Spam,
        })
        .collect();
    let to_sign = DenylistToSign {
        etag: "etag-1",
        generated_at_ms: 1_700_000_000_001,
        kind: EntryKind::RelayUrl,
        entries: &entries,
    };
    let sign_bytes = postcard::to_allocvec(&to_sign).unwrap();
    let sig = signer.sign(&sign_bytes).unwrap();
    DenylistResponse {
        etag: "etag-1".into(),
        generated_at_ms: 1_700_000_000_001,
        kind: EntryKind::RelayUrl,
        entries,
        issuer_signature_hex: hex::encode(sig),
        issuer_key_id: signer.key_id.clone(),
    }
}

#[tokio::test]
async fn offline_boot_reads_disk_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("denylist");
    let signer = IssuerSigner::generate("test").unwrap();

    // Online run: populate the disk cache.
    {
        let stub = StubHttp::new();
        let resp = signed_relay_response(&signer, &["wss://x.example/v1/ws"]);
        stub.pre_bake("relay_url", serde_json::to_vec(&resp).unwrap());

        let consumer = DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            Some(cache.clone()),
        );
        consumer.refresh(&stub).await.unwrap();
    }

    // Simulate offline boot.
    let consumer = DenylistConsumer::new(
        signer.public_key_bytes(),
        "https://etchit.io/v1".into(),
        Some(cache),
    );
    consumer.load_cache_blocking();
    assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://x.example/v1/ws"));
}

#[tokio::test]
async fn poisoned_cache_file_is_rejected_index_recovers_on_next_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("denylist");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("relay_url.json"), b"GARBAGE").unwrap();

    let signer = IssuerSigner::generate("test").unwrap();
    let consumer = DenylistConsumer::new(
        signer.public_key_bytes(),
        "https://etchit.io/v1".into(),
        Some(cache),
    );
    consumer.load_cache_blocking();
    assert!(!consumer.is_blocked(EntryKind::RelayUrl, "wss://x.example/v1/ws"));

    let stub = StubHttp::new();
    let resp = signed_relay_response(&signer, &["wss://x.example/v1/ws"]);
    stub.pre_bake("relay_url", serde_json::to_vec(&resp).unwrap());
    consumer.refresh(&stub).await.unwrap();
    assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://x.example/v1/ws"));
}

#[tokio::test]
async fn refresh_writes_cache_file_per_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("denylist");
    let signer = IssuerSigner::generate("test").unwrap();

    let stub = StubHttp::new();
    let resp = signed_relay_response(&signer, &["wss://x.example/v1/ws"]);
    stub.pre_bake("relay_url", serde_json::to_vec(&resp).unwrap());

    let consumer = DenylistConsumer::new(
        signer.public_key_bytes(),
        "https://etchit.io/v1".into(),
        Some(cache.clone()),
    );
    consumer.refresh(&stub).await.unwrap();

    let cached = cache.join("relay_url.json");
    assert!(cached.exists(), "cache file should exist after refresh");
    let bytes = std::fs::read(&cached).unwrap();
    let _: DenylistResponse = serde_json::from_slice(&bytes).expect("cache file is valid JSON");
}
