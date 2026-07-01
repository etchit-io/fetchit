//! Profile-manifest v1 test-fixture generator.
//!
//! Reads (or, on first run, generates and writes) a committed test
//! ML-DSA-65 keypair + an ML-KEM-768 public key, then emits the three
//! manifests + bytes-of-truth blobs documented in
//! `docs/profile-manifest-v1.md`.
//!
//! ML-DSA-65 in saorsa-pqc is non-deterministic by design, so a fresh
//! `sign()` is never byte-identical to the previous run. To keep the
//! fixture reproducible, the generator is **idempotent**: it writes
//! `canonical.bin` (always — JCS is deterministic) and `sig.bin` only
//! when missing, then verifies the on-disk sig against the live
//! pubkey + canonical bytes. A drift between the spec and the
//! committed signature surfaces as a verify failure on the next run.
//!
//! Run from repo root:
//!
//! ```text
//! cargo run -p fetchit-chat --bin profile-fixture-gen
//! ```

#![allow(clippy::expect_used, clippy::print_stdout)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use fetchit_relay_proto::derive_agent_id;
use saorsa_pqc::api::kem::{MlKem, MlKemPublicKey, MlKemVariant};
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const SIGN_DOMAIN_PROFILE: &[u8] = b"fetchit/profile-manifest/v1";

/// `issued_at_ms` baked into the fixture — a fixed Unix epoch ms
/// (2026-05-30T00:00:00Z) so the manifests + sigs are deterministic.
const FIXTURE_ISSUED_AT_MS: u64 = 1_748_563_200_000;

/// Optional `expires_at_ms` on the maximal manifest — one year out.
const FIXTURE_EXPIRES_AT_MS: u64 = 1_780_099_200_000;

fn fixture_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("../../tests/fixtures/profile-manifest-v1")
        .canonicalize()
        .expect("fixture dir must exist (run from repo root)")
}

fn load_or_generate_ml_dsa(root: &Path) -> (MlDsa, MlDsaPublicKey, MlDsaSecretKey) {
    let pk_path = root.join("test-ml-dsa-65.pk.bin");
    let sk_path = root.join("test-ml-dsa-65.sk.bin");
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);

    if pk_path.exists() && sk_path.exists() {
        let pk_bytes = fs::read(&pk_path).expect("read pk");
        let sk_bytes = fs::read(&sk_path).expect("read sk");
        let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes).expect("parse pk");
        let sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes).expect("parse sk");
        println!("[gen] reused existing ML-DSA-65 test key");
        return (dsa, pk, sk);
    }

    let (pk, sk) = dsa.generate_keypair().expect("dsa keygen");
    fs::write(&pk_path, pk.to_bytes()).expect("write pk");
    fs::write(&sk_path, sk.to_bytes()).expect("write sk");
    println!("[gen] generated + wrote ML-DSA-65 test key");
    (dsa, pk, sk)
}

fn load_or_generate_ml_kem_pubkey(root: &Path) -> MlKemPublicKey {
    let pk_path = root.join("test-ml-kem-768.pk.bin");
    if pk_path.exists() {
        let pk_bytes = fs::read(&pk_path).expect("read kem pk");
        let pk =
            MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &pk_bytes).expect("parse kem pk");
        println!("[gen] reused existing ML-KEM-768 test pubkey");
        return pk;
    }
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let (pk, _sk) = kem.generate_keypair().expect("kem keygen");
    fs::write(&pk_path, pk.to_bytes()).expect("write kem pk");
    println!("[gen] generated + wrote ML-KEM-768 test pubkey (secret discarded)");
    pk
}

fn build_minimal(agent_id_hex: &str, ml_dsa_b64: &str, kem_b64: &str) -> serde_json::Value {
    json!({
        "version": 1,
        "agent_id": agent_id_hex,
        "display_name": "fixture-alice",
        "ml_dsa_pubkey": ml_dsa_b64,
        "kem_pubkey": kem_b64,
        "issued_at_ms": FIXTURE_ISSUED_AT_MS,
    })
}

fn build_maximal(agent_id_hex: &str, ml_dsa_b64: &str, kem_b64: &str) -> serde_json::Value {
    json!({
        "version": 1,
        "agent_id": agent_id_hex,
        "display_name": "fixture-alice",
        "bio": "Test fixture profile. Do not trust in production.",
        "website": "https://example.invalid/alice",
        "links": [
            { "kind": "website", "label": "Blog",     "addr": "https://example.invalid/blog" },
            { "kind": "image",   "label": "Header",   "addr": "1".repeat(64) },
            { "kind": "etchit",  "label": "etch>it",  "addr": "2".repeat(64) },
            { "kind": "fetchit", "label": "fetch>it", "addr": "3".repeat(64) },
            { "kind": "x0x",     "label": "Chat",     "addr": agent_id_hex }
        ],
        "avatar": {
            "addr": "4".repeat(64),
            "mime": "image/webp",
            "w": 256,
            "h": 256,
            "bytes_len": 12345_u32
        },
        "ml_dsa_pubkey": ml_dsa_b64,
        "kem_pubkey": kem_b64,
        "issued_at_ms": FIXTURE_ISSUED_AT_MS,
        "expires_at_ms": FIXTURE_EXPIRES_AT_MS,
    })
}

fn jcs_canonical(manifest: &serde_json::Value) -> Vec<u8> {
    serde_jcs::to_vec(manifest).expect("jcs canonicalise")
}

fn sign_input(canonical: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIGN_DOMAIN_PROFILE.len() + canonical.len());
    v.extend_from_slice(SIGN_DOMAIN_PROFILE);
    v.extend_from_slice(canonical);
    v
}

/// Write `canonical.bin` (always; deterministic) and `sig.bin` (only
/// when missing — preserves the committed signature). Then read the
/// sig back and verify it against the pubkey + the freshly-computed
/// canonical bytes. A verify miss tells the operator to delete the
/// stale sig and re-run.
fn write_signed_variant(
    root: &Path,
    name: &str,
    dsa: &MlDsa,
    pk: &MlDsaPublicKey,
    sk: &MlDsaSecretKey,
    manifest: serde_json::Value,
) {
    let dir = root.join(name);
    fs::create_dir_all(&dir).expect("mkdir variant");

    let canonical = jcs_canonical(&manifest);
    fs::write(dir.join("canonical.bin"), &canonical).expect("write canonical");

    let sig_path = dir.join("sig.bin");
    if sig_path.exists() {
        println!("[gen] {name}: kept existing sig");
    } else {
        let fresh = dsa.sign(sk, &sign_input(&canonical)).expect("dsa sign");
        fs::write(&sig_path, fresh.to_bytes()).expect("write sig");
        println!("[gen] {name}: signed fresh");
    }

    let sig_bytes = fs::read(&sig_path).expect("read sig");
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes).expect("parse sig");
    let ok = dsa
        .verify(pk, &sign_input(&canonical), &sig)
        .expect("verify");
    assert!(
        ok,
        "{name}: committed sig does NOT verify against canonical + pk. \
         Delete {} and re-run the generator if the spec changed.",
        sig_path.display()
    );

    let pretty = {
        let mut m = manifest;
        m.as_object_mut()
            .expect("object")
            .insert("sig".into(), json!(B64URL.encode(&sig_bytes)));
        serde_json::to_string_pretty(&m).expect("pretty")
    };
    fs::write(dir.join("manifest.json"), format!("{pretty}\n")).expect("write manifest");

    println!(
        "[gen] wrote {name}/ (canonical={} B, sig={} B, verifies)",
        canonical.len(),
        sig_bytes.len()
    );
}

/// Take `maximal/manifest.json`, decode it back to a JSON value, flip
/// the first byte of `display_name`, drop the old `sig`, recompute the
/// canonical bytes, then write the artifacts. `sig.bin` is copied
/// verbatim from `maximal/sig.bin` — by design it does NOT verify
/// against the tampered canonical.
fn write_tampered(root: &Path, original_sig: &[u8]) {
    let dir = root.join("tampered-maximal");
    fs::create_dir_all(&dir).expect("mkdir tampered");

    let src = fs::read_to_string(root.join("maximal/manifest.json")).expect("read maximal");
    let mut v: serde_json::Value = serde_json::from_str(&src).expect("parse maximal");
    let obj = v.as_object_mut().expect("object");
    let mut name = obj
        .get("display_name")
        .and_then(|x| x.as_str())
        .expect("display_name str")
        .as_bytes()
        .to_vec();
    name[0] ^= 0x20; // flip a single bit: 'f' (0x66) ↔ 'F' (0x46)
    let flipped = String::from_utf8(name).expect("utf-8");
    obj.insert("display_name".into(), json!(flipped));
    obj.remove("sig");
    let canonical = jcs_canonical(&v);
    fs::write(dir.join("canonical.bin"), &canonical).expect("write tampered canonical");
    fs::write(dir.join("sig.bin"), original_sig).expect("write tampered sig");

    let pretty = {
        let mut m = v;
        m.as_object_mut()
            .expect("object")
            .insert("sig".into(), json!(B64URL.encode(original_sig)));
        serde_json::to_string_pretty(&m).expect("pretty")
    };
    fs::write(dir.join("manifest.json"), format!("{pretty}\n")).expect("write tampered manifest");

    println!(
        "[gen] wrote tampered-maximal/ (canonical={} B, sig={} B; does NOT verify by design)",
        canonical.len(),
        original_sig.len()
    );
}

fn main() {
    let root = fixture_root();
    let (dsa, pk, sk) = load_or_generate_ml_dsa(&root);
    let kem_pk = load_or_generate_ml_kem_pubkey(&root);

    let pk_bytes = pk.to_bytes();
    let agent_id = derive_agent_id(&pk_bytes);
    let agent_id_hex = hex::encode(agent_id);
    let ml_dsa_b64 = B64URL.encode(&pk_bytes);
    let kem_b64 = B64URL.encode(kem_pk.to_bytes());

    println!("[gen] agent_id = {agent_id_hex}");

    let minimal = build_minimal(&agent_id_hex, &ml_dsa_b64, &kem_b64);
    write_signed_variant(&root, "minimal", &dsa, &pk, &sk, minimal);

    let maximal = build_maximal(&agent_id_hex, &ml_dsa_b64, &kem_b64);
    write_signed_variant(&root, "maximal", &dsa, &pk, &sk, maximal);

    let max_sig = fs::read(root.join("maximal/sig.bin")).expect("read maximal sig");
    write_tampered(&root, &max_sig);

    println!("[gen] fixture refreshed at {}", root.display());
}
