//! Local-devnet integration test — fetch>it's production `AutonomiClient`
//! fetching real content off a real (local) Autonomi network.
//!
//! Between the `MockClient` unit tests (`fetchit-core`) and the live
//! production test (`tests/live.rs`), this tier stands up an in-process
//! network via `ant-core`'s `LocalDevnet`, has the `WithAutonomi` `ant`
//! CLI publish a fixture to it, then exercises fetch>it's full
//! connect -> fetch -> render path against it. fetch>it has no uploader
//! by design, so the publish half is a real `ant` CLI subprocess — no
//! upload or wallet code lives in the fetch>it tree.
//!
//! Gated behind the `devnet-tests` feature (it links `ant-node`) and
//! `#[ignore]`. Needs the `anvil` and `ant` binaries on PATH. Run it:
//!
//! ```text
//! cargo test -p fetchit-net --test devnet --features devnet-tests \
//!   -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ant_core::data::LocalDevnet;
use fetchit_core::handlers::default_registry;
use fetchit_core::{Address, Hint, NetworkClient, RenderContext, Rendition};
use fetchit_net::AutonomiClient;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a local devnet + Anvil and shells out to the ant CLI; needs --features devnet-tests and the anvil + ant binaries"]
async fn round_trips_content_through_a_local_devnet() {
    // 1. Spin a local network — in-process nodes + an embedded Anvil EVM.
    let devnet = LocalDevnet::start_small()
        .await
        .expect("local devnet should start — is the `anvil` binary on PATH?");

    // 2. Stage a manifest (so the `ant` CLI can attach) and a fixture.
    let tmp = tempfile::tempdir().expect("temp dir");
    let manifest = tmp.path().join("devnet-manifest.json");
    devnet
        .write_manifest(&manifest)
        .await
        .expect("write the devnet manifest");
    let payload: &[u8] = br#"{"devnet":true,"n":7}"#;
    let fixture = tmp.path().join("fixture.json");
    std::fs::write(&fixture, payload).expect("write the fixture file");

    // 3. Publish it with the `ant` CLI — the real WithAutonomi uploader.
    //    `--allow-loopback` + `--evm-network local` + `--devnet-manifest`
    //    point it at the devnet; SECRET_KEY is the devnet's funded wallet.
    let out = tokio::process::Command::new("ant")
        .args([
            "--json",
            "--allow-loopback",
            "--evm-network",
            "local",
            "--devnet-manifest",
            manifest.to_str().expect("manifest path is utf-8"),
            "file",
            "upload",
            "--public",
            fixture.to_str().expect("fixture path is utf-8"),
        ])
        .env("SECRET_KEY", devnet.wallet_private_key())
        .output()
        .await
        .expect("run the `ant` CLI — is it installed?");
    assert!(
        out.status.success(),
        "ant file upload failed:\n-- stdout --\n{}\n-- stderr --\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // 4. Parse the public data-map address from ant's JSON output.
    let stdout = String::from_utf8(out.stdout).expect("ant output is utf-8");
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("ant --json printed a JSON object");
    let json: serde_json::Value = serde_json::from_str(line).expect("ant --json output parses");
    let addr_hex = json["address"]
        .as_str()
        .expect("ant reported a public address");
    let address: Address = addr_hex.parse().expect("ant's address is 64-hex");

    // 5. Fetch it back through fetch>it's production client. `connect_local`
    //    enables loopback peering — the devnet is all on 127.0.0.1.
    let peers: Vec<String> = devnet
        .bootstrap_addrs()
        .iter()
        .map(ToString::to_string)
        .collect();
    let client = AutonomiClient::connect_local(&peers)
        .await
        .expect("the fetch>it client connects to the devnet");
    let bytes = client
        .fetch(&address)
        .await
        .expect("fetch the uploaded address");

    // 6. The bytes survive the round trip and classify correctly.
    assert_eq!(
        bytes.as_ref(),
        payload,
        "fetched bytes must equal the upload"
    );
    match default_registry()
        .render(bytes, &Hint::default(), &RenderContext::default())
        .expect("render the fetched bytes")
    {
        Rendition::Json { value } => assert_eq!(value["n"], 7),
        other => panic!("expected Json, got {other:?}"),
    }
}
