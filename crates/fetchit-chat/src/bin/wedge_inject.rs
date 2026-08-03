//! Test-only wedge injector (#297 device proof).
//!
//! Fabricates the exact production wedge on a headless peer's vault:
//! rolls a conversation's epoch FORWARD and re-keys it locally without
//! telling the other side. The peer then seals at an epoch the phone
//! holds no key for, so the phone's inbound frames land as `StaleEpoch`
//! — liveness without progress, which is precisely what the wedge
//! watchdog must catch and the forced-re-key ladder must heal.
//!
//! Never shipped to users: this binary exists so the resilience gate is
//! proven against a REAL desync rather than a mocked one. It touches
//! only a peer vault whose passphrase the operator already holds.
//!
//! ```text
//! wedge-inject --data-dir <peer vault> --passphrase-file <file> \
//!              [--group <hex>] [--bump 3]
//! ```

use std::path::PathBuf;

use fetchit_chat::at_rest::{open_from_path, seal_to_path};
use fetchit_chat::conversation::Conversation;
use fetchit_chat::local_store::StoreLayout;

fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
    }
    None
}

fn main() {
    let Some(data_dir) = arg("--data-dir") else {
        eprintln!("--data-dir <peer vault root> is required");
        std::process::exit(2);
    };
    let Some(pass_file) = arg("--passphrase-file") else {
        eprintln!("--passphrase-file <path> is required");
        std::process::exit(2);
    };
    let bump: u32 = arg("--bump").and_then(|b| b.parse().ok()).unwrap_or(3);
    let only_group = arg("--group");

    let passphrase = std::fs::read_to_string(&pass_file).map_or_else(
        |e| {
            eprintln!("read passphrase file {pass_file}: {e}");
            std::process::exit(1);
        },
        |s| s.trim().to_owned(),
    );

    let layout = StoreLayout::ensure(PathBuf::from(&data_dir)).unwrap_or_else(|e| {
        eprintln!("open layout: {e}");
        std::process::exit(1);
    });
    let identity_vault = layout.root.join("identity.json.enc");
    let (master, kdf_id, argon_salt) =
        fetchit_chat::resolve_master_key(identity_vault.as_path(), Some(&passphrase))
            .unwrap_or_else(|e| {
                eprintln!("resolve master key (wrong passphrase?): {e}");
                std::process::exit(1);
            });

    let dir = layout.root.join("conversations");
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        eprintln!("read {}: {e}", dir.display());
        std::process::exit(1);
    });

    let mut touched = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("enc") {
            continue;
        }
        let Ok(bytes) = open_from_path(&path, &master) else {
            continue;
        };
        let Ok(mut conv) = serde_json::from_slice::<Conversation>(&bytes) else {
            continue;
        };
        if let Some(want) = only_group.as_deref() {
            if conv.group_id_hex != want {
                continue;
            }
        }
        let before = conv.current_epoch;
        if bump == 0 {
            // Inspect-only: `--bump 0` must never mutate (this tool is
            // pointed at live vaults during the device proof).
            println!("{} : epoch {before} (inspect only)", conv.group_id_hex);
            touched += 1;
            continue;
        }
        // Advance the epoch + key WITHOUT emitting Welcomes: the peer now
        // seals at an epoch the counterpart cannot open.
        for _ in 0..bump {
            let mut key = [0u8; 32];
            getrandom_key(&mut key);
            conv.advance_epoch(key);
        }
        // Drop prior keys so the counterpart's in-flight frames at the old
        // epoch are equally undecryptable in BOTH directions.
        conv.prior_keys.clear();
        let Ok(out) = serde_json::to_vec(&conv) else {
            continue;
        };
        if let Err(e) = seal_to_path(&path, &out, &master, kdf_id, argon_salt.as_ref()) {
            eprintln!("reseal {}: {e}", path.display());
            continue;
        }
        println!(
            "wedged {} : epoch {} -> {}",
            conv.group_id_hex, before, conv.current_epoch
        );
        touched += 1;
    }
    if touched == 0 {
        eprintln!("no conversations matched (wrong --group, or empty vault)");
        std::process::exit(1);
    }
    if bump == 0 {
        println!("inspected {touched} conversation(s); nothing was modified");
    } else {
        println!("wedged {touched} conversation(s); restart the peer to load them");
    }
}

fn getrandom_key(out: &mut [u8; 32]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(out);
}
