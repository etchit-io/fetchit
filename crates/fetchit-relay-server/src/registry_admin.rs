//! Admin CLI for the registry ledger (feature-gated). A thin layer over
//! [`crate::registry::SqliteActorStore`] so a future admin GUI reuses the
//! SAME primitives. Operates on the DB at `FETCHIT_REGISTRY_DB` and exits
//! without starting the relay server.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::registry::{ActorRegistryStore, SqliteActorStore};

#[derive(Parser)]
#[command(name = "fetchit-relay-server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Registry directory admin (operates on `FETCHIT_REGISTRY_DB`).
    #[command(subcommand)]
    Registry(RegistryCmd),
}

#[derive(Subcommand)]
enum RegistryCmd {
    /// Erase a handle's identity data and HOLD the name (GDPR). The name
    /// stays blocked from self-serve until `release` or a paid re-issue.
    Tombstone {
        /// The handle to erase + hold.
        handle: String,
    },
    /// Re-pool a HELD handle so it returns to self-serve registration.
    Release {
        /// The handle to re-pool.
        handle: String,
    },
    /// Show a handle's status: active record, held, or absent.
    Get {
        /// The handle to inspect.
        handle: String,
    },
    /// List every handle in the ledger with its status.
    List,
}

/// Run a registry admin subcommand if argv requests one. Returns
/// `Ok(Some(()))` when an admin command was handled (the caller should
/// exit), `Ok(None)` when argv is a normal server launch.
///
/// # Errors
/// Surfaces DB-open / store errors; clap exits the process directly on a
/// parse error, `--help`, or `--version`.
pub fn run_if_admin() -> Result<Option<()>> {
    let Some(Command::Registry(cmd)) = Cli::parse().command else {
        return Ok(None);
    };
    let db =
        std::env::var("FETCHIT_REGISTRY_DB").unwrap_or_else(|_| "fetchit-registry.db".to_owned());
    let store = SqliteActorStore::open(&db).map_err(|e| anyhow!("open registry db {db}: {e}"))?;
    match cmd {
        RegistryCmd::Tombstone { handle } => {
            store
                .tombstone(&handle, crate::forwarding::now_ms())
                .map_err(|e| anyhow!("{e}"))?;
            println!("tombstoned + held: {handle}");
        }
        RegistryCmd::Release { handle } => {
            store.release(&handle).map_err(|e| anyhow!("{e}"))?;
            println!("released to self-serve: {handle}");
        }
        RegistryCmd::Get { handle } => {
            if let Some(r) = store.get(&handle) {
                println!(
                    "active  {handle}  agent={}  url={}",
                    r.agent_id_hex, r.actor_url
                );
            } else if store.is_held(&handle).map_err(|e| anyhow!("{e}"))? {
                println!("held    {handle}");
            } else {
                println!("absent  {handle}");
            }
        }
        RegistryCmd::List => {
            for (handle, held) in store.list_handles().map_err(|e| anyhow!("{e}"))? {
                println!("{}  {handle}", if held { "held  " } else { "active" });
            }
        }
    }
    Ok(Some(()))
}
