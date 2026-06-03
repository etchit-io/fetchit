// SPDX-License-Identifier: AGPL-3.0-only

//! Binary entrypoint — bootstrap config, init tracing, run the server.

use anyhow::Result;
use fetchit_relay_server::group_log::GroupLogStore;
use fetchit_relay_server::transit::TransitStore;
use fetchit_relay_server::{Server, ServerConfig, SqliteGroupLog, SqliteTransitStore};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Registry admin one-shots (only under --features fediverse-inbox):
    // `registry <tombstone|release|get|list>` operates on the ledger DB
    // and exits without starting the server.
    #[cfg(feature = "fediverse-inbox")]
    if fetchit_relay_server::registry_admin::run_if_admin()?.is_some() {
        return Ok(());
    }

    let config = ServerConfig::from_env()?;
    let transit_store: Option<Arc<dyn TransitStore + Send + Sync>> = match &config.transit_db_path {
        Some(path) => {
            let store = SqliteTransitStore::open(
                path,
                config.transit_ttl,
                config.transit_per_recipient,
                config.transit_total_bytes_cap,
            )?;
            tracing::info!(path = %path.display(), "transit: durable sqlite store");
            Some(Arc::new(store))
        }
        None => None,
    };
    // The group log shares the one durable database file with the
    // transit store (separate tables, WAL mode).
    let group_log_store: Option<Arc<dyn GroupLogStore + Send + Sync>> =
        match &config.transit_db_path {
            Some(path) => {
                let store = SqliteGroupLog::open(
                    path,
                    config.group_log_window,
                    config.group_log_per_group_cap,
                    config.group_log_total_bytes_cap,
                )?;
                tracing::info!(path = %path.display(), "group-log: durable sqlite store");
                Some(Arc::new(store))
            }
            None => None,
        };
    let server = Server::new(config);
    let server = match transit_store {
        Some(store) => server.with_transit_store(store),
        None => server,
    };
    let server = match group_log_store {
        Some(store) => server.with_group_log_store(store),
        None => server,
    };
    // M4 Stage 7: opt-in fediverse-inbox role. A no-op (route absent)
    // unless built with `--features fediverse-inbox` AND
    // `FETCHIT_FEDIVERSE_INBOX` is set.
    #[cfg(feature = "fediverse-inbox")]
    let server = fetchit_relay_server::inbox::operator::attach_if_enabled(server)?;
    server.run().await
}
