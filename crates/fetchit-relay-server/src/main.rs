//! Binary entrypoint — bootstrap config, init tracing, run the server.

use anyhow::Result;
use fetchit_relay_server::{Server, ServerConfig};

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
    let server = Server::new(config);
    // M4 Stage 7: opt-in fediverse-inbox role. A no-op (route absent)
    // unless built with `--features fediverse-inbox` AND
    // `FETCHIT_FEDIVERSE_INBOX` is set.
    #[cfg(feature = "fediverse-inbox")]
    let server = fetchit_relay_server::inbox::operator::attach_if_enabled(server)?;
    server.run().await
}
