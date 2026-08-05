//! Binary entrypoint — load config, open the store, run the server.

use fetchit_bridge_server::config::BridgeConfig;
use fetchit_bridge_server::server::Server;
use fetchit_bridge_server::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let config = BridgeConfig::from_env()?;
    let store = Store::open(&config.db_path)?;
    // Inside the runtime, so the consumer's poll loop has somewhere to
    // live; before `run`, so the gate is enforcing the cached snapshot
    // from the first accepted delivery onward.
    let denylist = fetchit_bridge_server::denylist::install(&config)?;
    let server = Server::new(config, store);
    let server = match denylist {
        Some(d) => server.with_denylist(d),
        None => server,
    };
    server.run().await?;
    Ok(())
}
