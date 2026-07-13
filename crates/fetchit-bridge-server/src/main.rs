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
    let server = Server::new(config, store);
    server.run().await?;
    Ok(())
}
