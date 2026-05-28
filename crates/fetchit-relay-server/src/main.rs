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

    let config = ServerConfig::from_env()?;
    Server::new(config).run().await
}
