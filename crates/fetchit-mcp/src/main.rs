//! `fetchit-mcp` binary: MCP stdio transport over the Autonomi network.
//!
//! Reads newline-delimited JSON-RPC from stdin, writes responses to stdout,
//! logs to stderr only. The Autonomi client connects lazily on the first
//! `fetch_render` call so `initialize` responds instantly.
//!
//! Peers: `FETCHIT_MCP_PEERS` (comma-separated multiaddrs / `ip:port`)
//! overrides the bundled `DEFAULT_PEERS`.

use std::io::{BufRead, Write};

use bytes::Bytes;
use fetchit_core::{Address, NetworkClient};
use fetchit_mcp::Server;
use fetchit_net::{AutonomiClient, DEFAULT_PEERS};

/// Connects on first use so the MCP handshake never waits on bootstrap.
struct LazyAutonomi {
    peers: Vec<String>,
    cell: tokio::sync::OnceCell<AutonomiClient>,
}

#[async_trait::async_trait]
impl NetworkClient for LazyAutonomi {
    async fn fetch(&self, addr: &Address) -> fetchit_core::Result<Bytes> {
        let client = self
            .cell
            .get_or_try_init(|| async {
                AutonomiClient::connect(&self.peers)
                    .await
                    .map_err(|e| fetchit_core::Error::Network(e.to_string()))
            })
            .await?;
        client.fetch(addr).await
    }
}

fn peers_from_env() -> Vec<String> {
    match std::env::var("FETCHIT_MCP_PEERS") {
        Ok(raw) if !raw.trim().is_empty() => raw
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => DEFAULT_PEERS.iter().map(ToString::to_string).collect(),
    }
}

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let server = Server::new(LazyAutonomi {
        peers: peers_from_env(),
        cell: tokio::sync::OnceCell::new(),
    });

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    eprintln!("fetchit-mcp: ready (stdio)");
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = runtime.block_on(server.handle_line(&line)) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
