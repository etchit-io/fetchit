//! `fetchit-mcp` binary: MCP stdio transport over the Autonomi network.
//!
//! Reads newline-delimited JSON-RPC from stdin, writes responses to stdout,
//! logs to stderr only. The Autonomi client connects lazily on the first
//! `fetch_render` call so `initialize` responds instantly.
//!
//! Peers: `FETCHIT_MCP_PEERS` (comma-separated multiaddrs / `ip:port`)
//! overrides the bundled `DEFAULT_PEERS`.
//!
//! Denylist: set `FETCHIT_MCP_TRUST_URL` (e.g. `https://etchit.io/v1`) to
//! fetch the signed community denylist at startup and refuse blocked
//! addresses, same as the human shells. Unset = no denylist (local use).

use std::io::{BufRead, Write};
use std::sync::Arc;

use bytes::Bytes;
use fetchit_core::{Address, NetworkClient};
use fetchit_mcp::Server;
use fetchit_net::{AutonomiClient, DEFAULT_PEERS};
use fetchit_trust_client::{etchitio_pubkey, DenylistConsumer, ReqwestClient};
use fetchit_trust_types::DenylistQuery;

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

/// Build the community-denylist gate when `FETCHIT_MCP_TRUST_URL` is set.
///
/// One verified refresh at startup; MCP sessions are short-lived, so a
/// background poll loop buys nothing here.
fn denylist_from_env(runtime: &tokio::runtime::Runtime) -> Option<Arc<dyn DenylistQuery>> {
    let url = std::env::var("FETCHIT_MCP_TRUST_URL").ok()?;
    let url = url.trim().to_string();
    if url.is_empty() {
        return None;
    }
    let consumer = Arc::new(DenylistConsumer::new(etchitio_pubkey(), url, None));
    match ReqwestClient::new() {
        Ok(http) => {
            if let Err(e) = runtime.block_on(consumer.refresh(&http)) {
                eprintln!("fetchit-mcp: denylist refresh failed (continuing unblocked): {e}");
            } else {
                eprintln!("fetchit-mcp: community denylist active");
            }
        }
        Err(e) => eprintln!("fetchit-mcp: denylist http client failed: {e}"),
    }
    Some(consumer as Arc<dyn DenylistQuery>)
}

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let mut server = Server::new(LazyAutonomi {
        peers: peers_from_env(),
        cell: tokio::sync::OnceCell::new(),
    });
    if let Some(denylist) = denylist_from_env(&runtime) {
        server = server.with_denylist(denylist);
    }

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
