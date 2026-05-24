// SPDX-License-Identifier: AGPL-3.0-only
//
// fetch>it CLI — command-line driver over fetchit-core + fetchit-net.
// Copyright (C) the fetch>it contributors.

//! `fetchit` — command-line driver for `fetchit-core` + `fetchit-net`.
//!
//! Subcommands:
//!
//! * `fetchit detect <FILE>` — runs the default handler registry on
//!   local bytes. No network. Useful for ground-truthing handler
//!   behaviour.
//! * `fetchit get <ADDR>` — connects to the Autonomi network and
//!   renders the addressed content. Defaults to the bundled production
//!   bootstrap peers; override with `--peer` (repeatable).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use fetchit_core::handlers::default_registry;
use fetchit_core::{Address, Hint, NetworkClient, RenderContext, Rendition};
use fetchit_net::{set_data_home, AutonomiClient, DEFAULT_PEERS};

#[derive(Debug, Parser)]
#[command(
    name = "fetchit",
    version,
    about = "fetch>it — read-only viewer for the Autonomi network.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run handler detection on a local file.
    Detect {
        /// Path to the file to classify and render.
        file: PathBuf,
        /// Override the soft cap on rendered text/JSON, in bytes.
        #[arg(long)]
        max_bytes: Option<usize>,
    },
    /// Get the bytes at an Autonomi address and render them.
    Get {
        /// 64-character lowercase-hex Autonomi address.
        addr: String,
        /// Bootstrap peer (repeatable). Accepts `ip:port` shorthand or
        /// a full `/ip4/.../udp/.../quic` multiaddr. Defaults to the
        /// bundled production peer list when not supplied.
        #[arg(long = "peer", value_name = "ADDR")]
        peers: Vec<String>,
        /// Override `HOME`/`XDG_DATA_HOME`. Required on platforms
        /// where the shell does not set `HOME` (e.g. Android).
        #[arg(long)]
        data_home: Option<PathBuf>,
        /// Override the soft cap on rendered text/JSON, in bytes.
        #[arg(long)]
        max_bytes: Option<usize>,
        /// Stream the download to this path instead of rendering.
        /// Switches the underlying call from `data_download` (returns
        /// `Bytes`, no progress) to `file_download_with_progress`
        /// (writes to disk, emits progress events) — the same path
        /// the `ant` CLI uses, for apples-to-apples benchmarking.
        #[arg(long, value_name = "PATH")]
        to: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Detect { file, max_bytes } => match run_detect(&file, max_bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("fetchit: {e:#}");
                ExitCode::from(1)
            }
        },
        Command::Get {
            addr,
            peers,
            data_home,
            max_bytes,
            to,
        } => run_get(&addr, peers, data_home.as_deref(), max_bytes, to.as_deref()),
    }
}

fn run_detect(path: &Path, max_bytes: Option<usize>) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut ctx = RenderContext::default();
    if let Some(n) = max_bytes {
        ctx.max_text_bytes = n;
    }
    let rendition = default_registry()
        .render(Bytes::from(bytes), &Hint::default(), &ctx)
        .context("default registry produced no rendition")?;
    print_rendition(&rendition);
    Ok(())
}

fn run_get(
    addr: &str,
    peer_overrides: Vec<String>,
    data_home: Option<&Path>,
    max_bytes: Option<usize>,
    to: Option<&Path>,
) -> ExitCode {
    let parsed = match addr.parse::<Address>() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fetchit: {e}");
            return ExitCode::from(1);
        }
    };

    if let Some(path) = data_home {
        set_data_home(path);
    }

    let peers: Vec<String> = if peer_overrides.is_empty() {
        DEFAULT_PEERS.iter().map(|s| (*s).to_owned()).collect()
    } else {
        peer_overrides
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fetchit: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let to_owned = to.map(Path::to_path_buf);
    runtime.block_on(async move {
        eprintln!("fetchit: connecting to {} bootstrap peer(s)…", peers.len());
        let client = match AutonomiClient::connect(&peers).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("fetchit: connect failed: {e}");
                return ExitCode::from(1);
            }
        };
        eprintln!("fetchit: connected ({} peer(s))", client.peer_count().await);

        eprintln!("fetchit: fetching {parsed}…");
        if let Some(out_path) = to_owned {
            // Stream-to-disk path — matches `ant file download`'s call
            // shape exactly. Progress events are accepted but discarded
            // so stderr stays quiet enough for benchmark timings.
            match client
                .fetch_with_progress(&parsed, &out_path, |_| {})
                .await
            {
                Ok(()) => {
                    let bytes = std::fs::metadata(&out_path).map_or(0, |m| m.len());
                    eprintln!("fetchit: wrote {bytes} bytes to {}", out_path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("fetchit: fetch failed: {e}");
                    ExitCode::from(1)
                }
            }
        } else {
            let bytes = match client.fetch(&parsed).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("fetchit: fetch failed: {e}");
                    return ExitCode::from(1);
                }
            };
            let mut ctx = RenderContext::default();
            if let Some(n) = max_bytes {
                ctx.max_text_bytes = n;
            }
            match default_registry().render(bytes, &Hint::default(), &ctx) {
                Ok(rendition) => {
                    print_rendition(&rendition);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("fetchit: render failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
    })
}

fn print_rendition(r: &Rendition) {
    match r {
        Rendition::Text { language, body } => {
            println!("kind: text/plain");
            if let Some(lang) = language {
                println!("language: {lang}");
            }
            println!("bytes: {}", body.len());
            println!("---");
            println!("{}", preview_text(body, 2_000));
        }
        Rendition::Image { mime, data }
        | Rendition::Audio { mime, data }
        | Rendition::Video { mime, data } => {
            println!("kind: {mime}");
            println!("bytes: {}", data.len());
        }
        Rendition::Pdf { data } => {
            println!("kind: application/pdf");
            println!("bytes: {}", data.len());
        }
        Rendition::Json { value } => {
            println!("kind: application/json");
            match serde_json::to_string_pretty(value) {
                Ok(s) => {
                    println!("---");
                    println!("{}", preview_text(&s, 2_000));
                }
                Err(e) => println!("(could not pretty-print: {e})"),
            }
        }
        Rendition::Tabular { columns, rows } => {
            println!("kind: text/csv");
            println!("columns: {}", columns.len());
            println!("rows: {}", rows.len());
        }
        Rendition::Archive { entries } => {
            println!("kind: application/archive");
            println!("entries: {}", entries.len());
        }
        Rendition::EtchitEnvelope {
            title,
            content,
            language,
        } => {
            println!("kind: etchit/envelope-v1");
            println!("title: {title}");
            if let Some(lang) = language {
                println!("language: {lang}");
            }
            println!("bytes: {}", content.len());
            println!("---");
            println!("{}", preview_text(content, 2_000));
        }
        Rendition::OpaqueBinary { mime, data } => {
            println!("kind: {mime}");
            println!("bytes: {}", data.len());
            println!("---");
            println!("{}", hex_preview(data, 64));
        }
        Rendition::Html { body } => {
            println!("kind: text/html");
            println!("bytes: {}", body.len());
            println!("---");
            println!("{}", preview_text(body, 4_000));
        }
        // Rendition is #[non_exhaustive]; future variants print a
        // generic header so the CLI never panics on a new kind.
        _ => println!("kind: (unknown rendition variant)"),
    }
}

fn preview_text(body: &str, cap: usize) -> String {
    if body.len() <= cap {
        body.to_owned()
    } else {
        let truncated: String = body.chars().take(cap).collect();
        format!("{truncated}\n... [truncated, total {} bytes]", body.len())
    }
}

fn hex_preview(data: &[u8], cap: usize) -> String {
    let take = data.len().min(cap);
    let mut hex = String::with_capacity(take * 3);
    for b in &data[..take] {
        let _ = write!(hex, "{b:02x} ");
    }
    if data.len() > cap {
        let _ = write!(hex, "... [+{} bytes]", data.len() - cap);
        hex
    } else {
        hex.trim_end().to_owned()
    }
}
