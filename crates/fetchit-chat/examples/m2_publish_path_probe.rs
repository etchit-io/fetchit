//! Measure encrypt-only latency for Path A and publish-only latency for
//! Path B against a live x0xd. Decision 1 of M2 spec was settled by
//! architectural reasoning (transport unification), not by this measure
//! — this binary is a future-reproducibility tool. Set
//! `X0XD_PROBE_GROUP_ID` and `X0XD_PROBE_TOPIC` to a pre-created
//! private-secure group + its chat topic, then:
//!     cargo run -p fetchit-chat --example `m2_publish_path_probe`

use std::time::Instant;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow::anyhow!("required env var {name} is not set"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let home = std::env::var("HOME")?;
    let port_file = env_or(
        "X0XD_PORT_FILE",
        &format!("{home}/.local/share/x0x-claude-here/api.port"),
    );
    let token_path = env_or(
        "X0XD_TOKEN_PATH",
        &format!("{home}/.local/share/x0x-claude-here/api-token"),
    );
    let group_id = env_required("X0XD_PROBE_GROUP_ID")?;
    let topic = env_required("X0XD_PROBE_TOPIC")?;

    let token = std::fs::read_to_string(&token_path)?.trim().to_string();
    let port_line = std::fs::read_to_string(&port_file)?;
    let port = port_line
        .trim()
        .split(':')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed api.port: expected host:port"))?
        .to_string();
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();

    let path_a_start = Instant::now();
    let _enc = http
        .post(format!("{base}/groups/{group_id}/secure/encrypt"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"payload_b64": "aGVsbG8="}))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    let path_a = path_a_start.elapsed();
    println!("path_a encrypt-only: {}us", path_a.as_micros());

    let path_b_start = Instant::now();
    let _pub = http
        .post(format!("{base}/publish"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"topic": topic, "payload": "aGVsbG8="}))
        .send()
        .await?
        .error_for_status()?;
    let path_b = path_b_start.elapsed();
    println!("path_b publish-only: {}us", path_b.as_micros());

    Ok(())
}
