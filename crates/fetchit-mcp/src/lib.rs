//! Minimal MCP (Model Context Protocol) stdio server over `fetchit-core`.
//!
//! Gives AI agents safe, read-only access to Autonomi content: fetch an
//! immutable address, classify it with fetch>it's handler registry, and
//! return a typed, text-safe summary. Binary payloads are described (kind,
//! MIME, size), never returned. No wallet, no writes, no active content.
//!
//! The protocol layer is hand-rolled and deliberately small: newline-delimited
//! JSON-RPC 2.0 with `initialize`, `ping`, `tools/list`, and `tools/call`.
//! Local-stdio prototype; MCPB bundling is the upgrade path if this is ever
//! distributed.

use base64::Engine as _;
use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use std::sync::Arc;

use fetchit_core::{
    Address, HandlerRegistry, Hint, NetworkClient, RenderContext, RenderingContext, Rendition,
};
use fetchit_trust_types::{DenylistQuery, EntryKind};
use serde_json::{json, Value};

/// Protocol revision offered when the client requests one we don't know.
pub const PROTOCOL_FALLBACK: &str = "2024-11-05";

/// Protocol revisions we echo back verbatim.
const KNOWN_PROTOCOLS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

/// Soft cap on text bodies returned to the agent, in bytes.
pub const TEXT_CAP: usize = 64 * 1024;

/// Hard cap on `detect` input after base64 decoding.
const MAX_DETECT_BYTES: usize = 32 * 1024 * 1024;

/// Rows / entries included in tabular and archive summaries.
const LIST_CAP: usize = 100;

/// Cap on the in-memory byte cache. Addresses are immutable, so cached
/// bytes are always correct; the cap only bounds memory.
const MAX_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// Insertion-order byte cache for immutable address content.
struct ByteCache {
    map: std::collections::HashMap<Address, Bytes>,
    order: std::collections::VecDeque<Address>,
    total: usize,
}

impl ByteCache {
    fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            total: 0,
        }
    }

    fn get(&self, addr: &Address) -> Option<Bytes> {
        self.map.get(addr).cloned()
    }

    fn insert(&mut self, addr: Address, bytes: &Bytes) {
        if bytes.len() > MAX_CACHE_BYTES || self.map.contains_key(&addr) {
            return;
        }
        while self.total.saturating_add(bytes.len()) > MAX_CACHE_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.map.remove(&oldest) {
                self.total = self.total.saturating_sub(evicted.len());
            }
        }
        self.total = self.total.saturating_add(bytes.len());
        self.order.push_back(addr);
        self.map.insert(addr, bytes.clone());
    }
}

/// MCP server state: a network client plus the handler registry.
pub struct Server<C> {
    client: C,
    registry: HandlerRegistry,
    denylist: Option<Arc<dyn DenylistQuery>>,
    cache: std::sync::Mutex<ByteCache>,
}

impl<C: NetworkClient> Server<C> {
    /// Build a server over any [`NetworkClient`] with the default handlers.
    pub fn new(client: C) -> Self {
        Self {
            client,
            registry: default_registry(),
            denylist: None,
            cache: std::sync::Mutex::new(ByteCache::new()),
        }
    }

    /// Install a community denylist; blocked addresses are refused before
    /// any bytes are fetched, mirroring the human shells.
    #[must_use]
    pub fn with_denylist(mut self, denylist: Arc<dyn DenylistQuery>) -> Self {
        self.denylist = Some(denylist);
        self
    }

    /// Handle one newline-delimited JSON-RPC message.
    ///
    /// Returns `None` for notifications (no response goes on the wire).
    pub async fn handle_line(&self, line: &str) -> Option<String> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(error_response(&Value::Null, -32700, "parse error")),
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let Some(id) = id else {
            // Notification (e.g. notifications/initialized): never respond.
            return None;
        };
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let response = match method {
            "initialize" => result_response(&id, &initialize_result(&params)),
            "ping" => result_response(&id, &json!({})),
            "tools/list" => result_response(&id, &json!({ "tools": tool_definitions() })),
            "tools/call" => self.handle_tool_call(&id, &params).await,
            _ => error_response(&id, -32601, "method not found"),
        };
        Some(response)
    }

    async fn handle_tool_call(&self, id: &Value, params: &Value) -> String {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let outcome = match name {
            "detect" => self.tool_detect(&args),
            "fetch_render" => self.tool_fetch_render(&args).await,
            _ => return error_response(id, -32602, "unknown tool"),
        };
        match outcome {
            Ok(summary) => result_response(
                id,
                &json!({
                    "content": [{ "type": "text", "text": summary.to_string() }],
                    "isError": false,
                }),
            ),
            Err(message) => result_response(
                id,
                &json!({
                    "content": [{ "type": "text", "text": message }],
                    "isError": true,
                }),
            ),
        }
    }

    fn tool_detect(&self, args: &Value) -> Result<Value, String> {
        let b64 = args
            .get("bytes_base64")
            .and_then(Value::as_str)
            .ok_or("missing required argument: bytes_base64")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("bytes_base64 is not valid base64: {e}"))?;
        if bytes.len() > MAX_DETECT_BYTES {
            return Err(format!(
                "input too large: {} bytes (cap {MAX_DETECT_BYTES})",
                bytes.len()
            ));
        }
        let total = bytes.len();
        let rendition = self
            .registry
            .render(
                Bytes::from(bytes),
                &Hint::default(),
                &RenderContext::default(),
            )
            .map_err(|e| format!("render failed: {e}"))?;
        Ok(summarize(&rendition, total))
    }

    async fn tool_fetch_render(&self, args: &Value) -> Result<Value, String> {
        let raw = args
            .get("address")
            .and_then(Value::as_str)
            .ok_or("missing required argument: address")?;
        let normalized = normalize_address(raw);
        // Core's parse error already reads "invalid Autonomi address: …";
        // pass it through instead of stacking a second prefix on it.
        let addr: Address = normalized
            .parse()
            .map_err(|e: fetchit_core::Error| e.to_string())?;
        let hex = addr.to_hex();

        // Denylist gate BEFORE any bytes move: an agent must not be able to
        // pull blocked content, and we should not spend bandwidth on it.
        if let Some(denylist) = &self.denylist {
            if denylist.is_blocked(EntryKind::XorName, &hex) {
                return Ok(json!({
                    "kind": "blocked",
                    "reason": format!("xor_name: {hex}"),
                    "address": hex,
                }));
            }
        }

        // Addresses are immutable, so the cache is always correct.
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&addr);
        let bytes = if let Some(bytes) = cached {
            bytes
        } else {
            let fetched = self
                .client
                .fetch(&addr)
                .await
                .map_err(|e| format!("fetch failed: {e}"))?;
            self.cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(addr, &fetched);
            fetched
        };

        let total = bytes.len();
        // Belt-and-braces: the registry re-runs the same denylist gate and
        // will cover further entry kinds as they land.
        let rendering_ctx = RenderingContext {
            denylist: self.denylist.clone(),
            addr_hex: Some(hex.clone()),
        };
        let rendition = self
            .registry
            .render_with_context(
                bytes,
                &Hint::default(),
                &RenderContext::default(),
                &rendering_ctx,
            )
            .map_err(|e| format!("render failed: {e}"))?;
        let mut summary = summarize(&rendition, total);
        if let Some(map) = summary.as_object_mut() {
            map.insert("address".into(), Value::String(hex));
        }
        Ok(summary)
    }
}

/// Strip `autonomi://` prefixes, whitespace, and a trailing slash.
#[must_use]
pub fn normalize_address(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("autonomi://").unwrap_or(s);
    let s = s.strip_suffix('/').unwrap_or(s);
    s.to_string()
}

fn initialize_result(params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_FALLBACK);
    let version = if KNOWN_PROTOCOLS.contains(&requested) {
        requested
    } else {
        PROTOCOL_FALLBACK
    };
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "fetchit-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "fetch_render",
            "description": "Fetch an immutable Autonomi address (64 hex chars; autonomi:// prefix accepted) and render it to a typed, text-safe summary. Read-only. Binary payloads are described (kind, MIME, size), never returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Autonomi address: 64 hex characters, with or without the autonomi:// prefix",
                    },
                },
                "required": ["address"],
            },
        },
        {
            "name": "detect",
            "description": "Classify and render local bytes with fetch>it's content handlers. No network. Binary renditions return metadata only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bytes_base64": {
                        "type": "string",
                        "description": "Base64 (standard alphabet) of the bytes to classify",
                    },
                },
                "required": ["bytes_base64"],
            },
        },
    ])
}

/// Map a [`Rendition`] to a text-safe JSON summary.
///
/// Text-family bodies are included up to [`TEXT_CAP`] bytes with a
/// `truncated` flag; binary payloads are described, never inlined.
#[must_use]
pub fn summarize(rendition: &Rendition, total_bytes: usize) -> Value {
    match rendition {
        Rendition::Text { language, body } => {
            text_summary("text", language.as_deref(), body, total_bytes)
        }
        Rendition::Html { body } => text_summary("html", None, body, total_bytes),
        Rendition::EtchitEnvelope {
            title,
            content,
            language,
        } => {
            let mut v = text_summary("etchit-envelope", language.as_deref(), content, total_bytes);
            if let Some(map) = v.as_object_mut() {
                map.insert("title".into(), Value::String(title.clone()));
            }
            v
        }
        Rendition::Json { value } => {
            let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
            text_summary("json", None, &pretty, total_bytes)
        }
        Rendition::EncryptedEnvelope {
            group_hint,
            ciphertext_len,
        } => json!({
            "kind": "encrypted-envelope",
            "bytes": total_bytes,
            "ciphertext_bytes": ciphertext_len,
            "group_hint": group_hint,
            "note": "saorsa-mls/v1 envelope; fetch>it does not hold keys and cannot decrypt",
        }),
        Rendition::Tabular { columns, rows } => json!({
            "kind": "tabular",
            "bytes": total_bytes,
            "columns": columns,
            "row_count": rows.len(),
            "rows": rows.iter().take(LIST_CAP).collect::<Vec<_>>(),
        }),
        Rendition::Archive { entries } => json!({
            "kind": "archive",
            "bytes": total_bytes,
            "entry_count": entries.len(),
            "entries": entries
                .iter()
                .take(LIST_CAP)
                .map(|e| json!({ "path": e.path, "size": e.size }))
                .collect::<Vec<_>>(),
        }),
        Rendition::Image { mime, data } => binary_summary("image", mime, data.len()),
        Rendition::Audio { mime, data } => binary_summary("audio", mime, data.len()),
        Rendition::Video { mime, data } => binary_summary("video", mime, data.len()),
        Rendition::Pdf { data } => binary_summary("pdf", "application/pdf", data.len()),
        Rendition::OpaqueBinary { mime, data } => binary_summary("binary", mime, data.len()),
        Rendition::Blocked { reason } => json!({
            "kind": "blocked",
            "bytes": total_bytes,
            "reason": reason,
        }),
        _ => json!({ "kind": "unknown", "bytes": total_bytes }),
    }
}

fn text_summary(kind: &str, language: Option<&str>, body: &str, total_bytes: usize) -> Value {
    let (body, truncated) = truncate_utf8(body);
    json!({
        "kind": kind,
        "bytes": total_bytes,
        "language": language,
        "truncated": truncated,
        "body": body,
    })
}

fn binary_summary(kind: &str, mime: &str, len: usize) -> Value {
    json!({
        "kind": kind,
        "mime": mime,
        "bytes": len,
        "note": "binary payload not returned; fetch with a fetch>it shell to view",
    })
}

fn truncate_utf8(body: &str) -> (&str, bool) {
    if body.len() <= TEXT_CAP {
        return (body, false);
    }
    let mut end = TEXT_CAP;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    (&body[..end], true)
}

fn result_response(id: &Value, result: &Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: &Value, code: i64, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fetchit_core::network::MockClient;

    fn server() -> Server<MockClient> {
        Server::new(MockClient::new())
    }

    fn call(line: &str) -> Option<Value> {
        let srv = server();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(srv.handle_line(line))
            .map(|s| serde_json::from_str(&s).unwrap())
    }

    #[test]
    fn initialize_echoes_known_protocol_and_names_server() {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        )
        .unwrap();
        let result = &resp["result"];
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert_eq!(result["serverInfo"]["name"], "fetchit-mcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn initialize_falls_back_on_unknown_protocol() {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"9999-01-01"}}"#,
        )
        .unwrap();
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_FALLBACK);
    }

    #[test]
    fn initialized_notification_gets_no_response() {
        assert!(call(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
    }

    #[test]
    fn tools_list_exposes_both_tools_with_schemas() {
        let resp = call(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"fetch_render"));
        assert!(names.contains(&"detect"));
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let resp = call(r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn parse_error_returns_minus_32700() {
        let resp = call("this is not json").unwrap();
        assert_eq!(resp["error"]["code"], -32700);
    }

    #[test]
    fn detect_classifies_png_magic_as_image_metadata_only() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];
        let b64 = base64::engine::general_purpose::STANDARD.encode(png);
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"detect","arguments":{{"bytes_base64":"{b64}"}}}}}}"#
        );
        let resp = call(&line).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let summary: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(summary["kind"], "image");
        assert_eq!(summary["mime"], "image/png");
        assert!(summary.get("body").is_none());
    }

    #[test]
    fn fetch_render_returns_text_body_via_network_client() {
        let hex = "aa".repeat(32);
        let addr: Address = hex.parse().unwrap();
        let client = MockClient::new();
        client.insert(addr, Bytes::from_static(b"hello from autonomi"));
        let srv = Server::new(client);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"fetch_render","arguments":{{"address":"autonomi://{hex}"}}}}}}"#
        );
        let resp: Value =
            serde_json::from_str(&rt.block_on(srv.handle_line(&line)).unwrap()).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let summary: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(summary["kind"], "text");
        assert_eq!(summary["body"], "hello from autonomi");
        assert_eq!(summary["address"], hex);
    }

    #[test]
    fn fetch_render_rejects_bad_address_as_tool_error() {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fetch_render","arguments":{"address":"not-hex"}}}"#,
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains("invalid Autonomi address: invalid Autonomi address"),
            "error prefix doubled: {text}"
        );
        assert!(text.contains("invalid Autonomi address"));
    }

    #[test]
    fn unknown_tool_is_invalid_params() {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{}}}"#,
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[test]
    fn summarize_truncates_large_text_on_char_boundary() {
        let body = "é".repeat(TEXT_CAP); // 2 bytes per char, well past the cap
        let r = Rendition::Text {
            language: None,
            body,
        };
        let v = summarize(&r, TEXT_CAP * 2);
        assert_eq!(v["truncated"], true);
        assert!(v["body"].as_str().unwrap().len() <= TEXT_CAP);
        // still valid UTF-8 by construction; parse proves it round-trips
        assert!(v["body"].as_str().is_some());
    }

    #[test]
    fn summarize_encrypted_envelope_reports_shape_without_payload() {
        let r = Rendition::EncryptedEnvelope {
            group_hint: Some("reading-club".into()),
            ciphertext_len: 1088,
        };
        let v = summarize(&r, 1200);
        assert_eq!(v["kind"], "encrypted-envelope");
        assert_eq!(v["ciphertext_bytes"], 1088);
        assert_eq!(v["group_hint"], "reading-club");
        assert!(v.get("body").is_none());
    }

    /// Counts fetches so cache/denylist tests can assert network use.
    struct CountingClient {
        inner: MockClient,
        count: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl fetchit_core::NetworkClient for CountingClient {
        async fn fetch(&self, addr: &Address) -> fetchit_core::Result<bytes::Bytes> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.fetch(addr).await
        }
    }

    struct StubDenylist(String);

    impl DenylistQuery for StubDenylist {
        fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
            kind == EntryKind::XorName && value == self.0
        }
    }

    fn fetch_line(hex: &str, id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"fetch_render","arguments":{{"address":"{hex}"}}}}}}"#
        )
    }

    #[test]
    fn denylisted_address_is_blocked_before_any_fetch() {
        let hex = "bb".repeat(32);
        let addr: Address = hex.parse().unwrap();
        let inner = MockClient::new();
        inner.insert(addr, Bytes::from_static(b"should never be seen"));
        let client = CountingClient {
            inner,
            count: std::sync::atomic::AtomicUsize::new(0),
        };
        let srv = Server::new(client).with_denylist(Arc::new(StubDenylist(hex.clone())));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let resp: Value =
            serde_json::from_str(&rt.block_on(srv.handle_line(&fetch_line(&hex, 10))).unwrap())
                .unwrap();
        let summary: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(summary["kind"], "blocked");
        assert!(summary.get("body").is_none());
        assert_eq!(
            srv.client.count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "blocked address must not be fetched"
        );
    }

    #[test]
    fn repeat_fetches_are_served_from_cache() {
        let hex = "cc".repeat(32);
        let addr: Address = hex.parse().unwrap();
        let inner = MockClient::new();
        inner.insert(addr, Bytes::from_static(b"cache me"));
        let client = CountingClient {
            inner,
            count: std::sync::atomic::AtomicUsize::new(0),
        };
        let srv = Server::new(client);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for id in [11, 12] {
            let resp: Value =
                serde_json::from_str(&rt.block_on(srv.handle_line(&fetch_line(&hex, id))).unwrap())
                    .unwrap();
            assert_eq!(resp["result"]["isError"], false);
        }
        assert_eq!(
            srv.client.count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "second fetch must come from the cache"
        );
    }

    #[test]
    fn summarize_blocked_names_the_reason() {
        let r = Rendition::Blocked {
            reason: "xor_name: abcd".into(),
        };
        let v = summarize(&r, 0);
        assert_eq!(v["kind"], "blocked");
        assert_eq!(v["reason"], "xor_name: abcd");
    }

    #[test]
    fn normalize_address_strips_prefix_and_slash() {
        assert_eq!(normalize_address(" autonomi://abc/ "), "abc");
        assert_eq!(normalize_address("abc"), "abc");
    }
}
