//! Live event stream from the daemon's Server-Sent Events endpoints.
//!
//! x0xd publishes events as plain SSE on several routes:
//!
//! | route               | scope                          |
//! |---------------------|--------------------------------|
//! | `/events`           | unified (subscribed topics)    |
//! | `/direct/events`    | inbound direct messages        |
//! | `/presence/events`  | online/offline transitions     |
//! | `/peers/events`     | low-level peer lifecycle       |
//!
//! Each frame is `event: NAME\ndata: JSON\n\n`. This module parses
//! that wire format and emits typed [`Event`] values.

use crate::contacts::Contact;
use crate::error::{ChatError, Result};
use crate::http::Http;
use crate::identity::AgentId;
use crate::messages::DirectMessage;
use crate::presence::PresenceTransition;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use std::pin::Pin;

/// All event variants this client recognises from the daemon SSE
/// streams. Unrecognised event names are surfaced as [`Event::Other`]
/// so forward-compatibility doesn't drop the connection.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A direct message arrived.
    DirectMessage(DirectMessage),
    /// A presence transition (online/offline).
    Presence(PresenceTransition),
    /// A contact was added locally.
    ContactAdded(Contact),
    /// A contact was removed locally.
    ContactRemoved {
        /// Removed contact's agent id.
        agent_id: AgentId,
    },
    /// A topic-subscribed gossip message arrived.
    GossipMessage {
        /// The topic the message was published on.
        topic: String,
        /// Raw payload bytes (base64-decoded from the SSE frame).
        payload: Vec<u8>,
        /// Sender's agent id, if signed.
        from: Option<AgentId>,
    },
    /// Anything not yet modelled. Carries the raw event name + body
    /// so callers can opt into new variants without a client bump.
    Other {
        /// SSE `event:` name as sent by the daemon.
        event_name: String,
        /// Parsed JSON body.
        data: serde_json::Value,
    },
}

/// A live stream of [`Event`]s.
pub struct EventStream<S> {
    inner: Pin<Box<S>>,
}

impl<S> EventStream<S>
where
    S: Stream<Item = Result<Event>>,
{
    pub(crate) fn from_stream(stream: S) -> Self {
        Self {
            inner: Box::pin(stream),
        }
    }

    /// Pull the next event. Returns `None` when the stream ends.
    pub async fn next(&mut self) -> Option<Result<Event>> {
        self.inner.next().await
    }
}

pub(crate) async fn open_stream(
    http: &Http,
    path: &str,
) -> Result<EventStream<impl Stream<Item = Result<Event>>>> {
    let resp = http.stream_get(path).await?;
    let byte_stream = Box::pin(resp.bytes_stream());
    let stream = sse_frames(byte_stream).filter_map(|frame| async move {
        match frame {
            Ok(f) => decode_frame(&f).transpose(),
            Err(e) => Some(Err(e)),
        }
    });
    Ok(EventStream::from_stream(stream))
}

/// Parsed SSE frame.
#[derive(Debug, Clone, Default)]
struct Frame {
    event: String,
    data: String,
}

fn sse_frames<S>(stream: S) -> impl Stream<Item = Result<Frame>>
where
    S: Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Unpin,
{
    let buf = String::new();
    let cur = Frame::default();
    futures_util::stream::unfold(
        (stream, buf, cur, Vec::<Frame>::new()),
        |(mut s, mut buf, mut cur, mut pending)| async move {
            loop {
                if let Some(f) = pending.pop() {
                    return Some((Ok(f), (s, buf, cur, pending)));
                }
                match s.next().await {
                    None => {
                        if !cur.event.is_empty() || !cur.data.is_empty() {
                            let f = std::mem::take(&mut cur);
                            return Some((Ok(f), (s, buf, cur, pending)));
                        }
                        return None;
                    }
                    Some(Err(e)) => {
                        return Some((Err(ChatError::Transport(e)), (s, buf, cur, pending)))
                    }
                    Some(Ok(chunk)) => {
                        let text = match std::str::from_utf8(&chunk) {
                            Ok(t) => t,
                            Err(e) => {
                                return Some((
                                    Err(ChatError::WebSocket(format!("non-utf8 SSE: {e}"))),
                                    (s, buf, cur, pending),
                                ));
                            }
                        };
                        buf.push_str(text);
                        while let Some(idx) = buf.find('\n') {
                            let raw_line = buf[..idx].trim_end_matches('\r').to_string();
                            buf.drain(..=idx);
                            if raw_line.is_empty() {
                                if !cur.event.is_empty() || !cur.data.is_empty() {
                                    pending.push(std::mem::take(&mut cur));
                                }
                            } else if let Some(rest) = raw_line.strip_prefix("event:") {
                                cur.event = rest.trim().to_string();
                            } else if let Some(rest) = raw_line.strip_prefix("data:") {
                                if !cur.data.is_empty() {
                                    cur.data.push('\n');
                                }
                                cur.data.push_str(rest.trim_start());
                            }
                        }
                    }
                }
            }
        },
    )
}

fn decode_dm(value: serde_json::Value) -> Result<DirectMessage> {
    #[derive(Deserialize)]
    struct Raw {
        sender: AgentId,
        payload: String,
        #[serde(default)]
        received_at: Option<u64>,
        #[serde(default)]
        verified: Option<bool>,
        #[serde(default)]
        message_id: Option<String>,
    }
    #[derive(Deserialize)]
    struct Env {
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        sender_name: Option<String>,
        #[serde(default)]
        ts: Option<u64>,
    }
    let raw: Raw = serde_json::from_value(value)?;
    let env_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &raw.payload)
            .map_err(|e| ChatError::Invalid(format!("dm payload b64: {e}")))?;
    let env: Env = serde_json::from_slice(&env_bytes).unwrap_or(Env {
        text: None,
        sender_name: None,
        ts: None,
    });
    Ok(DirectMessage {
        from: raw.sender,
        to: None,
        body: env.text.unwrap_or_default(),
        sender_name: env.sender_name,
        timestamp_ms: env.ts.or(raw.received_at),
        message_id: raw.message_id,
        verified: raw.verified,
    })
}

fn decode_frame(frame: &Frame) -> Result<Option<Event>> {
    if frame.data.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_str(&frame.data)?;
    let ev = match frame.event.as_str() {
        "dm" | "direct" | "direct_message" => Event::DirectMessage(decode_dm(value)?),
        "presence" => Event::Presence(serde_json::from_value::<PresenceTransition>(value)?),
        "contact_added" => Event::ContactAdded(serde_json::from_value::<Contact>(value)?),
        "contact_removed" => {
            #[derive(Deserialize)]
            struct R {
                agent_id: AgentId,
            }
            let R { agent_id } = serde_json::from_value(value)?;
            Event::ContactRemoved { agent_id }
        }
        "gossip" | "message" => {
            #[derive(Deserialize)]
            struct R {
                topic: String,
                #[serde(default)]
                payload: Option<String>,
                // x0xd emits `sender` (hex string); legacy / test
                // callers use `from`.
                #[serde(default, alias = "sender")]
                from: Option<AgentId>,
            }
            // x0xd's `/subscribe`-forwarder wraps gossip events in an
            // outer `SseEvent { type: "message", data: { topic,
            // payload, sender, … } }` (see `x0xd::SseEvent` +
            // `subscribe` handler). Strip the wrapper if present; the
            // bare shape `{ topic, payload, … }` from older callers
            // and unit tests still parses on the same arm.
            let inner = match (value.get("type"), value.get("data")) {
                (Some(_), Some(data)) if data.is_object() => data.clone(),
                _ => value,
            };
            let R {
                topic,
                payload,
                from,
            } = serde_json::from_value(inner)?;
            let bytes = if let Some(b64) = payload {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                    .map_err(|e| ChatError::Invalid(format!("gossip payload b64: {e}")))?
            } else {
                Vec::new()
            };
            Event::GossipMessage {
                topic,
                payload: bytes,
                from,
            }
        }
        other => Event::Other {
            event_name: other.to_string(),
            data: value,
        },
    };
    Ok(Some(ev))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn frame(event: &str, data: &str) -> Frame {
        Frame {
            event: event.into(),
            data: data.into(),
        }
    }

    #[test]
    fn presence_frame_decodes() {
        let f = frame(
            "presence",
            r#"{"agent_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","event":"online","reachable":true}"#,
        );
        let ev = decode_frame(&f).unwrap().unwrap();
        assert!(matches!(ev, Event::Presence(_)));
    }

    #[test]
    fn direct_message_frame_decodes() {
        let id = "a".repeat(64);
        // The envelope `{"text":"hi","sender_name":"Alice","ts":1}` as base64.
        let payload = "eyJ0ZXh0IjoiaGkiLCJzZW5kZXJfbmFtZSI6IkFsaWNlIiwidHMiOjF9";
        let f = frame(
            "direct_message",
            &format!(r#"{{"sender":"{id}","payload":"{payload}","verified":true}}"#),
        );
        let ev = decode_frame(&f).unwrap().unwrap();
        match ev {
            Event::DirectMessage(dm) => {
                assert_eq!(dm.body, "hi");
                assert_eq!(dm.sender_name.as_deref(), Some("Alice"));
                assert_eq!(dm.verified, Some(true));
            }
            _ => panic!("expected DirectMessage"),
        }
    }

    #[test]
    fn unknown_event_falls_through_to_other() {
        let f = frame("brand_new_thing", r#"{"x":1}"#);
        let ev = decode_frame(&f).unwrap().unwrap();
        match ev {
            Event::Other { event_name, .. } => assert_eq!(event_name, "brand_new_thing"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn empty_data_returns_none() {
        let f = frame("presence", "");
        assert!(decode_frame(&f).unwrap().is_none());
    }

    #[test]
    fn dm_alias_event_names_all_decode() {
        let id = "a".repeat(64);
        // {"text":"hi","sender_name":"Alice","ts":1}
        let payload = "eyJ0ZXh0IjoiaGkiLCJzZW5kZXJfbmFtZSI6IkFsaWNlIiwidHMiOjF9";
        for name in ["dm", "direct", "direct_message"] {
            let f = frame(
                name,
                &format!(r#"{{"sender":"{id}","payload":"{payload}"}}"#),
            );
            match decode_frame(&f).unwrap().unwrap() {
                Event::DirectMessage(dm) => assert_eq!(dm.body, "hi"),
                _ => panic!("expected DirectMessage for event '{name}'"),
            }
        }
    }

    #[test]
    fn dm_with_missing_envelope_fields_yields_empty_body() {
        let id = "a".repeat(64);
        // empty JSON `{}` base64 = "e30="
        let f = frame(
            "direct_message",
            &format!(r#"{{"sender":"{id}","payload":"e30="}}"#),
        );
        match decode_frame(&f).unwrap().unwrap() {
            Event::DirectMessage(dm) => {
                assert_eq!(dm.body, "");
                assert!(dm.sender_name.is_none());
                assert!(dm.verified.is_none());
                assert!(dm.message_id.is_none());
                assert!(dm.to.is_none());
            }
            _ => panic!("expected DirectMessage"),
        }
    }

    #[test]
    fn dm_with_malformed_base64_payload_errors() {
        let id = "a".repeat(64);
        let f = frame(
            "direct_message",
            &format!(r#"{{"sender":"{id}","payload":"@@@not-base64@@@"}}"#),
        );
        let r = decode_frame(&f);
        assert!(r.is_err(), "expected base64 error, got {r:?}");
    }

    #[test]
    fn dm_falls_back_to_received_at_when_envelope_ts_missing() {
        let id = "a".repeat(64);
        // envelope `{"text":"x"}` → "eyJ0ZXh0IjoieCJ9"
        let f = frame(
            "direct_message",
            &format!(
                r#"{{"sender":"{id}","payload":"eyJ0ZXh0IjoieCJ9","received_at":1700000000}}"#
            ),
        );
        match decode_frame(&f).unwrap().unwrap() {
            Event::DirectMessage(dm) => {
                assert_eq!(dm.timestamp_ms, Some(1_700_000_000));
            }
            _ => panic!("expected DirectMessage"),
        }
    }

    #[test]
    fn contact_added_decodes() {
        let id = "c".repeat(64);
        let f = frame(
            "contact_added",
            &format!(r#"{{"agent_id":"{id}","trust_level":"trusted","label":"Bob"}}"#),
        );
        match decode_frame(&f).unwrap().unwrap() {
            Event::ContactAdded(c) => {
                assert_eq!(c.label.as_deref(), Some("Bob"));
            }
            _ => panic!("expected ContactAdded"),
        }
    }

    #[test]
    fn contact_removed_decodes() {
        let id = "d".repeat(64);
        let f = frame("contact_removed", &format!(r#"{{"agent_id":"{id}"}}"#));
        match decode_frame(&f).unwrap().unwrap() {
            Event::ContactRemoved { agent_id } => assert_eq!(agent_id.0, id),
            _ => panic!("expected ContactRemoved"),
        }
    }

    #[test]
    fn gossip_message_decodes_with_base64_payload() {
        // payload "hello" → "aGVsbG8="
        let f = frame("gossip", r#"{"topic":"news","payload":"aGVsbG8="}"#);
        match decode_frame(&f).unwrap().unwrap() {
            Event::GossipMessage { topic, payload, .. } => {
                assert_eq!(topic, "news");
                assert_eq!(payload, b"hello");
            }
            _ => panic!("expected GossipMessage"),
        }
    }

    #[test]
    fn message_event_name_routes_to_gossip() {
        let f = frame("message", r#"{"topic":"t","payload":null}"#);
        assert!(matches!(
            decode_frame(&f).unwrap().unwrap(),
            Event::GossipMessage { .. }
        ));
    }

    /// x0xd's `/subscribe`-forwarder serializes
    /// `SseEvent { type: "message", data: { topic, payload, sender, … } }`
    /// — the inner gossip fields live one level deeper than a bare
    /// `{ topic, payload }` frame. Pin that the decoder unwraps the
    /// envelope and surfaces the inner topic + base64 payload + sender.
    #[test]
    fn x0xd_wrapped_subscribe_frame_decodes_to_gossip() {
        let wire = r#"{
            "type": "message",
            "data": {
                "subscription_id": "abc",
                "topic": "x0x.group.5ffbb3c93daea2e6.meta",
                "payload": "aGVsbG8=",
                "sender": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "verified": true,
                "trust_level": null
            }
        }"#;
        let f = frame("message", wire);
        match decode_frame(&f).unwrap().unwrap() {
            Event::GossipMessage {
                topic,
                payload,
                from,
            } => {
                assert_eq!(topic, "x0x.group.5ffbb3c93daea2e6.meta");
                assert_eq!(payload, b"hello");
                assert_eq!(
                    from.expect("sender alias picked up").0,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                );
            }
            other => panic!("expected GossipMessage, got {other:?}"),
        }
    }

    /// Defence-in-depth: a wrapped frame with no inner `sender`
    /// (e.g. an unsigned admin event) still decodes; `from` is None.
    #[test]
    fn x0xd_wrapped_frame_without_sender_decodes() {
        let wire = r#"{
            "type": "message",
            "data": {
                "topic": "x0x.group.deadbeef00000000.meta",
                "payload": "aGVsbG8="
            }
        }"#;
        let f = frame("message", wire);
        match decode_frame(&f).unwrap().unwrap() {
            Event::GossipMessage { topic, from, .. } => {
                assert_eq!(topic, "x0x.group.deadbeef00000000.meta");
                assert!(from.is_none());
            }
            other => panic!("expected GossipMessage, got {other:?}"),
        }
    }

    /// The decoder must still accept the bare `{ topic, payload }` shape
    /// older tests + direct callers produce. Regression guard so the
    /// wrapper-unwrap doesn't break the existing contract.
    #[test]
    fn bare_gossip_frame_still_decodes_after_unwrap_logic() {
        let f = frame(
            "gossip",
            r#"{"topic":"news","payload":"aGVsbG8=","from":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        );
        match decode_frame(&f).unwrap().unwrap() {
            Event::GossipMessage {
                topic,
                payload,
                from,
            } => {
                assert_eq!(topic, "news");
                assert_eq!(payload, b"hello");
                assert!(from.is_some());
            }
            other => panic!("expected GossipMessage, got {other:?}"),
        }
    }
}
