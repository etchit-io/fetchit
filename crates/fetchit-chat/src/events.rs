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
use crate::identity::AgentId;
use crate::messages::DirectMessage;
use crate::presence::PresenceTransition;
use crate::transport::Http;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use std::pin::Pin;

/// All event variants this client recognises from the daemon SSE
/// streams. Unrecognised event names are surfaced as [`Event::Other`]
/// so forward-compatibility doesn't drop the connection.
#[derive(Debug, Clone)]
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
        kind: String,
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
        Self { inner: Box::pin(stream) }
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
                    Some(Err(e)) => return Some((Err(ChatError::Transport(e)), (s, buf, cur, pending))),
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

fn decode_frame(frame: &Frame) -> Result<Option<Event>> {
    if frame.data.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_str(&frame.data)?;
    let ev = match frame.event.as_str() {
        "dm" | "direct" | "direct_message" => {
            Event::DirectMessage(serde_json::from_value::<DirectMessage>(value)?)
        }
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
                #[serde(default)]
                from: Option<AgentId>,
            }
            let R { topic, payload, from } = serde_json::from_value(value)?;
            let bytes = if let Some(b64) = payload {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                    .map_err(|e| ChatError::Invalid(format!("gossip payload b64: {e}")))?
            } else {
                Vec::new()
            };
            Event::GossipMessage { topic, payload: bytes, from }
        }
        other => Event::Other {
            kind: other.to_string(),
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
        Frame { event: event.into(), data: data.into() }
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
        let f = frame(
            "direct_message",
            &format!(r#"{{"from":"{id}","to":"{id}","body":"hi"}}"#),
        );
        let ev = decode_frame(&f).unwrap().unwrap();
        assert!(matches!(ev, Event::DirectMessage(_)));
    }

    #[test]
    fn unknown_event_falls_through_to_other() {
        let f = frame("brand_new_thing", r#"{"x":1}"#);
        let ev = decode_frame(&f).unwrap().unwrap();
        match ev {
            Event::Other { kind, .. } => assert_eq!(kind, "brand_new_thing"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn empty_data_returns_none() {
        let f = frame("presence", "");
        assert!(decode_frame(&f).unwrap().is_none());
    }
}
