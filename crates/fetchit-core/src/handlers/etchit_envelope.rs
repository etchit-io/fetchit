//! Handler for the etch/it JSON envelope:
//! `{"v":1,"meta":{"title":"...","lang":""},"content":"..."}`.
//!
//! Reference: etchit's `PasteUtils.kt` writes this shape from the
//! Android client. We parse it strictly with `serde_json` rather than
//! the regex/string-search dance the Kotlin uses — Rust's `serde_json`
//! handles escaping and edge cases by construction.

use bytes::Bytes;
use serde::Deserialize;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Parses the etch/it v1 envelope.
#[derive(Debug, Default, Clone, Copy)]
pub struct EtchitEnvelopeHandler;

const KIND: &str = "etchit/envelope-v1";

#[derive(Debug, Deserialize)]
struct Envelope {
    v: u32,
    meta: Meta,
    content: String,
}

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    title: String,
    #[serde(default)]
    lang: String,
}

impl ContentHandler for EtchitEnvelopeHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        let Ok(text) = std::str::from_utf8(head) else {
            return Confidence::None;
        };
        let trimmed = text.trim_start();
        if !trimmed.starts_with('{') {
            return Confidence::None;
        }
        // Cheap structural sniff: an envelope must mention both keys.
        // Full validation happens in render. Avoids parsing the entire
        // payload during detection on every fetch.
        if trimmed.contains("\"v\"")
            && trimmed.contains("\"meta\"")
            && trimmed.contains("\"content\"")
        {
            Confidence::Definite
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|e| Error::Render {
            kind: KIND,
            reason: format!("envelope JSON parse failed: {e}"),
        })?;
        if envelope.v != 1 {
            return Err(Error::Render {
                kind: KIND,
                reason: format!("unsupported envelope version: {}", envelope.v),
            });
        }
        // etchit-android currently ships `lang: ""` for every etch.
        // To still render markdown-shaped notes nicely, fall back to
        // the same content heuristic the standalone MarkdownHandler
        // uses. An explicit `lang` always wins over the heuristic.
        let language = if envelope.meta.lang.is_empty() {
            if super::markdown::looks_like_markdown(&envelope.content) {
                Some("markdown".to_owned())
            } else {
                None
            }
        } else {
            Some(envelope.meta.lang)
        };
        Ok(Rendition::EtchitEnvelope {
            title: envelope.meta.title,
            content: envelope.content,
            language,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn render(bytes: &[u8]) -> Result<Rendition> {
        EtchitEnvelopeHandler.render(Bytes::copy_from_slice(bytes), &RenderContext::default())
    }

    fn confidence(bytes: &[u8]) -> Confidence {
        EtchitEnvelopeHandler.can_handle(bytes, &Hint::default())
    }

    #[test]
    fn parses_minimal_envelope() {
        let raw = br#"{"v":1,"meta":{"title":"hello","lang":""},"content":"world"}"#;
        assert_eq!(confidence(raw), Confidence::Definite);
        let r = render(raw).expect("should render");
        match r {
            Rendition::EtchitEnvelope {
                title,
                content,
                language,
            } => {
                assert_eq!(title, "hello");
                assert_eq!(content, "world");
                assert_eq!(language, None);
            }
            _ => panic!("expected EtchitEnvelope variant"),
        }
    }

    #[test]
    fn detects_markdown_in_envelope_with_empty_lang() {
        // etchit-android always writes lang: "" — we recover markdown
        // rendering for envelope content shaped like markdown.
        // Using `br##` so the embedded `"#` (the heading marker
        // adjacent to a quote) doesn't terminate the raw byte string.
        let raw = br##"{"v":1,"meta":{"title":"notes","lang":""},"content":"# heading\n\n- one\n- two\n"}"##;
        match render(raw).expect("should render") {
            Rendition::EtchitEnvelope { language, .. } => {
                assert_eq!(language, Some("markdown".to_owned()));
            }
            _ => panic!("expected EtchitEnvelope variant"),
        }
    }

    #[test]
    fn does_not_force_markdown_for_plain_envelope_content() {
        // No markdown markers — envelope stays untagged.
        let raw = br#"{"v":1,"meta":{"title":"plain","lang":""},"content":"just some prose, nothing fancy."}"#;
        match render(raw).expect("should render") {
            Rendition::EtchitEnvelope { language, .. } => {
                assert_eq!(language, None);
            }
            _ => panic!("expected EtchitEnvelope variant"),
        }
    }

    #[test]
    fn parses_envelope_with_language() {
        let raw = br#"{"v":1,"meta":{"title":"snippet","lang":"rust"},"content":"fn main(){}"}"#;
        let r = render(raw).expect("should render");
        match r {
            Rendition::EtchitEnvelope { language, .. } => {
                assert_eq!(language, Some("rust".into()));
            }
            _ => panic!("expected EtchitEnvelope variant"),
        }
    }

    #[test]
    fn handles_escaped_content() {
        let raw = br#"{"v":1,"meta":{"title":"q","lang":""},"content":"line1\nline2\t\"quoted\""}"#;
        let r = render(raw).expect("should render");
        match r {
            Rendition::EtchitEnvelope { content, .. } => {
                assert_eq!(content, "line1\nline2\t\"quoted\"");
            }
            _ => panic!("expected EtchitEnvelope variant"),
        }
    }

    #[test]
    fn rejects_wrong_version() {
        let raw = br#"{"v":2,"meta":{"title":"x","lang":""},"content":"y"}"#;
        // Sniff still says definite (looks envelope-shaped); render must reject.
        assert_eq!(confidence(raw), Confidence::Definite);
        let err = render(raw).expect_err("should reject v2");
        assert!(matches!(err, Error::Render { kind: KIND, .. }));
    }

    #[test]
    fn rejects_missing_required_field() {
        let raw = br#"{"v":1,"meta":{"title":"x","lang":""}}"#;
        let err = render(raw).expect_err("should reject");
        assert!(matches!(err, Error::Render { .. }));
    }

    #[test]
    fn rejects_malformed_json() {
        let raw = br#"{"v":1,"meta":{"title":"x"#;
        let err = render(raw).expect_err("should reject");
        assert!(matches!(err, Error::Render { .. }));
    }

    #[test]
    fn does_not_claim_plain_json() {
        let raw = br#"{"foo":"bar","baz":42}"#;
        assert_eq!(confidence(raw), Confidence::None);
    }

    #[test]
    fn does_not_claim_image_bytes() {
        let raw = b"\x89PNG\r\n\x1a\n\x00\x00";
        assert_eq!(confidence(raw), Confidence::None);
    }

    #[test]
    fn tolerates_leading_whitespace() {
        let raw = br#"   {"v":1,"meta":{"title":"x","lang":""},"content":"y"}"#;
        assert_eq!(confidence(raw), Confidence::Definite);
    }
}
