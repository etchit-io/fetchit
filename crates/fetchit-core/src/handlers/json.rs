//! Generic JSON handler. Parses with `serde_json`; emits a
//! [`Rendition::Json`] carrying the parsed tree so the UI can show a
//! tree view as well as the pretty-printed string.

use bytes::Bytes;
use serde_json::Value;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Recognises any payload that parses as a JSON value.
///
/// Order this **after** [`EtchitEnvelopeHandler`](super::EtchitEnvelopeHandler) —
/// envelopes are JSON, but they want the dedicated handler. The
/// confidence levels (Definite for envelope, High for plain JSON)
/// resolve this without explicit ordering, but registering envelope
/// first keeps the priority intent clear in code.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonHandler;

const KIND: &str = "application/json";

fn looks_like_json(head: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(head) else {
        return false;
    };
    let trimmed = s.trim_start();
    matches!(
        trimmed.as_bytes().first(),
        Some(b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n')
    )
}

impl ContentHandler for JsonHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        if looks_like_json(head) {
            // Cheap structural pre-filter; full validation in render.
            Confidence::High
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| Error::Render {
            kind: KIND,
            reason: format!("not valid JSON: {e}"),
        })?;
        Ok(Rendition::Json { value })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(bytes: &[u8]) -> Confidence {
        JsonHandler.can_handle(bytes, &Hint::default())
    }

    fn render(bytes: &[u8]) -> Result<Rendition> {
        JsonHandler.render(Bytes::copy_from_slice(bytes), &RenderContext::default())
    }

    #[test]
    fn claims_object() {
        assert_eq!(confidence(br#"{"x":1}"#), Confidence::High);
        let r = render(br#"{"x":1}"#).expect("render");
        match r {
            Rendition::Json { value } => assert_eq!(value["x"], 1),
            _ => panic!("expected Json"),
        }
    }

    #[test]
    fn claims_array() {
        assert_eq!(confidence(b"[1,2,3]"), Confidence::High);
        let r = render(b"[1,2,3]").expect("render");
        match r {
            Rendition::Json { value } => assert_eq!(value.as_array().unwrap().len(), 3),
            _ => panic!("expected Json"),
        }
    }

    #[test]
    fn claims_with_leading_whitespace() {
        assert_eq!(confidence(b"   {\"x\":1}"), Confidence::High);
    }

    #[test]
    fn does_not_claim_plain_text() {
        assert_eq!(confidence(b"hello world"), Confidence::None);
    }

    #[test]
    fn does_not_claim_binary() {
        assert_eq!(confidence(&[0xFF, 0xD8, 0xFF]), Confidence::None);
    }

    #[test]
    fn render_rejects_trailing_comma() {
        let err = render(br#"{"x":1,}"#).expect_err("should reject");
        assert!(matches!(err, Error::Render { kind: KIND, .. }));
    }
}
