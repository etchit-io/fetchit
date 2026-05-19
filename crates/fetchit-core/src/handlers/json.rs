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
    // Only object/array starts — the realistic etch payload shapes.
    // Bare JSON literals (`"…"`, `42`, `true`/`false`/`null`) are
    // syntactically valid but ambiguous with plain-text uploads that
    // start with a quote, a digit, or those words; treating them as
    // text avoids hijacking everyday content.
    matches!(trimmed.as_bytes().first(), Some(b'{' | b'['))
}

impl ContentHandler for JsonHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        if !looks_like_json(head) {
            return Confidence::None;
        }
        // Actually parse the head. EOF means we ran out of bytes
        // mid-valid-JSON (large payload whose tail didn't fit in
        // head) — still claim. Any other error means it isn't JSON;
        // back off so the text fallback can take it. The earlier
        // bug let `{ unquoted_key }` upload-text past the cheap
        // prefilter into a render error instead.
        match serde_json::from_slice::<Value>(head) {
            Ok(_) => Confidence::High,
            Err(e) if e.classify() == serde_json::error::Category::Eof => Confidence::High,
            Err(_) => Confidence::None,
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
    fn does_not_claim_text_starting_with_brace_but_invalid_json() {
        // Regression: prior cheap-prefilter ran render on this and
        // surfaced the user-visible "expected ident at line 1 column 3"
        // error instead of falling back to the text handler.
        assert_eq!(confidence(br#"{ this is plain text, just happens to start with a brace }"#), Confidence::None);
    }

    #[test]
    fn does_not_claim_text_starting_with_letter() {
        // Earlier prefilter matched `t` / `f` / `n` because they could
        // begin `true` / `false` / `null` — hijacking any English word
        // starting with one of them.
        assert_eq!(confidence(b"this cat sat on the mat"), Confidence::None);
        assert_eq!(confidence(b"fancy a coffee?"), Confidence::None);
        assert_eq!(confidence(b"no thanks"), Confidence::None);
    }

    #[test]
    fn claims_truncated_large_json() {
        // Head ends mid-valid-JSON — likely a >head-sized payload.
        // serde_json reports Category::Eof, which we treat as a
        // "still JSON" signal so large files don't get misclassified.
        assert_eq!(confidence(br#"{"key":"value with a very lo"#), Confidence::High);
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
