//! Plain UTF-8 text handler.
//!
//! Claims any payload that decodes as UTF-8 and does not contain a NUL
//! byte (the standard "this is binary" smell). The optional UTF-8 BOM
//! is stripped; line endings are preserved verbatim — line-ending
//! normalisation belongs in the renderer.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Renders UTF-8 text.
#[derive(Debug, Default, Clone, Copy)]
pub struct TextHandler;

const KIND: &str = "text/plain";
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(BOM).unwrap_or(bytes)
}

impl ContentHandler for TextHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        let head = strip_bom(head);
        if head.is_empty() {
            return Confidence::Medium;
        }
        if head.contains(&0u8) {
            return Confidence::None;
        }
        if std::str::from_utf8(head).is_ok() {
            Confidence::Medium
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, ctx: &RenderContext) -> Result<Rendition> {
        let stripped = strip_bom(&bytes);
        let cap = ctx.max_text_bytes.min(stripped.len());
        let slice = &stripped[..cap];
        let body = std::str::from_utf8(slice)
            .map_err(|e| Error::Render {
                kind: KIND,
                reason: format!("invalid UTF-8: {e}"),
            })?
            .to_owned();
        // Auto-detect a code language from content shape so UI shells
        // can apply syntax highlighting without doing their own
        // regex passes. Markdown-shaped text was claimed by
        // MarkdownHandler upstream, so this only fires for non-prose
        // text — code, mostly.
        let language = super::lang_detect::detect(&body).map(str::to_owned);
        Ok(Rendition::Text { language, body })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(bytes: &[u8]) -> Confidence {
        TextHandler.can_handle(bytes, &Hint::default())
    }

    fn render(bytes: &[u8]) -> Result<Rendition> {
        TextHandler.render(Bytes::copy_from_slice(bytes), &RenderContext::default())
    }

    #[test]
    fn claims_ascii() {
        assert_eq!(confidence(b"hello world"), Confidence::Medium);
    }

    #[test]
    fn claims_multi_byte_utf8() {
        assert_eq!(confidence("héllo — 世界".as_bytes()), Confidence::Medium);
    }

    #[test]
    fn claims_empty() {
        assert_eq!(confidence(b""), Confidence::Medium);
    }

    #[test]
    fn rejects_bytes_containing_nul() {
        assert_eq!(confidence(b"hello\x00world"), Confidence::None);
    }

    #[test]
    fn rejects_invalid_utf8() {
        let bad = &[0xFFu8, 0xFE, 0xFD][..];
        assert_eq!(confidence(bad), Confidence::None);
    }

    #[test]
    fn strips_utf8_bom_in_render() {
        let with_bom = [&[0xEF, 0xBB, 0xBF][..], b"hello"].concat();
        assert_eq!(confidence(&with_bom), Confidence::Medium);
        let r = render(&with_bom).expect("render");
        match r {
            Rendition::Text { body, .. } => assert_eq!(body, "hello"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn render_truncates_at_max_text_bytes() {
        let bytes = vec![b'a'; 1024];
        let ctx = RenderContext { max_text_bytes: 10 };
        let r = TextHandler
            .render(Bytes::from(bytes), &ctx)
            .expect("render");
        match r {
            Rendition::Text { body, .. } => assert_eq!(body.len(), 10),
            _ => panic!("expected Text"),
        }
    }
}
