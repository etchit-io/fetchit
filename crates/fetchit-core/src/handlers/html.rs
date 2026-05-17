//! HTML document handler. Detects self-contained HTML pages by their
//! opening signatures and emits [`Rendition::Html`] so the UI can
//! render them through a `WebView` (or `<iframe>` in the future
//! browser viewer) rather than show source code.
//!
//! Detection is intentionally narrow — only "this is *meant* to be a
//! webpage" content (DOCTYPE, leading `<html`, XML preamble) claims
//! the bytes. HTML fragments embedded in larger payloads stay text.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Recognises self-contained HTML / XHTML documents.
#[derive(Debug, Default, Clone, Copy)]
pub struct HtmlHandler;

const KIND: &str = "text/html";
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(BOM).unwrap_or(bytes)
}

fn looks_like_html(text: &str) -> bool {
    let trimmed = text.trim_start();
    let head = trimmed.get(..256).unwrap_or(trimmed).to_ascii_lowercase();
    head.starts_with("<!doctype html")
        || head.starts_with("<html")
        || head.starts_with("<?xml")
        || head.contains("<html")
}

impl ContentHandler for HtmlHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        let head = strip_bom(head);
        if head.is_empty() || head.contains(&0u8) {
            return Confidence::None;
        }
        let Ok(text) = std::str::from_utf8(head) else {
            return Confidence::None;
        };
        if looks_like_html(text) {
            Confidence::Definite
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, ctx: &RenderContext) -> Result<Rendition> {
        let stripped = strip_bom(&bytes);
        let cap = ctx.max_text_bytes.min(stripped.len());
        let body = std::str::from_utf8(&stripped[..cap])
            .map_err(|e| Error::Render {
                kind: KIND,
                reason: format!("invalid UTF-8: {e}"),
            })?
            .to_owned();
        Ok(Rendition::Html { body })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(text: &str) -> Confidence {
        HtmlHandler.can_handle(text.as_bytes(), &Hint::default())
    }

    fn render(text: &str) -> Rendition {
        HtmlHandler
            .render(
                Bytes::copy_from_slice(text.as_bytes()),
                &RenderContext::default(),
            )
            .expect("html handler should not error on UTF-8")
    }

    #[test]
    fn claims_html5_doctype() {
        assert_eq!(
            confidence("<!DOCTYPE html>\n<html><body>hi</body></html>"),
            Confidence::Definite,
        );
        match render("<!DOCTYPE html><html><body>hi</body></html>") {
            Rendition::Html { body } => assert!(body.contains("body")),
            other => panic!("expected Html, got {other:?}"),
        }
    }

    #[test]
    fn claims_lowercase_doctype() {
        assert_eq!(
            confidence("<!doctype html>\n<html></html>"),
            Confidence::Definite,
        );
    }

    #[test]
    fn claims_bare_html_tag() {
        assert_eq!(
            confidence("<html lang=\"en\"></html>"),
            Confidence::Definite
        );
    }

    #[test]
    fn claims_xhtml_xml_preamble() {
        assert_eq!(
            confidence(
                "<?xml version=\"1.0\"?>\n<html xmlns=\"http://www.w3.org/1999/xhtml\"></html>"
            ),
            Confidence::Definite,
        );
    }

    #[test]
    fn rejects_plain_text() {
        assert_eq!(
            confidence("just some prose, nothing tagged."),
            Confidence::None
        );
    }

    #[test]
    fn rejects_html_fragment_only() {
        // `<div>` alone isn't a document — stays text.
        assert_eq!(confidence("<div>fragment</div>"), Confidence::None);
    }

    #[test]
    fn rejects_binary() {
        let bytes: &[u8] = &[0x89, 0x50, 0x4E, 0x47];
        assert_eq!(
            HtmlHandler.can_handle(bytes, &Hint::default()),
            Confidence::None,
        );
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(""), Confidence::None);
    }
}
