//! Markdown handler. Heuristically detects markdown-shaped UTF-8
//! text and tags it with `language: "markdown"` so UI shells render
//! it through a markdown engine (Markwon on Android, future browser
//! `<article>` for the WASM viewer).
//!
//! Detection is fuzzy because Autonomi is content-addressed — we have
//! no filename. We score the leading bytes for typical markdown
//! markers (headings, code fences, lists, links, bold) and claim
//! the content if any strong marker fires or the score crosses a
//! threshold. Plain prose without markdown punctuation falls through
//! to [`TextHandler`](super::TextHandler).

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Recognises markdown-shaped UTF-8 text.
#[derive(Debug, Default, Clone, Copy)]
pub struct MarkdownHandler;

const KIND: &str = "text/markdown";
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(BOM).unwrap_or(bytes)
}

/// Score a slice of UTF-8 text for markdown-shape signals.
///
/// Strong markers (ATX headings, fenced code blocks) are decisive on
/// their own. Weaker markers (bullet lists, blockquotes, link syntax,
/// bold/italic) accumulate to a threshold. Calibrated to keep plain
/// prose with the occasional asterisk out of the markdown bucket.
///
/// `pub(crate)` so the etch/it envelope handler can recover markdown
/// rendering for envelopes whose `lang` was left empty by the writer.
pub(crate) fn looks_like_markdown(text: &str) -> bool {
    let mut score = 0;
    let mut had_heading = false;
    let mut had_fence = false;

    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("# ")
            || trimmed.starts_with("## ")
            || trimmed.starts_with("### ")
            || trimmed.starts_with("#### ")
        {
            had_heading = true;
        }
        if trimmed.starts_with("```") {
            had_fence = true;
        }
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("+ ") {
            score += 1;
        }
        if trimmed.starts_with("> ") {
            score += 1;
        }
    }

    // Inline syntax markers — weak, only count once.
    if text.contains("](") {
        score += 1;
    }
    if text.matches("**").count() >= 2 {
        score += 1;
    }

    had_heading || had_fence || score >= 3
}

impl ContentHandler for MarkdownHandler {
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
        if looks_like_markdown(text) {
            // High beats TextHandler's Medium so markdown wins for
            // content that has both UTF-8 shape and markdown signals.
            Confidence::High
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
        Ok(Rendition::Text {
            language: Some("markdown".to_owned()),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(text: &str) -> Confidence {
        MarkdownHandler.can_handle(text.as_bytes(), &Hint::default())
    }

    fn render(text: &str) -> Rendition {
        MarkdownHandler
            .render(
                Bytes::copy_from_slice(text.as_bytes()),
                &RenderContext::default(),
            )
            .expect("markdown handler should not error on UTF-8")
    }

    #[test]
    fn claims_with_atx_heading() {
        assert_eq!(confidence("# hello\n\nbody."), Confidence::High);
        match render("# hello\n\nbody.") {
            Rendition::Text { language, .. } => {
                assert_eq!(language, Some("markdown".to_owned()));
            }
            other => panic!("expected Text variant, got {other:?}"),
        }
    }

    #[test]
    fn claims_with_code_fence() {
        let md = "```rust\nfn main(){}\n```\n";
        assert_eq!(confidence(md), Confidence::High);
    }

    #[test]
    fn claims_with_multiple_weak_markers() {
        // 1 list bullet + 1 link + 1 blockquote = score 3
        let md = "- item one\n\n[a link](https://x)\n\n> a quote\n";
        assert_eq!(confidence(md), Confidence::High);
    }

    #[test]
    fn rejects_plain_prose() {
        let prose = "This is just a paragraph of regular prose with \
            nothing markdown about it. Nothing to see here, move along.";
        assert_eq!(confidence(prose), Confidence::None);
    }

    #[test]
    fn rejects_single_bullet() {
        // One list item alone shouldn't be enough.
        assert_eq!(confidence("- single item\n"), Confidence::None);
    }

    #[test]
    fn rejects_inline_asterisks_alone() {
        // "**" exists but only once, no other markers.
        assert_eq!(
            confidence("This has ** in it but isn't markdown."),
            Confidence::None,
        );
    }

    #[test]
    fn rejects_binary() {
        // Inline-bytes here aren't valid UTF-8, so from_utf8 falls back
        // to the empty string. That's intentional — the test is asserting
        // markdown detection on a non-text payload doesn't fire, and the
        // empty string is the safest "looks like text but isn't" sample.
        #[allow(invalid_from_utf8)]
        let s = std::str::from_utf8(&[0u8, 0xFF, 0x42]).unwrap_or("");
        assert_eq!(confidence(s), Confidence::None);
    }

    #[test]
    fn rejects_with_nul() {
        let bytes: &[u8] = b"# heading\x00\nbody";
        assert_eq!(
            MarkdownHandler.can_handle(bytes, &Hint::default()),
            Confidence::None,
        );
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(""), Confidence::None);
    }

    #[test]
    fn strong_marker_wins_over_threshold() {
        // A single heading is enough on its own.
        assert_eq!(confidence("# only heading\n"), Confidence::High);
    }
}
