//! Binary fallback handler.
//!
//! Always returns [`Confidence::Low`] — meaning every other handler
//! gets first refusal. Uses the `infer` crate to guess a MIME from
//! magic bytes; falls back to `application/octet-stream` if nothing
//! matches.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::Result;

/// Last-resort handler. Wraps unrecognised bytes in
/// [`Rendition::OpaqueBinary`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BinaryHandler;

const KIND: &str = "application/octet-stream";

fn sniff_mime(head: &[u8]) -> String {
    infer::get(head).map_or_else(|| KIND.to_owned(), |t| t.mime_type().to_owned())
}

impl ContentHandler for BinaryHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, _head: &[u8], _hint: &Hint) -> Confidence {
        Confidence::Low
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let mime = sniff_mime(&bytes[..bytes.len().min(64)]);
        Ok(Rendition::OpaqueBinary { mime, data: bytes })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn render(bytes: &[u8]) -> Rendition {
        BinaryHandler
            .render(Bytes::copy_from_slice(bytes), &RenderContext::default())
            .expect("binary handler never fails")
    }

    #[test]
    fn always_low_confidence() {
        assert_eq!(
            BinaryHandler.can_handle(b"anything", &Hint::default()),
            Confidence::Low
        );
        assert_eq!(
            BinaryHandler.can_handle(b"", &Hint::default()),
            Confidence::Low
        );
        assert_eq!(
            BinaryHandler.can_handle(&[0xFF; 8], &Hint::default()),
            Confidence::Low
        );
    }

    #[test]
    fn renders_unknown_as_octet_stream() {
        let r = render(&[0xAA, 0xBB, 0xCC, 0xDD]);
        match r {
            Rendition::OpaqueBinary { mime, .. } => {
                assert_eq!(mime, "application/octet-stream");
            }
            _ => panic!("expected OpaqueBinary"),
        }
    }

    #[test]
    fn detects_pdf_via_infer() {
        let pdf = b"%PDF-1.4\n%aaa\n";
        let r = render(pdf);
        match r {
            Rendition::OpaqueBinary { mime, .. } => assert_eq!(mime, "application/pdf"),
            _ => panic!("expected OpaqueBinary"),
        }
    }

    #[test]
    fn passes_bytes_through_unchanged() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let r = render(&bytes);
        match r {
            Rendition::OpaqueBinary { data, .. } => assert_eq!(data.as_ref(), bytes.as_slice()),
            _ => panic!("expected OpaqueBinary"),
        }
    }
}
