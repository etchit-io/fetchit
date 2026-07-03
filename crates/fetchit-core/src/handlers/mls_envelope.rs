//! Handler for `saorsa-mls/v1` encrypted envelopes — a type seam only.
//!
//! fetch>it recognises the container so shells can render "encrypted
//! content" and offer a decrypt affordance backed by an external key holder
//! (x0xd). **No decrypt path exists here**; keys never enter fetchit-core.
//!
//! Envelope format v1 (this file is the normative reader; etch>it is the
//! publisher):
//!
//! ```text
//! saorsa-mls/v1\n          exact ASCII magic, first line
//! key=value\n              zero or more header lines; only `group=` is
//!                          understood, unknown keys are ignored (forward
//!                          compatibility)
//! \n                       one empty line ends the headers
//! <ciphertext bytes>       opaque, to end of input
//! ```

use bytes::Bytes;

use crate::{Confidence, ContentHandler, Error, Hint, RenderContext, Rendition, Result};

/// First-line magic that claims the envelope.
const MAGIC: &[u8] = b"saorsa-mls/v1\n";

/// Cap on the header region we will scan, in bytes. A missing blank-line
/// separator must not make `render` walk an arbitrarily large body.
const MAX_HEADER_BYTES: usize = 4096;

/// Recognises `saorsa-mls/v1` envelopes and reports their shape.
pub struct MlsEnvelopeHandler;

impl ContentHandler for MlsEnvelopeHandler {
    fn kind(&self) -> &'static str {
        "saorsa-mls/envelope-v1"
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        if head.starts_with(MAGIC) {
            Confidence::Definite
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let rest = bytes.strip_prefix(MAGIC).ok_or_else(|| Error::Render {
            kind: "saorsa-mls/envelope-v1",
            reason: "missing saorsa-mls/v1 magic".to_string(),
        })?;

        let mut group_hint: Option<String> = None;
        let mut offset = 0usize;
        loop {
            let scan = &rest[offset..];
            let Some(newline) = scan
                .iter()
                .take(MAX_HEADER_BYTES.saturating_sub(offset))
                .position(|&b| b == b'\n')
            else {
                return Err(Error::Render {
                    kind: "saorsa-mls/envelope-v1",
                    reason: "no blank line ends the header block".to_string(),
                });
            };
            let line = &scan[..newline];
            offset += newline + 1;
            if line.is_empty() {
                // Blank line: headers end, the rest is ciphertext.
                break;
            }
            let Ok(line) = std::str::from_utf8(line) else {
                return Err(Error::Render {
                    kind: "saorsa-mls/envelope-v1",
                    reason: "header line is not UTF-8".to_string(),
                });
            };
            if let Some(value) = line.strip_prefix("group=") {
                if group_hint.is_none() && !value.is_empty() {
                    group_hint = Some(value.to_string());
                }
            }
            // Unknown header keys are ignored: future publishers may add
            // fields without breaking older readers.
        }

        Ok(Rendition::EncryptedEnvelope {
            group_hint,
            ciphertext_len: rest.len() - offset,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn render(bytes: &[u8]) -> Result<Rendition> {
        MlsEnvelopeHandler.render(Bytes::copy_from_slice(bytes), &RenderContext::default())
    }

    #[test]
    fn claims_definite_on_magic() {
        let c = MlsEnvelopeHandler.can_handle(b"saorsa-mls/v1\n\nct", &Hint::default());
        assert_eq!(c, Confidence::Definite);
    }

    #[test]
    fn refuses_without_magic() {
        let c = MlsEnvelopeHandler.can_handle(b"saorsa-mls/v2\n\nct", &Hint::default());
        assert_eq!(c, Confidence::None);
        let c = MlsEnvelopeHandler.can_handle(b"hello world", &Hint::default());
        assert_eq!(c, Confidence::None);
    }

    #[test]
    fn renders_group_hint_and_ciphertext_len() {
        let r = render(b"saorsa-mls/v1\ngroup=reading-club\n\n\x00\x01\x02\x03").unwrap();
        match r {
            Rendition::EncryptedEnvelope {
                group_hint,
                ciphertext_len,
            } => {
                assert_eq!(group_hint.as_deref(), Some("reading-club"));
                assert_eq!(ciphertext_len, 4);
            }
            other => panic!("wrong rendition: {other:?}"),
        }
    }

    #[test]
    fn renders_without_hint() {
        let r = render(b"saorsa-mls/v1\n\ncipher").unwrap();
        match r {
            Rendition::EncryptedEnvelope {
                group_hint,
                ciphertext_len,
            } => {
                assert!(group_hint.is_none());
                assert_eq!(ciphertext_len, 6);
            }
            other => panic!("wrong rendition: {other:?}"),
        }
    }

    #[test]
    fn unknown_header_keys_are_ignored() {
        let r = render(b"saorsa-mls/v1\nfuture=thing\ngroup=g1\nother=x\n\nct").unwrap();
        match r {
            Rendition::EncryptedEnvelope { group_hint, .. } => {
                assert_eq!(group_hint.as_deref(), Some("g1"));
            }
            other => panic!("wrong rendition: {other:?}"),
        }
    }

    #[test]
    fn missing_blank_line_is_a_render_error() {
        let err = render(b"saorsa-mls/v1\ngroup=g1\nno terminator").unwrap_err();
        assert!(matches!(err, Error::Render { .. }));
    }

    #[test]
    fn empty_ciphertext_is_allowed() {
        let r = render(b"saorsa-mls/v1\n\n").unwrap();
        match r {
            Rendition::EncryptedEnvelope { ciphertext_len, .. } => {
                assert_eq!(ciphertext_len, 0);
            }
            other => panic!("wrong rendition: {other:?}"),
        }
    }

    #[test]
    fn oversized_header_block_errors_instead_of_scanning_forever() {
        let mut bytes = b"saorsa-mls/v1\n".to_vec();
        bytes.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 10));
        let err = render(&bytes).unwrap_err();
        assert!(matches!(err, Error::Render { .. }));
    }
}
