//! Inline image attachments for chat messages (excellence spec 2.4).
//!
//! An [`Attachment`] rides inside the sealed message payload (no new
//! envelope kind), so it is end-to-end encrypted like any message. The
//! raw image bytes are capped at [`MAX_ATTACHMENT_BYTES`] before base64
//! encoding -- larger images are shared via `autonomi://` instead. The
//! MIME allowlist is raster-only: `image/svg+xml` is rejected because SVG
//! can carry script and would execute when the image is rendered.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Maximum RAW image size (pre-base64) an inline attachment may carry.
///
/// Chosen well under the relay's per-envelope cap
/// (`fetchit_relay_proto::DEFAULT_MAX_ENVELOPE_BYTES`, 1.5 MiB): 256 KiB
/// raw → ~342 KiB base64 → ~350 KiB sealed, roughly 4× headroom. Larger
/// images use the `autonomi://` share path in the UI.
pub const MAX_ATTACHMENT_BYTES: usize = 256 * 1024;

/// MIME types permitted for an inline attachment. Raster formats only --
/// `image/svg+xml` is deliberately excluded (SVG can embed script, an XSS
/// vector when the attachment is rendered).
pub const ALLOWED_ATTACHMENT_MIMES: &[&str] =
    &["image/jpeg", "image/png", "image/webp", "image/gif"];

/// An inline image attachment carried inside a sealed message payload.
///
/// `bytes_b64` is standard base64 (no line wrapping) of the raw image
/// bytes, because the message payload is JSON-serialised before sealing
/// and JSON cannot hold a raw byte string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// MIME type; must be one of [`ALLOWED_ATTACHMENT_MIMES`].
    pub mime: String,
    /// Intrinsic width in pixels (lets the UI reserve layout before the
    /// bytes decode).
    pub width: u32,
    /// Intrinsic height in pixels.
    pub height: u32,
    /// Standard base64 (no line wrapping) of the raw image bytes.
    pub bytes_b64: String,
}

/// Why an [`Attachment`] failed validation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttachmentError {
    /// The MIME type is not in [`ALLOWED_ATTACHMENT_MIMES`].
    #[error("disallowed attachment mime: {0}")]
    DisallowedMime(String),
    /// The declared dimensions are degenerate (zero width or height).
    #[error("attachment has zero width or height")]
    ZeroDimension,
    /// `bytes_b64` was not valid standard base64.
    #[error("attachment base64 is invalid")]
    InvalidBase64,
    /// The decoded raw image exceeds [`MAX_ATTACHMENT_BYTES`].
    #[error("attachment too large: {raw_len} raw bytes (max {max})")]
    TooLarge {
        /// Decoded raw byte length.
        raw_len: usize,
        /// The cap that was exceeded.
        max: usize,
    },
}

impl Attachment {
    /// Build an attachment from raw image bytes, base64-encoding them.
    /// Validates the MIME, dimensions, and size cap before encoding so a
    /// rejected image is never encoded.
    ///
    /// # Errors
    /// Returns an [`AttachmentError`] for a disallowed MIME, zero
    /// dimension, or raw bytes over [`MAX_ATTACHMENT_BYTES`].
    pub fn from_raw(
        mime: &str,
        width: u32,
        height: u32,
        raw: &[u8],
    ) -> Result<Self, AttachmentError> {
        check_mime(mime)?;
        check_dimensions(width, height)?;
        check_len(raw.len())?;
        Ok(Self {
            mime: mime.to_owned(),
            width,
            height,
            bytes_b64: B64.encode(raw),
        })
    }

    /// Validate an attachment received on the wire: allowed MIME,
    /// non-zero dimensions, valid base64, and decoded size within the
    /// cap. Returns the decoded raw bytes so a caller that needs to
    /// render the image does not decode twice.
    ///
    /// # Errors
    /// Returns an [`AttachmentError`] describing the first failed check.
    pub fn validate(&self) -> Result<Vec<u8>, AttachmentError> {
        check_mime(&self.mime)?;
        check_dimensions(self.width, self.height)?;
        let raw = B64
            .decode(self.bytes_b64.as_bytes())
            .map_err(|_| AttachmentError::InvalidBase64)?;
        check_len(raw.len())?;
        Ok(raw)
    }
}

fn check_mime(mime: &str) -> Result<(), AttachmentError> {
    if ALLOWED_ATTACHMENT_MIMES.contains(&mime) {
        Ok(())
    } else {
        Err(AttachmentError::DisallowedMime(mime.to_owned()))
    }
}

fn check_dimensions(width: u32, height: u32) -> Result<(), AttachmentError> {
    if width == 0 || height == 0 {
        Err(AttachmentError::ZeroDimension)
    } else {
        Ok(())
    }
}

fn check_len(raw_len: usize) -> Result<(), AttachmentError> {
    if raw_len > MAX_ATTACHMENT_BYTES {
        Err(AttachmentError::TooLarge {
            raw_len,
            max: MAX_ATTACHMENT_BYTES,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn from_raw_round_trips_through_validate() {
        let raw = vec![0xABu8; 4096];
        let a = Attachment::from_raw("image/png", 64, 48, &raw).unwrap();
        assert_eq!(a.mime, "image/png");
        assert_eq!(a.width, 64);
        assert_eq!(a.height, 48);
        assert_eq!(a.validate().unwrap(), raw);
    }

    #[test]
    fn serde_round_trips() {
        let a = Attachment::from_raw("image/jpeg", 10, 10, b"hello").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        let back: Attachment = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn rejects_svg_mime() {
        let err = Attachment::from_raw("image/svg+xml", 10, 10, b"<svg/>").unwrap_err();
        assert!(matches!(err, AttachmentError::DisallowedMime(m) if m == "image/svg+xml"));
    }

    #[test]
    fn rejects_arbitrary_mime() {
        let err = Attachment::from_raw("application/pdf", 10, 10, b"%PDF").unwrap_err();
        assert!(matches!(err, AttachmentError::DisallowedMime(_)));
    }

    #[test]
    fn rejects_zero_dimension() {
        assert!(matches!(
            Attachment::from_raw("image/png", 0, 10, b"x").unwrap_err(),
            AttachmentError::ZeroDimension
        ));
        assert!(matches!(
            Attachment::from_raw("image/png", 10, 0, b"x").unwrap_err(),
            AttachmentError::ZeroDimension
        ));
    }

    #[test]
    fn from_raw_rejects_oversize() {
        let raw = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
        assert!(matches!(
            Attachment::from_raw("image/jpeg", 10, 10, &raw).unwrap_err(),
            AttachmentError::TooLarge { raw_len, max }
                if raw_len == MAX_ATTACHMENT_BYTES + 1 && max == MAX_ATTACHMENT_BYTES
        ));
    }

    #[test]
    fn from_raw_accepts_exactly_cap() {
        let raw = vec![0u8; MAX_ATTACHMENT_BYTES];
        assert!(Attachment::from_raw("image/webp", 1, 1, &raw).is_ok());
    }

    #[test]
    fn validate_rejects_oversize_on_the_wire() {
        // Hand-craft a wire attachment whose base64 decodes over the cap,
        // bypassing the from_raw guard, to prove the receive-side check.
        let raw = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
        let forged = Attachment {
            mime: "image/png".to_owned(),
            width: 1,
            height: 1,
            bytes_b64: B64.encode(&raw),
        };
        assert!(matches!(
            forged.validate().unwrap_err(),
            AttachmentError::TooLarge { .. }
        ));
    }

    #[test]
    fn validate_rejects_bad_base64() {
        let bad = Attachment {
            mime: "image/png".to_owned(),
            width: 1,
            height: 1,
            bytes_b64: "not valid base64 !!!".to_owned(),
        };
        assert!(matches!(
            bad.validate().unwrap_err(),
            AttachmentError::InvalidBase64
        ));
    }

    #[test]
    fn validate_rejects_disallowed_mime_on_the_wire() {
        let forged = Attachment {
            mime: "image/svg+xml".to_owned(),
            width: 1,
            height: 1,
            bytes_b64: B64.encode(b"<svg/>"),
        };
        assert!(matches!(
            forged.validate().unwrap_err(),
            AttachmentError::DisallowedMime(_)
        ));
    }
}
