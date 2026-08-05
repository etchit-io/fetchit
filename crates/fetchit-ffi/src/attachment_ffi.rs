//! [`ChatAttachmentFfi`] -- an inline image on a DM, as the shell sees it.
//!
//! The uniffi mirror of [`fetchit_chat::attachment::Attachment`] with one
//! deliberate difference: the shell handles RAW bytes, never base64.
//! Base64 is a wire encoding forced by the JSON message payload, so it is
//! applied on the way out and stripped on the way in AT THIS BOUNDARY --
//! Kotlin gets exactly the bytes `BitmapFactory` takes, and never spends a
//! main-thread millisecond re-encoding a quarter-megabyte string.
//!
//! Both directions run through the engine's validation
//! ([`fetchit_chat::attachment::Attachment::from_raw`] outbound,
//! [`fetchit_chat::attachment::Attachment::validate`] inbound), so the
//! MIME allowlist (raster only -- SVG can carry script), the non-zero
//! dimensions, and the 256 `KiB` raw cap hold on every crossing. An
//! inbound attachment that fails any of them is dropped to `None` rather
//! than surfaced: the message still renders, minus an image the shell
//! could not have drawn safely anyway.

use crate::chat_error::ChatFfiError;
use fetchit_chat::attachment::Attachment;

/// An inline image carried inside a sealed (end-to-end encrypted) DM.
///
/// `width` / `height` are the image's intrinsic pixel dimensions, carried
/// alongside the bytes so a shell can reserve the right amount of layout
/// before it decodes anything.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatAttachmentFfi {
    /// MIME type; one of [`fetchit_chat::attachment::ALLOWED_ATTACHMENT_MIMES`].
    pub mime: String,
    /// Intrinsic width in pixels.
    pub width: u32,
    /// Intrinsic height in pixels.
    pub height: u32,
    /// RAW (already base64-decoded) image bytes, at most
    /// [`fetchit_chat::attachment::MAX_ATTACHMENT_BYTES`].
    pub bytes: Vec<u8>,
}

impl ChatAttachmentFfi {
    /// Validate + base64-encode for the wire.
    ///
    /// # Errors
    /// [`ChatFfiError::Invalid`] when the MIME is not on the raster
    /// allowlist, a dimension is zero, or the bytes exceed
    /// [`fetchit_chat::attachment::MAX_ATTACHMENT_BYTES`]. The shell gets
    /// the engine's own message so it can tell the user which it was.
    pub(crate) fn to_engine(&self) -> Result<Attachment, ChatFfiError> {
        Attachment::from_raw(&self.mime, self.width, self.height, &self.bytes).map_err(|e| {
            ChatFfiError::Invalid {
                reason: e.to_string(),
            }
        })
    }

    /// Decode a wire attachment for the shell, or `None` when it does not
    /// validate. A sender is not trusted to have obeyed the cap or the
    /// allowlist, and a vault written by an older build is not trusted
    /// either -- both arrive here, and both must degrade to "no image".
    pub(crate) fn from_engine(att: &Attachment) -> Option<Self> {
        let bytes = att.validate().ok()?;
        Some(Self {
            mime: att.mime.clone(),
            width: att.width,
            height: att.height,
            bytes,
        })
    }
}

/// Map an optional engine attachment into the FFI shape, dropping one that
/// fails validation. The single helper every inbound / history projection
/// calls, so "a bad attachment is no attachment" is decided in one place.
pub(crate) fn attachment_to_ffi(att: Option<&Attachment>) -> Option<ChatAttachmentFfi> {
    att.and_then(ChatAttachmentFfi::from_engine)
}

/// Map an optional shell attachment to the engine shape, validating it.
///
/// # Errors
/// [`ChatFfiError::Invalid`] from [`ChatAttachmentFfi::to_engine`].
pub(crate) fn attachment_from_ffi(
    att: Option<&ChatAttachmentFfi>,
) -> Result<Option<Attachment>, ChatFfiError> {
    att.map(ChatAttachmentFfi::to_engine).transpose()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use fetchit_chat::attachment::MAX_ATTACHMENT_BYTES;

    fn png(len: usize) -> Vec<u8> {
        vec![0x89; len]
    }

    #[test]
    fn round_trips_raw_bytes_across_the_boundary() {
        let raw = png(1024);
        let ffi = ChatAttachmentFfi {
            mime: "image/png".to_owned(),
            width: 320,
            height: 240,
            bytes: raw.clone(),
        };
        let engine = ffi.to_engine().unwrap();
        // The wire copy is base64; the shell copy is raw.
        assert_ne!(engine.bytes_b64.as_bytes(), raw.as_slice());
        let back = ChatAttachmentFfi::from_engine(&engine).unwrap();
        assert_eq!(back, ffi);
    }

    #[test]
    fn to_engine_rejects_a_disallowed_mime() {
        let ffi = ChatAttachmentFfi {
            mime: "image/svg+xml".to_owned(),
            width: 8,
            height: 8,
            bytes: b"<svg/>".to_vec(),
        };
        let err = ffi.to_engine().unwrap_err();
        assert!(
            matches!(&err, ChatFfiError::Invalid { reason } if reason.contains("svg")),
            "{err:?}",
        );
    }

    #[test]
    fn to_engine_rejects_oversize_bytes() {
        let ffi = ChatAttachmentFfi {
            mime: "image/jpeg".to_owned(),
            width: 8,
            height: 8,
            bytes: png(MAX_ATTACHMENT_BYTES + 1),
        };
        assert!(ffi.to_engine().is_err());
    }

    #[test]
    fn to_engine_rejects_zero_dimensions() {
        let ffi = ChatAttachmentFfi {
            mime: "image/jpeg".to_owned(),
            width: 0,
            height: 8,
            bytes: png(16),
        };
        assert!(ffi.to_engine().is_err());
    }

    #[test]
    fn from_engine_drops_an_attachment_that_fails_validation() {
        // A hostile peer's payload: valid base64, disallowed MIME.
        let forged = Attachment {
            mime: "image/svg+xml".to_owned(),
            width: 4,
            height: 4,
            bytes_b64: "PHN2Zy8+".to_owned(),
        };
        assert_eq!(ChatAttachmentFfi::from_engine(&forged), None);
        assert_eq!(attachment_to_ffi(Some(&forged)), None);
    }

    #[test]
    fn from_engine_drops_corrupt_base64() {
        let forged = Attachment {
            mime: "image/png".to_owned(),
            width: 4,
            height: 4,
            bytes_b64: "not base64 !!".to_owned(),
        };
        assert_eq!(ChatAttachmentFfi::from_engine(&forged), None);
    }

    #[test]
    fn none_maps_to_none_in_both_directions() {
        assert_eq!(attachment_to_ffi(None), None);
        assert_eq!(attachment_from_ffi(None).unwrap(), None);
    }

    #[test]
    fn attachment_from_ffi_surfaces_validation_errors() {
        let bad = ChatAttachmentFfi {
            mime: "application/pdf".to_owned(),
            width: 4,
            height: 4,
            bytes: b"%PDF".to_vec(),
        };
        assert!(attachment_from_ffi(Some(&bad)).is_err());
    }
}
