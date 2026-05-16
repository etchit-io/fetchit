//! Built-in [`ContentHandler`](crate::ContentHandler) implementations.
//!
//! Use [`default_registry`] to build a registry pre-populated with the
//! standard set in the canonical priority order.

pub mod audio;
pub mod binary;
pub mod csv;
pub mod etchit_envelope;
pub mod html;
pub mod image;
pub mod json;
pub mod lang_detect;
pub mod markdown;
pub mod text;
pub mod video;
pub mod zip;

pub use audio::AudioHandler;
pub use binary::BinaryHandler;
pub use csv::CsvHandler;
pub use etchit_envelope::EtchitEnvelopeHandler;
pub use html::HtmlHandler;
pub use image::ImageHandler;
pub use json::JsonHandler;
pub use markdown::MarkdownHandler;
pub use text::TextHandler;
pub use video::VideoHandler;
pub use zip::{extract_entry, ZipHandler};

use crate::HandlerRegistry;

/// Build a [`HandlerRegistry`] populated with the default handler
/// set in priority order: envelope, image, audio, video, HTML, JSON,
/// markdown, text, binary fallback.
///
/// **Order matters**: image runs before video so HEIC `ftyp` brands
/// claim correctly; HTML runs before markdown/text so HTML markup
/// doesn't get mis-classified as prose.
#[must_use]
pub fn default_registry() -> HandlerRegistry {
    let mut reg = HandlerRegistry::new();
    reg.register(EtchitEnvelopeHandler)
        .register(ImageHandler)
        .register(AudioHandler)
        .register(VideoHandler)
        .register(ZipHandler)
        .register(HtmlHandler)
        .register(JsonHandler)
        .register(CsvHandler)
        .register(MarkdownHandler)
        .register(TextHandler)
        .register(BinaryHandler);
    reg
}
