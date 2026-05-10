//! [`RenditionFFI`] — FFI-friendly mirror of [`fetchit_core::Rendition`].
//!
//! `bytes::Bytes` payloads cross the boundary as `Vec<u8>` (copied);
//! `serde_json::Value` is flattened to a pretty-printed `String`. The
//! variant set is otherwise identical so Kotlin code can pattern-match
//! the same way Rust callers do.

use fetchit_core::handler::ArchiveEntry;
use fetchit_core::Rendition;

/// FFI-shaped rendition.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum RenditionFFI {
    /// Plain text, optionally tagged with a language.
    Text {
        /// Optional language tag.
        language: Option<String>,
        /// Decoded UTF-8 body.
        body: String,
    },
    /// A still image. `data` is raw encoded bytes.
    Image {
        /// IANA MIME.
        mime: String,
        /// Raw encoded image bytes.
        data: Vec<u8>,
    },
    /// An audio asset.
    Audio {
        /// IANA MIME.
        mime: String,
        /// Raw encoded audio bytes.
        data: Vec<u8>,
    },
    /// A video asset.
    Video {
        /// IANA MIME.
        mime: String,
        /// Raw encoded video bytes.
        data: Vec<u8>,
    },
    /// A PDF document.
    Pdf {
        /// Raw PDF bytes.
        data: Vec<u8>,
    },
    /// JSON, pre-pretty-printed for display.
    Json {
        /// Pretty-printed JSON string. The original tree shape is not
        /// preserved across the FFI boundary; UI code that needs it
        /// can re-parse with the platform JSON library.
        pretty_printed: String,
    },
    /// Tabular data (CSV-style).
    Tabular {
        /// Column headers.
        columns: Vec<String>,
        /// Rows aligned with `columns`.
        rows: Vec<Vec<String>>,
    },
    /// Archive index. Extraction is a UI concern.
    Archive {
        /// One entry per archive member.
        entries: Vec<ArchiveEntryFFI>,
    },
    /// An etch/it envelope.
    EtchitEnvelope {
        /// Envelope title.
        title: String,
        /// Decoded content.
        content: String,
        /// Optional language tag.
        language: Option<String>,
    },
    /// A self-contained HTML document — render in a `WebView`.
    Html {
        /// Raw HTML source.
        body: String,
    },
    /// Bytes the registry could not classify any more specifically.
    OpaqueBinary {
        /// Best-effort MIME guess.
        mime: String,
        /// Raw bytes.
        data: Vec<u8>,
    },
}

/// FFI mirror of [`fetchit_core::handler::ArchiveEntry`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct ArchiveEntryFFI {
    /// Path within the archive.
    pub path: String,
    /// Uncompressed size in bytes, if known.
    pub size: Option<u64>,
}

impl From<ArchiveEntry> for ArchiveEntryFFI {
    fn from(e: ArchiveEntry) -> Self {
        Self {
            path: e.path,
            size: e.size,
        }
    }
}

impl From<Rendition> for RenditionFFI {
    fn from(r: Rendition) -> Self {
        match r {
            Rendition::Text { language, body } => Self::Text { language, body },
            Rendition::Image { mime, data } => Self::Image {
                mime,
                data: data.to_vec(),
            },
            Rendition::Audio { mime, data } => Self::Audio {
                mime,
                data: data.to_vec(),
            },
            Rendition::Video { mime, data } => Self::Video {
                mime,
                data: data.to_vec(),
            },
            Rendition::Pdf { data } => Self::Pdf {
                data: data.to_vec(),
            },
            Rendition::Json { value } => Self::Json {
                pretty_printed: serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|_| value.to_string()),
            },
            Rendition::Tabular { columns, rows } => Self::Tabular { columns, rows },
            Rendition::Archive { entries } => Self::Archive {
                entries: entries.into_iter().map(Into::into).collect(),
            },
            Rendition::EtchitEnvelope {
                title,
                content,
                language,
            } => Self::EtchitEnvelope {
                title,
                content,
                language,
            },
            Rendition::Html { body } => Self::Html { body },
            Rendition::OpaqueBinary { mime, data } => Self::OpaqueBinary {
                mime,
                data: data.to_vec(),
            },
            // Rendition is #[non_exhaustive]; surface any future variant
            // as opaque text so the FFI never panics on a new kind.
            other => Self::Text {
                language: None,
                body: format!("(unknown rendition variant: {other:?})"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use bytes::Bytes;
    use serde_json::json;

    #[test]
    fn maps_text() {
        let r = Rendition::Text {
            language: Some("rust".into()),
            body: "fn main(){}".into(),
        };
        match RenditionFFI::from(r) {
            RenditionFFI::Text { language, body } => {
                assert_eq!(language, Some("rust".into()));
                assert_eq!(body, "fn main(){}");
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn maps_image_bytes_to_vec() {
        let r = Rendition::Image {
            mime: "image/png".into(),
            data: Bytes::from_static(&[1, 2, 3, 4]),
        };
        match RenditionFFI::from(r) {
            RenditionFFI::Image { mime, data } => {
                assert_eq!(mime, "image/png");
                assert_eq!(data, vec![1, 2, 3, 4]);
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn flattens_json_to_pretty_printed_string() {
        let r = Rendition::Json {
            value: json!({ "x": 1, "y": [2, 3] }),
        };
        match RenditionFFI::from(r) {
            RenditionFFI::Json { pretty_printed } => {
                assert!(pretty_printed.contains('\n'));
                assert!(pretty_printed.contains("\"x\""));
                assert!(pretty_printed.contains('1'));
            }
            _ => panic!("expected Json"),
        }
    }

    #[test]
    fn maps_envelope_with_language() {
        let r = Rendition::EtchitEnvelope {
            title: "hi".into(),
            content: "body".into(),
            language: Some("md".into()),
        };
        match RenditionFFI::from(r) {
            RenditionFFI::EtchitEnvelope {
                title,
                content,
                language,
            } => {
                assert_eq!(title, "hi");
                assert_eq!(content, "body");
                assert_eq!(language, Some("md".into()));
            }
            _ => panic!("expected EtchitEnvelope"),
        }
    }

    #[test]
    fn maps_opaque_binary_passthrough() {
        let r = Rendition::OpaqueBinary {
            mime: "application/pdf".into(),
            data: Bytes::from_static(b"%PDF-1.4"),
        };
        match RenditionFFI::from(r) {
            RenditionFFI::OpaqueBinary { mime, data } => {
                assert_eq!(mime, "application/pdf");
                assert_eq!(data, b"%PDF-1.4".to_vec());
            }
            _ => panic!("expected OpaqueBinary"),
        }
    }
}
