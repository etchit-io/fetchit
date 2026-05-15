//! Serde-shaped mirror of [`fetchit_core::Rendition`] for the IPC boundary.
//!
//! Text-ish payloads (text, JSON, CSV, archive, HTML) cross inline. Binary
//! payloads carry only their MIME and length — the bytes are served to the
//! WebView over the `fetchit://` custom URI scheme.

use fetchit_core::handler::ArchiveEntry;
use fetchit_core::Rendition;
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RenditionDto {
    Text { language: Option<String>, body: String },
    EtchitEnvelope { title: String, content: String, language: Option<String> },
    Json { pretty: String },
    Tabular { columns: Vec<String>, rows: Vec<Vec<String>> },
    Archive { entries: Vec<ArchiveEntryDto> },
    Html { body: String },
    Image { mime: String, byte_len: usize },
    Audio { mime: String, byte_len: usize },
    Video { mime: String, byte_len: usize },
    Pdf { byte_len: usize },
    Binary { mime: String, byte_len: usize },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveEntryDto {
    pub path: String,
    pub size: Option<u64>,
}

impl From<ArchiveEntry> for ArchiveEntryDto {
    fn from(e: ArchiveEntry) -> Self {
        Self { path: e.path, size: e.size }
    }
}

impl From<Rendition> for RenditionDto {
    fn from(r: Rendition) -> Self {
        match r {
            Rendition::Text { language, body } => Self::Text { language, body },
            Rendition::EtchitEnvelope { title, content, language } => {
                Self::EtchitEnvelope { title, content, language }
            }
            Rendition::Json { value } => Self::Json {
                pretty: serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            },
            Rendition::Tabular { columns, rows } => Self::Tabular { columns, rows },
            Rendition::Archive { entries } => {
                Self::Archive { entries: entries.into_iter().map(Into::into).collect() }
            }
            Rendition::Html { body } => Self::Html { body },
            Rendition::Image { mime, data } => Self::Image { mime, byte_len: data.len() },
            Rendition::Audio { mime, data } => Self::Audio { mime, byte_len: data.len() },
            Rendition::Video { mime, data } => Self::Video { mime, byte_len: data.len() },
            Rendition::Pdf { data } => Self::Pdf { byte_len: data.len() },
            Rendition::OpaqueBinary { mime, data } => Self::Binary { mime, byte_len: data.len() },
            // `Rendition` is `#[non_exhaustive]`.
            other => Self::Text { language: None, body: format!("(unhandled rendition: {other:?})") },
        }
    }
}
