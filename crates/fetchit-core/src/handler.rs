//! The [`ContentHandler`] contract and the typed [`Rendition`] handlers
//! produce.
//!
//! Adding a new content type means writing one type that implements
//! [`ContentHandler`] and registering it on a
//! [`HandlerRegistry`](crate::HandlerRegistry). See
//! `docs/HANDLER-AUTHORS.md` for the walk-through.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde_json::Value as JsonValue;

use crate::Result;

/// How strongly a handler claims a chunk of bytes.
///
/// Variants are ordered: [`Confidence::Definite`] beats
/// [`Confidence::High`] beats [`Confidence::Medium`] beats
/// [`Confidence::Low`]; [`Confidence::None`] means *I cannot handle
/// these bytes*. The [`HandlerRegistry`](crate::HandlerRegistry) picks
/// the highest-confidence match and breaks ties by registration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Cannot handle these bytes — exclude this handler from the
    /// candidate set entirely.
    None,
    /// Last-resort fallback. Reserved for the binary handler.
    Low,
    /// Heuristic match (e.g. JSON-shaped text). Could plausibly be
    /// mis-classified.
    Medium,
    /// Strong structural match (e.g. valid JSON parses cleanly).
    High,
    /// Magic-byte match that admits no false positives in practice
    /// (e.g. PNG header).
    Definite,
}

/// Out-of-band hints a caller can pass to bias detection. None of the
/// fields are required; the empty hint is the common case for
/// Autonomi content-addressed reads where nothing is known up front.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct Hint {
    /// Filename, if the caller has one. Rare on Autonomi — included so
    /// handlers that already accept a filename hint elsewhere can reuse
    /// the same shape.
    pub filename: Option<String>,
    /// Total fetched length in bytes, when known.
    pub size: Option<u64>,
    /// Free-form key/value strings, e.g. for protocol-supplied MIME.
    pub extra: BTreeMap<String, String>,
}

/// Configuration available to a handler while rendering.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RenderContext {
    /// Soft cap on how much text/JSON a handler should materialise into
    /// a single [`Rendition`]. Handlers may exceed this for binary
    /// payloads (image bytes are passed through verbatim) but should
    /// truncate decoded text and surface a marker rather than building
    /// a multi-gigabyte string in memory.
    pub max_text_bytes: usize,
}

impl Default for RenderContext {
    fn default() -> Self {
        Self {
            max_text_bytes: 16 * 1024 * 1024,
        }
    }
}

/// A typed, in-memory representation of fetched content.
///
/// UI shells dispatch on the variant: text into a code view, image into
/// an `ImageView`, JSON into a tree widget, and so on. The variant set
/// is stable across handlers — adding a new MIME does not add a new
/// variant unless the rendering shape genuinely differs.
///
/// `fetchit-core` never persists a [`Rendition`] to disk. It lives in
/// memory until the caller drops it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Rendition {
    /// Plain text, optionally tagged with a language hint that a code
    /// renderer can use for syntax highlighting.
    Text {
        /// Optional language tag (e.g. `"rust"`, `"markdown"`).
        language: Option<String>,
        /// Decoded UTF-8 body. May have been truncated at
        /// [`RenderContext::max_text_bytes`].
        body: String,
    },
    /// A still image. Bytes are passed through verbatim — decoding to
    /// pixels happens in the UI layer.
    Image {
        /// IANA MIME, e.g. `"image/png"`.
        mime: String,
        /// Raw encoded image bytes.
        data: Bytes,
    },
    /// An audio asset, MIME-tagged for a UI `<audio>` element or
    /// platform decoder.
    Audio {
        /// IANA MIME, e.g. `"audio/wav"`.
        mime: String,
        /// Raw encoded audio bytes.
        data: Bytes,
    },
    /// A video asset, MIME-tagged.
    Video {
        /// IANA MIME, e.g. `"video/mp4"`.
        mime: String,
        /// Raw encoded video bytes.
        data: Bytes,
    },
    /// A PDF document, raw bytes for a PDF viewer.
    Pdf {
        /// Raw PDF bytes.
        data: Bytes,
    },
    /// Pretty-printed JSON. The original parsed structure is kept so
    /// the UI may render a tree view rather than the printed string.
    Json {
        /// Parsed JSON tree.
        value: JsonValue,
    },
    /// Tabular data (e.g. CSV) decoded into headers + rows of strings.
    Tabular {
        /// Column headers, in order.
        columns: Vec<String>,
        /// Each inner `Vec` is one row, aligned with `columns`.
        rows: Vec<Vec<String>>,
    },
    /// An archive index — entry names and sizes only. Extraction is
    /// deliberately not performed by the core; surfaces decide whether
    /// to offer it.
    Archive {
        /// One entry per archive member.
        entries: Vec<ArchiveEntry>,
    },
    /// A self-contained HTML document — surfaces hand it to a
    /// `WebView` / browser-equivalent to render as a webpage.
    Html {
        /// Raw HTML source. UI layers decide whether to render with
        /// JavaScript / network access enabled.
        body: String,
    },
    /// An etch/it envelope: a `{"v":1,"meta":{...},"content":"..."}`
    /// payload as written by etchit clients.
    EtchitEnvelope {
        /// Envelope title (`meta.title`), possibly empty.
        title: String,
        /// Decoded content body.
        content: String,
        /// Language tag from `meta.lang` if non-empty, otherwise a
        /// markdown heuristic may supply `"markdown"`.
        language: Option<String>,
    },
    /// Bytes the registry could not classify any more specifically.
    OpaqueBinary {
        /// Best-effort MIME guess (e.g. via the `infer` crate). May be
        /// `"application/octet-stream"` if nothing matched.
        mime: String,
        /// Raw bytes, unchanged.
        data: Bytes,
    },
    /// M3 federation core: the renderer was asked to render content
    /// whose source identity (`XorName`, `AgentId`, `RelayUrl`, or
    /// `ActorUrl`) is on the community-maintained denylist. Surfaces
    /// short-circuit before any decode runs; the UI swaps in a
    /// "blocked content" placeholder that names the reason verbatim.
    ///
    /// Populated by [`crate::registry::HandlerRegistry::render_with_context`]
    /// (Phase F2) when the supplied [`fetchit_trust_types::DenylistQuery`]
    /// matches; never returned by an individual handler's `render`.
    Blocked {
        /// Human-readable reason rendered into the placeholder.
        /// Format: `"<kind>: <value>"` where `kind` is the
        /// [`fetchit_trust_types::EntryKind`] discriminant and `value` is
        /// the canonical-form entry that matched. Example:
        /// `"xor_name: 4d216f18…"`.
        reason: String,
    },
}

/// M3 Phase F2 — runtime context the renderer consults before
/// dispatching a payload through the handler set.
///
/// When `denylist` is `Some(_)` and `addr_hex` is `Some(_)`,
/// [`crate::registry::HandlerRegistry::render_with_context`] checks
/// `is_blocked(EntryKind::XorName, addr_hex)` before any handler is
/// chosen. A hit short-circuits to [`Rendition::Blocked`]; a miss
/// falls through to the normal render path. The UI shell wires up
/// the consumer (typically the chat / trust-client's
/// `DenylistConsumer`) and threads the user-pasted Autonomi address
/// through `addr_hex` on every fetch.
///
/// Either field being `None` disables the gate. Both fields are
/// `None` by default so REST-only / offline / test callers keep the
/// pre-M3 behaviour without a consumer wired up.
#[derive(Default, Clone)]
pub struct RenderingContext {
    /// Optional community denylist consumer. The chat / trust-client
    /// `DenylistConsumer` is the canonical implementation; tests
    /// inject stubs.
    pub denylist: Option<std::sync::Arc<dyn fetchit_trust_types::DenylistQuery>>,
    /// The 64-char lowercase hex `XorName` the caller is about to
    /// render. Required for the short-circuit; without it, the gate
    /// silently passes through.
    pub addr_hex: Option<String>,
}

impl std::fmt::Debug for RenderingContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderingContext")
            .field("denylist", &self.denylist.as_ref().map(|_| "<consumer>"))
            .field("addr_hex", &self.addr_hex)
            .finish()
    }
}

/// A single member of an archive [`Rendition::Archive`].
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// Path within the archive.
    pub path: String,
    /// Uncompressed size in bytes, if the archive format records it.
    pub size: Option<u64>,
}

/// Implemented by every content handler.
///
/// The registry calls [`can_handle`](ContentHandler::can_handle) on a
/// short head-slice (the first few KB of the fetched payload, or the
/// whole thing if smaller). Handlers must not block on I/O or perform
/// heavy work in this method — it runs against every registered
/// handler on every fetch.
///
/// [`render`](ContentHandler::render) receives the full payload and
/// produces a [`Rendition`]. Render is allowed to fail; failure is not
/// a panic.
pub trait ContentHandler: Send + Sync {
    /// Stable identifier for this handler, used in error messages and
    /// telemetry. Convention: an IANA-style MIME or `fetchit/`-prefixed
    /// pseudo-MIME for non-standard formats (e.g. `etchit/envelope-v1`).
    fn kind(&self) -> &'static str;

    /// Cheap classification on the leading bytes. Returning
    /// [`Confidence::None`] removes this handler from the candidate
    /// set for these bytes.
    fn can_handle(&self, head: &[u8], hint: &Hint) -> Confidence;

    /// Produce a typed [`Rendition`] from the full payload. The bytes
    /// are passed by `Bytes` so handlers may pass them through cheaply
    /// (image / audio / video data flows through verbatim).
    fn render(&self, bytes: Bytes, ctx: &RenderContext) -> Result<Rendition>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rendition_blocked_carries_reason() {
        let r = Rendition::Blocked {
            reason: "xor_name: 4d216f18".into(),
        };
        match r {
            Rendition::Blocked { reason } => assert_eq!(reason, "xor_name: 4d216f18"),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    /// Doc-invariant tripwire: an exhaustive match over every
    /// `Rendition` variant with NO `_` arm. Adding a variant breaks
    /// compilation here -- that IS the tripwire. It lives in-crate
    /// (rather than in `tests/doc_invariants.rs`) because `Rendition`
    /// is `#[non_exhaustive]`: a downstream match would be forced to
    /// add a `_` arm and a new variant would slip through silently.
    /// Update this match AND the architecture reference when adding a
    /// Rendition variant.
    #[test]
    fn rendition_variants_match_snapshot() {
        fn _assert(r: &Rendition) {
            match r {
                Rendition::Text { .. }
                | Rendition::Image { .. }
                | Rendition::Audio { .. }
                | Rendition::Video { .. }
                | Rendition::Pdf { .. }
                | Rendition::Json { .. }
                | Rendition::Tabular { .. }
                | Rendition::Archive { .. }
                | Rendition::Html { .. }
                | Rendition::EtchitEnvelope { .. }
                | Rendition::OpaqueBinary { .. }
                | Rendition::Blocked { .. } => {}
            }
        }
    }
}
