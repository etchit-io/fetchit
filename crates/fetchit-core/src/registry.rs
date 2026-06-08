//! [`HandlerRegistry`] — the dispatch table that turns fetched bytes
//! into a [`Rendition`].
//!
//! Detection runs every registered handler's
//! [`ContentHandler::can_handle`] over a short head-slice, picks the
//! highest [`Confidence`], breaks ties by registration order, and then
//! calls [`ContentHandler::render`] on the chosen handler.

use std::sync::Arc;

use bytes::Bytes;

use crate::handler::{
    Confidence, ContentHandler, Hint, RenderContext, RenderingContext, Rendition,
};
use crate::{Error, Result};

/// Number of leading bytes passed to [`ContentHandler::can_handle`].
/// Big enough for every magic-byte sniff used in 0.1.0; small enough
/// that we never copy a full payload during detection.
const SNIFF_BYTES: usize = 4096;

/// A set of registered [`ContentHandler`]s plus the dispatch logic
/// that maps bytes to a [`Rendition`].
///
/// Built once, registered through [`register`](Self::register), then
/// reused for every fetch. Cheap to clone (handlers are wrapped in
/// `Arc`).
#[derive(Clone, Default)]
pub struct HandlerRegistry {
    handlers: Vec<Arc<dyn ContentHandler>>,
}

impl HandlerRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `handler` to the candidate set.
    ///
    /// Order of registration matters only for tiebreaks: handlers
    /// registered earlier win when two return the same
    /// [`Confidence`]. Register specific handlers first, the binary
    /// fallback last.
    pub fn register<H: ContentHandler + 'static>(&mut self, handler: H) -> &mut Self {
        self.handlers.push(Arc::new(handler));
        self
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// `true` if no handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Pick the best handler for `bytes` and render. Returns the
    /// [`Rendition`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoHandlerMatched`] if every handler returned
    /// [`Confidence::None`] (only possible if the binary fallback has
    /// been excluded). Returns [`Error::Render`] if the chosen handler
    /// failed to render.
    pub fn render(&self, bytes: Bytes, hint: &Hint, ctx: &RenderContext) -> Result<Rendition> {
        let head_len = bytes.len().min(SNIFF_BYTES);
        let head = &bytes[..head_len];
        let chosen = self.choose(head, hint).ok_or(Error::NoHandlerMatched)?;
        chosen.render(bytes, ctx)
    }

    /// M3 Phase F2 — denylist-gated render entry point.
    ///
    /// When `rendering_ctx` carries both a `denylist` and an
    /// `addr_hex`, the gate runs `is_blocked(EntryKind::XorName,
    /// addr_hex)` BEFORE any handler is chosen. A hit short-circuits
    /// to [`Rendition::Blocked`] with a UI-renderable `reason`
    /// string; a miss delegates to [`Self::render`] unchanged.
    ///
    /// Either gate field being `None` (or both) makes this method
    /// behaviour-identical to `render` — that's the test/offline
    /// path. The UI shell wires the consumer once at boot and threads
    /// the user-pasted address through `addr_hex` per fetch.
    ///
    /// # Errors
    /// Same as [`Self::render`]. The denylist short-circuit returns
    /// `Ok(Rendition::Blocked)`, never an error.
    pub fn render_with_context(
        &self,
        bytes: Bytes,
        hint: &Hint,
        ctx: &RenderContext,
        rendering_ctx: &RenderingContext,
    ) -> Result<Rendition> {
        if let (Some(denylist), Some(addr)) = (&rendering_ctx.denylist, &rendering_ctx.addr_hex) {
            if denylist.is_blocked(fetchit_trust_types::EntryKind::XorName, addr) {
                return Ok(Rendition::Blocked {
                    reason: format!("xor_name: {addr}"),
                });
            }
        }
        self.render(bytes, hint, ctx)
    }

    /// Visible for tests: just the detection step.
    fn choose(&self, head: &[u8], hint: &Hint) -> Option<&Arc<dyn ContentHandler>> {
        let mut best: Option<(Confidence, usize)> = None;
        for (idx, handler) in self.handlers.iter().enumerate() {
            let confidence = handler.can_handle(head, hint);
            if confidence == Confidence::None {
                continue;
            }
            match best {
                Some((bc, _)) if confidence <= bc => {}
                _ => best = Some((confidence, idx)),
            }
        }
        best.map(|(_, idx)| &self.handlers[idx])
    }
}

impl std::fmt::Debug for HandlerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerRegistry")
            .field(
                "handlers",
                &self.handlers.iter().map(|h| h.kind()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    struct FakeHandler {
        kind: &'static str,
        confidence: Confidence,
    }

    impl ContentHandler for FakeHandler {
        fn kind(&self) -> &'static str {
            self.kind
        }
        fn can_handle(&self, _head: &[u8], _hint: &Hint) -> Confidence {
            self.confidence
        }
        fn render(&self, _bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
            Ok(Rendition::Text {
                language: None,
                body: self.kind.into(),
            })
        }
    }

    fn rendition_kind(r: &Rendition) -> &str {
        match r {
            Rendition::Text { body, .. } => body,
            _ => "other",
        }
    }

    #[test]
    fn empty_registry_returns_no_match() {
        let reg = HandlerRegistry::new();
        let err = reg
            .render(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
            )
            .expect_err("empty registry should fail");
        assert!(matches!(err, Error::NoHandlerMatched));
    }

    #[test]
    fn single_handler_wins() {
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "alpha",
            confidence: Confidence::High,
        });
        let r = reg
            .render(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
            )
            .expect("should render");
        assert_eq!(rendition_kind(&r), "alpha");
    }

    #[test]
    fn highest_confidence_wins() {
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "low",
            confidence: Confidence::Low,
        });
        reg.register(FakeHandler {
            kind: "high",
            confidence: Confidence::High,
        });
        reg.register(FakeHandler {
            kind: "medium",
            confidence: Confidence::Medium,
        });
        let r = reg
            .render(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
            )
            .expect("should render");
        assert_eq!(rendition_kind(&r), "high");
    }

    #[test]
    fn ties_broken_by_registration_order() {
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "first",
            confidence: Confidence::High,
        });
        reg.register(FakeHandler {
            kind: "second",
            confidence: Confidence::High,
        });
        let r = reg
            .render(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
            )
            .expect("should render");
        assert_eq!(rendition_kind(&r), "first");
    }

    /// M3 F2: when the denylist matches the addr, the renderer short-
    /// circuits before any handler is chosen. The `reason` string
    /// carries the `EntryKind` discriminant + the canonical value.
    #[test]
    fn render_with_context_short_circuits_blocked_xorname() {
        struct Block(&'static str);
        impl fetchit_trust_types::DenylistQuery for Block {
            fn is_blocked(&self, kind: fetchit_trust_types::EntryKind, value: &str) -> bool {
                kind == fetchit_trust_types::EntryKind::XorName && value == self.0
            }
        }
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "alpha",
            confidence: Confidence::High,
        });
        let blocked_hex = "abcd".repeat(16);
        let rctx = RenderingContext {
            denylist: Some(Arc::new(Block(Box::leak(
                blocked_hex.clone().into_boxed_str(),
            )))),
            addr_hex: Some(blocked_hex.clone()),
        };
        let r = reg
            .render_with_context(
                Bytes::from_static(b"any bytes"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx,
            )
            .expect("blocked short-circuit returns Ok(Blocked)");
        match r {
            Rendition::Blocked { reason } => {
                assert!(reason.starts_with("xor_name:"), "reason = {reason}");
                assert!(reason.contains(&blocked_hex), "reason = {reason}");
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    /// M3 F2: when the `denylist` is set but `addr_hex` is missing,
    /// the gate silently passes through to the existing render path.
    /// Same for the reverse case (`addr_hex` set but no `denylist`)
    /// — neither is a misconfiguration the renderer should escalate.
    #[test]
    fn render_with_context_passes_through_when_gate_incomplete() {
        struct AlwaysBlock;
        impl fetchit_trust_types::DenylistQuery for AlwaysBlock {
            fn is_blocked(&self, _: fetchit_trust_types::EntryKind, _: &str) -> bool {
                true
            }
        }
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "alpha",
            confidence: Confidence::High,
        });
        // denylist Some, addr_hex None
        let rctx_no_addr = RenderingContext {
            denylist: Some(Arc::new(AlwaysBlock)),
            addr_hex: None,
        };
        let r1 = reg
            .render_with_context(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx_no_addr,
            )
            .expect("incomplete gate must not error");
        assert_eq!(rendition_kind(&r1), "alpha");
        // denylist None, addr_hex Some
        let rctx_no_dl = RenderingContext {
            denylist: None,
            addr_hex: Some("abcd".repeat(16)),
        };
        let r2 = reg
            .render_with_context(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx_no_dl,
            )
            .expect("incomplete gate must not error");
        assert_eq!(rendition_kind(&r2), "alpha");
    }

    /// M3 F2: when the `denylist` + `addr_hex` are both set but the
    /// addr doesn't match, the gate falls through to the existing
    /// render path. This is the common happy-path case (most
    /// addresses aren't blocked).
    #[test]
    fn render_with_context_passes_through_when_addr_not_blocked() {
        struct BlockOnly(&'static str);
        impl fetchit_trust_types::DenylistQuery for BlockOnly {
            fn is_blocked(&self, kind: fetchit_trust_types::EntryKind, value: &str) -> bool {
                kind == fetchit_trust_types::EntryKind::XorName && value == self.0
            }
        }
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "alpha",
            confidence: Confidence::High,
        });
        let rctx = RenderingContext {
            denylist: Some(Arc::new(BlockOnly("ffff".repeat(16).leak()))),
            addr_hex: Some("abcd".repeat(16)),
        };
        let r = reg
            .render_with_context(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx,
            )
            .expect("unblocked addr renders normally");
        assert_eq!(rendition_kind(&r), "alpha");
    }

    #[test]
    fn none_handlers_are_excluded() {
        let mut reg = HandlerRegistry::new();
        reg.register(FakeHandler {
            kind: "skip",
            confidence: Confidence::None,
        });
        reg.register(FakeHandler {
            kind: "keep",
            confidence: Confidence::Low,
        });
        let r = reg
            .render(
                Bytes::from_static(b"x"),
                &Hint::default(),
                &RenderContext::default(),
            )
            .expect("should render");
        assert_eq!(rendition_kind(&r), "keep");
    }
}
