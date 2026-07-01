//! Content-robustness and fetch-failure tests for the default engine.
//!
//! A user pastes an arbitrary 64-hex address; the engine must return a
//! clean typed [`Rendition`] or a clean [`Error`] and must NEVER panic,
//! hang, or unbounded-allocate. These cases feed the default registry
//! crafted corrupt / malformed / edge-case bytes (raw
//! [`HandlerRegistry::render`] like `registry_integration.rs`, or
//! through [`MockClient`] like `pipeline.rs` where a fetch path is
//! exercised) and assert the exact clean outcome -- a specific variant
//! or `Error::Render` / `Error::Network`, never a panic.
//!
//! Each assertion documents the engine's ACTUAL behaviour, verified
//! against the handler sources, not an aspiration.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use fetchit_core::network::MockClient;
use fetchit_core::{Address, Error, Hint, NetworkClient, RenderContext, Rendition};

/// Render crafted bytes through the production `default_registry()` with
/// a default [`RenderContext`] -- the raw classify+render path.
fn render(bytes: &[u8]) -> fetchit_core::Result<Rendition> {
    default_registry().render(
        Bytes::copy_from_slice(bytes),
        &Hint::default(),
        &RenderContext::default(),
    )
}

/// Render crafted bytes with an explicit `max_text_bytes` cap so a test
/// can drive the text-truncation path. `RenderContext` is
/// `#[non_exhaustive]`, so it is built via `Default` and the public
/// field is then set, rather than with a struct literal.
fn render_capped(bytes: &[u8], max_text_bytes: usize) -> fetchit_core::Result<Rendition> {
    let mut ctx = RenderContext::default();
    ctx.max_text_bytes = max_text_bytes;
    default_registry().render(Bytes::copy_from_slice(bytes), &Hint::default(), &ctx)
}

/// A 64-hex-char [`Address`] built by repeating one hex digit.
fn addr(digit: char) -> Address {
    digit
        .to_string()
        .repeat(64)
        .parse()
        .expect("64 hex chars is a valid address")
}

// 1. Empty content (0 bytes) -----------------------------------------------

/// Zero bytes must classify cleanly, not panic. The empty head makes
/// `TextHandler::can_handle` return `Medium` (empty head is explicitly
/// treated as text), which beats the binary fallback's `Low`, so the
/// engine yields an empty `Text` body. The point is the clean,
/// non-panicking outcome -- pin whichever it actually is.
#[test]
fn empty_content_renders_cleanly() {
    match render(b"").expect("empty input must not error") {
        Rendition::Text { body, .. } => assert!(body.is_empty(), "empty in, empty out"),
        other => panic!("expected empty Text for 0 bytes, got {other:?}"),
    }
}

// 2. Truncated ZIP ----------------------------------------------------------

/// `PK\x03\x04` is the ZIP local-file-header magic, so `ZipHandler`
/// claims `Definite`. The bytes that follow are garbage, so the central-
/// directory parse fails. That must surface as a clean `Error::Render`
/// tagged with the zip handler's kind -- never a panic from the `zip`
/// crate's parser.
#[test]
fn truncated_zip_is_clean_render_error() {
    let mut bytes = vec![0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    let err = render(&bytes).expect_err("truncated zip must fail to render");
    assert!(
        matches!(
            err,
            Error::Render {
                kind: "application/zip",
                ..
            }
        ),
        "expected zip Error::Render, got {err:?}"
    );
}

// 3. Malformed JSON that passes can_handle ---------------------------------

/// `{"a":` starts with `{` and `serde_json` reports `Category::Eof` on
/// the head (it ran out of bytes mid-value), so `JsonHandler::can_handle`
/// claims `High` -- exactly the path that sends a partial object into
/// `render`. The full parse then fails, and the failure must be a clean
/// `Error::Render`, not a panic and not a silent fall-through.
#[test]
fn malformed_json_passing_sniff_is_render_error() {
    let err = render(br#"{"a":"#).expect_err("incomplete JSON must fail at render");
    assert!(
        matches!(
            err,
            Error::Render {
                kind: "application/json",
                ..
            }
        ),
        "expected json Error::Render, got {err:?}"
    );
}

// 4. Mid-multibyte UTF-8 truncation (the key gap) --------------------------

/// THE KEY CASE. A valid UTF-8 string whose multibyte characters mean a
/// byte-length `max_text_bytes` cap lands mid-codepoint. `TextHandler`
/// slices the raw bytes at the cap (`&stripped[..cap]`, a byte slice --
/// never a `str` slice, so the slice itself cannot panic) and then runs
/// `std::str::from_utf8` over the result. A mid-codepoint cut makes that
/// validation fail, so the engine returns a clean `Error::Render`. The
/// load-bearing assertion is NO PANIC; the documented outcome is the
/// `text/plain` render error.
#[test]
fn mid_codepoint_truncation_is_clean_not_panic() {
    // "a" then U+00E9 (eclair e-acute, 2 bytes: 0xC3 0xA9). cap = 2
    // keeps the 'a' (1 byte) and the first byte of the 2-byte char,
    // splitting the codepoint.
    let s = "aé";
    assert_eq!(s.len(), 3, "byte length: 1 (a) + 2 (é)");
    let err = render_capped(s.as_bytes(), 2)
        .expect_err("a cap landing mid-codepoint must be a clean error, not a panic");
    assert!(
        matches!(
            err,
            Error::Render {
                kind: "text/plain",
                ..
            }
        ),
        "expected text Error::Render for mid-codepoint cut, got {err:?}"
    );
}

/// Companion to the case above: when the same byte cap lands ON a char
/// boundary, the text renders cleanly and the body is truncated exactly
/// at that boundary -- proving the engine truncates safely rather than
/// always erroring on multibyte content.
#[test]
fn truncation_on_char_boundary_renders_truncated_text() {
    let s = "aé"; // cap = 1 keeps just "a", a clean boundary.
    match render_capped(s.as_bytes(), 1).expect("boundary cut must render") {
        Rendition::Text { body, .. } => assert_eq!(body, "a"),
        other => panic!("expected truncated Text, got {other:?}"),
    }
}

/// Regression for a reachable panic found while writing these tests:
/// the engine's language auto-detection sliced the rendered text by raw
/// byte index (`text[..min(2000)]`). When a multibyte character
/// straddled byte 2000, that `str` slice panicked -- on perfectly valid
/// UTF-8 a user could paste. The fix clamps to a char boundary; this
/// case drives the whole `default_registry().render(...)` path with such
/// content and asserts it renders as `Text`, never panicking.
#[test]
fn valid_utf8_with_multibyte_at_detect_boundary_does_not_panic() {
    // 1999 ASCII bytes, then a 2-byte 'é' spanning bytes 1999..2001, so
    // byte index 2000 falls mid-codepoint. Plus a tail so the body is
    // comfortably over 2000 bytes. Default max_text_bytes keeps it all.
    let mut s = "a".repeat(1999);
    s.push('é');
    s.push_str(" and some trailing prose to push well past two thousand bytes.");
    assert!(s.len() > 2000);
    match render(s.as_bytes()).expect("valid UTF-8 must render, not panic") {
        Rendition::Text { body, .. } => {
            assert_eq!(body, s, "body should be the full UTF-8 text, uncorrupted");
        }
        other => panic!("expected Text, got {other:?}"),
    }
}

// 5. Corrupt etch/it envelope ----------------------------------------------

/// Correct envelope sniff shape (mentions `"v"`, `"meta"`, `"content"`
/// so `can_handle` claims `Definite`) but `v` is `2`, an unsupported
/// version. Render must reject with a clean `Error::Render` tagged with
/// the envelope kind, not coerce or panic.
#[test]
fn corrupt_envelope_wrong_version_is_render_error() {
    let raw = br#"{"v":2,"meta":{"title":"x","lang":""},"content":"y"}"#;
    let err = render(raw).expect_err("v2 envelope must be rejected");
    assert!(
        matches!(
            err,
            Error::Render {
                kind: "etchit/envelope-v1",
                ..
            }
        ),
        "expected envelope Error::Render, got {err:?}"
    );
}

/// Envelope shape that sniffs `Definite` (all three keys present in the
/// head) but is missing the required `content` field. `serde` rejects it
/// at render with a clean `Error::Render`.
#[test]
fn corrupt_envelope_missing_field_is_render_error() {
    // `"content"` appears only as a key name inside meta, satisfying the
    // cheap substring sniff, but the top-level `content` field is absent.
    let raw = br#"{"v":1,"meta":{"title":"x","lang":"","content":"misplaced"}}"#;
    let err = render(raw).expect_err("envelope missing content must be rejected");
    assert!(
        matches!(
            err,
            Error::Render {
                kind: "etchit/envelope-v1",
                ..
            }
        ),
        "expected envelope Error::Render, got {err:?}"
    );
}

// 6. Large text (a few MB) -------------------------------------------------

/// A multi-megabyte ASCII payload must render as `Text` whose body is
/// bounded by `max_text_bytes` -- the engine truncates rather than
/// materialising an unbounded string. ASCII keeps every cap on a char
/// boundary, isolating this from the mid-codepoint case above.
#[test]
fn large_text_is_bounded_by_max_text_bytes() {
    let cap = 64 * 1024;
    let big = vec![b'a'; 4 * 1024 * 1024]; // 4 MiB of 'a'
    match render_capped(&big, cap).expect("large text must render") {
        Rendition::Text { body, .. } => {
            assert_eq!(body.len(), cap, "body must be capped at max_text_bytes");
        }
        other => panic!("expected bounded Text, got {other:?}"),
    }
}

// 7. Fetch failure propagation ---------------------------------------------

/// An absent address must surface as a clean `Error::Network` through the
/// fetch+classify path -- the fetch failure reaches the caller rather
/// than being swallowed or turned into an empty render. Mirrors
/// `pipeline.rs::unknown_address_surfaces_a_network_error`.
#[tokio::test]
async fn absent_address_surfaces_network_error() {
    let client = MockClient::new();
    let a = addr('d'); // nothing inserted
    let err = match client.fetch(&a).await {
        Ok(bytes) => {
            // Unreachable for an absent address, but if a future mock
            // ever returned bytes we still route them through render to
            // keep the path honest rather than asserting blindly.
            default_registry()
                .render(bytes, &Hint::default(), &RenderContext::default())
                .expect_err("absent address should not have produced renderable bytes")
        }
        Err(e) => e,
    };
    assert!(
        matches!(err, Error::Network(_)),
        "expected Error::Network for absent address, got {err:?}"
    );
}

// 8. Binary garbage (no known magic) ---------------------------------------

/// Random non-UTF-8 bytes with a leading NUL and no recognised magic
/// signature fall all the way through to `BinaryHandler`. The NUL
/// excludes the text/markdown handlers; nothing else claims it. Result:
/// `OpaqueBinary` with the `application/octet-stream` MIME (nothing for
/// `infer` to match), bytes passed through unchanged, no panic.
#[test]
fn binary_garbage_falls_back_to_opaque_octet_stream() {
    let garbage: &[u8] = &[
        0x00, 0xFF, 0x01, 0xFE, 0x80, 0x7F, 0xC0, 0x3F, 0xAB, 0xCD, 0x00, 0x99,
    ];
    match render(garbage).expect("binary garbage must classify, not error") {
        Rendition::OpaqueBinary { mime, data } => {
            assert_eq!(mime, "application/octet-stream");
            assert_eq!(data.as_ref(), garbage, "bytes must pass through unchanged");
        }
        other => panic!("expected OpaqueBinary, got {other:?}"),
    }
}
