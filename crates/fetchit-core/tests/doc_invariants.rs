//! Tripwire tests: lock the public shapes that docs describe, so a
//! change to the code forces a conscious doc update. If this fails,
//! update BOTH the snapshot here AND the handler list in
//! the architecture reference.
//!
//! The matching `Rendition`-variant tripwire lives as an in-crate unit
//! test in `src/handler.rs`, not here: `Rendition` is
//! `#[non_exhaustive]`, so an exhaustive match from a downstream crate
//! (this integration test is one) always needs a `_` arm and a new
//! variant would NOT break compilation. Inside `fetchit-core` the
//! `#[non_exhaustive]` marker does not apply, so the match is genuinely
//! exhaustive and a new variant is a compile error there.

use fetchit_core::handlers::default_registry;

/// The handler `kind()` strings, in registration order, that
/// `default_registry()` builds today. Registration order is
/// load-bearing: handlers tie on confidence and break the tie by this
/// order (image before video, html before markdown/text, binary last).
///
/// These are the `ContentHandler::kind()` values (MIME-style ids), not
/// the friendly handler names. Update this snapshot AND
/// the architecture reference when adding, removing, or reordering a handler.
#[test]
fn handler_kinds_and_order_match_snapshot() {
    let expected = [
        "etchit/envelope-v1",
        "saorsa-mls/envelope-v1",
        "image/*",
        "audio/*",
        "video/*",
        "application/zip",
        "text/html",
        "application/json",
        "text/csv",
        "text/markdown",
        "text/plain",
        "application/octet-stream",
    ];
    let actual: Vec<&str> = default_registry().handler_kinds().collect();
    assert_eq!(
        actual, expected,
        "handler set/order changed: update the snapshot in this test AND the \
         handler list in the architecture reference"
    );
}
