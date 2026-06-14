//! Tripwire: a new EnvelopeKind variant is a compile error here,
//! forcing a conscious doc update (docs/ARCHITECTURE.md envelope-kinds
//! list). Update this match AND docs/ARCHITECTURE.md when adding an
//! EnvelopeKind.

/// Exhaustive match over every `EnvelopeKind` variant with NO `_` arm
/// (the wildcard `Unknown(_)` is the forward-compat catch-all variant,
/// not a match wildcard). Adding a variant breaks compilation here.
#[test]
fn envelope_kinds_locked() {
    fn _assert(k: &fetchit_relay_proto::EnvelopeKind) {
        use fetchit_relay_proto::EnvelopeKind::{
            AdminEvent, DeliveryReceipt, Dm, GroupChat, PrivateGroupChat, PublicPost, Reserved6,
            Reserved7, Unknown, X0xdGroupMetadataEvent,
        };
        match k {
            Dm
            | GroupChat
            | AdminEvent
            | DeliveryReceipt
            | PrivateGroupChat
            | X0xdGroupMetadataEvent
            | Reserved6
            | Reserved7
            | PublicPost
            | Unknown(_) => {}
        }
    }
}
