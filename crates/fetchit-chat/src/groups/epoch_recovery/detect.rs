//! `EpochBehind` detection: is an inbound frame's epoch ahead of ours?
//!
//! Pure comparison, no crypto. The inbound `secret_epoch` rides on the
//! x0xd [`x0xd_client::secure::EncryptedFrame`] (a `u32`); our local epoch
//! comes from [`x0xd_client::secure::GroupSelfStatus`] (a `u64`, since the
//! daemon reports it wider). We widen the frame epoch to `u64` and compare
//! directly — never subtract — so there is no wrap/underflow to reason
//! about even at the type boundary.

/// How an inbound frame's epoch relates to our local group epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochRelation {
    /// The inbound epoch is higher than ours — WE are behind and must
    /// recover (fetch + apply commits) before we can decrypt.
    Behind,
    /// Same epoch — decryptable now; no recovery needed.
    Equal,
    /// The inbound epoch is lower than ours — a stale/replayed frame from
    /// an older epoch; not a reason to recover.
    Ahead,
}

/// Classify an inbound epoch against the local group epoch.
///
/// `inbound > local` => [`EpochRelation::Behind`] (we are behind the
/// group), `==` => [`EpochRelation::Equal`], `<` => [`EpochRelation::Ahead`].
#[must_use]
pub fn epoch_relation(inbound_epoch: u64, local_epoch: u64) -> EpochRelation {
    match inbound_epoch.cmp(&local_epoch) {
        std::cmp::Ordering::Greater => EpochRelation::Behind,
        std::cmp::Ordering::Equal => EpochRelation::Equal,
        std::cmp::Ordering::Less => EpochRelation::Ahead,
    }
}

/// Convenience: given the `u32` frame `secret_epoch` and the `u64` local
/// epoch, are we behind? Widens the frame epoch to `u64` first.
#[must_use]
pub fn frame_is_behind(frame_epoch: u32, local_epoch: u64) -> bool {
    epoch_relation(u64::from(frame_epoch), local_epoch) == EpochRelation::Behind
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn behind_when_inbound_higher() {
        assert_eq!(epoch_relation(5, 3), EpochRelation::Behind);
        assert_eq!(epoch_relation(1, 0), EpochRelation::Behind);
    }

    #[test]
    fn equal_when_same() {
        assert_eq!(epoch_relation(3, 3), EpochRelation::Equal);
        assert_eq!(epoch_relation(0, 0), EpochRelation::Equal);
    }

    #[test]
    fn ahead_when_inbound_lower() {
        assert_eq!(epoch_relation(2, 7), EpochRelation::Ahead);
        assert_eq!(epoch_relation(0, 1), EpochRelation::Ahead);
    }

    #[test]
    fn edge_values_never_wrap() {
        // Direct comparison, so u64::MAX boundaries are well-defined.
        assert_eq!(
            epoch_relation(u64::MAX, u64::MAX - 1),
            EpochRelation::Behind
        );
        assert_eq!(epoch_relation(u64::MAX - 1, u64::MAX), EpochRelation::Ahead);
        assert_eq!(epoch_relation(u64::MAX, u64::MAX), EpochRelation::Equal);
    }

    #[test]
    fn frame_widening_compares_across_the_u32_u64_boundary() {
        // A local epoch past u32::MAX is still comparable to a u32 frame
        // epoch after widening — the frame is (correctly) behind.
        let local = u64::from(u32::MAX) + 10;
        assert!(!frame_is_behind(u32::MAX, local));
        // Frame epoch above local => behind.
        assert!(frame_is_behind(9, 3));
        // Equal => not behind.
        assert!(!frame_is_behind(3, 3));
    }
}
