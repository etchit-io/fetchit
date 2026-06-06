//! #251 Layer 2 contingency gate. The Welcome bridge only runs while
//! the local x0xd (bundled or installed) is below v0.21.3 (the release
//! that carries David's 63b5c63b Welcome-retry fix). Once the local
//! binary catches up, callers short-circuit to x0xd's native Welcome
//! flow.
//!
//! Asymmetric by design: only the JOINER side gates against this
//! version threshold. The OWNER side responds unconditionally to a
//! `WelcomeBlobRequest` envelope it receives, because the owner has
//! no way to know which version the joiner is running and a stray
//! response is harmless (the joiner just ignores it if its x0xd
//! already accepted the native Welcome). Do not add owner-side
//! gating here.

/// Minimum x0xd version that obviates the Welcome bridge. Bumped in
/// lockstep with David's release tagging cadence.
#[must_use]
pub fn welcome_bridge_retires_at() -> semver::Version {
    semver::Version::new(0, 21, 3)
}

/// True when the bridge must run. False short-circuits to the native
/// x0xd Welcome flow.
#[must_use]
pub fn bridge_required(local_x0xd: &semver::Version) -> bool {
    local_x0xd < &welcome_bridge_retires_at()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bridge_required_below_threshold() {
        let v = semver::Version::parse("0.21.2").unwrap();
        assert!(bridge_required(&v));
    }

    #[test]
    fn bridge_not_required_at_threshold() {
        let v = semver::Version::parse("0.21.3").unwrap();
        assert!(!bridge_required(&v));
    }

    #[test]
    fn bridge_not_required_above_threshold() {
        let v = semver::Version::parse("0.22.0").unwrap();
        assert!(!bridge_required(&v));
    }

    #[tokio::test]
    async fn welcome_bridge_skipped_when_local_x0xd_at_or_above_v0_21_3() {
        // Caller pattern:
        //   let local_v = x0xd_version_probe(); // returns semver::Version
        //   if !welcome_gate::bridge_required(&local_v) {
        //       return Ok(());  // x0xd's native Welcome handles it
        //   }
        //   dispatch_welcome_request_to_owner(...).await?;
        let local = semver::Version::parse("0.21.3").unwrap();
        assert!(!crate::groups::welcome_gate::bridge_required(&local));
    }
}
