//! Directory-registration outcome for the minted fediverse handle.
//!
//! Minting is local-first: the identity is always created and sealed
//! locally, and the directory POST is best-effort. That leaves three
//! materially different outcomes which the shells must not conflate --
//! a handle held by *someone else* can never be won by retrying, while
//! a bridge outage clears on its own. This module names those outcomes
//! ([`RegistrationState`]) and persists the last one ([`MintState`]) so
//! a conflict survives a restart instead of decaying into an eternal
//! "registration pending".
//!
//! Best-effort local state, like the resolutions ledger: a corrupt file
//! resets to "nothing known" and never blocks a mint.

use crate::error::ChatError;
use crate::local_store::{write_json_atomic, StoreLayout};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Serializes read-modify-write cycles on the state file (same pattern
/// as `fedi_resolutions::RESOLUTIONS_LOCK`).
static MINT_STATE_LOCK: Mutex<()> = Mutex::new(());

/// How the directory answered the last registration attempt.
///
/// The bridge distinguishes the three cases by status: `201` on a first
/// registration and `200` when the SAME agent id re-registers (an
/// idempotent update, still success), `409` only when the handle row is
/// held by a DIFFERENT agent id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RegistrationState {
    /// The directory holds our record (`201` created or `200` idempotent
    /// re-register under the same agent id).
    Registered,
    /// `409`: the handle is bound to a different agent id. **Terminal** --
    /// re-POSTing the same handle can never succeed, so the user has to
    /// pick another name.
    NameTaken,
    /// Transport failure, `5xx`, or any other status: a later attempt can
    /// still succeed, so the retry path stays armed.
    Transient {
        /// User-facing failure text.
        reason: String,
    },
}

impl RegistrationState {
    /// True when the directory holds our record.
    #[must_use]
    pub fn registered(&self) -> bool {
        matches!(self, Self::Registered)
    }

    /// True when retrying this handle is pointless (the name is taken).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::NameTaken)
    }

    /// User-facing reason the directory does not hold our record, or
    /// `None` when it does.
    #[must_use]
    pub fn error_text(&self) -> Option<String> {
        match self {
            Self::Registered => None,
            // Matches `RegistryError::HandleTaken`'s Display, the text the
            // shells have always shown for a 409.
            Self::NameTaken => Some("handle already registered".to_owned()),
            Self::Transient { reason } => Some(reason.clone()),
        }
    }
}

/// The last registration attempt this device made, persisted so the UI
/// can render an honest state on a cold start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintState {
    /// Handle local-part the attempt was for (e.g. `josh`).
    pub handle: String,
    /// How the directory answered.
    pub registration: RegistrationState,
    /// When the attempt was classified, milliseconds since the epoch.
    pub at_ms: u64,
}

/// Read the last recorded registration attempt. A missing or corrupt
/// file reads as `None`.
#[must_use]
pub fn load(layout: &StoreLayout) -> Option<MintState> {
    let _guard = MINT_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bytes = std::fs::read(layout.fedi_mint_state_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Record the outcome of a registration attempt, replacing any earlier
/// one.
///
/// # Errors
///
/// [`ChatError`] when the state file cannot be written.
pub fn save(layout: &StoreLayout, state: &MintState) -> Result<(), ChatError> {
    let _guard = MINT_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    write_json_atomic(&layout.fedi_mint_state_path(), state)
}

/// True when `handle` is recorded as held by another agent id. The
/// automatic re-register pass consults this to stop retrying a name it
/// can never win; an explicit user-driven mint ignores it and asks the
/// directory again.
#[must_use]
pub fn is_name_taken(layout: &StoreLayout, handle: &str) -> bool {
    load(layout).is_some_and(|s| s.handle == handle && s.registration.is_terminal())
}

/// The handle a shell should present as "your public @name", chosen from
/// the minted vaults: the one the directory last accepted, never one it
/// refused, else the first minted.
///
/// A refused handle is not a working public identity -- the directory
/// serves someone else's actor at that name -- so presenting it would both
/// lie and hide the "pick another name" affordance the shells gate on a
/// `None` here. The accepted-handle preference matters once a conflicted
/// vault is left behind: the plain vault listing is alphabetical, so
/// without it a dead name can outrank the live one.
#[must_use]
pub fn active_handle(layout: &StoreLayout) -> Option<String> {
    let state = load(layout);
    let minted = crate::fedi_vault::list_actor_handles(layout);
    if let Some(s) = &state {
        if s.registration.registered() && minted.iter().any(|h| h == &s.handle) {
            return Some(s.handle.clone());
        }
    }
    let refused = state
        .filter(|s| s.registration.is_terminal())
        .map(|s| s.handle);
    minted.into_iter().find(|h| Some(h) != refused.as_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_layout() -> (StoreLayout, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        (layout, dir)
    }

    fn taken(handle: &str) -> MintState {
        MintState {
            handle: handle.to_owned(),
            registration: RegistrationState::NameTaken,
            at_ms: 42,
        }
    }

    #[test]
    fn no_state_file_reads_as_none() {
        let (layout, _tmp) = test_layout();
        assert!(load(&layout).is_none());
        assert!(!is_name_taken(&layout, "josh"));
    }

    #[test]
    fn conflict_survives_a_reload() {
        let (layout, _tmp) = test_layout();
        save(&layout, &taken("josh")).unwrap();
        // A fresh layout over the same root models a process restart.
        let reopened = StoreLayout::ensure(layout.root.clone()).unwrap();
        assert_eq!(load(&reopened), Some(taken("josh")));
        assert!(is_name_taken(&reopened, "josh"));
    }

    #[test]
    fn conflict_is_scoped_to_its_own_handle() {
        let (layout, _tmp) = test_layout();
        save(&layout, &taken("josh")).unwrap();
        assert!(!is_name_taken(&layout, "josh2"));
    }

    #[test]
    fn a_later_success_clears_the_conflict() {
        let (layout, _tmp) = test_layout();
        save(&layout, &taken("josh")).unwrap();
        save(
            &layout,
            &MintState {
                handle: "josh".into(),
                registration: RegistrationState::Registered,
                at_ms: 43,
            },
        )
        .unwrap();
        assert!(!is_name_taken(&layout, "josh"));
    }

    #[test]
    fn a_transient_failure_keeps_the_retry_armed() {
        let (layout, _tmp) = test_layout();
        save(
            &layout,
            &MintState {
                handle: "josh".into(),
                registration: RegistrationState::Transient {
                    reason: "bridge down".into(),
                },
                at_ms: 1,
            },
        )
        .unwrap();
        assert!(!is_name_taken(&layout, "josh"));
    }

    #[test]
    fn corrupt_state_reads_as_none_rather_than_erroring() {
        let (layout, _tmp) = test_layout();
        std::fs::write(layout.fedi_mint_state_path(), b"not json").unwrap();
        assert!(load(&layout).is_none());
        assert!(!is_name_taken(&layout, "josh"));
    }

    #[test]
    fn state_round_trips_through_json() {
        for state in [
            RegistrationState::Registered,
            RegistrationState::NameTaken,
            RegistrationState::Transient {
                reason: "bridge down".into(),
            },
        ] {
            let record = MintState {
                handle: "josh".into(),
                registration: state,
                at_ms: 7,
            };
            let json = serde_json::to_string(&record).unwrap();
            assert_eq!(serde_json::from_str::<MintState>(&json).unwrap(), record);
        }
    }

    /// Seal a placeholder identity for `handle` so the vault listing sees it.
    fn mint_vault(layout: &StoreLayout, handle: &str) {
        let master = crate::at_rest::MasterKey::from_bytes_for_test([0x42; 32]);
        let vault = crate::fedi_vault::ActorIdentityVault {
            handle: handle.to_owned(),
            actor_url: format!("https://etchit.io/actors/{handle}")
                .parse()
                .unwrap(),
            agent_id_hex: "a".repeat(64),
            rsa_priv_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n".into(),
            spki_der: vec![1, 2],
            ml_dsa_attestation: fetchit_fedi::attestation::MlDsaAttestation::new(
                vec![0xAA; 4],
                vec![0xBB; 4],
            ),
            ml_dsa_attestation_v2: None,
        };
        crate::fedi_vault::save_actor_identity(&vault, &master, layout).unwrap();
    }

    #[test]
    fn active_handle_is_the_only_minted_one_when_nothing_is_recorded() {
        let (layout, _tmp) = test_layout();
        mint_vault(&layout, "alice");
        assert_eq!(active_handle(&layout), Some("alice".to_owned()));
    }

    #[test]
    fn a_refused_handle_is_never_presented_as_active() {
        // The directory serves someone else at that name, so the shell must
        // see "no public handle" and offer to mint a different one.
        let (layout, _tmp) = test_layout();
        mint_vault(&layout, "alice");
        save(&layout, &taken("alice")).unwrap();
        assert_eq!(active_handle(&layout), None);
    }

    #[test]
    fn the_accepted_handle_outranks_a_leftover_conflicted_vault() {
        // Alphabetically "alice" wins the plain listing; the directory
        // accepted "zoe", so "zoe" is the live identity.
        let (layout, _tmp) = test_layout();
        mint_vault(&layout, "alice");
        mint_vault(&layout, "zoe");
        save(
            &layout,
            &MintState {
                handle: "zoe".into(),
                registration: RegistrationState::Registered,
                at_ms: 2,
            },
        )
        .unwrap();
        assert_eq!(active_handle(&layout), Some("zoe".to_owned()));
    }

    #[test]
    fn a_recorded_handle_with_no_vault_falls_back_to_what_is_minted() {
        let (layout, _tmp) = test_layout();
        mint_vault(&layout, "alice");
        save(
            &layout,
            &MintState {
                handle: "zoe".into(),
                registration: RegistrationState::Registered,
                at_ms: 2,
            },
        )
        .unwrap();
        assert_eq!(active_handle(&layout), Some("alice".to_owned()));
    }

    #[test]
    fn a_transient_failure_leaves_the_handle_active() {
        // A bridge outage must not hide the handle the user already minted.
        let (layout, _tmp) = test_layout();
        mint_vault(&layout, "alice");
        save(
            &layout,
            &MintState {
                handle: "alice".into(),
                registration: RegistrationState::Transient {
                    reason: "bridge down".into(),
                },
                at_ms: 2,
            },
        )
        .unwrap();
        assert_eq!(active_handle(&layout), Some("alice".to_owned()));
    }

    #[test]
    fn only_a_conflict_is_terminal() {
        assert!(RegistrationState::NameTaken.is_terminal());
        assert!(!RegistrationState::Registered.is_terminal());
        assert!(!RegistrationState::Transient { reason: "x".into() }.is_terminal());
    }

    #[test]
    fn error_text_is_none_only_when_registered() {
        assert!(RegistrationState::Registered.error_text().is_none());
        assert_eq!(
            RegistrationState::NameTaken.error_text().as_deref(),
            Some("handle already registered"),
            "must match RegistryError::HandleTaken's Display",
        );
        assert_eq!(
            RegistrationState::Transient {
                reason: "bridge down".into()
            }
            .error_text()
            .as_deref(),
            Some("bridge down")
        );
    }
}
