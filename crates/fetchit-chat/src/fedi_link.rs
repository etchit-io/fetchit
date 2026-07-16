//! Durable at-rest store for the fediverse↔LIT person links (M7 P4,
//! "go private").
//!
//! One sealed file per minted handle
//! (`<root>/fedi/links/<handle>.json.enc`) records the go-private
//! lifecycle per correspondent — `none → invited → linked` — so the
//! unified Chats list can collapse a linked fediverse thread and its new
//! private (PQ) contact into a single 🔒 row.
//!
//! Same seal shape as [`crate::fedi_thread`] (magic ‖ nonce ‖ AEAD
//! ciphertext), same HKDF-derived key, distinct magic + AAD so a
//! swapped-blob attack between the stores fails the tag check.
//!
//! The link is **local only** and is never published: LIT and fediverse
//! identities share no keys, and associating a fediverse handle with a
//! PQ agent id is a user-confirmed local decision (the pair link crossed
//! the recipient's server in the clear, so a human is the trust anchor).

use crate::at_rest::MasterKey;
use crate::client::Client;
use crate::error::{ChatError, Result};
use crate::fedi_identity::derive_fedi_vault_key;
use crate::fedi_thread::canonical_thread_label;
use crate::fedi_vault::{read_sealed, write_sealed_atomic};
use crate::local_store::StoreLayout;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// File magic identifying a Fetchit Fedi Links v1 file.
pub const FEDI_LINKS_MAGIC: &[u8; 4] = b"FFL1";

/// AAD bound into every seal/open — domain-separated from the thread
/// store under the shared derived key.
pub const FEDI_LINKS_AAD: &[u8] = b"fetchit-fedi-links-v1";

/// The go-private state for one fediverse correspondent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonLink {
    /// When a go-private invite was last delivered (`None` = never).
    #[serde(default)]
    pub invited_at_ms: Option<i64>,
    /// The PQ agent id this handle is linked to (`None` = not linked).
    #[serde(default)]
    pub agent_id_hex: Option<String>,
    /// When the link was confirmed.
    #[serde(default)]
    pub linked_at_ms: Option<i64>,
}

/// All person links for one minted handle, keyed by
/// [`canonical_thread_label`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FediLinks {
    /// Link state per correspondent label.
    #[serde(default)]
    pub links: BTreeMap<String, PersonLink>,
}

impl FediLinks {
    /// Record that a go-private invite was delivered to `label`.
    pub fn record_invite(&mut self, label: &str, at_ms: i64) {
        self.links
            .entry(canonical_thread_label(label))
            .or_default()
            .invited_at_ms = Some(at_ms);
    }

    /// Confirm a link from `label` to `agent_id_hex`. Returns `true` when
    /// this created or changed the target agent id.
    pub fn link(&mut self, label: &str, agent_id_hex: &str, at_ms: i64) -> bool {
        let e = self.links.entry(canonical_thread_label(label)).or_default();
        let changed = e.agent_id_hex.as_deref() != Some(agent_id_hex);
        e.agent_id_hex = Some(agent_id_hex.to_owned());
        e.linked_at_ms = Some(at_ms);
        changed
    }

    /// Drop the link for `label` (keeps invite history for the re-open
    /// flow).
    pub fn unlink(&mut self, label: &str) {
        if let Some(e) = self.links.get_mut(&canonical_thread_label(label)) {
            e.agent_id_hex = None;
            e.linked_at_ms = None;
        }
    }

    /// Labels invited to private chat but not yet linked.
    #[must_use]
    pub fn pending(&self) -> Vec<String> {
        self.links
            .iter()
            .filter(|(_, p)| p.invited_at_ms.is_some() && p.agent_id_hex.is_none())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The link record for `label` (canonicalised).
    #[must_use]
    pub fn get(&self, label: &str) -> Option<PersonLink> {
        self.links.get(&canonical_thread_label(label)).cloned()
    }

    /// Reverse lookup: the canonical label linked to `agent_id_hex`, if
    /// any. Used to collapse a linked fediverse thread into its PQ
    /// contact row.
    #[must_use]
    pub fn is_linked_agent(&self, agent_id_hex: &str) -> Option<String> {
        self.links
            .iter()
            .find(|(_, p)| p.agent_id_hex.as_deref() == Some(agent_id_hex))
            .map(|(k, _)| k.clone())
    }
}

/// Load the person-link store for `handle`. A missing file is a fresh,
/// empty store; a present-but-unreadable file is an error so existing
/// links are never silently clobbered.
///
/// # Errors
/// [`ChatError`] on IO, seal, or JSON-decode failures.
pub fn load_fedi_links(
    handle: &str,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<FediLinks> {
    let key = derive_fedi_vault_key(master);
    let path = layout.fedi_links_path(handle);
    let Some(plain) = read_sealed(&path, *FEDI_LINKS_MAGIC, &key, FEDI_LINKS_AAD)? else {
        return Ok(FediLinks::default());
    };
    serde_json::from_slice(&plain)
        .map_err(|e| ChatError::Invalid(format!("fedi links decode: {e}")))
}

/// Seal and atomically persist the person-link store for `handle`.
///
/// # Errors
/// [`ChatError`] on JSON-encode, IO, or seal failures.
pub fn save_fedi_links(
    handle: &str,
    links: &FediLinks,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<()> {
    let key = derive_fedi_vault_key(master);
    let plain = serde_json::to_vec(links)
        .map_err(|e| ChatError::Invalid(format!("fedi links encode: {e}")))?;
    write_sealed_atomic(
        &layout.fedi_links_path(handle),
        *FEDI_LINKS_MAGIC,
        &key,
        FEDI_LINKS_AAD,
        &plain,
    )
}

impl Client {
    /// Record that a go-private invite was delivered to `target` under
    /// our minted `handle`. The FFI layer composes + sends the invite
    /// (the pair URI is FFI-layer state) and calls this ONLY on a
    /// confirmed delivery, so the pending state can never claim an
    /// invite the recipient never received.
    ///
    /// # Errors
    /// [`ChatError`] on store IO.
    pub fn record_fedi_invite(&self, handle: &str, target: &str, at_ms: i64) -> Result<()> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut links = load_fedi_links(handle, &master, &layout)?;
        links.record_invite(target, at_ms);
        save_fedi_links(handle, &links, &master, &layout)
    }

    /// Handles invited to private chat but not yet linked.
    ///
    /// # Errors
    /// [`ChatError`] on store load.
    pub fn pending_go_private(&self, handle: &str) -> Result<Vec<String>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_links(handle, &master, &layout)?.pending())
    }

    /// Link `target` (fediverse label) to a PQ `agent_id_hex` — the
    /// manual "Same person?" confirm. Local only; never published.
    ///
    /// # Errors
    /// [`ChatError`] on store IO.
    pub fn link_fedi_person(&self, handle: &str, target: &str, agent_id_hex: &str) -> Result<()> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut links = load_fedi_links(handle, &master, &layout)?;
        links.link(target, agent_id_hex, now_ms_i64());
        save_fedi_links(handle, &links, &master, &layout)
    }

    /// Drop the link for `target`.
    ///
    /// # Errors
    /// [`ChatError`] on store IO.
    pub fn unlink_fedi_person(&self, handle: &str, target: &str) -> Result<()> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut links = load_fedi_links(handle, &master, &layout)?;
        links.unlink(target);
        save_fedi_links(handle, &links, &master, &layout)
    }

    /// Every person link for `handle`, as `(label, link)` pairs.
    ///
    /// # Errors
    /// [`ChatError`] on store load.
    pub fn fedi_person_links(&self, handle: &str) -> Result<Vec<(String, PersonLink)>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_links(handle, &master, &layout)?
            .links
            .into_iter()
            .collect())
    }

    /// The fediverse label linked to `agent_id_hex`, if any (reverse
    /// lookup used to collapse a linked thread into its PQ contact row).
    ///
    /// # Errors
    /// [`ChatError`] on store load.
    pub fn linked_label_for_agent(
        &self,
        handle: &str,
        agent_id_hex: &str,
    ) -> Result<Option<String>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_links(handle, &master, &layout)?.is_linked_agent(agent_id_hex))
    }
}

/// Wall-clock unix ms as `i64`, clamped on a pre-epoch or overflowing
/// clock.
fn now_ms_i64() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use tempfile::tempdir;

    fn agent(byte: &str) -> String {
        byte.repeat(32)
    }

    #[test]
    fn lifecycle_none_invited_linked() {
        let mut l = FediLinks::default();
        assert!(l.pending().is_empty());
        l.record_invite("@happyborg@fosstodon.org", 100);
        assert_eq!(l.pending(), vec!["happyborg@fosstodon.org"]);
        // Case-insensitive label; linking drops it out of pending.
        assert!(l.link("HappyBorg@Fosstodon.org", &agent("aa"), 200));
        assert!(l.pending().is_empty(), "linked drops out of pending");
        let got = l.get("happyborg@fosstodon.org").unwrap();
        assert_eq!(got.agent_id_hex.as_deref(), Some(agent("aa").as_str()));
        assert_eq!(got.invited_at_ms, Some(100));
        assert_eq!(
            l.is_linked_agent(&agent("aa")).as_deref(),
            Some("happyborg@fosstodon.org")
        );
        // Re-linking the same agent is a no-op change.
        assert!(!l.link("happyborg@fosstodon.org", &agent("aa"), 300));
        // Unlink clears the target but keeps invite history.
        l.unlink("happyborg@fosstodon.org");
        assert!(l
            .get("happyborg@fosstodon.org")
            .unwrap()
            .agent_id_hex
            .is_none());
        assert_eq!(
            l.get("happyborg@fosstodon.org").unwrap().invited_at_ms,
            Some(100)
        );
        assert!(l.is_linked_agent(&agent("aa")).is_none());
    }

    #[test]
    fn save_and_load_round_trip_sealed() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = MasterKey::from_bytes_for_test([0x42; AEAD_KEY_LEN]);

        let mut l = FediLinks::default();
        l.record_invite("a@h", 1);
        l.link("a@h", &agent("bb"), 2);
        save_fedi_links("josh", &l, &master, &layout).unwrap();

        let back = load_fedi_links("josh", &master, &layout).unwrap();
        assert_eq!(back.get("a@h").unwrap().agent_id_hex, Some(agent("bb")));

        // On disk it is sealed under the links/ subdir, not plaintext.
        let raw = std::fs::read(layout.fedi_links_path("josh")).unwrap();
        assert_eq!(&raw[..4], FEDI_LINKS_MAGIC);
        assert!(!raw.windows(2).any(|w| w == b"bb"));
    }

    #[test]
    fn missing_file_loads_fresh_and_wrong_key_errors() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let fresh = load_fedi_links(
            "josh",
            &MasterKey::from_bytes_for_test([1; AEAD_KEY_LEN]),
            &layout,
        )
        .unwrap();
        assert!(fresh.links.is_empty());

        let mut l = FediLinks::default();
        l.link("a@h", &agent("cc"), 1);
        save_fedi_links(
            "josh",
            &l,
            &MasterKey::from_bytes_for_test([1; AEAD_KEY_LEN]),
            &layout,
        )
        .unwrap();
        assert!(
            load_fedi_links(
                "josh",
                &MasterKey::from_bytes_for_test([2; AEAD_KEY_LEN]),
                &layout
            )
            .is_err(),
            "links must never be silently clobbered by a wrong key",
        );
    }
}
