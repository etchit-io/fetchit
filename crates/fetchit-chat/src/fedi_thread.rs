//! Durable at-rest store for fediverse DM threads (M7 P3).
//!
//! One sealed file per minted handle (`<root>/fedi/threads/<handle>.json.enc`)
//! holds every fediverse direct message this device has sent or pulled,
//! grouped by correspondent, plus the bridge-inbox `since_ms` cursor.
//! Messages and cursor persist in a single atomic write so a cursor
//! advance can never outlive the messages it covers — the loss class
//! behind fedi DMs vanishing on-device (2026-07-14): the shell kept the
//! thread only in process memory while its separately-persisted cursor
//! marched past every message the bridge had already served.
//!
//! Same seal shape as [`crate::fedi_vault`] (magic ‖ nonce ‖ AEAD
//! ciphertext), same HKDF-derived key, distinct magic + AAD so a
//! swapped-blob attack between the identity vault and the thread store
//! fails the tag check.
//!
//! Fedi DMs ride ordinary `ActivityPub` rails and are readable by the
//! correspondent's server — the at-rest seal protects the local copy
//! (a stolen device or backup), it adds no transport privacy.

use crate::at_rest::MasterKey;
use crate::error::ChatError;
use crate::fedi_dm::FediInboxMessage;
use crate::fedi_identity::derive_fedi_vault_key;
use crate::fedi_vault::{read_sealed, write_sealed_atomic};
use crate::local_store::StoreLayout;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// File magic identifying a Fetchit Fedi Threads v1 file.
pub const FEDI_THREADS_MAGIC: &[u8; 4] = b"FFT1";

/// AAD bound into every seal/open — domain-separated from
/// [`crate::fedi_vault::FEDI_VAULT_AAD`] under the shared derived key.
pub const FEDI_THREADS_AAD: &[u8] = b"fetchit-fedi-threads-v1";

/// Canonical thread label for a fediverse correspondent: trimmed, one
/// leading `@` removed, lowercased. Mirrors the Android shell's
/// `canonicalFediHandle` exactly so the engine store and the shell's
/// `f:<label>` conversation keys always agree.
#[must_use]
pub fn canonical_thread_label(s: &str) -> String {
    let t = s.trim();
    let t = t.strip_prefix('@').unwrap_or(t);
    t.to_lowercase()
}

/// One fediverse direct message as persisted in a thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FediThreadMsg {
    /// `true` when this device sent it.
    pub outbound: bool,
    /// Plain-text body (inbound bodies were HTML-reduced by the bridge).
    pub text: String,
    /// The Note id — the dedup key within a thread.
    pub note_id: String,
    /// Ordering axis: our send clock for outbound, the bridge receive
    /// time (`created_ms`) for inbound.
    pub at_ms: i64,
    /// The correspondent's actor URL (recipient for outbound, sender
    /// for inbound).
    pub peer_actor_url: String,
    /// Outbound only: `true` when the recipient's inbox accepted the
    /// delivery. Meaningless on inbound rows.
    #[serde(default)]
    pub delivered: bool,
}

/// All fediverse DM threads for one minted handle, plus the shared
/// bridge-inbox cursor.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FediThreads {
    /// `since_ms` high-water mark over the bridge inbox. Advances only
    /// in the same save that persists the messages it skips past.
    #[serde(default)]
    pub cursor_ms: i64,
    /// Thread per correspondent, keyed by [`canonical_thread_label`].
    #[serde(default)]
    pub threads: BTreeMap<String, Vec<FediThreadMsg>>,
}

/// A one-line summary of a fediverse DM thread, for the unified
/// conversation list. Derived from the last message in each thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FediThreadSummary {
    /// Canonical correspondent label (`user@host`), the `f:<label>`
    /// conversation key without the prefix.
    pub label: String,
    /// The most recent message's plain-text body — the list preview.
    pub last_body: String,
    /// The most recent message's ordering stamp — the list sort key.
    pub last_at_ms: i64,
    /// `true` when the most recent message was sent by this device.
    pub last_outbound: bool,
}

impl FediThreads {
    /// Insert `msg` into the thread for `label` (canonicalised here).
    /// Returns `false` (and stores nothing) when a message with the same
    /// note id is already in that thread. Threads stay sorted by
    /// [`FediThreadMsg::at_ms`]; the sort is stable so same-stamp
    /// messages keep arrival order.
    pub fn insert(&mut self, label: &str, msg: FediThreadMsg) -> bool {
        let list = self
            .threads
            .entry(canonical_thread_label(label))
            .or_default();
        if list.iter().any(|m| m.note_id == msg.note_id) {
            return false;
        }
        list.push(msg);
        list.sort_by_key(|m| m.at_ms);
        true
    }

    /// Messages for `label` (canonicalised), oldest first. Empty when no
    /// thread exists.
    #[must_use]
    pub fn history(&self, label: &str) -> Vec<FediThreadMsg> {
        self.threads
            .get(&canonical_thread_label(label))
            .cloned()
            .unwrap_or_default()
    }

    /// Fold a batch of pulled inbox `items` in: every item lands in its
    /// sender's own thread (labelled via
    /// [`crate::fedi_feed::author_label`]) — never skipped for being
    /// addressed to a thread the user doesn't have open — and the
    /// cursor advances past every item, including redelivered
    /// duplicates, because the caller persists messages and cursor in
    /// the same atomic save. Returns how many messages were new.
    pub fn fold_inbox(&mut self, items: &[FediInboxMessage]) -> u32 {
        let mut inserted = 0u32;
        for it in items {
            self.cursor_ms = self.cursor_ms.max(it.created_ms);
            let label = crate::fedi_feed::author_label(&it.sender_actor_url);
            let msg = FediThreadMsg {
                outbound: false,
                text: it.text.clone(),
                note_id: it.note_id.clone(),
                at_ms: it.created_ms,
                peer_actor_url: it.sender_actor_url.clone(),
                delivered: false,
            };
            if self.insert(&label, msg) {
                inserted += 1;
            }
        }
        inserted
    }

    /// One [`FediThreadSummary`] per non-empty thread, newest activity
    /// first (ties broken by label ascending so the order is stable). The
    /// render source for fediverse rows in the unified conversation list.
    #[must_use]
    pub fn overview(&self) -> Vec<FediThreadSummary> {
        let mut out: Vec<FediThreadSummary> = self
            .threads
            .iter()
            .filter_map(|(label, msgs)| {
                let last = msgs.last()?;
                Some(FediThreadSummary {
                    label: label.clone(),
                    last_body: last.text.clone(),
                    last_at_ms: last.at_ms,
                    last_outbound: last.outbound,
                })
            })
            .collect();
        out.sort_by(|a, b| {
            b.last_at_ms
                .cmp(&a.last_at_ms)
                .then_with(|| a.label.cmp(&b.label))
        });
        out
    }
}

/// Load the thread store for `handle`. A missing file is a fresh, empty
/// store (cursor 0 — the first sync re-pulls everything the bridge
/// still holds); a present-but-unreadable file is an error so existing
/// history is never silently clobbered.
///
/// # Errors
/// [`ChatError`] on IO, seal, or JSON-decode failures.
pub fn load_fedi_threads(
    handle: &str,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<FediThreads, ChatError> {
    let key = derive_fedi_vault_key(master);
    let path = layout.fedi_threads_path(handle);
    let Some(plain) = read_sealed(&path, *FEDI_THREADS_MAGIC, &key, FEDI_THREADS_AAD)? else {
        return Ok(FediThreads::default());
    };
    serde_json::from_slice(&plain)
        .map_err(|e| ChatError::Invalid(format!("fedi threads decode: {e}")))
}

/// Seal and atomically persist the thread store for `handle`.
///
/// # Errors
/// [`ChatError`] on JSON-encode, IO, or seal failures.
pub fn save_fedi_threads(
    handle: &str,
    threads: &FediThreads,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<(), ChatError> {
    let key = derive_fedi_vault_key(master);
    let plain = serde_json::to_vec(threads)
        .map_err(|e| ChatError::Invalid(format!("fedi threads encode: {e}")))?;
    write_sealed_atomic(
        &layout.fedi_threads_path(handle),
        *FEDI_THREADS_MAGIC,
        &key,
        FEDI_THREADS_AAD,
        &plain,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use tempfile::tempdir;

    fn fixture_master(byte: u8) -> MasterKey {
        MasterKey::from_bytes_for_test([byte; AEAD_KEY_LEN])
    }

    fn inbound(sender: &str, note: &str, ms: i64) -> FediInboxMessage {
        FediInboxMessage {
            sender_actor_url: sender.to_owned(),
            note_id: note.to_owned(),
            text: format!("body of {note}"),
            published: String::new(),
            created_ms: ms,
        }
    }

    fn outbound(note: &str, ms: i64) -> FediThreadMsg {
        FediThreadMsg {
            outbound: true,
            text: format!("sent {note}"),
            note_id: note.to_owned(),
            at_ms: ms,
            peer_actor_url: "https://fosstodon.org/users/happyborg".into(),
            delivered: true,
        }
    }

    #[test]
    fn canonical_label_mirrors_android_shell() {
        // Same three transforms as Kotlin's canonicalFediHandle:
        // trim, remove ONE leading @, lowercase.
        assert_eq!(
            canonical_thread_label(" @Happy@Foss.org "),
            "happy@foss.org"
        );
        assert_eq!(canonical_thread_label("@@x"), "@x");
        assert_eq!(canonical_thread_label("plain@host"), "plain@host");
    }

    #[test]
    fn insert_dedups_by_note_id_and_sorts_by_time() {
        let mut t = FediThreads::default();
        assert!(t.insert("@a@h", outbound("n2", 20)));
        assert!(t.insert("A@H", outbound("n1", 10)));
        assert!(!t.insert("a@h", outbound("n1", 10)), "dup note id");
        let h = t.history("a@h");
        assert_eq!(
            h.iter().map(|m| m.note_id.as_str()).collect::<Vec<_>>(),
            vec!["n1", "n2"],
        );
    }

    #[test]
    fn fold_inbox_lands_every_sender_and_advances_cursor_past_dups() {
        let mut t = FediThreads::default();
        let items = vec![
            inbound("https://fosstodon.org/users/happyborg", "r1", 100),
            // A sender with no open thread must still be stored, not
            // skipped-and-cursor-passed (the old shell bug).
            inbound("https://mas.to/users/stranger", "r2", 200),
        ];
        assert_eq!(t.fold_inbox(&items), 2);
        assert_eq!(t.cursor_ms, 200);
        assert_eq!(t.history("happyborg@fosstodon.org").len(), 1);
        assert_eq!(t.history("stranger@mas.to").len(), 1);

        // Redelivery: no new rows, but the cursor still advances so the
        // next pull doesn't refetch it forever.
        let redelivered = vec![inbound("https://mas.to/users/stranger", "r2", 300)];
        assert_eq!(t.fold_inbox(&redelivered), 0);
        assert_eq!(t.cursor_ms, 300);
        assert_eq!(t.history("stranger@mas.to").len(), 1);
    }

    #[test]
    fn inbound_replies_interleave_with_outbound_sends() {
        let mut t = FediThreads::default();
        t.insert("@happyborg@fosstodon.org", outbound("s1", 100));
        t.fold_inbox(&[inbound("https://fosstodon.org/users/happyborg", "r1", 150)]);
        t.insert("@happyborg@fosstodon.org", outbound("s2", 200));
        let h = t.history("happyborg@fosstodon.org");
        assert_eq!(
            h.iter()
                .map(|m| (m.note_id.as_str(), m.outbound))
                .collect::<Vec<_>>(),
            vec![("s1", true), ("r1", false), ("s2", true)],
        );
    }

    #[test]
    fn save_and_load_round_trip_sealed() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);

        let mut t = FediThreads::default();
        t.insert("happyborg@fosstodon.org", outbound("s1", 100));
        t.cursor_ms = 100;
        save_fedi_threads("josh", &t, &master, &layout).unwrap();

        let back = load_fedi_threads("josh", &master, &layout).unwrap();
        assert_eq!(back.cursor_ms, 100);
        assert_eq!(
            back.history("happyborg@fosstodon.org"),
            t.history("happyborg@fosstodon.org")
        );

        // On disk it is sealed, not plaintext JSON.
        let raw = std::fs::read(layout.fedi_threads_path("josh")).unwrap();
        assert_eq!(&raw[..4], FEDI_THREADS_MAGIC);
        assert!(!raw.windows(2).any(|w| w == b"s1"));
    }

    #[test]
    fn missing_file_loads_as_fresh_store() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let t = load_fedi_threads("josh", &fixture_master(1), &layout).unwrap();
        assert_eq!(t.cursor_ms, 0);
        assert!(t.threads.is_empty());
    }

    #[test]
    fn wrong_key_is_an_error_not_a_fresh_store() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let mut t = FediThreads::default();
        t.insert("a@h", outbound("s1", 1));
        save_fedi_threads("josh", &t, &fixture_master(1), &layout).unwrap();
        assert!(
            load_fedi_threads("josh", &fixture_master(2), &layout).is_err(),
            "history must never be silently clobbered",
        );
    }

    #[test]
    fn overview_is_one_row_per_thread_newest_first() {
        let mut t = FediThreads::default();
        // happyborg: last activity at 200 (an inbound reply)
        t.insert("@happyborg@fosstodon.org", outbound("s1", 100));
        t.fold_inbox(&[inbound("https://fosstodon.org/users/happyborg", "r1", 200)]);
        // stranger: last activity at 150
        t.fold_inbox(&[inbound("https://mas.to/users/stranger", "r2", 150)]);

        let ov = t.overview();
        assert_eq!(ov.len(), 2, "one summary per thread");
        // newest-first: happyborg (200) before stranger (150)
        assert_eq!(ov[0].label, "happyborg@fosstodon.org");
        assert_eq!(ov[0].last_at_ms, 200);
        assert_eq!(ov[0].last_body, "body of r1");
        assert!(!ov[0].last_outbound, "last row was an inbound reply");
        assert_eq!(ov[1].label, "stranger@mas.to");
        assert_eq!(ov[1].last_at_ms, 150);
    }

    #[test]
    fn overview_skips_empty_threads_and_is_deterministic_on_ties() {
        let mut t = FediThreads::default();
        // Two threads with the same last_at_ms — label breaks the tie.
        t.insert("@bbb@h", outbound("s1", 100));
        t.insert("@aaa@h", outbound("s2", 100));
        let ov = t.overview();
        assert_eq!(
            ov.iter().map(|s| s.label.as_str()).collect::<Vec<_>>(),
            vec!["aaa@h", "bbb@h"],
            "equal timestamps sort by label ascending",
        );
    }

    #[test]
    fn thread_store_is_invisible_to_actor_handle_enumeration() {
        // list_actor_handles scans fedi/*.json.enc — the thread store
        // lives one level down so it can never masquerade as a handle.
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        save_fedi_threads("josh", &FediThreads::default(), &fixture_master(1), &layout).unwrap();
        assert!(crate::fedi_vault::list_actor_handles(&layout).is_empty());
    }
}
