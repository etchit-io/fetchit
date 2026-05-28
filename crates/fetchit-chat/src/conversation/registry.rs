//! Persistent registry of open conversations, backed by `at_rest`.

use super::types::Conversation;
use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::error::ChatError;
use crate::local_store::StoreLayout;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// In-memory registry of open conversations, persisted via `at_rest`.
pub struct ConversationRegistry {
    layout: StoreLayout,
    master: Arc<MasterKey>,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    by_group_id: Mutex<HashMap<String, Conversation>>,
}

impl ConversationRegistry {
    /// Build an empty registry. Conversations are loaded on demand.
    #[must_use]
    pub fn new(
        layout: StoreLayout,
        master: Arc<MasterKey>,
        kdf_id: u8,
        argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        Self {
            layout,
            master,
            kdf_id,
            argon_salt,
            by_group_id: Mutex::new(HashMap::new()),
        }
    }

    /// Borrow / load a conversation by `group_id_hex`.
    /// Returns None if it's not on disk and not in memory.
    ///
    /// # Errors
    /// IO, AEAD, or JSON parse errors.
    pub async fn get(&self, group_id_hex: &str) -> Result<Option<Conversation>, ChatError> {
        {
            let g = self.by_group_id.lock().await;
            if let Some(c) = g.get(group_id_hex) {
                return Ok(Some(c.clone()));
            }
        }
        let path = self.layout.conversation_path(group_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = open_from_path(&path, &self.master)?;
        let conv: Conversation = serde_json::from_slice(&bytes)
            .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
        self.by_group_id
            .lock()
            .await
            .insert(group_id_hex.to_owned(), conv.clone());
        Ok(Some(conv))
    }

    /// Find an existing DM with `peer_agent_id_hex` (any conversation
    /// that has exactly 2 members and one of them is the peer).
    ///
    /// # Errors
    /// IO or vault open failures while scanning disk.
    pub async fn find_dm_with(
        &self,
        peer_agent_id_hex: &str,
    ) -> Result<Option<Conversation>, ChatError> {
        {
            let g = self.by_group_id.lock().await;
            for c in g.values() {
                if dm_with(c, peer_agent_id_hex) {
                    return Ok(Some(c.clone()));
                }
            }
        }
        for entry in std::fs::read_dir(&self.layout.conversations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                continue;
            }
            let bytes = open_from_path(&path, &self.master)?;
            let conv: Conversation = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
            if dm_with(&conv, peer_agent_id_hex) {
                self.by_group_id
                    .lock()
                    .await
                    .insert(conv.group_id_hex.clone(), conv.clone());
                return Ok(Some(conv));
            }
        }
        Ok(None)
    }

    /// Persist a conversation to disk and update the in-memory cache.
    ///
    /// # Errors
    /// IO, AEAD seal, or JSON serialize errors.
    pub async fn save(&self, conv: &Conversation) -> Result<(), ChatError> {
        let path = self.layout.conversation_path(&conv.group_id_hex);
        let bytes = serde_json::to_vec(conv)
            .map_err(|e| ChatError::Invalid(format!("conv serialize: {e}")))?;
        seal_to_path(
            &path,
            &bytes,
            &self.master,
            self.kdf_id,
            self.argon_salt.as_ref(),
        )?;
        self.by_group_id
            .lock()
            .await
            .insert(conv.group_id_hex.clone(), conv.clone());
        Ok(())
    }
}

fn dm_with(conv: &Conversation, peer_agent_id_hex: &str) -> bool {
    if conv.members.len() != 2 {
        return false;
    }
    conv.members
        .iter()
        .flat_map(|m| m.devices.iter())
        .any(|d| d.agent_id_hex == peer_agent_id_hex)
}
