package io.etchit.fetchit.chat

import android.content.Context
import io.etchit.fetchit.SettingsStore

/**
 * Returns the user's chosen display name for outgoing DMs.
 *
 * Reads [SettingsStore.chatDisplayName]; when unset (empty) falls back to
 * `"agent-"` + the first 6 hex characters of [agentIdHex]. This is the
 * single source of truth for the fallback — both [ChatModeView] (thread
 * send) and [io.etchit.fetchit.showQrPreviewDialog] (share-in-chat send)
 * delegate here so the logic cannot drift.
 */
fun displayNameOrDefault(context: Context, agentIdHex: String): String {
    val saved = SettingsStore(context).chatDisplayName()
    return if (saved.isNotEmpty()) saved else "agent-${agentIdHex.take(6)}"
}
