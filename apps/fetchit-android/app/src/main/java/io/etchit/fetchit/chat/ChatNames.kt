package io.etchit.fetchit.chat

import android.content.Context
import io.etchit.fetchit.SettingsStore
import uniffi.fetchit_ffi.GroupFfi

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

/**
 * Display title for a group thread header and its conversation-list row.
 *
 * Prefers [group]'s human name; falls back to the first 8 chars of
 * [groupId] when the name is null/blank or no [GroupFfi] is loaded yet
 * (just-joined id, or before `listGroups` resolves). Single source of
 * truth so the header and the list row cannot show different labels.
 */
fun groupTitle(group: GroupFfi?, groupId: String): String {
    val name = group?.name?.trim()
    return if (!name.isNullOrEmpty()) name else groupId.take(8)
}
