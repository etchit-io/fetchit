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

/**
 * Whether the first-run onboarding empty-state should show: true only when
 * the user has neither a contact nor a group yet. Pure predicate so the
 * list-screen detection is JVM-testable without inflating a view, mirroring
 * desktop's `convs.length === 0` onboarding gate.
 */
fun showChatOnboarding(contactCount: Int, groupCount: Int): Boolean =
    contactCount == 0 && groupCount == 0

/**
 * Label for an inbound group message's sender.
 *
 * Precedence mirrors desktop's `notify.ts`: the sender's self-attached
 * [senderName] (the display name that rode the encrypted message) wins when
 * non-blank, then a locally-saved [contactName], then a short `agent-<6hex>`
 * form. Keeps group attribution readable for un-saved senders — the common
 * case — instead of dropping to a raw agent id. Single source of truth so the
 * bubble label cannot drift from this ordering.
 */
fun groupSenderLabel(senderName: String?, contactName: String?, agentIdHex: String): String =
    senderName?.trim()?.takeIf { it.isNotEmpty() }
        ?: contactName?.trim()?.takeIf { it.isNotEmpty() }
        ?: "agent-${agentIdHex.take(6)}"
