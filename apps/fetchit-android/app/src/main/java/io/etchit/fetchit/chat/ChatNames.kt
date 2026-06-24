package io.etchit.fetchit.chat

import android.content.Context
import io.etchit.fetchit.R
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

/**
 * String-resource id for a conversation row's destructive overflow action:
 * `chat_leave_group` for a group row, `chat_remove_chat` for a contact row.
 * Kept as a pure function (returns the res id, doesn't resolve the string) so
 * the kind-aware label choice is JVM-testable without a Context, mirroring
 * desktop's kind-aware "Remove this chat / Leave this group".
 */
fun rowRemoveLabel(isGroup: Boolean): Int =
    if (isGroup) R.string.chat_leave_group else R.string.chat_remove_chat

/**
 * Label for one row in the group member list.
 *
 * Precedence: the member's on-wire [wireName] (the display name x0xd has for
 * them) wins when non-blank, then a locally-saved [contactName], then a short
 * `<8hex>…` form. Pure so the member-row label is JVM-testable without a
 * Context, mirroring [groupSenderLabel] and the desktop member roster.
 */
fun memberDisplayName(wireName: String?, contactName: String?, agentIdHex: String): String =
    wireName?.trim()?.takeIf { it.isNotEmpty() }
        ?: contactName?.trim()?.takeIf { it.isNotEmpty() }
        ?: "${agentIdHex.take(8)}…"

/**
 * Whether the *viewer* can moderate this group at all -- i.e. their own role
 * is owner or admin. Cosmetic gate only: it decides whether the UI shows the
 * moderation affordances, NOT whether a call is authorized. x0xd is the real
 * authorization gate and rejects an unauthorized call regardless of this.
 */
fun canModerate(myRole: String?): Boolean = myRole == "owner" || myRole == "admin"

/**
 * Whether the per-row moderation overflow (Remove / Ban) should show for a
 * given target member: only when the [viewerCanModerate], the target is not
 * the viewer themselves ([isSelf]), and the target is not the group owner
 * ([targetIsOwner]) -- x0xd refuses an owner-target, so the control is hidden
 * to match. Cosmetic only; x0xd remains the authority on every actual call.
 */
fun canModerateMember(viewerCanModerate: Boolean, isSelf: Boolean, targetIsOwner: Boolean): Boolean =
    viewerCanModerate && !isSelf && !targetIsOwner

/**
 * The role chip to draw beside a member's name, or `null` for an ordinary
 * member (no chip). Only `owner` / `admin` get a tag; any other (or null)
 * role yields `null`. Pure so the chip choice is JVM-testable.
 */
fun memberRoleTag(role: String?): String? = role?.takeIf { it == "owner" || it == "admin" }
