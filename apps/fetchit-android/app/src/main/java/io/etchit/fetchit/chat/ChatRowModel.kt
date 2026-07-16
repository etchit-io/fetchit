package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.FediThreadSummaryFfi
import uniffi.fetchit_ffi.GroupFfi

/**
 * One row in the unified Chats list. Private DMs and private groups
 * carry a lock; fediverse threads carry a globe. Each row knows its
 * own sort stamp so the whole list orders by most-recent activity
 * regardless of kind.
 */
sealed interface ChatRow {
    /** Sort key: last-activity epoch ms, newest first. */
    val sortMs: Long

    /** A private (PQ) direct message thread. */
    data class Contact(val contact: ChatContact, val preview: String, override val sortMs: Long) : ChatRow

    /** A private/public group thread. */
    data class Group(val group: GroupFfi, val preview: String, override val sortMs: Long) : ChatRow

    /** A fediverse (plaintext-rails) DM thread. */
    data class Fedi(val summary: FediThreadSummaryFfi, override val sortMs: Long) : ChatRow
}

/**
 * Build the unified, most-recent-first conversation list from the three
 * sources. [groupPreview] and [contactPreview] resolve a conversation
 * key to its `(previewBody, lastStampMs)`, or null when the thread has
 * no messages yet — passed in so this stays a pure function over the
 * live [ConversationStore]. A source with no messages sorts oldest
 * (stamp 0) rather than being dropped, so a brand-new contact/group
 * still shows.
 */
fun buildChatRows(
    contacts: List<ChatContact>,
    groups: List<GroupFfi>,
    groupPreview: (convKey: String) -> Pair<String, Long>?,
    contactPreview: (convKey: String) -> Pair<String, Long>?,
    fediThreads: List<FediThreadSummaryFfi>,
    linkedFediLabels: Set<String> = emptySet(),
): List<ChatRow> {
    val rows = ArrayList<ChatRow>(contacts.size + groups.size + fediThreads.size)
    groups.forEach { g ->
        val (body, ms) = groupPreview(ConversationStore.convKeyGroup(g.groupId)) ?: ("" to 0L)
        rows.add(ChatRow.Group(g, body, ms))
    }
    contacts.forEach { c ->
        val (body, ms) = contactPreview(ConversationStore.convKeyDm(c.agentIdHex)) ?: ("" to 0L)
        rows.add(ChatRow.Contact(c, body, ms))
    }
    // A fediverse thread linked to a PQ contact is suppressed — its
    // contact row (🔒) already represents the person, merged in the thread.
    fediThreads
        .filterNot { it.label in linkedFediLabels }
        .forEach { t -> rows.add(ChatRow.Fedi(t, t.lastAtMs)) }
    // Newest first; a stable sort keeps insertion order (groups, then
    // contacts, then fedi) among equal stamps.
    return rows.sortedByDescending { it.sortMs }
}
