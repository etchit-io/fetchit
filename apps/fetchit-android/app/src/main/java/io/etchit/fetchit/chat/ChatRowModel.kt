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
    data class Contact(
        val contact: ChatContact,
        val preview: String,
        override val sortMs: Long,
        /** Inbound messages since the thread was last opened; 0 renders no badge. */
        val unread: Int = 0,
    ) : ChatRow

    /** A private/public group thread. */
    data class Group(
        val group: GroupFfi,
        val preview: String,
        override val sortMs: Long,
        /** Inbound messages since the thread was last opened; 0 renders no badge. */
        val unread: Int = 0,
    ) : ChatRow

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
 *
 * [litUnread] maps a conversation key to the engine's unread count for
 * private DMs and groups (fediverse rows carry theirs on their own
 * summary). A key that is absent is not-yet-known, which renders as no
 * badge rather than a guess.
 */
fun buildChatRows(
    contacts: List<ChatContact>,
    groups: List<GroupFfi>,
    groupPreview: (convKey: String) -> Pair<String, Long>?,
    contactPreview: (convKey: String) -> Pair<String, Long>?,
    fediThreads: List<FediThreadSummaryFfi>,
    linkedFediLabels: Set<String> = emptySet(),
    litUnread: Map<String, Int> = emptyMap(),
): List<ChatRow> {
    val rows = ArrayList<ChatRow>(contacts.size + groups.size + fediThreads.size)
    groups.forEach { g ->
        val key = ConversationStore.convKeyGroup(g.groupId)
        val (body, ms) = groupPreview(key) ?: ("" to 0L)
        rows.add(ChatRow.Group(g, body, ms, litUnread[key] ?: 0))
    }
    contacts.forEach { c ->
        val key = ConversationStore.convKeyDm(c.agentIdHex)
        val (body, ms) = contactPreview(key) ?: ("" to 0L)
        rows.add(ChatRow.Contact(c, body, ms, litUnread[key] ?: 0))
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
