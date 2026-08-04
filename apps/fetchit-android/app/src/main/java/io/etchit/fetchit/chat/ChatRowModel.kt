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
        /**
         * The fediverse label this person is linked to, when the user has
         * confirmed they are the same person. Non-null means the row may
         * reuse that identity's profile picture; null means the row keeps
         * its existing placeholder.
         *
         * Only ever read from the avatar cache — see
         * `ChatGateway.fediAvatarCached`. A private row must never cause a
         * request to a fediverse server.
         */
        val fediLabel: String? = null,
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
 *
 * [linkedFediLabelByAgent] maps an agent id to the fediverse label its
 * person is linked to, so a linked contact's row can reuse that
 * identity's picture. It comes from the same person-link table as
 * [linkedFediLabels] — the link that hides the globe row is the link
 * that supplies the face — and is keyed by agent id because only a
 * person, never a group, can be linked.
 */
fun buildChatRows(
    contacts: List<ChatContact>,
    groups: List<GroupFfi>,
    groupPreview: (convKey: String) -> Pair<String, Long>?,
    contactPreview: (convKey: String) -> Pair<String, Long>?,
    fediThreads: List<FediThreadSummaryFfi>,
    linkedFediLabels: Set<String> = emptySet(),
    litUnread: Map<String, Int> = emptyMap(),
    linkedFediLabelByAgent: Map<String, String> = emptyMap(),
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
        // A blank stored label is "no link" — never a cache key to look up.
        val fediLabel = linkedFediLabelByAgent[c.agentIdHex]?.takeIf { it.isNotBlank() }
        rows.add(ChatRow.Contact(c, body, ms, litUnread[key] ?: 0, fediLabel))
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
