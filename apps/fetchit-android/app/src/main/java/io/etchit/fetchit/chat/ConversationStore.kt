package io.etchit.fetchit.chat

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * In-memory store of message threads, keyed by an opaque conversation key.
 *
 * DM threads key on the bare peer agent-id hex ([convKeyDm]); group threads
 * key on a `g:`-prefixed group id ([convKeyGroup]) so a group whose id equals
 * a peer's hex never collides with that peer's DM thread.
 *
 * Thread-safe: all mutations hold [lock] so concurrent coroutine writers
 * (event pump + send path) never interleave partial updates.
 * [StateFlow]s themselves are thread-safe for observers.
 *
 * The in-memory map is a per-process projection; the durable transcript lives
 * in the engine's encrypted at-rest vault. On open / list load the controller
 * hydrates threads from that vault via [ChatGateway.conversationHistory] and
 * folds them in with [mergeHistory] (de-duped by message id), so messages
 * survive a process kill instead of starting empty.
 */
class ConversationStore {

    private val lock = Any()
    private val byKey = mutableMapOf<String, MutableStateFlow<List<ChatMessage>>>()

    /**
     * Observable message list for conversation [key] (a [convKeyDm] or
     * [convKeyGroup] value). Creates an empty flow on first access so callers
     * can subscribe before any message arrives.
     */
    fun messagesFor(key: String): StateFlow<List<ChatMessage>> =
        synchronized(lock) { flowFor(key) }.asStateFlow()

    /**
     * Append [msg] to the thread for conversation [key].
     * Safe to call from any coroutine.
     */
    fun append(key: String, msg: ChatMessage) {
        synchronized(lock) {
            val flow = flowFor(key)
            flow.value = flow.value + msg
        }
    }

    /**
     * Flip [ChatMessage.delivered] to `true` for the outbound message whose
     * [ChatMessage.messageId] matches [messageId]. Scans all peers; no-op if
     * not found (duplicate receipts and unknown ids are silently ignored).
     *
     * Only outbound messages are marked — inbound messages have no receipt
     * semantics in v1.
     */
    fun markDelivered(messageId: String) {
        synchronized(lock) {
            for (flow in byKey.values) {
                val list = flow.value
                val idx = list.indexOfFirst { it.outbound && it.messageId == messageId }
                if (idx >= 0) {
                    flow.value = list.toMutableList().also { it[idx] = it[idx].copy(delivered = true) }
                    return
                }
            }
        }
    }

    /**
     * Insert or update the outbound message backed by outbox bubble [outboxId]
     * in the thread for [peerAgentIdHex]. Keyed by [outboxId] so the optimistic
     * `Sending` echo, the `Delivered` transition, and a `Failed` terminal all
     * land on the same bubble instead of stacking duplicates.
     */
    fun upsertOutbox(
        peerAgentIdHex: String,
        outboxId: String,
        body: String,
        sentAtMs: Long,
        messageId: String?,
        delivered: Boolean,
        failed: Boolean,
        lastError: String?,
    ) {
        synchronized(lock) {
            val flow = flowFor(peerAgentIdHex)
            val list = flow.value
            val idx = list.indexOfFirst { it.outboxId == outboxId }
            // Defense-in-depth parity with desktop: never downgrade a bubble that
            // already reached Delivered. The engine does not emit a post-Delivered
            // downgrade today, but a reordered or duplicated event must not flip a
            // delivered bubble back to Sending or Failed.
            if (idx >= 0 && list[idx].delivered && !delivered) return
            val msg = ChatMessage(
                outbound = true,
                body = body,
                sentAtMs = sentAtMs,
                messageId = messageId,
                delivered = delivered,
                failed = failed,
                outboxId = outboxId,
                lastError = lastError,
            )
            flow.value = if (idx >= 0) {
                list.toMutableList().also { it[idx] = msg }
            } else {
                list + msg
            }
        }
    }

    /**
     * Merge a persisted transcript ([msgs]) into the thread for [key],
     * de-duplicating against messages already present so a reloaded copy and
     * its live event never double up.
     *
     * De-dup key is [ChatMessage.messageId]: a hydrated entry is dropped when a
     * message with the same non-blank id is already in the thread (whether it
     * arrived as a live inbound event or as an outbox bubble — both carry the
     * engine's `messageId`). Entries with a blank/null id (legacy pre-id
     * persisted messages) are always kept, since they cannot be matched.
     *
     * Surviving entries are appended and the whole thread is re-sorted by
     * [ChatMessage.sentAtMs] so persisted history interleaves correctly with
     * any live messages already shown. A stable sort preserves the relative
     * order of same-timestamp messages.
     *
     * Safe to call from any coroutine; holds [lock] for the whole merge.
     */
    fun mergeHistory(key: String, msgs: List<ChatMessage>) {
        if (msgs.isEmpty()) return
        synchronized(lock) {
            val flow = flowFor(key)
            val existing = flow.value
            val seenIds = existing.mapNotNull { it.messageId?.takeIf(String::isNotBlank) }.toHashSet()
            val additions = ArrayList<ChatMessage>(msgs.size)
            for (m in msgs) {
                val id = m.messageId?.takeIf(String::isNotBlank)
                // Drop a hydrated message whose id is already shown (live event
                // or outbox bubble). Keep id-less legacy entries — unmatchable.
                if (id != null && !seenIds.add(id)) continue
                additions.add(m)
            }
            if (additions.isEmpty()) return
            flow.value = (existing + additions).sortedBy { it.sentAtMs }
        }
    }

    /**
     * Conversation keys that have at least one message, in insertion order.
     * Group keys carry the `g:` prefix ([convKeyGroup]); DM keys are bare hex.
     */
    fun peersWithTraffic(): List<String> = synchronized(lock) { byKey.keys.toList() }

    // Must be called inside synchronized(lock).
    private fun flowFor(key: String): MutableStateFlow<List<ChatMessage>> =
        byKey.getOrPut(key) { MutableStateFlow(emptyList()) }

    companion object {
        /**
         * Conversation key for a group thread: a `g:` prefix over the 64-hex
         * group id, so a group never collides with a DM keyed by the same hex.
         */
        fun convKeyGroup(groupId: String): String = "g:$groupId"

        /**
         * Conversation key for a DM thread: the bare peer agent-id hex, kept
         * unprefixed for back-compat with existing DM call sites.
         */
        fun convKeyDm(agentIdHex: String): String = agentIdHex

        /**
         * Conversation key for a fediverse (plaintext-rails) thread: an
         * `f:` prefix over the canonical `user@host` handle, so the same
         * person's future PQ thread (keyed by agent hex) stays distinct.
         */
        fun convKeyFedi(handle: String): String = "f:${canonicalFediHandle(handle)}"
    }
}
