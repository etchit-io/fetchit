package io.etchit.fetchit.chat

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * In-memory store of 1:1 message threads, keyed by peer agent-id hex.
 *
 * Thread-safe: all mutations hold [lock] so concurrent coroutine writers
 * (event pump + send path) never interleave partial updates.
 * [StateFlow]s themselves are thread-safe for observers.
 *
 * In-memory only for v1 — messages are ephemeral across process restarts,
 * matching desktop behaviour. Persistence is a designated follow-up.
 */
class ConversationStore {

    private val lock = Any()
    private val byPeer = mutableMapOf<String, MutableStateFlow<List<ChatMessage>>>()

    /**
     * Observable message list for [peerAgentIdHex]. Creates an empty flow
     * on first access so callers can subscribe before any message arrives.
     */
    fun messagesFor(peerAgentIdHex: String): StateFlow<List<ChatMessage>> =
        synchronized(lock) { flowFor(peerAgentIdHex) }.asStateFlow()

    /**
     * Append [msg] to the thread for [peerAgentIdHex].
     * Safe to call from any coroutine.
     */
    fun append(peerAgentIdHex: String, msg: ChatMessage) {
        synchronized(lock) {
            val flow = flowFor(peerAgentIdHex)
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
            for (flow in byPeer.values) {
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

    /** Peers that have at least one message, in insertion order. */
    fun peersWithTraffic(): List<String> = synchronized(lock) { byPeer.keys.toList() }

    // Must be called inside synchronized(lock).
    private fun flowFor(peerAgentIdHex: String): MutableStateFlow<List<ChatMessage>> =
        byPeer.getOrPut(peerAgentIdHex) { MutableStateFlow(emptyList()) }
}

/**
 * In-memory store of bridged fediverse posts.
 *
 * Capped at [MAX_POSTS] newest entries so unbounded relay traffic cannot
 * exhaust memory. StateFlow observers receive every update.
 */
class FeedStore {

    private val _posts = MutableStateFlow<List<FeedPost>>(emptyList())

    /** All received posts, newest-last (append order). */
    val posts: StateFlow<List<FeedPost>> = _posts.asStateFlow()

    /** Append [post], dropping the oldest entry if the cap is exceeded. */
    fun append(post: FeedPost) {
        val current = _posts.value
        _posts.value = if (current.size >= MAX_POSTS) {
            current.drop(1) + post
        } else {
            current + post
        }
    }

    private companion object {
        const val MAX_POSTS = 200
    }
}
