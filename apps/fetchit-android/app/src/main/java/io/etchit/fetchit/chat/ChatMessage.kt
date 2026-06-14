package io.etchit.fetchit.chat

/** One message in a 1:1 thread. In-memory only for v1 (mirrors desktop ephemerality). */
data class ChatMessage(
    val outbound: Boolean,
    val body: String,
    val sentAtMs: Long,
    val messageId: String?,
    val delivered: Boolean = false,
    /** Terminal send failure for an outbound message; drives the retry affordance. */
    val failed: Boolean = false,
    /**
     * Stable id of the engine outbox bubble backing this outbound message, or
     * null for inbound messages. The outbox projection upserts by this key so
     * the Sending -> Delivered -> Failed transitions land on one bubble instead
     * of stacking duplicates.
     */
    val outboxId: String? = null,
    /** Last send error from the outbox bubble, populated when [failed] is true. */
    val lastError: String? = null,
)

/** One bridged fediverse post, already reduced to plain text. */
data class FeedPost(val actorUrl: String, val body: String, val receivedAtMs: Long = 0L)
