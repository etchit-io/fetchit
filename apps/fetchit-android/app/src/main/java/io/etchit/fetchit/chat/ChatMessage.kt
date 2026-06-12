package io.etchit.fetchit.chat

/** One message in a 1:1 thread. In-memory only for v1 (mirrors desktop ephemerality). */
data class ChatMessage(
    val outbound: Boolean,
    val body: String,
    val sentAtMs: Long,
    val messageId: String?,
    val delivered: Boolean = false,
)

/** One bridged fediverse post, already reduced to plain text. */
data class FeedPost(val actorUrl: String, val body: String, val receivedAtMs: Long = 0L)
