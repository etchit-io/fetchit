package io.etchit.fetchit.chat.notify

/** Which inbound surface a notifiable message arrived on. */
enum class InboundKind {
    /** Direct message; [InboundNotify.senderLabel] is null (DMs are 1:1). */
    DM,

    /** Private-group message; the label is the sender's self-attached name. */
    GROUP,
}

/**
 * The notification-relevant projection of one inbound chat message, emitted
 * by the event pump's `Dm` / `GroupMessage` arms. Carries no framework
 * types so the notify decision and content building stay JVM-testable.
 */
data class InboundNotify(
    /** [io.etchit.fetchit.chat.ConversationStore] conversation key. */
    val convKey: String,
    val kind: InboundKind,
    /** 64-hex agent id of the message author. */
    val senderAgentIdHex: String,
    /** Sender's self-attached display name (group messages), or null. */
    val senderLabel: String?,
    val body: String,
    /** Engine message id — stable notification dedup key. */
    val messageId: String,
)

/**
 * Whether [inbound] should raise a notification: never for self-authored
 * messages (multi-device fanout and group echo deliver the author's own
 * words back), and never for the conversation currently on screen (the
 * user is already reading it). Pure so the truth table is JVM-tested.
 */
fun shouldNotify(
    inbound: InboundNotify,
    selfAgentIdHex: String,
    visibleConvKey: String?,
): Boolean {
    if (inbound.senderAgentIdHex.equals(selfAgentIdHex, ignoreCase = true)) return false
    if (visibleConvKey != null && inbound.convKey == visibleConvKey) return false
    return true
}
