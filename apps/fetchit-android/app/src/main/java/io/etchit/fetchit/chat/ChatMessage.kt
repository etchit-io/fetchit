package io.etchit.fetchit.chat

/**
 * One message in a 1:1 or group thread. Held in-memory per process, but
 * rehydrated on open / list load from the engine's encrypted at-rest vault
 * (see [ConversationStore.mergeHistory]) so messages survive a process kill.
 */
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
    /**
     * 64-hex agent id of an inbound group message's sender, for sender
     * attribution in group threads. Null for DMs (the peer is the thread) and
     * for outbound messages. The UI renders a sender label when non-null.
     */
    val senderAgentIdHex: String? = null,
    /**
     * Sender's self-attached display name that rode the encrypted group
     * message, when present. Preferred over a locally-saved contact name and
     * the `agent-<hex>` fallback for the inbound group sender label. Null for
     * DMs and outbound messages.
     */
    val senderName: String? = null,
)

/**
 * One `@user@host` mention inside a feed post: the visible text and the
 * actor URL behind it. Tapping the text opens that account's profile.
 */
data class FeedMention(val name: String, val href: String)

/**
 * One bridged fediverse post, already reduced to plain text.
 *
 * [authorLabel] is the display identity (`user@host` / `@user@host`) and
 * is the only field older persisted records carry — it doubles as the
 * avatar-cache key and the block key. [authorUrl] and [objectUrl] are
 * the real identities the engine resolved: the author's actor URL and
 * the post's URL on its home server. Both default to empty because a
 * record restored from an older blob, or a post this device published
 * itself, genuinely has neither — every consumer must treat blank as
 * "not known" rather than assume.
 */
data class FeedPost(
    val authorLabel: String,
    val body: String,
    val receivedAtMs: Long = 0L,
    /** The author's canonical actor URL; empty when unknown. */
    val authorUrl: String = "",
    /** The post's URL on its home server — the dedup and like key; empty when unknown. */
    val objectUrl: String = "",
    /** The author's chosen display name, when their server publishes one. */
    val authorName: String? = null,
    /** `Mention` tags on the post, engine-capped. */
    val mentions: List<FeedMention> = emptyList(),
    /** This device has liked the post. */
    val liked: Boolean = false,
)
