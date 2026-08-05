package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.FediPostFfi

/**
 * What a post's thread view is showing right now.
 *
 * Four outcomes, not two. A thread that is still loading, one that
 * failed, one nobody has answered, and one whose server does not publish
 * replies are four different facts, and a view that draws any of them as
 * a silent blank is lying about the other three.
 */
sealed interface FediThreadState {

    /** The pull is in flight. */
    data object Loading : FediThreadState

    /** Replies came back. */
    data class Loaded(val count: Int) : FediThreadState

    /** The server published a replies collection and it was empty. */
    data object NoRepliesYet : FediThreadState

    /**
     * The server published no readable replies collection.
     *
     * Common and not an error: plenty of instances (and every static
     * `ActivityPub` site) serve posts without one. Saying "no replies"
     * here would assert something we were never told.
     */
    data object RepliesNotPublished : FediThreadState

    /** The pull itself failed -- unreachable server, bad URL, timeout. */
    data object Failed : FediThreadState
}

/** Pure mapping + state logic for the post thread view. */
object FediThreadRows {

    /**
     * Project engine replies onto the same [FeedPost] rows the feed
     * renders, so a reply looks and behaves exactly like a post: the
     * author chip opens the profile, `autonomi://` addresses grow cards,
     * @-mentions are tappable, the heart works.
     *
     * [stampMs] parses the ISO-8601 `published` string; it is injected so
     * this stays testable without Android's clock or locale.
     */
    fun replies(posts: List<FediPostFfi>, stampMs: (String) -> Long): List<FeedPost> =
        posts.map {
            FeedPost(
                authorLabel = it.authorLabel,
                body = it.text,
                receivedAtMs = stampMs(it.published),
                authorUrl = it.authorUrl,
                objectUrl = it.objectUrl,
                authorName = it.authorName,
                mentions = it.mentions.map { m -> FeedMention(m.name, m.href) },
                liked = it.liked,
            )
        }

    /**
     * Which empty state (if any) a finished pull earned.
     *
     * [shown] is the count AFTER this device's own block list has been
     * applied: replies the user chose not to see are not evidence that
     * nobody replied, but they are also not something to announce, so a
     * fully-blocked thread reads as the quiet empty state rather than a
     * count of hidden rows.
     */
    fun state(shown: Int, repliesServed: Boolean): FediThreadState = when {
        shown > 0 -> FediThreadState.Loaded(shown)
        repliesServed -> FediThreadState.NoRepliesYet
        else -> FediThreadState.RepliesNotPublished
    }

    /**
     * The draft a reply composer opens with: the post's author, already
     * addressed.
     *
     * A fediverse reply only reaches its author if it mentions them, so
     * pre-filling is not a convenience -- it is the difference between a
     * reply that lands and one that vanishes into a stranger's outbox.
     * The user can still delete it, which is why it is a draft and not a
     * hidden addition at send time.
     */
    fun replyDraft(post: FeedPost): String {
        val handle = authorHandle(post)
        return if (handle.startsWith("@") && handle.count { it == '@' } == 2) "$handle " else ""
    }
}
