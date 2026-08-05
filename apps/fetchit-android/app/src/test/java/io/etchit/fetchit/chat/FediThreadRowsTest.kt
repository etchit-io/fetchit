package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.fetchit_ffi.FediMentionFfi
import uniffi.fetchit_ffi.FediPostFfi

class FediThreadRowsTest {

    private fun ffiPost(
        text: String = "a reply",
        authorLabel: String = "alice@mastodon.example",
        authorUrl: String = "https://mastodon.example/users/alice",
        objectUrl: String = "https://mastodon.example/@alice/1",
        published: String = "2026-07-13T06:00:00Z",
        authorName: String? = null,
        mentions: List<FediMentionFfi> = emptyList(),
        liked: Boolean = false,
    ) = FediPostFfi(
        authorUrl = authorUrl,
        authorLabel = authorLabel,
        authorName = authorName,
        text = text,
        published = published,
        objectUrl = objectUrl,
        mentions = mentions,
        liked = liked,
    )

    private val stamp: (String) -> Long = { if (it.isEmpty()) 0L else 1_780_000_000_000L }

    @Test
    fun `a reply carries every field a feed row renders from`() {
        // A reply row IS a post row -- the author chip, the mention spans,
        // the content cards and the heart all read these fields, so a
        // dropped one silently disables a control rather than erroring.
        val mapped = FediThreadRows.replies(
            listOf(
                ffiPost(
                    text = "hi @bob@x.io",
                    authorName = "Alice",
                    mentions = listOf(FediMentionFfi("@bob@x.io", "https://x.io/users/bob")),
                    liked = true,
                ),
            ),
            stamp,
        )
        assertEquals(1, mapped.size)
        val post = mapped[0]
        assertEquals("hi @bob@x.io", post.body)
        assertEquals("alice@mastodon.example", post.authorLabel)
        assertEquals("https://mastodon.example/users/alice", post.authorUrl)
        assertEquals("https://mastodon.example/@alice/1", post.objectUrl)
        assertEquals("Alice", post.authorName)
        assertEquals(listOf(FeedMention("@bob@x.io", "https://x.io/users/bob")), post.mentions)
        assertTrue(post.liked)
        assertEquals(1_780_000_000_000L, post.receivedAtMs)
    }

    @Test
    fun `an unparsable publish stamp does not drop the reply`() {
        val mapped = FediThreadRows.replies(listOf(ffiPost(published = "")), stamp)
        assertEquals(1, mapped.size)
        assertEquals(0L, mapped[0].receivedAtMs)
    }

    @Test
    fun `engine order is preserved -- the engine already sorted oldest-first`() {
        val mapped = FediThreadRows.replies(
            listOf(ffiPost(text = "first"), ffiPost(text = "second"), ffiPost(text = "third")),
            stamp,
        )
        assertEquals(listOf("first", "second", "third"), mapped.map { it.body })
    }

    @Test
    fun `a silent server and an empty thread are different states`() {
        // The whole point of the repliesServed flag: these two must never
        // collapse into one sentence on screen.
        assertEquals(FediThreadState.NoRepliesYet, FediThreadRows.state(0, repliesServed = true))
        assertEquals(
            FediThreadState.RepliesNotPublished,
            FediThreadRows.state(0, repliesServed = false),
        )
    }

    @Test
    fun `replies present is a loaded state whatever the server published`() {
        assertEquals(FediThreadState.Loaded(3), FediThreadRows.state(3, repliesServed = true))
        // Defensive: a server that served replies without advertising a
        // readable collection is still showing a conversation.
        assertEquals(FediThreadState.Loaded(1), FediThreadRows.state(1, repliesServed = false))
    }

    @Test
    fun `the reply draft pre-addresses the post's author`() {
        // A fediverse reply only reaches its author if it mentions them,
        // so this is correctness, not convenience.
        val post = FeedPost(
            authorLabel = "alice@mastodon.example",
            body = "hello",
            authorUrl = "https://mastodon.example/users/alice",
        )
        assertEquals("@alice@mastodon.example ", FediThreadRows.replyDraft(post))
    }

    @Test
    fun `a post with no usable handle opens an empty composer`() {
        // Better a blank composer than a draft addressed to a host, or to
        // a fragment of one -- either would send a reply nobody receives.
        val hostOnly = FeedPost(authorLabel = "mastodon.example", body = "hello")
        assertEquals("", FediThreadRows.replyDraft(hostOnly))

        val ownPost = FeedPost(authorLabel = "", body = "mine")
        assertEquals("", FediThreadRows.replyDraft(ownPost))
    }
}
