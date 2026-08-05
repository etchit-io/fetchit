package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [fediActorDisplay] — pure string formatting, plain JUnit.
 */
class FediActorDisplayTest {

    @Test
    fun mastodon_at_style_url() {
        assertEquals("@alice@mastodon.social", fediActorDisplay("https://mastodon.social/@alice"))
    }

    @Test
    fun users_path_style_url() {
        assertEquals("@bob@example.com", fediActorDisplay("https://example.com/users/bob"))
    }

    @Test
    fun trailing_slash_is_trimmed() {
        assertEquals("@carol@example.com", fediActorDisplay("https://example.com/@carol/"))
    }

    @Test
    fun host_lowercased() {
        assertEquals("@alice@mastodon.social", fediActorDisplay("https://Mastodon.Social/@alice"))
    }

    @Test
    fun host_only_falls_back_to_host() {
        assertEquals("example.com", fediActorDisplay("https://example.com"))
    }

    @Test
    fun blank_falls_back_to_input() {
        assertEquals("", fediActorDisplay(""))
    }

    // ── feed-post author identity ─────────────────────────────────────

    @Test
    fun author_handle_prefers_the_resolved_actor_url() {
        val post = FeedPost(
            authorLabel = "alice@example.com",
            body = "hi",
            authorUrl = "https://example.com/users/alice",
        )
        assertEquals("@alice@example.com", authorHandle(post))
        assertEquals("https://example.com/users/alice", profileTarget(post))
    }

    @Test
    fun a_post_with_no_actor_url_falls_back_to_its_label() {
        // Our own published post, and any record restored from a blob
        // written before URLs were carried, has no actor URL — the row
        // must still read correctly and still be tappable.
        val post = FeedPost(authorLabel = "@josh@etchit.io", body = "hi")
        assertEquals("@josh@etchit.io", authorHandle(post))
        assertEquals("@josh@etchit.io", profileTarget(post))
    }
}
