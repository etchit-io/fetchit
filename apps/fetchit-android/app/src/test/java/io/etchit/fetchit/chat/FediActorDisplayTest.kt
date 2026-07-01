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
}
