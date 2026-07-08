package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Persistence + serde tests for the fediverse feed store. */
class FeedStoreTest {

    private val posts = listOf(
        FeedPost("@josh@etchit.io", "hello world", 1_000L),
        FeedPost("https://m.example/users/alice", "bridged post", 2_000L),
    )

    @Test
    fun serdeRoundTrips() {
        assertEquals(posts, FeedSerde.decode(FeedSerde.encode(posts)))
    }

    @Test
    fun decodeIsFailSoft() {
        assertEquals(emptyList<FeedPost>(), FeedSerde.decode(null))
        assertEquals(emptyList<FeedPost>(), FeedSerde.decode(""))
        assertEquals(emptyList<FeedPost>(), FeedSerde.decode("not json at all"))
        assertEquals(emptyList<FeedPost>(), FeedSerde.decode("{\"an\":\"object\"}"))
    }

    @Test
    fun appendPersistsAndANewStoreHydrates() {
        // Fake prefs slot: whatever save wrote, the next store's load returns —
        // the app-restart scenario (own posts are never re-delivered, so this
        // is the only way they survive).
        var slot: String? = null
        val store = FeedStore(
            load = { FeedSerde.decode(slot) },
            save = { slot = FeedSerde.encode(it) },
        )
        posts.forEach(store::append)
        assertEquals(posts, store.posts.value)

        val reborn = FeedStore(
            load = { FeedSerde.decode(slot) },
            save = { slot = FeedSerde.encode(it) },
        )
        assertEquals(posts, reborn.posts.value)
    }

    @Test
    fun capDropsOldestButKeepsPersisting() {
        var slot: String? = null
        val store = FeedStore(
            load = { FeedSerde.decode(slot) },
            save = { slot = FeedSerde.encode(it) },
        )
        repeat(205) { i -> store.append(FeedPost("@a@b", "post $i", i.toLong())) }
        val kept = store.posts.value
        assertEquals(200, kept.size)
        assertEquals("post 204", kept.last().body)
        assertEquals("post 5", kept.first().body)
        assertTrue(FeedSerde.decode(slot) == kept)
    }
}
