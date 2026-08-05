package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Persistence + serde tests for the fediverse feed store. */
class FeedStoreTest {

    private val posts = listOf(
        FeedPost("@josh@etchit.io", "hello world", 1_000L),
        FeedPost(
            authorLabel = "alice@m.example",
            body = "bridged post",
            receivedAtMs = 2_000L,
            authorUrl = "https://m.example/users/alice",
            objectUrl = "https://m.example/@alice/1",
            authorName = "Alice",
            mentions = listOf(FeedMention("@bob@fosstodon.org", "https://fosstodon.org/users/bob")),
            liked = true,
        ),
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
    fun aRecordWrittenBeforeUrlsWereCarriedStillLoads() {
        // The shape the store persisted before the author URL, post URL,
        // mentions, and like state existed: the display identity sat under
        // `actorUrl` and nothing else was present. It must decode rather
        // than silently emptying someone's feed on upgrade.
        val legacy = """
            [{"actorUrl":"@josh@etchit.io","body":"hello world","receivedAtMs":1000}]
        """.trimIndent()
        val decoded = FeedSerde.decode(legacy)
        assertEquals(1, decoded.size)
        val p = decoded.single()
        assertEquals("@josh@etchit.io", p.authorLabel)
        assertEquals("hello world", p.body)
        assertEquals(1_000L, p.receivedAtMs)
        // Everything added since reads as "not known", never as a wrong value.
        assertEquals("", p.authorUrl)
        assertEquals("", p.objectUrl)
        assertEquals(null, p.authorName)
        assertEquals(emptyList<FeedMention>(), p.mentions)
        assertFalse(p.liked)
    }

    @Test
    fun malformedMentionEntriesAreDroppedNotFatal() {
        val raw = """
            [{"authorLabel":"a@h","body":"x","receivedAtMs":1,"mentions":[
              {"name":"@a@h","href":"https://h/users/a"},
              {"name":"@b@h"},
              {"href":"https://h/users/c"},
              "junk"
            ]}]
        """.trimIndent()
        assertEquals(
            listOf(FeedMention("@a@h", "https://h/users/a")),
            FeedSerde.decode(raw).single().mentions,
        )
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

    @Test
    fun mergeDedupsOnThePostUrlWhenThereIsOne() {
        val store = FeedStore()
        val first = FeedPost(
            authorLabel = "a@h",
            body = "original text",
            receivedAtMs = 1,
            objectUrl = "https://h/@a/1",
        )
        store.mergeRemote(listOf(first))
        // Same post, edited body: the URL is the identity, so it does NOT
        // arrive as a second row.
        store.mergeRemote(listOf(first.copy(body = "edited text")))
        assertEquals(1, store.posts.value.size)
        assertEquals("original text", store.posts.value.single().body)
    }

    @Test
    fun mergeFallsBackToAuthorAndBodyWithoutAPostUrl() {
        val store = FeedStore()
        val p = FeedPost("a@h", "same body", 1)
        store.mergeRemote(listOf(p))
        store.mergeRemote(listOf(p.copy(receivedAtMs = 2)))
        assertEquals(1, store.posts.value.size)
        // A different author with the same words is a different post.
        store.mergeRemote(listOf(p.copy(authorLabel = "b@h")))
        assertEquals(2, store.posts.value.size)
    }

    @Test
    fun mergeDedupsWithinOneBatch() {
        val store = FeedStore()
        val p = FeedPost("a@h", "hi", 1, objectUrl = "https://h/@a/1")
        store.mergeRemote(listOf(p, p.copy(receivedAtMs = 2)))
        assertEquals(1, store.posts.value.size)
    }

    @Test
    fun setLikedFlipsTheRowAndPersists() {
        var slot: String? = null
        val store = FeedStore(
            load = { FeedSerde.decode(slot) },
            save = { slot = FeedSerde.encode(it) },
        )
        store.append(FeedPost("a@h", "hi", 1, objectUrl = "https://h/@a/1"))
        assertTrue(store.setLiked("https://h/@a/1", true))
        assertTrue(store.posts.value.single().liked)
        assertTrue(FeedSerde.decode(slot).single().liked)

        // A no-op flip must not churn the blob: the optimistic revert path
        // calls this on every failure, matched or not.
        assertFalse(store.setLiked("https://h/@a/1", true))
        assertFalse(store.setLiked("https://h/@a/nothing", true))
        assertFalse(store.setLiked("", true))

        assertTrue(store.setLiked("https://h/@a/1", false))
        assertFalse(store.posts.value.single().liked)
    }
}
