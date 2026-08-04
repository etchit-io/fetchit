package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM cover for the avatar cache's arithmetic and query gating. The
 * decode itself needs a real `BitmapFactory`, but the two properties that
 * matter for safety and battery — never decoding at full resolution, never
 * hammering the engine for an avatar that isn't there — are decoder-free.
 */
class FediAvatarsTest {

    @Test
    fun sample_size_halves_until_target_is_reached() {
        assertEquals(1, FediAvatars.sampleSize(96, 96, 96))
        assertEquals(2, FediAvatars.sampleSize(192, 192, 96))
        assertEquals(4, FediAvatars.sampleSize(400, 400, 96))
        assertEquals(8, FediAvatars.sampleSize(1024, 1024, 96))
    }

    @Test
    fun sample_size_never_undershoots_the_target_on_either_axis() {
        // A wide banner-shaped "avatar": halving stops as soon as the SHORT
        // edge would drop below the target, so the thumbnail stays sharp.
        assertEquals(1, FediAvatars.sampleSize(2000, 100, 96))
    }

    @Test
    fun sample_size_is_one_for_images_already_at_or_below_target() {
        assertEquals(1, FediAvatars.sampleSize(48, 48, 96))
        assertEquals(1, FediAvatars.sampleSize(1, 1, 96))
    }

    @Test
    fun sample_size_is_defensive_about_degenerate_input() {
        assertEquals(1, FediAvatars.sampleSize(0, 0, 96))
        assertEquals(1, FediAvatars.sampleSize(-5, 100, 96))
        assertEquals(1, FediAvatars.sampleSize(100, 100, 0))
    }

    @Test
    fun key_matches_the_engine_canonical_label() {
        assertEquals(
            FediAvatars.key("happyborg@fosstodon.org"),
            FediAvatars.key(" @HappyBorg@Fosstodon.org "),
        )
    }

    @Test
    fun an_unseen_label_is_worth_querying() {
        val avatars = FediAvatars(96)
        assertTrue(avatars.shouldQuery("happyborg@fosstodon.org", 0L))
    }

    @Test
    fun a_miss_suppresses_requerying_until_the_recheck_window_elapses() {
        val avatars = FediAvatars(96)
        val label = "nobody@nowhere.example"
        avatars.noteAbsent(label, 1_000L)
        assertFalse(
            "scrolling a picture-less row must not become a query storm",
            avatars.shouldQuery(label, 1_000L + FediAvatars.ABSENT_RECHECK_MS - 1),
        )
        assertTrue(
            "a background fetch that lands later must still be picked up",
            avatars.shouldQuery(label, 1_000L + FediAvatars.ABSENT_RECHECK_MS),
        )
    }

    @Test
    fun a_second_query_for_the_same_label_is_suppressed_while_one_is_in_flight() {
        val avatars = FediAvatars(96)
        val label = "happyborg@fosstodon.org"
        assertTrue(avatars.shouldQuery(label, 0L))
        assertFalse(
            "one author across several feed rows must fetch once, not once per row",
            avatars.shouldQuery(label, 0L),
        )
        // Releasing without an answer (screen closed mid-fetch) must not
        // strand the label as permanently in-flight.
        avatars.releaseQuery(label)
        assertTrue(avatars.shouldQuery(label, 0L))
    }

    @Test
    fun the_absent_window_is_tracked_per_canonical_label() {
        val avatars = FediAvatars(96)
        avatars.noteAbsent("@A@Host", 1_000L)
        assertFalse(avatars.shouldQuery("a@host", 1_001L))
        assertTrue(avatars.shouldQuery("b@host", 1_001L))
    }

    @Test
    fun undecodable_bytes_arm_the_absent_window_rather_than_throwing() {
        val avatars = FediAvatars(96)
        val label = "a@host"
        // Null, empty, and garbage all degrade to "no avatar" — the row keeps
        // its placeholder and nothing crashes.
        assertEquals(null, avatars.decodeAndCache(label, null, 0L))
        assertEquals(null, avatars.decodeAndCache(label, ByteArray(0), 0L))
        assertFalse(avatars.shouldQuery(label, 1L))
    }

    @Test
    fun clear_forgets_both_bitmaps_and_the_absent_window() {
        val avatars = FediAvatars(96)
        avatars.noteAbsent("a@host", 0L)
        assertFalse(avatars.shouldQuery("a@host", 1L))
        avatars.clear()
        assertTrue(avatars.shouldQuery("a@host", 1L))
    }

    // ----- the cache-only lane (LIT contact rows) -----

    @Test
    fun a_cache_only_miss_does_not_suppress_the_fetching_lane() {
        // A LIT row's miss must not stand in for a fediverse surface's miss:
        // the fedi surfaces are the only thing that keeps the cache warm, so
        // silencing them for 30s because a private row looked would starve
        // the very cache the private row reads.
        val avatars = FediAvatars(96)
        val label = "happyborg@fosstodon.org"
        assertTrue(avatars.shouldQuery(label, 0L, cacheOnly = true))
        avatars.noteAbsent(label, 0L, cacheOnly = true)
        assertFalse(
            "the cache-only lane holds its own re-check window",
            avatars.shouldQuery(label, 1L, cacheOnly = true),
        )
        assertTrue(
            "the fetching lane is untouched by a cache-only miss",
            avatars.shouldQuery(label, 1L),
        )
    }

    @Test
    fun a_fetching_lane_miss_does_not_block_a_cache_only_read() {
        // The converse: a cache-only read is free (one disk read, no network),
        // so a fedi surface's backoff must not stop a LIT row from picking up
        // bytes that landed in the meantime.
        val avatars = FediAvatars(96)
        val label = "happyborg@fosstodon.org"
        avatars.noteAbsent(label, 0L)
        assertFalse(avatars.shouldQuery(label, 1L))
        assertTrue(avatars.shouldQuery(label, 1L, cacheOnly = true))
    }

    @Test
    fun the_cache_only_lane_is_single_flight_too() {
        val avatars = FediAvatars(96)
        val label = "a@host"
        assertTrue(avatars.shouldQuery(label, 0L, cacheOnly = true))
        assertFalse(avatars.shouldQuery(label, 0L, cacheOnly = true))
        avatars.releaseQuery(label, cacheOnly = true)
        assertTrue(avatars.shouldQuery(label, 0L, cacheOnly = true))
    }

    @Test
    fun a_cache_only_miss_arms_only_its_own_window_on_undecodable_bytes() {
        val avatars = FediAvatars(96)
        val label = "a@host"
        assertEquals(null, avatars.decodeAndCache(label, ByteArray(0), 0L, cacheOnly = true))
        assertFalse(avatars.shouldQuery(label, 1L, cacheOnly = true))
        assertTrue(avatars.shouldQuery(label, 1L))
    }

    @Test
    fun clear_forgets_the_cache_only_window_too() {
        val avatars = FediAvatars(96)
        avatars.noteAbsent("a@host", 0L, cacheOnly = true)
        assertFalse(avatars.shouldQuery("a@host", 1L, cacheOnly = true))
        avatars.clear()
        assertTrue(avatars.shouldQuery("a@host", 1L, cacheOnly = true))
    }
}
