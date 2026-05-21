package io.etchit.fetchit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** Unit tests for [BytesCache] — round-trip, sharding, stats, LRU eviction. */
class BytesCacheTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val addrA = "a".repeat(64)
    private val addrB = "b".repeat(64)
    private val addrC = "c".repeat(64)

    @Test
    fun put_then_get_round_trips() {
        val c = BytesCache(tmp.newFolder())
        c.put(addrA, byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), c.get(addrA))
    }

    @Test
    fun get_returns_null_on_miss() {
        assertNull(BytesCache(tmp.newFolder()).get(addrA))
    }

    @Test
    fun invalid_address_is_rejected_by_get_and_put() {
        val c = BytesCache(tmp.newFolder())
        c.put("not-a-64-hex-address", byteArrayOf(9))
        assertNull(c.get("not-a-64-hex-address"))
        assertEquals(0, c.stats().entries)
    }

    @Test
    fun lookup_is_case_insensitive() {
        val c = BytesCache(tmp.newFolder())
        c.put(addrA.uppercase(), byteArrayOf(7))
        assertArrayEquals(byteArrayOf(7), c.get(addrA.lowercase()))
    }

    @Test
    fun stores_under_a_two_hex_char_shard() {
        val root = tmp.newFolder()
        BytesCache(root).put(addrA, byteArrayOf(1))
        // addrA is 64 'a's → shard directory "aa".
        assertTrue(File(root, "aa/$addrA").exists())
    }

    @Test
    fun stats_report_entry_count_and_total_size() {
        val c = BytesCache(tmp.newFolder())
        c.put(addrA, ByteArray(10))
        c.put(addrB, ByteArray(7))
        val s = c.stats()
        assertEquals(2, s.entries)
        assertEquals(17L, s.sizeBytes)
    }

    @Test
    fun clear_empties_the_cache() {
        val c = BytesCache(tmp.newFolder())
        c.put(addrA, byteArrayOf(1))
        c.put(addrB, byteArrayOf(2))
        c.clear()
        assertEquals(0, c.stats().entries)
        assertNull(c.get(addrA))
    }

    @Test
    fun evicts_oldest_entries_when_over_the_size_cap() {
        // Cap = 10 bytes; three 4-byte writes total 12 → the oldest evicts.
        val c = BytesCache(tmp.newFolder(), maxSizeBytes = 10)
        c.put(addrA, ByteArray(4))
        Thread.sleep(15) // distinct mtimes so LRU order is deterministic
        c.put(addrB, ByteArray(4))
        Thread.sleep(15)
        c.put(addrC, ByteArray(4))
        assertNull("oldest entry should be evicted", c.get(addrA))
        assertEquals(4, c.get(addrB)?.size)
        assertEquals(4, c.get(addrC)?.size)
    }
}
