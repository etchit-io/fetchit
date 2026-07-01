package io.etchit.fetchit

import android.app.Application
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for [encodeBookmarksForShare]. Robolectric-run because
 * the encoder uses Android's [`Base64`].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class BookmarkShareUrlTest {

    private val addr1 = "0".repeat(64)
    private val addr2 = "1".repeat(64)

    private fun bm(address: String, label: String) =
        Bookmark.create(label = label, address = address)

    @Test
    fun empty_list_is_Empty_outcome() {
        assertEquals(EncodeResult.Empty, encodeBookmarksForShare(emptyList()))
    }

    @Test
    fun within_cap_succeeds_with_fetchit_import_url() {
        val r = encodeBookmarksForShare(listOf(bm(addr1, "first")))
        assertTrue(r is EncodeResult.Ok)
        assertTrue((r as EncodeResult.Ok).url.startsWith("fetchit://import?v=1&data="))
    }

    @Test
    fun over_cap_reports_TooMany() {
        val many = (0 until MAX_BOOKMARKS_PER_QR + 1).map {
            bm(addr1.substring(0, 62) + "%02d".format(it), "bm-$it")
        }
        val r = encodeBookmarksForShare(many)
        assertTrue(r is EncodeResult.TooMany)
        assertEquals(MAX_BOOKMARKS_PER_QR + 1, (r as EncodeResult.TooMany).attempted)
    }

    @Test
    fun encoded_url_round_trips_through_the_parser() {
        val original = listOf(bm(addr1, "first"), bm(addr2, "second 💾"))
        val r = encodeBookmarksForShare(original)
        assertTrue(r is EncodeResult.Ok)
        val parsed = parseBookmarkImportUrl((r as EncodeResult.Ok).url)
        assertNotNull(parsed)
        assertEquals(2, parsed!!.bookmarks.size)
        assertEquals(addr1, parsed.bookmarks[0].address)
        assertEquals("first", parsed.bookmarks[0].label)
        assertEquals(addr2, parsed.bookmarks[1].address)
        assertEquals("second 💾", parsed.bookmarks[1].label)
    }

    @Test
    fun at_the_exact_cap_succeeds() {
        val list = (0 until MAX_BOOKMARKS_PER_QR).map {
            bm(addr1.substring(0, 62) + "%02d".format(it), "bm-$it")
        }
        val r = encodeBookmarksForShare(list)
        assertTrue(r is EncodeResult.Ok)
        val parsed = parseBookmarkImportUrl((r as EncodeResult.Ok).url)
        assertEquals(MAX_BOOKMARKS_PER_QR, parsed!!.bookmarks.size)
    }
}
