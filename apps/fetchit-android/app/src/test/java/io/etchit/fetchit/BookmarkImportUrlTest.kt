package io.etchit.fetchit

import android.app.Application
import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for [parseBookmarkImportUrl]. Robolectric-run because the
 * parser uses Android's [`Uri`] and [`Base64`] — both framework
 * classes stubbed on the host JVM only via Robolectric.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class BookmarkImportUrlTest {

    private val addr1 = "0".repeat(64)
    private val addr2 = "1".repeat(64)

    /** Encode a payload the same way the desktop side does — base64url, no padding. */
    private fun urlFor(json: String): String {
        val b64 = Base64.encodeToString(
            json.toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )
        return "fetchit://import?v=1&data=$b64"
    }

    @Test
    fun parses_single_bookmark() {
        val url = urlFor("""{"bookmarks":[{"a":"$addr1","l":"first"}]}""")
        val parsed = parseBookmarkImportUrl(url)
        assertNotNull(parsed)
        assertEquals(1, parsed!!.bookmarks.size)
        assertEquals(addr1, parsed.bookmarks[0].address)
        assertEquals("first", parsed.bookmarks[0].label)
    }

    @Test
    fun parses_multiple_bookmarks_preserving_order() {
        val url = urlFor(
            """{"bookmarks":[{"a":"$addr1","l":"one"},{"a":"$addr2","l":"two"}]}""",
        )
        val parsed = parseBookmarkImportUrl(url)
        assertNotNull(parsed)
        assertEquals(2, parsed!!.bookmarks.size)
        assertEquals(addr1, parsed.bookmarks[0].address)
        assertEquals(addr2, parsed.bookmarks[1].address)
    }

    @Test
    fun rejects_non_fetchit_scheme() {
        assertNull(parseBookmarkImportUrl("autonomi://${"a".repeat(64)}"))
        assertNull(parseBookmarkImportUrl("https://example.com"))
    }

    @Test
    fun rejects_wrong_action() {
        assertNull(parseBookmarkImportUrl("fetchit://something-else?v=1&data=x"))
    }

    @Test
    fun rejects_unknown_version() {
        val url = urlFor("""{"bookmarks":[{"a":"$addr1","l":"x"}]}""")
        val tampered = url.replace("v=1", "v=99")
        assertNull(parseBookmarkImportUrl(tampered))
    }

    @Test
    fun rejects_missing_data_param() {
        assertNull(parseBookmarkImportUrl("fetchit://import?v=1"))
    }

    @Test
    fun rejects_undecodable_data() {
        assertNull(parseBookmarkImportUrl("fetchit://import?v=1&data=!!!not-base64!!!"))
    }

    @Test
    fun returns_empty_list_when_bookmarks_array_is_empty() {
        val url = urlFor("""{"bookmarks":[]}""")
        val parsed = parseBookmarkImportUrl(url)
        assertNotNull(parsed)
        assertEquals(0, parsed!!.bookmarks.size)
    }

    @Test
    fun skips_entries_with_invalid_address_but_keeps_valid_ones() {
        val url = urlFor(
            """{"bookmarks":[{"a":"$addr1","l":"good"},{"a":"nope","l":"bad"}]}""",
        )
        val parsed = parseBookmarkImportUrl(url)
        assertNotNull(parsed)
        assertEquals(1, parsed!!.bookmarks.size)
        assertEquals("good", parsed.bookmarks[0].label)
    }

    @Test
    fun normalises_uppercase_addresses_to_lowercase() {
        val upper = "A".repeat(64)
        val url = urlFor("""{"bookmarks":[{"a":"$upper","l":"x"}]}""")
        val parsed = parseBookmarkImportUrl(url)
        assertNotNull(parsed)
        assertEquals("a".repeat(64), parsed!!.bookmarks[0].address)
    }

    @Test
    fun ignores_surrounding_whitespace() {
        val url = "  ${urlFor("""{"bookmarks":[{"a":"$addr1","l":"x"}]}""")}  "
        val parsed = parseBookmarkImportUrl(url)
        assertNotNull(parsed)
        assertEquals(1, parsed!!.bookmarks.size)
    }
}
