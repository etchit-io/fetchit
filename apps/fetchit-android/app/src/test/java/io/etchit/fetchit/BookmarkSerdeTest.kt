package io.etchit.fetchit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for [BookmarkSerde]. Robolectric-run because the serializer
 * uses `org.json`, an Android-framework package that is only a throwing
 * stub on the plain JVM unit-test classpath.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BookmarkSerdeTest {

    private fun bookmark(
        id: String = "id-1",
        label: String = "A label",
        address: String = "c2b0285930b0a2c3df3928d0a4706b4e6d71e84ebeb4f7805c83ffbb63d0ab61",
        addedAt: Long = 1_700_000_000_000L,
        kind: String? = null,
    ) = Bookmark(id, label, address, addedAt, kind)

    // ── toJson / fromJson round-trip ──────────────────────────────────

    @Test
    fun json_round_trip_without_kind() {
        val b = bookmark()
        assertEquals(b, BookmarkSerde.fromJson(BookmarkSerde.toJson(b)))
    }

    @Test
    fun json_round_trip_with_kind() {
        val b = bookmark(kind = "html")
        assertEquals(b, BookmarkSerde.fromJson(BookmarkSerde.toJson(b)))
    }

    @Test
    fun fromJson_returns_null_when_a_required_field_is_missing() {
        val o = BookmarkSerde.toJson(bookmark())
        o.remove("address")
        assertNull(BookmarkSerde.fromJson(o))
    }

    @Test
    fun empty_kind_decodes_as_null() {
        val o = BookmarkSerde.toJson(bookmark())
        o.put("kind", "")
        assertNull(BookmarkSerde.fromJson(o)!!.kind)
    }

    // ── storage encode / decode ───────────────────────────────────────

    @Test
    fun storage_round_trip() {
        val list = listOf(bookmark(id = "a"), bookmark(id = "b", kind = "image"))
        assertEquals(list, BookmarkSerde.decodeStorage(BookmarkSerde.encodeStorage(list)))
    }

    @Test
    fun decodeStorage_is_empty_for_null_blank_and_garbage() {
        assertTrue(BookmarkSerde.decodeStorage(null).isEmpty())
        assertTrue(BookmarkSerde.decodeStorage("").isEmpty())
        assertTrue(BookmarkSerde.decodeStorage("not json at all").isEmpty())
        assertTrue(BookmarkSerde.decodeStorage("""{"not":"an array"}""").isEmpty())
    }

    @Test
    fun decodeStorage_skips_malformed_entries_and_keeps_valid_ones() {
        // First object is well-formed; the second is missing required fields.
        val raw = """[{"id":"a","label":"L","address":"X","addedAt":1},{"id":"b","label":"L"}]"""
        val out = BookmarkSerde.decodeStorage(raw)
        assertEquals(1, out.size)
        assertEquals("a", out[0].id)
    }

    // ── export envelope ───────────────────────────────────────────────

    @Test
    fun export_round_trip() {
        val list = listOf(bookmark(id = "a"), bookmark(id = "b"))
        val decoded = BookmarkSerde.decodeExport(BookmarkSerde.encodeExport(list))
        assertEquals(list, decoded.getOrNull())
    }

    @Test
    fun decodeExport_rejects_unsupported_version() {
        assertTrue(BookmarkSerde.decodeExport("""{"version":2,"bookmarks":[]}""").isFailure)
    }

    @Test
    fun decodeExport_rejects_missing_version() {
        assertTrue(BookmarkSerde.decodeExport("""{"bookmarks":[]}""").isFailure)
    }

    @Test
    fun decodeExport_rejects_malformed_json() {
        assertTrue(BookmarkSerde.decodeExport("{not json").isFailure)
    }
}
