package io.etchit.fetchit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/** Unit tests for the [Bookmark.create] factory. */
class BookmarkTest {

    @Test
    fun create_fills_fields_and_defaults_kind_to_null() {
        val before = System.currentTimeMillis()
        val b = Bookmark.create(label = "My page", address = "abc123")
        assertEquals("My page", b.label)
        assertEquals("abc123", b.address)
        assertNull(b.kind)
        assertTrue("addedAt should be a recent epoch-millis", b.addedAt >= before)
    }

    @Test
    fun create_carries_kind_when_given() {
        assertEquals("html", Bookmark.create("x", "y", kind = "html").kind)
    }

    @Test
    fun create_generates_a_valid_uuid_id() {
        val b = Bookmark.create("x", "y")
        // UUID.fromString throws if the id is not a well-formed UUID.
        assertEquals(b.id, UUID.fromString(b.id).toString())
    }

    @Test
    fun create_generates_a_unique_id_each_call() {
        assertNotEquals(Bookmark.create("x", "y").id, Bookmark.create("x", "y").id)
    }
}
