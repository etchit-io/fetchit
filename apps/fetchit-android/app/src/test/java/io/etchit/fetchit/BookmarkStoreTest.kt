package io.etchit.fetchit

import android.app.Application
import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Unit tests for [BookmarkStore]. Robolectric-run for a real
 * `SharedPreferences` (and `org.json` under [BookmarkSerde]).
 *
 * `application = Application::class` keeps Robolectric from instantiating
 * the manifest's `FetchitApplication`, whose `onCreate` calls into the
 * `fetchit_ffi` native library — absent on the host JVM test classpath.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class BookmarkStoreTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        // Each test owns a clean prefs file — Robolectric reuses the
        // process across tests in a class.
        context.getSharedPreferences("fetchit_bookmarks", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    private fun bookmark(
        id: String = "id-1",
        label: String = "A label",
        address: String = "a".repeat(64),
        addedAt: Long = 1_700_000_000_000L,
        kind: String? = null,
    ) = Bookmark(id, label, address, addedAt, kind)

    // ── add ───────────────────────────────────────────────────────────

    @Test
    fun starts_empty() {
        assertTrue(BookmarkStore(context).bookmarks.value.isEmpty())
    }

    @Test
    fun add_puts_the_bookmark_into_the_flow() {
        val store = BookmarkStore(context)
        val b = bookmark()
        store.add(b)
        assertEquals(listOf(b), store.bookmarks.value)
    }

    @Test
    fun add_prepends_newest_first() {
        val store = BookmarkStore(context)
        val first = bookmark(id = "first", address = "1".repeat(64))
        val second = bookmark(id = "second", address = "2".repeat(64))
        store.add(first)
        store.add(second)
        assertEquals(listOf(second, first), store.bookmarks.value)
    }

    // ── delete (remove) ───────────────────────────────────────────────

    @Test
    fun delete_removes_the_matching_bookmark() {
        val store = BookmarkStore(context)
        val keep = bookmark(id = "keep", address = "1".repeat(64))
        val drop = bookmark(id = "drop", address = "2".repeat(64))
        store.add(keep)
        store.add(drop)
        store.delete("drop")
        assertEquals(listOf(keep), store.bookmarks.value)
    }

    @Test
    fun delete_is_a_noop_for_an_unknown_id() {
        val store = BookmarkStore(context)
        val b = bookmark()
        store.add(b)
        store.delete("does-not-exist")
        assertEquals(listOf(b), store.bookmarks.value)
    }

    // ── update ────────────────────────────────────────────────────────

    @Test
    fun update_replaces_the_matching_bookmark() {
        val store = BookmarkStore(context)
        store.add(bookmark(id = "id-1", label = "old"))
        store.update("id-1") { it.copy(label = "new") }
        assertEquals("new", store.bookmarks.value.single().label)
    }

    @Test
    fun update_is_a_noop_for_an_unknown_id() {
        val store = BookmarkStore(context)
        val b = bookmark(label = "unchanged")
        store.add(b)
        store.update("nope") { it.copy(label = "changed") }
        assertEquals(listOf(b), store.bookmarks.value)
    }

    // ── mergeImport (dedupe by address) ───────────────────────────────

    @Test
    fun mergeImport_prepends_new_bookmarks() {
        val store = BookmarkStore(context)
        val existing = bookmark(id = "existing", address = "1".repeat(64))
        store.add(existing)
        val imported = bookmark(id = "imported", address = "2".repeat(64))
        store.mergeImport(listOf(imported))
        assertEquals(listOf(imported, existing), store.bookmarks.value)
    }

    @Test
    fun mergeImport_dedupes_by_address_existing_wins() {
        val store = BookmarkStore(context)
        val existing = bookmark(id = "existing", label = "user label", address = "1".repeat(64))
        store.add(existing)
        // Same address, different id/label — must be dropped, existing kept.
        val collide = bookmark(id = "import", label = "import label", address = "1".repeat(64))
        store.mergeImport(listOf(collide))
        assertEquals(listOf(existing), store.bookmarks.value)
    }

    @Test
    fun mergeImport_keeps_non_colliding_entries_when_some_collide() {
        val store = BookmarkStore(context)
        val existing = bookmark(id = "existing", address = "1".repeat(64))
        store.add(existing)
        val collide = bookmark(id = "collide", address = "1".repeat(64))
        val fresh = bookmark(id = "fresh", address = "2".repeat(64))
        store.mergeImport(listOf(collide, fresh))
        assertEquals(listOf(fresh, existing), store.bookmarks.value)
    }

    // ── persistence ───────────────────────────────────────────────────

    @Test
    fun a_fresh_instance_reads_what_a_prior_instance_wrote() {
        val b = bookmark(id = "persisted", kind = "html")
        BookmarkStore(context).add(b)
        // New instance over the same Context — must load from prefs.
        assertEquals(listOf(b), BookmarkStore(context).bookmarks.value)
    }

    @Test
    fun a_fresh_instance_reflects_a_delete_done_by_a_prior_instance() {
        val first = BookmarkStore(context)
        first.add(bookmark(id = "a", address = "1".repeat(64)))
        first.add(bookmark(id = "b", address = "2".repeat(64)))
        first.delete("a")
        assertEquals(listOf("b"), BookmarkStore(context).bookmarks.value.map { it.id })
    }

    @Test
    fun persistence_survives_an_empty_list() {
        val store = BookmarkStore(context)
        store.add(bookmark())
        store.delete("id-1")
        assertTrue(BookmarkStore(context).bookmarks.value.isEmpty())
    }
}
