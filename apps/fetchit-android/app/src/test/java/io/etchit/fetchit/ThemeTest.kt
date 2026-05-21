package io.etchit.fetchit

import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** Unit tests for [Theme.fromId]. */
class ThemeTest {

    @Test
    fun fromId_maps_each_known_id() {
        assertSame(Theme.Dark, Theme.fromId("dark"))
        assertSame(Theme.Dim, Theme.fromId("dim"))
        assertSame(Theme.Light, Theme.fromId("light"))
    }

    @Test
    fun fromId_is_null_for_unknown_or_empty() {
        assertNull(Theme.fromId("solarized"))
        assertNull(Theme.fromId(""))
        assertNull(Theme.fromId("Dark")) // ids are lowercase — match is exact
    }

    @Test
    fun every_entry_id_round_trips() {
        for (t in Theme.entries) assertSame(t, Theme.fromId(t.id))
    }
}
