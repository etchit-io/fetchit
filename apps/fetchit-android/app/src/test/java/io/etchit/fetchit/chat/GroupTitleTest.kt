package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.fetchit_ffi.GroupFfi

/**
 * Pure title-resolution for a group thread header / list row:
 * the group's name, falling back to a short id. JVM-testable so the
 * fallback rule cannot drift between the thread header and the list row.
 */
class GroupTitleTest {

    private fun group(name: String?): GroupFfi =
        GroupFfi("c".repeat(64), name, 1uL, isOwner = true, isPrivate = true)

    @Test
    fun namePreferredWhenPresent() {
        assertEquals("design team", groupTitle(group("design team"), "c".repeat(64)))
    }

    @Test
    fun blankNameFallsBackToShortId() {
        // x0xd can list a group with an empty name; show the short id, not "".
        assertEquals("cccccccc", groupTitle(group("  "), "c".repeat(64)))
    }

    @Test
    fun nullGroupFallsBackToShortId() {
        // Before listGroups resolves (or for a just-joined id) there is no
        // GroupFfi yet -- the row/header still needs a stable label.
        assertEquals("abababab", groupTitle(null, "ab".repeat(32)))
    }

    @Test
    fun shortIdIsFirstEightChars() {
        assertEquals("0123abcd", groupTitle(null, "0123abcd" + "e".repeat(56)))
    }
}
