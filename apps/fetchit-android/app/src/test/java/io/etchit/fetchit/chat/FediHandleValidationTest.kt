package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for [fediHandleError] — pure validation, plain JUnit. Mirrors
 * desktop's mint rule: 1–64 chars, ASCII letters/digits/`-`/`_`.
 */
class FediHandleValidationTest {

    @Test
    fun plain_handle_is_valid() {
        assertNull(fediHandleError("alice"))
    }

    @Test
    fun digits_dash_underscore_are_valid() {
        assertNull(fediHandleError("al_ice-99"))
    }

    @Test
    fun sixtyfour_chars_is_the_upper_bound() {
        assertNull(fediHandleError("a".repeat(64)))
    }

    @Test
    fun empty_is_rejected() {
        assertEquals(FediHandleError.EMPTY, fediHandleError(""))
    }

    @Test
    fun blank_is_rejected_as_empty() {
        assertEquals(FediHandleError.EMPTY, fediHandleError("   "))
    }

    @Test
    fun sixtyfive_chars_is_too_long() {
        assertEquals(FediHandleError.TOO_LONG, fediHandleError("a".repeat(65)))
    }

    @Test
    fun spaces_are_invalid_chars() {
        assertEquals(FediHandleError.INVALID_CHARS, fediHandleError("bad space"))
    }

    @Test
    fun symbols_are_invalid_chars() {
        assertEquals(FediHandleError.INVALID_CHARS, fediHandleError("bad@char"))
    }

    @Test
    fun non_ascii_is_invalid_chars() {
        assertEquals(FediHandleError.INVALID_CHARS, fediHandleError("café"))
    }
}
