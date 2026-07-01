package io.etchit.fetchit

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [normalizeRecoveryPhrase] — pure input hygiene, plain JUnit.
 * Guards the trim / whitespace-collapse / lowercase contract the restore flow
 * relies on so a correctly-worded phrase matches despite keyboard casing or
 * stray spacing.
 */
class RecoveryPhraseTest {

    @Test
    fun trims_leading_and_trailing_whitespace() {
        assertEquals("alpha bravo", normalizeRecoveryPhrase("   alpha bravo   "))
    }

    @Test
    fun collapses_internal_space_runs_to_single_spaces() {
        assertEquals("alpha bravo charlie", normalizeRecoveryPhrase("alpha   bravo    charlie"))
    }

    @Test
    fun collapses_tabs_and_newlines() {
        assertEquals("one two three", normalizeRecoveryPhrase("one\ttwo\r\nthree"))
    }

    @Test
    fun lowercases_ascii() {
        assertEquals("abandon ability able", normalizeRecoveryPhrase("Abandon ABILITY AbLe"))
    }

    @Test
    fun combined_trim_collapse_and_lowercase() {
        assertEquals(
            "abandon ability able about",
            normalizeRecoveryPhrase("  Abandon   ABILITY\tAbLe\nabout \n"),
        )
    }

    @Test
    fun empty_stays_empty() {
        assertEquals("", normalizeRecoveryPhrase(""))
    }

    @Test
    fun whitespace_only_becomes_empty() {
        assertEquals("", normalizeRecoveryPhrase("   \t\n "))
    }

    @Test
    fun already_normal_is_unchanged() {
        assertEquals("word word word", normalizeRecoveryPhrase("word word word"))
    }
}
