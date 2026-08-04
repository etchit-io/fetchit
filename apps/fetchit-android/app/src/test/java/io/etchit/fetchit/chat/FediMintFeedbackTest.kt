package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import uniffi.fetchit_ffi.MintRegistrationFfi
import uniffi.fetchit_ffi.MintStateFfi

/**
 * Unit tests for [takenHandle] — the mint screen's read of a directory
 * outcome (#331). The one that matters: a taken name must not be mistaken
 * for a pending one, or the screen retries a name it can never win.
 */
class FediMintFeedbackTest {

    @Test
    fun a_conflict_names_the_handle_to_edit() {
        assertEquals("alice", takenHandle(MintRegistrationFfi.NameTaken("alice")))
    }

    @Test
    fun success_is_not_a_conflict() {
        assertNull(takenHandle(MintRegistrationFfi.Registered))
    }

    @Test
    fun a_bridge_failure_is_not_a_conflict() {
        assertNull(takenHandle(MintRegistrationFfi.Retrying("bridge unreachable")))
    }

    @Test
    fun a_recorded_conflict_survives_as_the_name_to_reopen_on() {
        val state = MintStateFfi("alice", MintRegistrationFfi.NameTaken("alice"), 1L)
        assertEquals("alice", takenHandle(state))
    }

    @Test
    fun no_recorded_state_has_no_conflict() {
        assertNull(takenHandle(null))
    }

    @Test
    fun a_recorded_pending_state_is_not_a_conflict() {
        val state = MintStateFfi("alice", MintRegistrationFfi.Retrying("bridge down"), 1L)
        assertNull(takenHandle(state))
    }
}
