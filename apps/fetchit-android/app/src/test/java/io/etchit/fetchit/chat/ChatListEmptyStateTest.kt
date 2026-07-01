package io.etchit.fetchit.chat

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure first-run onboarding gate for the chat list: the welcome empty-state
 * shows only when the user has neither a contact nor a group. JVM-testable so
 * the detection rule cannot drift from the list-screen wiring (view inflation
 * itself isn't JVM-testable without Robolectric, so only this predicate is
 * exercised here, mirroring GroupTitleTest).
 */
class ChatListEmptyStateTest {

    @Test
    fun showsOnboardingWhenNoContactsAndNoGroups() {
        assertTrue(showChatOnboarding(0, 0))
    }

    @Test
    fun hiddenWithAContact() {
        assertFalse(showChatOnboarding(1, 0))
    }

    @Test
    fun hiddenWithAGroup() {
        assertFalse(showChatOnboarding(0, 1))
    }

    @Test
    fun hiddenWithBoth() {
        assertFalse(showChatOnboarding(2, 3))
    }
}
