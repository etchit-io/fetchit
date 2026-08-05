package io.etchit.fetchit.chat

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Block semantics for fediverse accounts, across every name form a
 *  surface can hold for the same person. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FediBlockStoreTest {

    private fun store() = FediBlockStore(RuntimeEnvironment.getApplication())

    @Test
    fun blocking_is_canonical_across_at_prefix_and_case() {
        val s = store()
        s.block("@HappyBorg@Fosstodon.org")
        assertTrue(s.isBlocked("happyborg@fosstodon.org"))
        assertTrue(s.isBlocked("@happyborg@fosstodon.org"))
        assertTrue(s.isBlocked(" @HAPPYBORG@FOSSTODON.ORG "))
        s.unblock("happyborg@fosstodon.org")
        assertFalse(s.isBlocked("@HappyBorg@Fosstodon.org"))
    }

    @Test
    fun an_entry_stored_under_the_label_still_hides_a_row_that_knows_the_url() {
        // The transition trap: a feed row used to carry only a label and
        // now carries an actor URL too. An entry blocked under the OLD
        // form must keep matching, or the block silently stops working.
        val s = store()
        s.block("happyborg@fosstodon.org")
        assertTrue(
            s.isAnyBlocked(
                "happyborg@fosstodon.org",
                fediActorDisplay("https://fosstodon.org/users/happyborg"),
            ),
        )
    }

    @Test
    fun an_entry_stored_under_the_at_handle_matches_a_url_derived_row() {
        val s = store()
        // What the People sheet writes: the "@user@host" form.
        s.block("@happyborg@fosstodon.org")
        assertTrue(
            s.isAnyBlocked("", fediActorDisplay("https://fosstodon.org/users/happyborg")),
        )
    }

    @Test
    fun blanks_are_skipped_and_an_unblocked_account_stays_visible() {
        val s = store()
        assertFalse(s.isAnyBlocked("", "", " "))
        s.block("someone@else.example")
        assertFalse(s.isAnyBlocked("happyborg@fosstodon.org", ""))
    }

    @Test
    fun blocked_list_is_sorted_and_canonical() {
        val s = store()
        s.block("@Zed@h")
        s.block("adam@h")
        assertTrue(s.blocked() == listOf("adam@h", "zed@h"))
    }
}
