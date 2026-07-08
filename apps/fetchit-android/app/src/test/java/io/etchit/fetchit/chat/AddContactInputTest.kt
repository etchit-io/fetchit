package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test

/** Unit tests for the "add someone" input classifier. */
class AddContactInputTest {

    @Test
    fun blankIsEmpty() {
        assertEquals(AddContactInput.Empty, classifyAddContactInput("   "))
        assertEquals(AddContactInput.Empty, classifyAddContactInput(""))
    }

    @Test
    fun lonelyAtSignIsEmpty() {
        assertEquals(AddContactInput.Empty, classifyAddContactInput("@"))
    }

    @Test
    fun anyUriSchemeImportsVerbatim() {
        val raw = "x0x://pair/${"a".repeat(64)}?r=https://nyc-relay.etchit.io"
        assertEquals(AddContactInput.PairUri(raw), classifyAddContactInput("  $raw  "))
    }

    @Test
    fun bareNameGetsHomeInstance() {
        assertEquals(
            AddContactInput.FediHandle("alice@etchit.io"),
            classifyAddContactInput("alice"),
        )
    }

    @Test
    fun leadingAtStrippedAndHomeInstanceAdded() {
        assertEquals(
            AddContactInput.FediHandle("alice@etchit.io"),
            classifyAddContactInput("@alice"),
        )
    }

    @Test
    fun fullHandleKeptAndLowercased() {
        assertEquals(
            AddContactInput.FediHandle("alice@mastodon.social"),
            classifyAddContactInput("@Alice@Mastodon.Social"),
        )
    }

    @Test
    fun homeHandleWithInstanceIsUnchanged() {
        assertEquals(
            AddContactInput.FediHandle("bob@etchit.io"),
            classifyAddContactInput("bob@etchit.io"),
        )
    }

    @Test
    fun homeInstanceConstantIsEtchit() {
        assertEquals("etchit.io", HOME_INSTANCE)
    }

    @Test
    fun contactNameTakesLocalPart() {
        assertEquals("alice", contactNameFromHandle("@alice@etchit.io"))
        assertEquals("alice", contactNameFromHandle("alice@mastodon.social"))
        assertEquals("bob", contactNameFromHandle("@bob"))
    }
}
