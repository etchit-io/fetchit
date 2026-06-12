package io.etchit.fetchit.chat

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
 * Unit tests for [ChatContactStore]. Robolectric-run for a real
 * `SharedPreferences` (and `org.json` under [ChatContactSerde]).
 *
 * `application = Application::class` keeps Robolectric from instantiating
 * the manifest's `FetchitApplication`, whose `onCreate` calls into the
 * `fetchit_ffi` native library — absent on the host JVM test classpath.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class ChatContactStoreTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("fetchit_contacts", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    private fun store() = ChatContactStore(context)

    @Test
    fun addPersistsAcrossInstances() {
        val a = store()
        a.add(ChatContact(agentIdHex = "a".repeat(64), displayName = "alice", addedAtMs = 1L))
        val b = store()
        assertEquals(1, b.contacts.value.size)
        assertEquals("alice", b.contacts.value.first().displayName)
    }

    @Test
    fun addDedupesOnAgentIdKeepingNewestName() {
        val s = store()
        s.add(ChatContact("b".repeat(64), "old", 1L))
        s.add(ChatContact("b".repeat(64), "new", 2L))
        assertEquals(1, s.contacts.value.size)
        assertEquals("new", s.contacts.value.first().displayName)
    }

    @Test
    fun deleteRemoves() {
        val s = store()
        s.add(ChatContact("c".repeat(64), "x", 1L))
        s.delete("c".repeat(64))
        assertTrue(s.contacts.value.isEmpty())
    }

    @Test
    fun renameUpdatesDisplayName() {
        val s = store()
        s.add(ChatContact("d".repeat(64), "before", 1L))
        s.rename("d".repeat(64), "after")
        assertEquals("after", s.contacts.value.single().displayName)
    }

    @Test
    fun renameUnknownAgentIsNoop() {
        val s = store()
        s.add(ChatContact("e".repeat(64), "keep", 1L))
        s.rename("f".repeat(64), "ignored")
        assertEquals("keep", s.contacts.value.single().displayName)
    }
}
