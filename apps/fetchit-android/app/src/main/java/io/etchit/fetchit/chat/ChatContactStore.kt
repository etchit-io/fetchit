package io.etchit.fetchit.chat

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists [ChatContact]s in `SharedPreferences` as a single JSON-encoded
 * key (`contacts_v1`).
 *
 * Plain `SharedPreferences`, not `EncryptedSharedPreferences` — agent IDs
 * are public keys and display names are user-chosen, so the encryption-at-rest
 * cost (a Keystore handshake on every read) buys no meaningful threat-model
 * improvement here.
 *
 * Single-process — fetch>it has no service or background worker, so
 * there's no inter-process synchronisation concern.
 */
class ChatContactStore(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _contacts = MutableStateFlow(load())

    /** Current state of the contact list, observable for UI updates. */
    val contacts: StateFlow<List<ChatContact>> = _contacts.asStateFlow()

    /**
     * Add or update a contact. If a contact with the same [ChatContact.agentIdHex]
     * already exists it is replaced; otherwise the new entry is inserted.
     * The list is kept sorted newest-first by [ChatContact.addedAtMs].
     */
    fun add(contact: ChatContact) {
        val without = _contacts.value.filter { it.agentIdHex != contact.agentIdHex }
        write((listOf(contact) + without).sortedByDescending { it.addedAtMs })
    }

    /** Rename the contact identified by [agentIdHex]. No-op if not found. */
    fun rename(agentIdHex: String, newName: String) {
        write(_contacts.value.map { if (it.agentIdHex == agentIdHex) it.copy(displayName = newName) else it })
    }

    /** Remove the contact identified by [agentIdHex]. No-op if not found. */
    fun delete(agentIdHex: String) {
        write(_contacts.value.filter { it.agentIdHex != agentIdHex })
    }

    private fun load(): List<ChatContact> = ChatContactSerde.decode(prefs.getString(KEY, null))

    private fun write(list: List<ChatContact>) {
        prefs.edit().putString(KEY, ChatContactSerde.encode(list)).apply()
        _contacts.value = list
    }

    private companion object {
        const val PREFS_NAME = "fetchit_contacts"
        const val KEY = "contacts_v1"
    }
}
