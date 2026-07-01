package io.etchit.fetchit

import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Robolectric Activity tests for [MainActivity] — network-free UI flows. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = TestFetchitApplication::class)
class MainActivityTest {

    @Before
    fun seedPeers() {
        // SettingsSheet.bind() reads SettingsStore.peers() during onCreate;
        // with no saved override that calls the FFI's defaultPeers(), which
        // has no native library off-device. A saved override skips the call.
        val store = SettingsStore(RuntimeEnvironment.getApplication())
        store.savePeers(listOf(SEEDED_PEER))
        // Persist browse mode so lastMode() does not trigger setMode(CHAT)
        // during onCreate — that would hide settingsSheet and break the
        // visibility assertions in this class.
        store.saveLastMode("browse")
    }

    private fun launch(): MainActivity =
        Robolectric.buildActivity(MainActivity::class.java).setup().get()

    @Test
    fun launches_with_the_main_chrome() {
        val activity = launch()
        for (id in intArrayOf(
            R.id.addressInput,
            R.id.fetchButton,
            R.id.scanButton,
            R.id.bookmarkButton,
            R.id.settingsSheet,
        )) {
            assertEquals(View.VISIBLE, activity.findViewById<View>(id).visibility)
        }
    }

    @Test
    fun rejects_a_non_hex_address_without_fetching() {
        val activity = launch()
        val input = activity.findViewById<EditText>(R.id.addressInput)
        input.setText(BAD_ADDRESS)
        // GO routes to onFetchClicked → parseAutonomiInput → invalid. A valid
        // address would start a fetch and hit the (absent) FFI, so reaching
        // the assertions without a crash confirms the address was rejected.
        input.onEditorAction(EditorInfo.IME_ACTION_GO)
        assertEquals(BAD_ADDRESS, input.text.toString())
        assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.fetchButton).visibility)
    }

    @Test
    fun binds_the_settings_sheet_from_stored_peers() {
        val activity = launch()
        val peersEdit = activity.findViewById<EditText>(R.id.peersEdit)
        assertEquals(SEEDED_PEER, peersEdit.text.toString())
        val version = activity.findViewById<TextView>(R.id.settingsVersionText)
        assertTrue(version.text.isNotEmpty())
    }

    private companion object {
        const val SEEDED_PEER = "/ip4/127.0.0.1/udp/12000/quic-v1"
        const val BAD_ADDRESS = "not-a-real-autonomi-address"
    }
}
