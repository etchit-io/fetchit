package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for the pure [chatConnectionStatus] mapping — plain JUnit, no
 * Android, since it is a pure function over [PumpState] + the connecting flag.
 */
class ChatConnectionStatusTest {

    @Test
    fun running_and_not_connecting_is_connected() {
        assertEquals(
            ChatConnectionStatus.CONNECTED,
            chatConnectionStatus(PumpState.RUNNING, connecting = false),
        )
    }

    @Test
    fun connecting_flag_wins_over_every_pump_state() {
        for (pump in PumpState.entries) {
            assertEquals(
                "connecting should win for pump=$pump",
                ChatConnectionStatus.CONNECTING,
                chatConnectionStatus(pump, connecting = true),
            )
        }
    }

    @Test
    fun idle_or_stopped_without_connecting_is_offline() {
        for (pump in listOf(PumpState.IDLE, PumpState.STOPPED_CLEAN, PumpState.STOPPED_ERROR)) {
            assertEquals(
                "pump=$pump should read offline",
                ChatConnectionStatus.OFFLINE,
                chatConnectionStatus(pump, connecting = false),
            )
        }
    }
}
