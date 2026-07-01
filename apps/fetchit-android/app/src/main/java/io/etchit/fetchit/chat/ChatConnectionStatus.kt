package io.etchit.fetchit.chat

/**
 * UI-facing chat connection state, derived from the inbound-pump lifecycle
 * plus an in-flight connect attempt. Rendered as the status dot in the chat
 * header so the user can see, at a glance, whether chat is connected.
 */
enum class ChatConnectionStatus {
    /** The pump is running: the relay is up and inbound is flowing. */
    CONNECTED,

    /** A connect attempt is in flight — the slow initial dial or a reconnect. */
    CONNECTING,

    /** No live connection: never started, cleanly stopped, or dropped. */
    OFFLINE,
}

/**
 * Pure mapping from [PumpState] + an in-flight-connect flag to the
 * [ChatConnectionStatus] shown in the header dot.
 *
 * [connecting] wins over the pump state so the slow initial dial (during which
 * the pump is still [PumpState.IDLE] until the connect lands) and a reconnect
 * (pump [PumpState.STOPPED_ERROR]) both read as CONNECTING rather than OFFLINE
 * — that distinction is exactly what tells the user "it's working on it" vs
 * "it's down". Otherwise RUNNING is CONNECTED and every other state is OFFLINE.
 */
fun chatConnectionStatus(pump: PumpState, connecting: Boolean): ChatConnectionStatus =
    when {
        connecting -> ChatConnectionStatus.CONNECTING
        pump == PumpState.RUNNING -> ChatConnectionStatus.CONNECTED
        else -> ChatConnectionStatus.OFFLINE
    }
