package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi

/** Seam over the uniffi surface so controller + UI are testable without a relay. */
interface ChatGateway {
    /** Hex-encoded local agent identity (64 lowercase hex chars). */
    fun agentIdHex(): String

    /** Returns a `x0x://pair/…` URI encoding this agent's pairing offer. */
    suspend fun pairShareUri(): String

    /** Consume a pairing URI produced by a remote peer. */
    suspend fun importPairUri(uri: String)

    /**
     * Send a direct message to [to] (64-hex agent id).
     * Returns the message-id string assigned by the relay, or `null` if the
     * relay does not issue one.
     */
    suspend fun sendDm(to: String, body: String, senderName: String): String?

    /**
     * Block until the next [ChatEventFfi] arrives from the relay, or return
     * `null` when the client has been disconnected and the event queue is
     * drained.
     */
    suspend fun nextEvent(): ChatEventFfi?

    /** Terminate the relay connection. Safe to call more than once. */
    fun disconnect()
}

/** Production adapter that delegates every call directly to the uniffi [ChatClient]. */
class FfiChatGateway(private val inner: ChatClient) : ChatGateway {
    override fun agentIdHex(): String = inner.agentIdHex()
    override suspend fun pairShareUri(): String = inner.pairShareUri()
    override suspend fun importPairUri(uri: String) = inner.importPairUri(uri)
    override suspend fun sendDm(to: String, body: String, senderName: String): String? =
        inner.sendDm(to, body, senderName)
    override suspend fun nextEvent(): ChatEventFfi? = inner.nextEvent()
    override fun disconnect() = inner.disconnect()
}
