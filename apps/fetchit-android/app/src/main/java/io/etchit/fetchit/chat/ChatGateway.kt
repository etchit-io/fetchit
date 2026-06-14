package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi
import uniffi.fetchit_ffi.OutboxBubbleFfi

/** Seam over the uniffi surface so controller + UI are testable without a relay. */
interface ChatGateway {
    /** Hex-encoded local agent identity (64 lowercase hex chars). */
    fun agentIdHex(): String

    /** Returns a `x0x://pair/…` URI encoding this agent's pairing offer. */
    suspend fun pairShareUri(): String

    /** Consume a pairing URI produced by a remote peer. */
    suspend fun importPairUri(uri: String)

    /**
     * Enqueue a direct message to [to] (64-hex agent id) into the durable
     * engine outbox and return the client-assigned bubble id (stable across
     * retries). The bubble's lifecycle -- the optimistic `Sending` echo, then
     * `Delivered` or `Failed` -- arrives as [ChatEventFfi.Outbox] events through
     * [nextEvent], NOT via this return value.
     */
    suspend fun enqueueDm(to: String, body: String, senderName: String): String

    /**
     * Start the engine outbox retry driver under [displayName]. The controller
     * calls it once per connect so undelivered messages flush on the next
     * presence edge.
     */
    fun startOutbox(displayName: String)

    /** Snapshot of every outbox bubble, for subscribe-then-hydrate on connect. */
    suspend fun outboxSnapshot(): List<OutboxBubbleFfi>

    /** Flush the outbox now -- the engine equivalent of a Retry tap. */
    fun retryOutbox()

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
    override suspend fun enqueueDm(to: String, body: String, senderName: String): String =
        inner.enqueueDm(to, body, senderName)
    override fun startOutbox(displayName: String) = inner.startOutbox(displayName)
    override suspend fun outboxSnapshot(): List<OutboxBubbleFfi> = inner.outboxSnapshot()
    override fun retryOutbox() = inner.retryOutbox()
    override suspend fun nextEvent(): ChatEventFfi? = inner.nextEvent()
    override fun disconnect() = inner.disconnect()
}
