package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi
import uniffi.fetchit_ffi.ChatHistoryMessageFfi
import uniffi.fetchit_ffi.CreatedLinkOfferFfi
import uniffi.fetchit_ffi.GroupFfi
import uniffi.fetchit_ffi.GroupMemberFfi
import uniffi.fetchit_ffi.LinkOfferPreviewFfi
import uniffi.fetchit_ffi.OutboxBubbleFfi

/** Seam over the uniffi surface so controller + UI are testable without a relay. */
interface ChatGateway {
    /** Hex-encoded local agent identity (64 lowercase hex chars). */
    fun agentIdHex(): String

    /**
     * Outcome of the connect-time pair-record publish, for surfacing relay
     * reachability. `null` while still in flight; then `"ok"`,
     * `"error: <reason>"`, or `"panic: <reason>"`.
     */
    fun pairPublishOutcome(): String?

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
     * Create a group. [private] true mints a PQ MLS/TreeKEM group (the UI
     * default); false mints a plaintext public room. Returns the created
     * [GroupFfi] with `isPrivate` already stamped from the chosen preset.
     */
    suspend fun createGroup(name: String, displayName: String?, private: Boolean): GroupFfi

    /** Join a group from an `x0x://invite/...` link, presenting [displayName]. */
    suspend fun joinGroup(invite: String, displayName: String?): GroupFfi

    /**
     * Send [body] to [groupId], routed private/public by the engine's
     * kind-aware `send_to_group`. Returns the message id, or `null` when the
     * transport succeeded but no id was minted.
     */
    suspend fun sendGroupMessage(groupId: String, body: String, senderName: String): String?

    /** Groups this agent belongs to. */
    suspend fun listGroups(): List<GroupFfi>

    /** Fresh `x0x://invite/...` link for [groupId]. */
    suspend fun groupInvite(groupId: String): String

    /**
     * Remove the contact [agentIdHex] (64-hex agent id) from the engine,
     * dropping its conversation. The caller clears any local UI/store state.
     */
    suspend fun removeContact(agentIdHex: String)

    /** Leave the group [groupId]; rejoining needs a fresh invite. */
    suspend fun leaveGroup(groupId: String)

    /**
     * Roster of active members for [groupId] -- "who is in this group". Each
     * [GroupMemberFfi] carries the member's role plus pre-derived
     * `isOwner` / `isAdmin` flags; those flags are COSMETIC (they only hide
     * controls that would 4xx). x0xd is the sole authorization gate.
     */
    suspend fun groupMembers(groupId: String): List<GroupMemberFfi>

    /**
     * Remove [agentIdHex] from [groupId]. x0xd authorizes (admin+, refuses an
     * owner-target) and drives the TreeKEM re-key; a failure (incl. an
     * unauthorized caller) surfaces as a thrown exception the UI must show.
     */
    suspend fun removeMember(groupId: String, agentIdHex: String)

    /** Ban [agentIdHex] from [groupId] (removed and cannot rejoin); x0xd-gated. */
    suspend fun banMember(groupId: String, agentIdHex: String)

    /** Rename [groupId] to [newName]; x0xd gates the rename to admin+. */
    suspend fun renameGroup(groupId: String, newName: String)

    /**
     * Persisted message transcript for a conversation, for reload-on-open. The
     * engine already persists every DM and private-group message to the
     * encrypted at-rest vault; this surfaces it so threads are not empty after
     * a process kill.
     *
     * [convKey] is the shell conversation key: a `g:`-prefixed group id
     * ([ConversationStore.convKeyGroup]) resolves the group conversation; a
     * bare peer agent-id hex ([ConversationStore.convKeyDm]) resolves that
     * peer's current DM. An unknown / not-yet-persisted conversation returns an
     * empty list. Entries are ordered oldest-first; `outbound` is pre-derived
     * by the engine against the local agent id.
     */
    suspend fun conversationHistory(convKey: String): List<ChatHistoryMessageFfi>

    /**
     * Mint a device-link offer from this device's own identity and publish it
     * to the relay (M6.4). Called by the device that wants to BE linked (the
     * "new" device): it returns a `fetchit://link/v1/…` QR pointer plus a short
     * human-comparable confirm code and an absolute expiry [ttlSecs] seconds
     * out. The existing device scans the pointer and confirms the code.
     */
    suspend fun createLinkOffer(ttlSecs: ULong): CreatedLinkOfferFfi

    /**
     * Fetch and preview a scanned device-link offer (M6.4). Called by the
     * EXISTING (already-connected) device after scanning the new device's QR:
     * returns the new device's agent id, the short code to compare against the
     * new device's screen, and whether the offer has expired. Preview never
     * mutates state -- enrollment happens only after the human confirms the
     * code via [enrollConfirmedDevice].
     */
    suspend fun previewLinkOffer(uri: String): LinkOfferPreviewFfi

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
    override fun pairPublishOutcome(): String? = inner.pairPublishOutcome()
    override suspend fun pairShareUri(): String = inner.pairShareUri()
    override suspend fun importPairUri(uri: String) = inner.importPairUri(uri)
    override suspend fun enqueueDm(to: String, body: String, senderName: String): String =
        inner.enqueueDm(to, body, senderName)
    override fun startOutbox(displayName: String) = inner.startOutbox(displayName)
    override suspend fun outboxSnapshot(): List<OutboxBubbleFfi> = inner.outboxSnapshot()
    override fun retryOutbox() = inner.retryOutbox()
    override suspend fun createGroup(name: String, displayName: String?, private: Boolean): GroupFfi =
        inner.createGroup(name, displayName, private)
    override suspend fun joinGroup(invite: String, displayName: String?): GroupFfi =
        inner.joinGroup(invite, displayName)
    override suspend fun sendGroupMessage(groupId: String, body: String, senderName: String): String? =
        // The regenerated bindings return a richer GroupSendReceiptFfi
        // (messageId + delivered); the gateway keeps its String? message-id
        // contract, so extract the id here. Surfacing `delivered` is a separate
        // group-send task, not M6.4.
        inner.sendGroupMessage(groupId, body, senderName).messageId
    override suspend fun listGroups(): List<GroupFfi> = inner.listGroups()
    override suspend fun groupInvite(groupId: String): String = inner.groupInvite(groupId)
    override suspend fun removeContact(agentIdHex: String) = inner.removeContact(agentIdHex)
    override suspend fun leaveGroup(groupId: String) = inner.leaveGroup(groupId)
    override suspend fun groupMembers(groupId: String): List<GroupMemberFfi> =
        inner.groupMembers(groupId)
    override suspend fun removeMember(groupId: String, agentIdHex: String) =
        inner.removeMember(groupId, agentIdHex)
    override suspend fun banMember(groupId: String, agentIdHex: String) =
        inner.banMember(groupId, agentIdHex)
    override suspend fun renameGroup(groupId: String, newName: String) =
        inner.renameGroup(groupId, newName)
    override suspend fun conversationHistory(convKey: String): List<ChatHistoryMessageFfi> =
        inner.conversationHistory(convKey)
    override suspend fun createLinkOffer(ttlSecs: ULong): CreatedLinkOfferFfi =
        inner.createLinkOffer(ttlSecs)
    override suspend fun previewLinkOffer(uri: String): LinkOfferPreviewFfi =
        inner.previewLinkOffer(uri)
    override suspend fun nextEvent(): ChatEventFfi? = inner.nextEvent()
    override fun disconnect() = inner.disconnect()
}
