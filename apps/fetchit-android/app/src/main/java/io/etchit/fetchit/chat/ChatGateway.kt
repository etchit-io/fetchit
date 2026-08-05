package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi
import uniffi.fetchit_ffi.ChatHistoryMessageFfi
import uniffi.fetchit_ffi.CreatedLinkOfferFfi
import uniffi.fetchit_ffi.GroupFfi
import uniffi.fetchit_ffi.GroupMemberFfi
import uniffi.fetchit_ffi.JoinOutcomeFfi
import uniffi.fetchit_ffi.LinkOfferPreviewFfi
import uniffi.fetchit_ffi.LookupFfi
import uniffi.fetchit_ffi.MintOutcomeFfi
import uniffi.fetchit_ffi.MintStateFfi
import uniffi.fetchit_ffi.OutboxBubbleFfi
import uniffi.fetchit_ffi.EnsureV2Ffi
import uniffi.fetchit_ffi.FediFollowingFfi
import uniffi.fetchit_ffi.FediPostFfi
import uniffi.fetchit_ffi.UnfollowReportFfi
import uniffi.fetchit_ffi.FediDmReportFfi
import uniffi.fetchit_ffi.FediPersonLinkFfi
import uniffi.fetchit_ffi.FediProfileFfi
import uniffi.fetchit_ffi.FediThreadSummaryFfi
import uniffi.fetchit_ffi.GoPrivateReportFfi
import uniffi.fetchit_ffi.FollowReportFfi
import uniffi.fetchit_ffi.PublishReportFfi

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

    /**
     * Flip the embedded daemon's mesh mode (see [MeshPolicy]): `true` =
     * full public mesh (foreground), `false` = daemon up but mesh parked
     * (background; inbound rides the relay). Idempotent on the FFI side.
     * Default no-op so test fakes without a daemon stay valid.
     */
    suspend fun setMeshActive(active: Boolean) {}

    /**
     * Reconnect the relay session in place after a network-identity
     * change -- the fresh session is verified live before the old one is
     * drained, so a thrown error means the existing session is intact and
     * the caller may fall back to a full rebuild. Default no-op so test
     * fakes stay valid.
     */
    suspend fun reconnectRelay() {}

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
     * Durable join: like [joinGroup] but a join that cannot converge now
     * (owner offline) returns [JoinOutcomeFfi.Pending] the resume pump
     * completes when the owner is next reachable -- never a hard error, never
     * a re-spent invite. Call [drivePendingJoins] on a timer to advance
     * pending joins; [pendingJoins] lists the ones still in flight.
     */
    suspend fun joinGroupDurable(invite: String, displayName: String?): JoinOutcomeFfi

    /** Group ids with a durable join still in progress (draw "joining…"). */
    fun pendingJoins(): List<String>

    /**
     * Advance every due durable join one step; returns the group ids STILL
     * pending after this pass, so a timer can refresh badges and detect
     * convergence (a group leaving the set). Idempotent; a no-op when nothing
     * is pending, and never a second `join_post`.
     */
    suspend fun drivePendingJoins(): List<String>

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
     * The active minted fediverse @handle, or `null` when the user has not
     * opted in to public posting. Local vault read (no network), safe to call
     * before anything connects — drives the onboarding gate.
     */
    fun fediActorStatus(): String?

    /**
     * How the directory answered the last mint attempt, or `null` when none
     * was made. Local vault read (no network) that survives a restart, so a
     * name the directory refused is still visible on a cold start.
     */
    fun fediMintState(): MintStateFfi?

    /**
     * Opt in to public posting: mint the actor identity for [handle] and
     * register it with the directory. One-tap on a fresh identity — the engine
     * publishes a minimal handle-only profile when none exists yet, so no
     * pre-published profile is required. Directory-registration failure is
     * reported in the result, not thrown — including
     * [uniffi.fetchit_ffi.MintRegistrationFfi.NameTaken], which no retry can
     * clear.
     */
    suspend fun fediMint(handle: String): MintOutcomeFfi

    /**
     * Resolve a fediverse `@local@instance` handle to a contact card:
     * [uniffi.fetchit_ffi.LookupKindFfi.VERIFIED] carries the chat agent id +
     * a `shareUri` so the user can message them privately (post-quantum),
     * `PUBLIC_ONLY` found the account but couldn't confirm the person, and
     * `NOT_FOUND` resolved to nobody. Needs a live connection (hits the
     * directory + the person's relay). A malformed handle throws.
     */
    suspend fun fediLookup(handle: String): LookupFfi

    /**
     * Publish [bodyMd] publicly as the minted @handle. The engine resolves
     * `@user@host` mentions, runs denylist gating, and delivers best-effort;
     * the report lists accepted + failed inboxes. Throws when no handle is
     * minted yet — gate the compose affordance on
     * [fediActorStatus] instead of letting that surface.
     */
    suspend fun fediPublish(bodyMd: String, replyToActorUrl: String?): PublishReportFfi

    /** Follow a remote fediverse account (`@user@instance`) from the minted handle. */
    suspend fun fediFollow(target: String): FollowReportFfi

    /**
     * Send a plaintext fediverse DM (`@user@instance`) from the minted
     * handle. Not end-to-end encrypted — the UI shows the unencrypted-thread
     * banner and offers escalation to PQ chat.
     */
    suspend fun fediDm(target: String, body: String): FediDmReportFfi

    /**
     * Re-run the fediverse actor upgrade + re-register pass for an
     * already-minted handle (idempotent, reuses the existing identity).
     * Self-heals the bridge registration after a bridge redeploy or a fresh
     * device leaves the local handle minted but unregistered. A no-op when
     * no handle is minted.
     */
    suspend fun fediEnsureV2(): EnsureV2Ffi

    /**
     * The accounts the minted handle follows, from the directory's
     * owner-only list. Throws when no handle is minted or the directory
     * is unreachable.
     */
    suspend fun fediFollowing(): List<FediFollowingFfi>

    /**
     * Unfollow a fediverse account by its actor URL: the device signs +
     * delivers the `Undo(Follow)` and the directory drops its record.
     */
    suspend fun fediUnfollow(targetActorUrl: String): UnfollowReportFfi

    /**
     * Pull the read feed: newest text posts from followed accounts,
     * merged newest-first. Per-account failures are skipped engine-side;
     * an empty list is a valid (quiet) feed.
     */
    suspend fun fediFeed(): List<FediPostFfi>

    /**
     * Fetch any fediverse account's profile for the profile sheet.
     * [target] accepts `@user@host`, `user@host`, or an actor URL, so a
     * tapped author chip and a tapped @-mention take the same path.
     *
     * Deliberately NOT gated on a minted handle: reading a public
     * profile is a read. The ACTIONS on the sheet still gate.
     */
    suspend fun fediProfile(target: String): FediProfileFfi

    /**
     * Like the post [objectUrl] authored by [authorUrl]. Returns whether
     * the author's inbox accepted the activity — a false is not a
     * failure to act on, the like is recorded either way. Throws when no
     * handle is minted or the author is blocked.
     */
    suspend fun fediLike(objectUrl: String, authorUrl: String): Boolean

    /** Undo a like of [objectUrl]. Mirrors [fediLike]. */
    suspend fun fediUnlike(objectUrl: String, authorUrl: String): Boolean

    /**
     * Sync inbound fediverse replies from the bridge inbox into the
     * engine's durable thread store. The engine owns the cursor and
     * persists messages + cursor in one atomic save, so nothing can be
     * skipped or lost to a process death. Returns how many messages
     * were new; render threads via [conversationHistory] with an
     * `f:<handle>` conversation key.
     */
    suspend fun fediSyncInbox(): UInt

    /**
     * Every fediverse DM thread as a one-line summary for the unified
     * conversation list, newest first. Empty when no handle is minted
     * (quiet — never throws for that).
     */
    suspend fun fediThreadsOverview(): List<FediThreadSummaryFfi>

    /**
     * Mark the fediverse DM thread with [label] read up to its newest
     * message: the row's unread count clears, and stays clear across
     * restarts (the engine seals the read mark next to the messages).
     * Returns true when the mark moved. Quiet no-op without a minted
     * handle; the default no-op keeps test doubles simple.
     */
    suspend fun fediMarkThreadRead(label: String): Boolean = false

    /**
     * Cached profile-picture bytes for the fediverse correspondent [label],
     * or null when nothing is cached.
     *
     * The engine fetched these behind its SSRF guard (https only, image
     * content-types only, 512 KiB cap) and never decoded them — decoding is
     * the platform's job, bounds-checked, in [FediAvatars]. A null is not
     * final: it asks the engine to fetch in the background, so a later call
     * for the same label can succeed. Never throws; an avatar is decoration
     * and every fedi surface renders identically without one. The default
     * no-op keeps test doubles simple.
     */
    fun fediAvatar(label: String): ByteArray? = null

    /**
     * Cached profile-picture bytes for [label] with no side effects at all:
     * a disk read that returns. No background fetch, no refresh cadence, no
     * failure backoff.
     *
     * This is the only avatar call a private (LIT) surface may make. A LIT
     * contact whose person is linked to a fediverse identity reuses that
     * picture, and drawing that row must stay unobservable: if it could
     * fetch, the arrival of a private message would show up as a request in
     * a fediverse server's access log, correlating fetch timing with
     * end-to-end encrypted activity. A stale face is fine — the fediverse
     * surfaces call [fediAvatar] and keep the cache warm.
     */
    fun fediAvatarCached(label: String): ByteArray? = null

    /**
     * Publish [bytes] as the user's own profile picture.
     *
     * The bytes must already be the final image — [ProfilePicture.prepare]
     * crops, downscales and RE-ENCODES the photo the user picked, which is
     * what strips its EXIF. Nothing below this call rewrites the image, so
     * whatever metadata is still in it goes out with it.
     *
     * Throws when no handle is minted, the image fails the format/size
     * checks, or the bridge refuses the upload.
     */
    suspend fun fediSetAvatar(bytes: ByteArray, contentType: String) {}

    /** Remove the user's own profile picture. Throws on failure. */
    suspend fun fediClearAvatar() {}

    /**
     * The user's own picture, or null when they have not set one. Reads
     * the local copy the set path wrote — never fetches, so the LIT
     * surfaces may draw it (see [fediAvatarCached] for why that matters).
     */
    fun fediSelfAvatar(): ByteArray? = null

    /**
     * The `@user@host` labels of accounts following the minted handle,
     * newest first. Throws when no handle is minted or the directory is
     * unreachable.
     */
    suspend fun fediFollowers(): List<String>

    /** Group ids currently in stale-epoch catch-up (#297 P1.4). */
    fun reconnectingGroups(): List<String> = emptyList()

    /**
     * Send a "go private" invite to [target] over the fediverse: it carries
     * this device's pair link plus an install nudge. Records the pending
     * invite only on delivery. Throws when no handle is minted.
     */
    suspend fun fediGoPrivateInvite(target: String, displayName: String): GoPrivateReportFfi

    /** Fediverse handles invited to private chat but not yet linked. */
    fun fediPendingInvites(): List<String>

    /**
     * Link [target] (fediverse label) to a PQ [agentIdHex] — the manual
     * "Same person?" confirm. Local only; never published.
     */
    fun fediLinkPerson(target: String, agentIdHex: String)

    /** Drop the link for [target]. */
    fun fediUnlinkPerson(target: String)

    /** Every fediverse↔LIT person link. */
    fun fediPersonLinks(): List<FediPersonLinkFfi>

    /** The fediverse label linked to [agentIdHex], if any (reverse lookup). */
    fun fediLinkedLabelForAgent(agentIdHex: String): String?

    /**
     * Remove the contact [agentIdHex] (64-hex agent id) from the engine,
     * dropping its conversation. The caller clears any local UI/store state.
     */
    suspend fun removeContact(agentIdHex: String)

    /**
     * Leave the group [groupId]; rejoining needs a fresh invite. Self-removal
     * only -- the group continues. Throws when the daemon refuses, notably the
     * last admin (a sole member always is one): use [deleteGroup] instead.
     */
    suspend fun leaveGroup(groupId: String)

    /**
     * Delete the group [groupId] for everyone (terminal withdrawal commit).
     * Admin-or-above only; the daemon authorizes. Irreversible.
     */
    suspend fun deleteGroup(groupId: String)

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
     * Messages waiting in the conversation [convKey] names — the count its
     * row badges. Same key scheme as [conversationHistory]; counted against
     * the engine's durable read mark, so a badge survives a process kill.
     * Our own sends never count. Zero for an unknown conversation; the
     * default no-op keeps test doubles simple.
     */
    suspend fun conversationUnread(convKey: String): UInt = 0u

    /**
     * Mark the conversation [convKey] names read up to its newest message:
     * the row's unread count clears, and stays clear across restarts (the
     * engine seals the mark next to the transcript). Returns true when the
     * mark moved. Quiet no-op default, mirroring [fediMarkThreadRead].
     */
    suspend fun conversationMarkRead(convKey: String): Boolean = false

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
    override suspend fun setMeshActive(active: Boolean) = inner.setMeshActive(active)

    override suspend fun reconnectRelay() = inner.reconnectRelay()

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
    override suspend fun joinGroupDurable(invite: String, displayName: String?): JoinOutcomeFfi =
        inner.joinGroupDurable(invite, displayName)
    override fun pendingJoins(): List<String> = inner.pendingJoins()
    override suspend fun drivePendingJoins(): List<String> = inner.drivePendingJoinsOnce()
    override suspend fun sendGroupMessage(groupId: String, body: String, senderName: String): String? =
        // The regenerated bindings return a richer GroupSendReceiptFfi
        // (messageId + delivered); the gateway keeps its String? message-id
        // contract, so extract the id here. Surfacing `delivered` is a separate
        // group-send task, not M6.4.
        inner.sendGroupMessage(groupId, body, senderName).messageId
    override suspend fun listGroups(): List<GroupFfi> = inner.listGroups()
    override suspend fun groupInvite(groupId: String): String = inner.groupInvite(groupId)
    override fun fediActorStatus(): String? = inner.fediActorStatus()
    override fun fediMintState(): MintStateFfi? = inner.fediMintState()
    override suspend fun fediMint(handle: String): MintOutcomeFfi = inner.fediMint(handle)
    override suspend fun fediLookup(handle: String): LookupFfi = inner.fediLookup(handle)
    override suspend fun fediPublish(bodyMd: String, replyToActorUrl: String?): PublishReportFfi =
        inner.fediPublish(bodyMd, replyToActorUrl)

    override suspend fun fediFollow(target: String): FollowReportFfi = inner.fediFollow(target)
    override suspend fun fediDm(target: String, body: String): FediDmReportFfi =
        inner.fediDm(target, body)
    override suspend fun fediEnsureV2(): EnsureV2Ffi = inner.fediEnsureV2()
    override suspend fun fediFollowing(): List<FediFollowingFfi> = inner.fediFollowing()
    override suspend fun fediUnfollow(targetActorUrl: String): UnfollowReportFfi =
        inner.fediUnfollow(targetActorUrl)
    override suspend fun fediFeed(): List<FediPostFfi> = inner.fediFeed()
    override suspend fun fediProfile(target: String): FediProfileFfi = inner.fediProfile(target)
    override suspend fun fediLike(objectUrl: String, authorUrl: String): Boolean =
        inner.fediLike(objectUrl, authorUrl)
    override suspend fun fediUnlike(objectUrl: String, authorUrl: String): Boolean =
        inner.fediUnlike(objectUrl, authorUrl)
    override suspend fun fediSyncInbox(): UInt = inner.fediSyncInbox()
    override suspend fun fediThreadsOverview(): List<FediThreadSummaryFfi> =
        inner.fediThreadsOverview()
    override suspend fun fediMarkThreadRead(label: String): Boolean =
        inner.fediMarkThreadRead(label)
    override fun fediAvatar(label: String): ByteArray? = inner.fediAvatar(label)
    override fun fediAvatarCached(label: String): ByteArray? = inner.fediAvatarCached(label)
    override suspend fun fediSetAvatar(bytes: ByteArray, contentType: String) =
        inner.fediSetAvatar(bytes, contentType)
    override suspend fun fediClearAvatar() = inner.fediClearAvatar()
    override fun fediSelfAvatar(): ByteArray? = inner.fediSelfAvatar()
    override suspend fun fediFollowers(): List<String> = inner.fediFollowers()

    override fun reconnectingGroups(): List<String> = inner.reconnectingGroups()
    override suspend fun fediGoPrivateInvite(target: String, displayName: String): GoPrivateReportFfi =
        inner.fediGoPrivateInvite(target, displayName)
    override fun fediPendingInvites(): List<String> = inner.fediPendingInvites()
    override fun fediLinkPerson(target: String, agentIdHex: String) =
        inner.fediLinkPerson(target, agentIdHex)
    override fun fediUnlinkPerson(target: String) = inner.fediUnlinkPerson(target)
    override fun fediPersonLinks(): List<FediPersonLinkFfi> = inner.fediPersonLinks()
    override fun fediLinkedLabelForAgent(agentIdHex: String): String? =
        inner.fediLinkedLabelForAgent(agentIdHex)
    override suspend fun removeContact(agentIdHex: String) = inner.removeContact(agentIdHex)
    override suspend fun leaveGroup(groupId: String) = inner.leaveGroup(groupId)
    override suspend fun deleteGroup(groupId: String) = inner.deleteGroup(groupId)
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
    override suspend fun conversationUnread(convKey: String): UInt =
        inner.conversationUnread(convKey)
    override suspend fun conversationMarkRead(convKey: String): Boolean =
        inner.conversationMarkRead(convKey)
    override suspend fun createLinkOffer(ttlSecs: ULong): CreatedLinkOfferFfi =
        inner.createLinkOffer(ttlSecs)
    override suspend fun previewLinkOffer(uri: String): LinkOfferPreviewFfi =
        inner.previewLinkOffer(uri)
    override suspend fun nextEvent(): ChatEventFfi? = inner.nextEvent()
    override fun disconnect() = inner.disconnect()
}
