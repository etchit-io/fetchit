package io.etchit.fetchit.chat

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.fetchit_ffi.ChatAttachmentFfi
import uniffi.fetchit_ffi.ChatEventFfi
import uniffi.fetchit_ffi.ChatHistoryMessageFfi
import uniffi.fetchit_ffi.CreatedLinkOfferFfi
import uniffi.fetchit_ffi.GroupFfi
import uniffi.fetchit_ffi.GroupMemberFfi
import uniffi.fetchit_ffi.JoinOutcomeFfi
import uniffi.fetchit_ffi.LinkOfferPreviewFfi
import uniffi.fetchit_ffi.EnsureV2Ffi
import uniffi.fetchit_ffi.FediDmReportFfi
import uniffi.fetchit_ffi.FediFollowingFfi
import uniffi.fetchit_ffi.FediPostFfi
import uniffi.fetchit_ffi.FediPersonLinkFfi
import uniffi.fetchit_ffi.FediProfileFfi
import uniffi.fetchit_ffi.FediThreadSummaryFfi
import uniffi.fetchit_ffi.GoPrivateReportFfi
import uniffi.fetchit_ffi.FollowReportFfi
import uniffi.fetchit_ffi.UnfollowReportFfi
import uniffi.fetchit_ffi.LookupFfi
import uniffi.fetchit_ffi.LookupKindFfi
import uniffi.fetchit_ffi.MintOutcomeFfi
import uniffi.fetchit_ffi.MintRegistrationFfi
import uniffi.fetchit_ffi.MintStateFfi
import uniffi.fetchit_ffi.OutboxBubbleFfi
import uniffi.fetchit_ffi.SendStateFfi
import uniffi.fetchit_ffi.PublishReportFfi

/** Regex-based HTML stripper used in place of [android.text.Html.fromHtml] so these tests run on the plain JVM. */
private fun stripHtml(html: String): String =
    html.replace(Regex("<[^>]+>"), "").trim()

class FakeGateway : ChatGateway {
    val events = Channel<ChatEventFfi?>(capacity = 8)
    val enqueued = mutableListOf<Triple<String, String, String>>()

    /** Attachment passed with each [enqueueDm], positionally paired with [enqueued]. */
    val enqueuedAttachments = mutableListOf<ChatAttachment?>()
    var startedOutbox: String? = null
    var retried = 0
    var snapshot: List<OutboxBubbleFfi> = emptyList()

    // Group surface recorders (delegation assertions).
    val createdGroups = mutableListOf<Triple<String, String?, Boolean>>()
    val joinedGroups = mutableListOf<Pair<String, String?>>()
    val sentGroupMessages = mutableListOf<Triple<String, String, String>>()
    val invitesRequested = mutableListOf<String>()
    var groups: List<GroupFfi> = emptyList()
    var pendingJoinIds: List<String> = emptyList()

    // Remove / leave recorders (delegation assertions). When set, the matching
    // throw lets a test exercise the swallow-the-failure path.
    val removedContacts = mutableListOf<String>()
    val leftGroups = mutableListOf<String>()
    val deletedGroups = mutableListOf<String>()
    var deleteGroupThrows = false
    var removeContactThrows = false
    var leaveGroupThrows = false

    // Member-list + moderation recorders. `members` is the roster groupMembers
    // returns; the *Throws flags exercise the report-then-refresh seam.
    var members: List<GroupMemberFfi> = emptyList()
    val removedMembers = mutableListOf<Pair<String, String>>()
    val bannedMembers = mutableListOf<Pair<String, String>>()
    val renamedGroups = mutableListOf<Pair<String, String>>()
    var groupMembersThrows = false
    var removeMemberThrows = false
    var banMemberThrows = false
    var renameGroupThrows = false

    // Persisted-history recorder. `history` is the transcript conversationHistory
    // returns, keyed by conv key; requestedHistory records the lookups; the
    // throws flag exercises the non-fatal hydrate path.
    var history: Map<String, List<ChatHistoryMessageFfi>> = emptyMap()
    val requestedHistory = mutableListOf<String>()
    var conversationHistoryThrows = false
    var fediHandle: String? = null
    var mintState: MintStateFfi? = null
    val mintedHandles = mutableListOf<String>()
    val lookedUpHandles = mutableListOf<String>()
    var lookupResult: LookupFfi =
        LookupFfi(LookupKindFfi.NOT_FOUND, "", "", null, null, null, null, null)
    val publishedPosts = mutableListOf<Pair<String, String?>>()

    override fun agentIdHex() = "f".repeat(64)
    override fun pairPublishOutcome(): String? = "ok"
    override suspend fun pairShareUri() = "x0x://pair/${"f".repeat(64)}?r=relay"
    override suspend fun importPairUri(uri: String) {}
    override suspend fun enqueueDm(
        to: String,
        body: String,
        senderName: String,
        attachment: ChatAttachment?,
    ): String {
        enqueued += Triple(to, body, senderName)
        enqueuedAttachments += attachment
        return "outbox-${enqueued.size}"
    }
    override fun startOutbox(displayName: String) { startedOutbox = displayName }
    override suspend fun outboxSnapshot(): List<OutboxBubbleFfi> = snapshot
    override fun retryOutbox() { retried++ }
    override suspend fun createGroup(name: String, displayName: String?, private: Boolean): GroupFfi {
        createdGroups += Triple(name, displayName, private)
        return GroupFfi("c".repeat(64), name, 1uL, isOwner = true, isPrivate = private)
    }
    override suspend fun joinGroup(invite: String, displayName: String?): GroupFfi {
        joinedGroups += (invite to displayName)
        return GroupFfi("d".repeat(64), null, 2uL, isOwner = false, isPrivate = true)
    }
    override suspend fun joinGroupDurable(invite: String, displayName: String?): JoinOutcomeFfi {
        joinedGroups += (invite to displayName)
        return JoinOutcomeFfi.Converged(
            GroupFfi("d".repeat(64), null, 2uL, isOwner = false, isPrivate = true),
        )
    }
    override fun pendingJoins(): List<String> = pendingJoinIds
    override suspend fun drivePendingJoins(): List<String> = pendingJoinIds
    override suspend fun sendGroupMessage(groupId: String, body: String, senderName: String): String? {
        sentGroupMessages += Triple(groupId, body, senderName); return "gm-${sentGroupMessages.size}"
    }
    override suspend fun listGroups(): List<GroupFfi> = groups
    override suspend fun groupInvite(groupId: String): String {
        invitesRequested += groupId; return "x0x://invite/$groupId"
    }
    override fun fediActorStatus(): String? = fediHandle
    override fun fediMintState(): MintStateFfi? = mintState
    override suspend fun fediMint(handle: String): MintOutcomeFfi {
        mintedHandles += handle
        fediHandle = handle
        return MintOutcomeFfi(
            "https://etchit.io/actors/$handle",
            MintRegistrationFfi.Registered,
        )
    }
    override suspend fun fediLookup(handle: String): LookupFfi {
        lookedUpHandles += handle
        return lookupResult
    }
    override suspend fun fediPublish(bodyMd: String, replyToActorUrl: String?): PublishReportFfi {
        publishedPosts += (bodyMd to replyToActorUrl)
        return PublishReportFfi(delivered = emptyList(), failed = emptyList())
    }

    override suspend fun fediFollow(target: String): FollowReportFfi =
        FollowReportFfi(
            targetActorUrl = target,
            followActivityId = "test-follow-id",
            delivered = true,
            recorded = true,
        )
    override suspend fun fediDm(target: String, body: String): FediDmReportFfi =
        FediDmReportFfi(
            recipientActorUrl = target,
            noteId = "test-note-id",
            delivered = true,
        )
    override suspend fun fediEnsureV2(): EnsureV2Ffi =
        EnsureV2Ffi(
            upgraded = false,
            registration = MintRegistrationFfi.Registered,
            pending = null,
        )
    override suspend fun fediFollowing(): List<FediFollowingFfi> = emptyList()
    override suspend fun fediUnfollow(targetActorUrl: String): UnfollowReportFfi =
        UnfollowReportFfi(delivered = true, removed = true)
    override suspend fun fediFeed(): List<FediPostFfi> = emptyList()
    override suspend fun fediProfile(target: String): FediProfileFfi =
        FediProfileFfi(target, target, null, "", null)
    override suspend fun fediLike(objectUrl: String, authorUrl: String): Boolean = true
    override suspend fun fediUnlike(objectUrl: String, authorUrl: String): Boolean = true
    override suspend fun fediSyncInbox(): UInt = 0u
    override suspend fun fediThreadsOverview(): List<FediThreadSummaryFfi> = emptyList()
    override suspend fun fediFollowers(): List<String> = emptyList()
    override suspend fun fediGoPrivateInvite(target: String, displayName: String): GoPrivateReportFfi =
        GoPrivateReportFfi(delivered = true)
    override fun fediPendingInvites(): List<String> = emptyList()
    override fun fediLinkPerson(target: String, agentIdHex: String) {}
    override fun fediUnlinkPerson(target: String) {}
    override fun fediPersonLinks(): List<FediPersonLinkFfi> = emptyList()
    override fun fediLinkedLabelForAgent(agentIdHex: String): String? = null
    override suspend fun removeContact(agentIdHex: String) {
        removedContacts += agentIdHex
        if (removeContactThrows) throw RuntimeException("remove boom")
    }
    override suspend fun leaveGroup(groupId: String) {
        leftGroups += groupId
        if (leaveGroupThrows) throw RuntimeException("leave boom")
    }
    override suspend fun deleteGroup(groupId: String) {
        deletedGroups += groupId
        if (deleteGroupThrows) throw RuntimeException("delete boom")
    }
    override suspend fun groupMembers(groupId: String): List<GroupMemberFfi> {
        if (groupMembersThrows) throw RuntimeException("members boom")
        return members
    }
    override suspend fun removeMember(groupId: String, agentIdHex: String) {
        removedMembers += (groupId to agentIdHex)
        if (removeMemberThrows) throw RuntimeException("remove member boom")
    }
    override suspend fun banMember(groupId: String, agentIdHex: String) {
        bannedMembers += (groupId to agentIdHex)
        if (banMemberThrows) throw RuntimeException("ban boom")
    }
    override suspend fun renameGroup(groupId: String, newName: String) {
        renamedGroups += (groupId to newName)
        if (renameGroupThrows) throw RuntimeException("rename boom")
    }
    override suspend fun conversationHistory(convKey: String): List<ChatHistoryMessageFfi> {
        requestedHistory += convKey
        if (conversationHistoryThrows) throw RuntimeException("history boom")
        return history[convKey].orEmpty()
    }

    // Device-link recorders (M6.4). `linkOfferTtls` records createLinkOffer
    // requests; `previewedLinkUris` records previewLinkOffer lookups; the canned
    // returns let a caller drive the offer/preview dialogs without a relay.
    val linkOfferTtls = mutableListOf<ULong>()
    val previewedLinkUris = mutableListOf<String>()
    var linkPreviewExpired = false
    override suspend fun createLinkOffer(ttlSecs: ULong): CreatedLinkOfferFfi {
        linkOfferTtls += ttlSecs
        return CreatedLinkOfferFfi("fetchit://link/v1/offer", "ABCD-EFGH-JKLM", 0uL)
    }
    override suspend fun previewLinkOffer(uri: String): LinkOfferPreviewFfi {
        previewedLinkUris += uri
        return LinkOfferPreviewFfi("a".repeat(64), "ABCD-EFGH-JKLM", linkPreviewExpired)
    }
    override suspend fun nextEvent(): ChatEventFfi? = events.receive()
    override fun disconnect() { events.trySend(null) }
}

class ChatControllerTest {
    @Test
    fun inboundDmLandsInConversation() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Dm("a".repeat(64), "hello", "m9", null))
        gw.events.send(null) // pump exits on null
        pump.join()
        assertEquals("hello", convo.messagesFor("a".repeat(64)).value.single().body)
    }

    @Test
    fun inboundDmCarriesItsInlineImage() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val peer = "a".repeat(64)
        val bytes = ByteArray(64) { 0x7f }
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(
            ChatEventFfi.Dm(
                peer,
                "",
                "m-att",
                ChatAttachmentFfi("image/jpeg", 640u, 480u, bytes),
            ),
        )
        gw.events.send(null)
        pump.join()
        val msg = convo.messagesFor(peer).value.single()
        // An image with no words is a message: empty body, image present.
        assertEquals("", msg.body)
        val att = msg.attachment!!
        assertEquals("image/jpeg", att.mime)
        assertEquals(640, att.width)
        assertEquals(480, att.height)
        assertTrue(bytes.contentEquals(att.bytes))
    }

    @Test
    fun inboundImageOnlyDmNotifiesWithTheGivenPhotoLabel() = runTest {
        val gw = FakeGateway()
        val seen = mutableListOf<String>()
        val pump = ChatController.pumpEvents(
            gw,
            ConversationStore(),
            feed = FeedStore(),
            scope = this,
            htmlStripper = ::stripHtml,
            onInbound = { seen += it.body },
            photoLabel = "Photo",
        )
        gw.events.send(
            ChatEventFfi.Dm(
                "a".repeat(64),
                "   ",
                "m-att",
                ChatAttachmentFfi("image/png", 8u, 8u, ByteArray(4)),
            ),
        )
        gw.events.send(ChatEventFfi.Dm("a".repeat(64), "words", "m-txt", null))
        gw.events.send(null)
        pump.join()
        // A blank body with a picture is announced as a photo; text is
        // announced as itself.
        assertEquals(listOf("Photo", "words"), seen)
    }

    @Test
    fun hydratedHistoryCarriesItsInlineImage() = runTest {
        val bytes = ByteArray(32) { 0x11 }
        val rows = ChatController.historyToMessages(
            listOf(
                historyMsg(
                    body = "",
                    sentAtMs = 5L,
                    messageId = "h-att",
                    outbound = true,
                    attachment = ChatAttachmentFfi("image/webp", 100u, 200u, bytes),
                ),
                historyMsg(body = "plain", sentAtMs = 6L, messageId = "h-txt"),
            ),
        )
        val att = rows[0].attachment!!
        assertEquals("image/webp", att.mime)
        assertEquals(100, att.width)
        assertEquals(200, att.height)
        assertTrue(bytes.contentEquals(att.bytes))
        assertNull("a text-only entry has no image", rows[1].attachment)
    }

    @Test
    fun inboundGroupMessageLandsInGroupConversation() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        val gid = "c".repeat(64)
        gw.events.send(
            ChatEventFfi.GroupMessage(
                groupId = gid,
                fromAgentIdHex = "a".repeat(64),
                senderName = "alice",
                body = "group hi",
                messageId = "gm1",
            ),
        )
        gw.events.send(null)
        pump.join()
        // Lands on the "g:" group key, NOT the bare sender-hex DM key.
        val msg = convo.messagesFor(ConversationStore.convKeyGroup(gid)).value.single()
        assertEquals("group hi", msg.body)
        assertEquals(false, msg.outbound)
        assertEquals("a".repeat(64), msg.senderAgentIdHex)
        // A DM keyed by the sender hex must be untouched (no collision).
        assertTrue(convo.messagesFor("a".repeat(64)).value.isEmpty())
    }

    @Test
    fun gatewayDelegatesGroupCalls() = runTest {
        val gw = FakeGateway()
        val created = gw.createGroup("team", "alice", private = true)
        assertEquals(Triple("team", "alice", true), gw.createdGroups.single())
        assertEquals("c".repeat(64), created.groupId)

        val joined = gw.joinGroup("x0x://invite/abc", "bob")
        assertEquals("x0x://invite/abc" to "bob", gw.joinedGroups.single())
        assertEquals(false, joined.isOwner)

        val id = gw.sendGroupMessage("g".repeat(64), "yo", "alice")
        assertEquals(Triple("g".repeat(64), "yo", "alice"), gw.sentGroupMessages.single())
        assertEquals("gm-1", id)

        val invite = gw.groupInvite("g".repeat(64))
        assertEquals("g".repeat(64), gw.invitesRequested.single())
        assertEquals("x0x://invite/${"g".repeat(64)}", invite)

        gw.groups = listOf(GroupFfi("h".repeat(64), "team", 3uL, isOwner = true, isPrivate = true))
        assertEquals("team", gw.listGroups().single().name)
    }

    @Test
    fun removeContactDelegatesToGatewayThenDropsLocal() = runTest {
        val gw = FakeGateway()
        var dropped: String? = null
        ChatController.removeContactVia(gw, "a".repeat(64), logWarn = { _, _ -> }) {
            dropped = "a".repeat(64)
        }
        // Engine forget happened, then the local drop ran.
        assertEquals("a".repeat(64), gw.removedContacts.single())
        assertEquals("a".repeat(64), dropped)
    }

    @Test
    fun removeContactDropsLocalEvenWhenGatewayFails() = runTest {
        val gw = FakeGateway().apply { removeContactThrows = true }
        var dropped = false
        ChatController.removeContactVia(gw, "a".repeat(64), logWarn = { _, _ -> }) {
            dropped = true
        }
        // The engine call was attempted (recorded) and threw, but the local
        // drop still ran — the user-visible removal must not depend on the relay.
        assertEquals("a".repeat(64), gw.removedContacts.single())
        assertTrue(dropped)
    }

    @Test
    fun removeContactDropsLocalWhenNotConnected() = runTest {
        var dropped = false
        ChatController.removeContactVia(gw = null, agentIdHex = "a".repeat(64)) {
            dropped = true
        }
        assertTrue(dropped)
    }

    @Test
    fun leaveGroupDelegatesToGatewayThenRefreshes() = runTest {
        val gw = FakeGateway()
        var refreshed = false
        ChatController.leaveGroupVia(gw, "g".repeat(64), logWarn = { _, _ -> }) {
            refreshed = true
        }
        assertEquals("g".repeat(64), gw.leftGroups.single())
        assertTrue(refreshed)
    }

    @Test
    fun leaveGroupRefreshesThenRETHROWSWhenTheDaemonRefuses() = runTest {
        // The daemon rejects a last-admin leave and the row legitimately
        // stays. Swallowing here is what let the UI claim "left <group>"
        // over a group that never went anywhere: reconcile, then rethrow.
        val gw = FakeGateway().apply { leaveGroupThrows = true }
        var refreshed = false
        var thrown: Throwable? = null
        try {
            ChatController.leaveGroupVia(gw, "g".repeat(64), logWarn = { _, _ -> }) {
                refreshed = true
            }
        } catch (e: RuntimeException) {
            thrown = e
        }
        assertEquals("g".repeat(64), gw.leftGroups.single())
        assertTrue(refreshed)
        assertEquals("leave boom", thrown?.message)
    }

    @Test
    fun deleteGroupDelegatesToGatewayThenRefreshes() = runTest {
        val gw = FakeGateway()
        var refreshed = false
        ChatController.deleteGroupVia(gw, "g".repeat(64)) { refreshed = true }
        assertEquals("g".repeat(64), gw.deletedGroups.single())
        assertTrue(refreshed)
    }

    @Test
    fun deleteGroupPropagatesARefusalAndSkipsTheRefresh() = runTest {
        // A refused delete (403 when not an admin) must reach the user, never
        // read as "deleted".
        val gw = FakeGateway().apply { deleteGroupThrows = true }
        var refreshed = false
        var thrown: Throwable? = null
        try {
            ChatController.deleteGroupVia(gw, "g".repeat(64)) { refreshed = true }
        } catch (e: RuntimeException) {
            thrown = e
        }
        assertEquals("delete boom", thrown?.message)
        assertFalse(refreshed)
    }

    @Test
    fun leaveGroupNoOpsWhenNotConnected() = runTest {
        var refreshed = false
        ChatController.leaveGroupVia(gw = null, groupId = "g".repeat(64)) {
            refreshed = true
        }
        // No gateway: nothing to leave and no refresh.
        assertTrue(!refreshed)
    }

    @Test
    fun rowRemoveLabelIsKindAware() {
        // Group rows leave; contact rows remove. Pure res-id mapping, no Context.
        assertEquals(io.etchit.fetchit.R.string.chat_leave_group, rowRemoveLabel(isGroup = true))
        assertEquals(io.etchit.fetchit.R.string.chat_remove_chat, rowRemoveLabel(isGroup = false))
    }

    // ── group member list + moderation: pure helpers ───────────────────

    @Test
    fun memberDisplayNamePrefersWireThenContactThenShortHex() {
        val hex = "a".repeat(64)
        // Wire name wins.
        assertEquals("Ada", memberDisplayName("  Ada  ", "Saved", hex))
        // Blank wire -> saved contact name.
        assertEquals("Saved", memberDisplayName("   ", "Saved", hex))
        assertEquals("Saved", memberDisplayName(null, "Saved", hex))
        // Neither -> short hex with ellipsis.
        assertEquals("${"a".repeat(8)}…", memberDisplayName(null, "  ", hex))
        assertEquals("${"a".repeat(8)}…", memberDisplayName(null, null, hex))
    }

    @Test
    fun canModerateIsOwnerOrAdmin() {
        assertTrue(canModerate("owner"))
        assertTrue(canModerate("admin"))
        assertTrue(!canModerate("member"))
        assertTrue(!canModerate(null))
    }

    @Test
    fun canModerateMemberExcludesSelfOwnerAndNonModerators() {
        // Happy path: a moderator targeting an ordinary other member.
        assertTrue(canModerateMember(viewerCanModerate = true, isSelf = false, targetIsOwner = false))
        // A non-moderator viewer never sees the control.
        assertTrue(!canModerateMember(viewerCanModerate = false, isSelf = false, targetIsOwner = false))
        // Cannot moderate yourself.
        assertTrue(!canModerateMember(viewerCanModerate = true, isSelf = true, targetIsOwner = false))
        // Cannot target the owner (x0xd refuses; control is hidden to match).
        assertTrue(!canModerateMember(viewerCanModerate = true, isSelf = false, targetIsOwner = true))
    }

    @Test
    fun memberRoleTagOnlyForOwnerOrAdmin() {
        assertEquals("owner", memberRoleTag("owner"))
        assertEquals("admin", memberRoleTag("admin"))
        assertEquals(null, memberRoleTag("member"))
        assertEquals(null, memberRoleTag(null))
    }

    // ── group member list + moderation: controller seams ───────────────

    @Test
    fun groupMembersDelegatesAndReturnsRoster() = runTest {
        val gw = FakeGateway().apply {
            members = listOf(
                GroupMemberFfi("a".repeat(64), "Ada", "owner", isOwner = true, isAdmin = true),
            )
        }
        // The seam mirrors the controller body: gateway present -> delegate.
        assertEquals("Ada", gw.groupMembers("g".repeat(64)).single().displayName)
    }

    @Test
    fun removeMemberDelegatesThenRefreshes() = runTest {
        val gw = FakeGateway()
        var refreshed = false
        ChatController.moderateVia(
            gw,
            onError = { _ -> },
            action = { it.removeMember("g".repeat(64), "a".repeat(64)) },
            logWarn = { _, _ -> },
        ) { refreshed = true }
        assertEquals("g".repeat(64) to "a".repeat(64), gw.removedMembers.single())
        assertTrue(refreshed)
    }

    @Test
    fun banMemberDelegatesThenRefreshes() = runTest {
        val gw = FakeGateway()
        var refreshed = false
        ChatController.moderateVia(
            gw,
            onError = { _ -> },
            action = { it.banMember("g".repeat(64), "a".repeat(64)) },
            logWarn = { _, _ -> },
        ) { refreshed = true }
        assertEquals("g".repeat(64) to "a".repeat(64), gw.bannedMembers.single())
        assertTrue(refreshed)
    }

    @Test
    fun renameGroupDelegatesThenRefreshes() = runTest {
        val gw = FakeGateway()
        var refreshed = false
        ChatController.moderateVia(
            gw,
            onError = { _ -> },
            action = { it.renameGroup("g".repeat(64), "new name") },
            logWarn = { _, _ -> },
        ) { refreshed = true }
        assertEquals("g".repeat(64) to "new name", gw.renamedGroups.single())
        assertTrue(refreshed)
    }

    @Test
    fun moderationFailureIsReportedNotSwallowedAndStillRefreshes() = runTest {
        val gw = FakeGateway().apply { removeMemberThrows = true }
        var reported: Throwable? = null
        var refreshed = false
        ChatController.moderateVia(
            gw,
            onError = { e -> reported = e },
            action = { it.removeMember("g".repeat(64), "a".repeat(64)) },
            logWarn = { _, _ -> },
        ) { refreshed = true }
        // x0xd is the authority: the rejection surfaces via onError (NOT
        // swallowed), and the refresh still runs to reconcile the list.
        assertEquals("g".repeat(64) to "a".repeat(64), gw.removedMembers.single())
        assertTrue(reported != null)
        assertTrue(refreshed)
    }

    @Test
    fun moderationNoOpsWhenNotConnected() = runTest {
        var reported: Throwable? = null
        var refreshed = false
        ChatController.moderateVia(
            gw = null,
            onError = { e -> reported = e },
            action = { error("should not be called") },
            logWarn = { _, _ -> },
        ) { refreshed = true }
        // No gateway: nothing to call, no error, no refresh.
        assertTrue(reported == null)
        assertTrue(!refreshed)
    }

    @Test
    fun receiptMarksDelivered() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        convo.append("a".repeat(64), ChatMessage(outbound = true, body = "x", sentAtMs = 1L, messageId = "m1"))
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Receipt("m1"))
        gw.events.send(null)
        pump.join()
        assertTrue(convo.messagesFor("a".repeat(64)).value.single().delivered)
    }

    @Test
    fun publicPostLandsInFeedAsPlainText() = runTest {
        val gw = FakeGateway()
        val feed = FeedStore()
        val pump = ChatController.pumpEvents(gw, ConversationStore(), feed, scope = this, htmlStripper = ::stripHtml)
        val activity =
            """{"object":{"id":"https://m.example/u/x/1","content":"<p>hi <b>there</b></p>"}}"""
                .toByteArray()
        gw.events.send(ChatEventFfi.PublicPost("https://m.example/u/x", activity))
        gw.events.send(null)
        pump.join()
        val post = feed.posts.value.single()
        assertEquals("hi there", post.body)
        // The relay-VERIFIED actor url is kept as the identity; the label
        // is derived from it, so a tap has a real actor to open.
        assertEquals("https://m.example/u/x", post.authorUrl)
        assertEquals("@x@m.example", post.authorLabel)
        assertEquals("https://m.example/u/x/1", post.objectUrl)
    }

    @Test
    fun pumpReportsErrorStop() = runTest {
        val throwingGateway = object : ChatGateway {
            override fun agentIdHex() = "f".repeat(64)
            override fun pairPublishOutcome(): String? = "ok"
            override suspend fun pairShareUri() = ""
            override suspend fun importPairUri(uri: String) {}
            override suspend fun enqueueDm(
                to: String,
                body: String,
                senderName: String,
                attachment: ChatAttachment?,
            ): String = ""
            override fun startOutbox(displayName: String) {}
            override suspend fun outboxSnapshot(): List<OutboxBubbleFfi> = emptyList()
            override fun retryOutbox() {}
            override suspend fun createGroup(name: String, displayName: String?, private: Boolean): GroupFfi =
                throw UnsupportedOperationException()
            override suspend fun joinGroup(invite: String, displayName: String?): GroupFfi =
                throw UnsupportedOperationException()
            override suspend fun joinGroupDurable(invite: String, displayName: String?): JoinOutcomeFfi =
                throw UnsupportedOperationException()
            override fun pendingJoins(): List<String> = emptyList()
            override suspend fun drivePendingJoins(): List<String> = emptyList()
            override suspend fun sendGroupMessage(groupId: String, body: String, senderName: String): String? = null
            override suspend fun listGroups(): List<GroupFfi> = emptyList()
            override suspend fun groupInvite(groupId: String): String = ""
            override fun fediActorStatus(): String? = null
            override fun fediMintState(): MintStateFfi? = null
            override suspend fun fediMint(handle: String): MintOutcomeFfi =
                MintOutcomeFfi("", MintRegistrationFfi.Registered)
            override suspend fun fediLookup(handle: String): LookupFfi =
                LookupFfi(LookupKindFfi.NOT_FOUND, "", "", null, null, null, null, null)
            override suspend fun fediPublish(bodyMd: String, replyToActorUrl: String?): PublishReportFfi =
                PublishReportFfi(delivered = emptyList(), failed = emptyList())
            override suspend fun fediFollow(target: String): FollowReportFfi =
                FollowReportFfi(target, "test-follow-id", delivered = true, recorded = true)
            override suspend fun fediDm(target: String, body: String): FediDmReportFfi =
                FediDmReportFfi(target, "test-note-id", delivered = true)
            override suspend fun fediEnsureV2(): EnsureV2Ffi =
                EnsureV2Ffi(
                    upgraded = false,
                    registration = MintRegistrationFfi.Registered,
                    pending = null,
                )
            override suspend fun fediFollowing(): List<FediFollowingFfi> = emptyList()
            override suspend fun fediUnfollow(targetActorUrl: String): UnfollowReportFfi =
                UnfollowReportFfi(delivered = true, removed = true)
            override suspend fun fediFeed(): List<FediPostFfi> = emptyList()
            override suspend fun fediProfile(target: String): FediProfileFfi =
                throw UnsupportedOperationException()
            override suspend fun fediLike(objectUrl: String, authorUrl: String): Boolean = true
            override suspend fun fediUnlike(objectUrl: String, authorUrl: String): Boolean = true
            override suspend fun fediSyncInbox(): UInt = 0u
            override suspend fun fediThreadsOverview(): List<FediThreadSummaryFfi> = emptyList()
            override suspend fun fediFollowers(): List<String> = emptyList()
            override suspend fun fediGoPrivateInvite(target: String, displayName: String): GoPrivateReportFfi =
                GoPrivateReportFfi(delivered = true)
            override fun fediPendingInvites(): List<String> = emptyList()
            override fun fediLinkPerson(target: String, agentIdHex: String) {}
            override fun fediUnlinkPerson(target: String) {}
            override fun fediPersonLinks(): List<FediPersonLinkFfi> = emptyList()
            override fun fediLinkedLabelForAgent(agentIdHex: String): String? = null
            override suspend fun removeContact(agentIdHex: String) {}
            override suspend fun leaveGroup(groupId: String) {}
            override suspend fun deleteGroup(groupId: String) {}
            override suspend fun groupMembers(groupId: String): List<GroupMemberFfi> = emptyList()
            override suspend fun removeMember(groupId: String, agentIdHex: String) {}
            override suspend fun banMember(groupId: String, agentIdHex: String) {}
            override suspend fun renameGroup(groupId: String, newName: String) {}
            override suspend fun conversationHistory(convKey: String): List<ChatHistoryMessageFfi> = emptyList()
            override suspend fun createLinkOffer(ttlSecs: ULong): CreatedLinkOfferFfi =
                throw UnsupportedOperationException()
            override suspend fun previewLinkOffer(uri: String): LinkOfferPreviewFfi =
                throw UnsupportedOperationException()
            override suspend fun nextEvent(): ChatEventFfi? = throw RuntimeException("boom")
            override fun disconnect() {}
        }
        var stopped: Boolean? = null
        val pump = ChatController.pumpEvents(
            throwingGateway,
            ConversationStore(),
            FeedStore(),
            scope = this,
            htmlStripper = ::stripHtml,
            onStopped = { stopped = it },
            logWarn = { _, _ -> },
        )
        pump.join()
        assertEquals(true, stopped)
    }

    @Test
    fun pumpReportsCleanStop() = runTest {
        val gw = FakeGateway()
        var stopped: Boolean? = null
        val pump = ChatController.pumpEvents(
            gw,
            ConversationStore(),
            FeedStore(),
            scope = this,
            htmlStripper = ::stripHtml,
            onStopped = { stopped = it },
            logWarn = { _, _ -> },
        )
        gw.events.send(null)
        pump.join()
        assertEquals(false, stopped)
    }

    @Test
    fun outboxSendingEventCreatesOutboundBubble() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = SendStateFfi.QUEUED)))
        gw.events.send(null)
        pump.join()
        val msg = convo.messagesFor("a".repeat(64)).value.single()
        assertTrue(msg.outbound)
        assertEquals("ob-1", msg.outboxId)
        assertEquals(false, msg.delivered)
        assertEquals(false, msg.failed)
    }

    @Test
    fun outboxDeliveredUpsertsSameBubbleWithoutDuplicating() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = SendStateFfi.QUEUED)))
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = SendStateFfi.DELIVERED, messageId = "m1")))
        gw.events.send(null)
        pump.join()
        val msgs = convo.messagesFor("a".repeat(64)).value
        assertEquals(1, msgs.size)
        assertTrue(msgs.single().delivered)
        assertEquals("m1", msgs.single().messageId)
    }

    @Test
    fun outboxFailedEventMarksFailedWithError() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = SendStateFfi.FAILED, lastError = "no route")))
        gw.events.send(null)
        pump.join()
        val msg = convo.messagesFor("a".repeat(64)).value.single()
        assertTrue(msg.failed)
        assertEquals("no route", msg.lastError)
    }

    @Test
    fun groupFanoutBubbleFlipsGroupTickAndCreatesNoDmRow() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val gid = "c".repeat(64)
        val gkey = ConversationStore.convKeyGroup(gid)
        // The send path appended the outbound group message with the receipt's
        // client message id and a queued (undelivered) tick.
        convo.append(
            gkey,
            ChatMessage(outbound = true, body = "hi all", sentAtMs = 1L, messageId = "cm-1"),
        )
        val member = "b".repeat(64)
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        // A queued fan-out copy still in flight must NOT fabricate a DM row
        // with the member, and must not flip the tick yet.
        gw.events.send(
            ChatEventFfi.Outbox(
                bubble("ob-1", peer = member, status = SendStateFfi.QUEUED, groupClientMessageId = "cm-1"),
            ),
        )
        // The first copy the relay accepts (SENT -- a group fan-out copy
        // never gets a per-member receipt) flips the ONE group message.
        gw.events.send(
            ChatEventFfi.Outbox(
                bubble("ob-1", peer = member, status = SendStateFfi.SENT, groupClientMessageId = "cm-1"),
            ),
        )
        gw.events.send(null)
        pump.join()
        assertTrue(convo.messagesFor(member).value.isEmpty())
        assertTrue(convo.messagesFor(gkey).value.single().delivered)
    }

    @Test
    fun upsertOutboxKeyedByIdSeparatesDistinctBubbles() {
        val convo = ConversationStore()
        convo.upsertOutbox("a".repeat(64), "ob-1", "one", 1L, null, delivered = false, failed = false, lastError = null)
        convo.upsertOutbox("a".repeat(64), "ob-2", "two", 2L, null, delivered = false, failed = false, lastError = null)
        convo.upsertOutbox("a".repeat(64), "ob-1", "one", 1L, "m1", delivered = true, failed = false, lastError = null)
        val msgs = convo.messagesFor("a".repeat(64)).value
        assertEquals(2, msgs.size)
        assertTrue(msgs.first { it.outboxId == "ob-1" }.delivered)
    }

    @Test
    fun upsertOutboxNeverDowngradesDelivered() {
        val convo = ConversationStore()
        convo.upsertOutbox("a".repeat(64), "ob-1", "hi", 1L, "m1", delivered = true, failed = false, lastError = null)
        // A late or reordered Sending for the same bubble must not un-deliver it.
        convo.upsertOutbox("a".repeat(64), "ob-1", "hi", 1L, null, delivered = false, failed = false, lastError = null)
        val msg = convo.messagesFor("a".repeat(64)).value.single()
        assertTrue(msg.delivered)
        assertEquals("m1", msg.messageId)
    }

    // ── persisted-history hydration (reload-on-open) ────────────────────

    @Test
    fun hydrateDmDedupsAgainstLiveMessageOfSameId() = runTest {
        val peer = "a".repeat(64)
        val key = ConversationStore.convKeyDm(peer)
        val convo = ConversationStore()
        // A live inbound event already landed this message (id "m1").
        convo.append(
            key,
            ChatMessage(outbound = false, body = "live one", sentAtMs = 100L, messageId = "m1"),
        )
        // The persisted transcript carries the SAME m1 plus an older m0 the live
        // pump never saw (it predates this process).
        val gw = FakeGateway().apply {
            history = mapOf(
                key to listOf(
                    historyMsg(body = "older zero", sentAtMs = 50L, messageId = "m0"),
                    historyMsg(body = "persisted one", sentAtMs = 100L, messageId = "m1"),
                ),
            )
        }

        ChatController.hydrateConversationVia(gw, key, convo, logWarn = { _, _ -> })

        val msgs = convo.messagesFor(key).value
        // m1 must NOT double; m0 is added; total is 2, ordered by timestamp.
        assertEquals(2, msgs.size)
        assertEquals(listOf("m0", "m1"), msgs.map { it.messageId })
        assertEquals("older zero", msgs.first().body)
        // The pre-existing live copy of m1 is the one kept (hydrated dup dropped).
        assertEquals("live one", msgs.last().body)
        assertEquals(listOf(key), gw.requestedHistory)
    }

    @Test
    fun hydrateDmOutboundDerivesFromEngineFlag() = runTest {
        val peer = "a".repeat(64)
        val key = ConversationStore.convKeyDm(peer)
        val convo = ConversationStore()
        val gw = FakeGateway().apply {
            history = mapOf(
                key to listOf(
                    historyMsg(body = "i sent", sentAtMs = 10L, messageId = "s1", outbound = true),
                    historyMsg(body = "they sent", sentAtMs = 20L, messageId = "r1", outbound = false),
                ),
            )
        }

        ChatController.hydrateConversationVia(gw, key, convo, logWarn = { _, _ -> })

        val msgs = convo.messagesFor(key).value
        assertEquals(2, msgs.size)
        assertTrue(msgs.first { it.messageId == "s1" }.outbound)
        assertTrue(!msgs.first { it.messageId == "r1" }.outbound)
    }

    @Test
    fun hydrateFailureIsNonFatalAndLeavesThreadUntouched() = runTest {
        val key = ConversationStore.convKeyDm("a".repeat(64))
        val convo = ConversationStore()
        convo.append(key, ChatMessage(outbound = false, body = "live", sentAtMs = 1L, messageId = "m1"))
        val gw = FakeGateway().apply { conversationHistoryThrows = true }

        // Must not throw; the existing live message is preserved.
        ChatController.hydrateConversationVia(gw, key, convo, logWarn = { _, _ -> })

        val msgs = convo.messagesFor(key).value
        assertEquals(1, msgs.size)
        assertEquals("live", msgs.single().body)
    }

    @Test
    fun hydrateNullGatewayIsNoOp() = runTest {
        val key = ConversationStore.convKeyDm("a".repeat(64))
        val convo = ConversationStore()
        ChatController.hydrateConversationVia(null, key, convo, logWarn = { _, _ -> })
        assertTrue(convo.messagesFor(key).value.isEmpty())
    }

    @Test
    fun aBlankSenderAgentIdBecomesNullSoFediBubblesCarryNoAgentLabel() {
        // A fediverse sender has no agent id: the engine persists a blank
        // fromAgentIdHex. An empty string is NOT an agent id — leaving it
        // non-null made the thread render a bare "agent-" attribution label
        // (and a per-identity bubble stripe) on inbound fediverse messages.
        val rows = ChatController.historyToMessages(
            listOf(historyMsg("hi from the fediverse", 10L, "m1", fromAgentIdHex = "")),
        )
        assertEquals(1, rows.size)
        assertNull(rows[0].senderAgentIdHex)
    }

    private fun historyMsg(
        body: String,
        sentAtMs: Long,
        messageId: String,
        outbound: Boolean = false,
        fromAgentIdHex: String = "a".repeat(64),
        senderName: String? = null,
        delivered: Boolean = false,
        attachment: ChatAttachmentFfi? = null,
    ) = ChatHistoryMessageFfi(
        outbound = outbound,
        fromAgentIdHex = fromAgentIdHex,
        senderName = senderName,
        body = body,
        sentAtMs = sentAtMs.toULong(),
        messageId = messageId,
        delivered = delivered,
        sendState = if (delivered) SendStateFfi.DELIVERED else SendStateFfi.SENT,
        stateChangedAtMs = sentAtMs.toULong(),
        attachment = attachment,
    )

    private fun bubble(
        id: String,
        peer: String = "a".repeat(64),
        body: String = "hi",
        status: SendStateFfi = SendStateFfi.QUEUED,
        messageId: String? = null,
        lastError: String? = null,
        groupClientMessageId: String? = null,
    ) = OutboxBubbleFfi(
        id = id,
        peerAgentIdHex = peer,
        body = body,
        status = status,
        messageId = messageId,
        enqueuedAtMs = 1uL,
        stateChangedAtMs = 1uL,
        lastError = lastError,
        groupClientMessageId = groupClientMessageId,
    )
}
