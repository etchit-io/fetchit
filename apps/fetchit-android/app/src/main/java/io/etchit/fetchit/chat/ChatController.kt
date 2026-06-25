package io.etchit.fetchit.chat

import android.content.Context
import android.widget.Toast
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi
import uniffi.fetchit_ffi.ChatHistoryMessageFfi
import uniffi.fetchit_ffi.GroupFfi
import uniffi.fetchit_ffi.GroupMemberFfi
import uniffi.fetchit_ffi.OutboxBubbleFfi
import uniffi.fetchit_ffi.OutboxStatusFfi
import java.io.File

/**
 * Lifecycle of the inbound event pump, observable by the UI. A pump that
 * stopped on ERROR means inbound delivery silently halted (no reconnect in
 * v1) — the chat surface shows its degraded-connection pill off this state.
 */
enum class PumpState {
    /** Chat was never started this process. */
    IDLE,

    /** The pump is draining inbound events. */
    RUNNING,

    /** The relay shut down cleanly or [ChatController.disconnect] ran. */
    STOPPED_CLEAN,

    /** The pump died on an unexpected error; inbound delivery has halted. */
    STOPPED_ERROR,
}

/**
 * Process-scoped chat runtime.
 *
 * Owns the [ChatGateway] lifecycle (mirrors [FetchitApplication.ensureConnected]
 * pattern), runs the event pump, and exposes the three in-memory stores that UI
 * layers observe. There is one instance per process, held by
 * [io.etchit.fetchit.FetchitApplication].
 *
 * Lifecycle: [ensureGateway] connects on first call; [disconnect] tears down
 * and resets so [ensureGateway] can reconnect. The [CoroutineScope] is
 * application-owned and outlives any activity.
 */
class ChatController(private val appContext: Context, private val scope: CoroutineScope) {

    /** Observable contact list, persisted across restarts. */
    val contacts = ChatContactStore(appContext)

    /** In-memory per-peer message threads. */
    val conversations = ConversationStore()

    /** In-memory bridged fediverse posts. */
    val feed = FeedStore()

    private val _groups = MutableStateFlow<List<GroupFfi>>(emptyList())

    /**
     * Groups this agent belongs to, loaded on connect (mirrors desktop
     * `loadGroups`). The list screen renders these as conversation rows; their
     * threads live in [conversations] under [ConversationStore.convKeyGroup].
     */
    val groups: StateFlow<List<GroupFfi>> = _groups.asStateFlow()

    @Volatile private var gateway: ChatGateway? = null
    private var pump: Job? = null
    private val connectMutex = Mutex()

    private val _pumpState = MutableStateFlow(PumpState.IDLE)

    /** Observable pump lifecycle; see [PumpState] for the contract. */
    val pumpState: StateFlow<PumpState> = _pumpState.asStateFlow()

    /** Returns the cached gateway without connecting, or `null` if not yet connected. */
    fun gateway(): ChatGateway? = gateway

    /**
     * Returns the active [ChatGateway], connecting to [DEFAULT_RELAY] on first
     * call. Subsequent calls are cheap (cached `@Volatile` fast path). The
     * connect path is serialized behind [connectMutex] with a double-check so
     * concurrent entries (mode switch, pair deep link, add-contact) cannot
     * double-connect and leak the first client's pump.
     */
    suspend fun ensureGateway(): ChatGateway {
        gateway?.let { if (_pumpState.value == PumpState.RUNNING) return it }
        connectMutex.withLock {
            gateway?.let { if (_pumpState.value == PumpState.RUNNING) return it }
            // A cached gateway whose pump has stopped (relay drop -> STOPPED_ERROR,
            // or a prior clean stop) is dead for inbound -- there is no in-pump
            // reconnect in v1, so reusing it would silently deliver nothing. Tear
            // the dead one down and rebuild here, so nav-away+back recovers inbound
            // after a relay drop instead of needing an app kill.
            if (gateway != null) disconnect()
            val dataDir = File(appContext.filesDir, "chat").apply { mkdirs() }
            val client = ChatClient.connect(
                DEFAULT_RELAY,
                dataDir.absolutePath,
                ChatSecrets(appContext).vaultPass(),
            )
            val gw = FfiChatGateway(client)
            gateway = gw
            _pumpState.value = PumpState.RUNNING
            pump = pumpEvents(
                gw,
                conversations,
                feed,
                scope,
                onStopped = { error ->
                    _pumpState.value =
                        if (error) PumpState.STOPPED_ERROR else PumpState.STOPPED_CLEAN
                },
            )
            // Subscribe-first: the pump above is already draining outbox events.
            // Now start the retry driver and hydrate any bubbles that were
            // enqueued (and vault-persisted) before this process subscribed.
            startOutboxAndHydrate(gw)
            // Seed the group list so the conversation screen can show existing
            // groups (and their threads) immediately after connect. loadGroups
            // also hydrates each group's persisted transcript.
            loadGroups(gw)
            // Hydrate known contacts' DM threads from the persisted vault so the
            // list shows previews and threads are not empty on reopen.
            hydrateContacts(gw)
            // Surface the connect-time pair-record publish outcome. On Android
            // its failure is otherwise invisible (fetchit_chat log records do not
            // reach logcat), so a relay/TLS failure would look like a phantom
            // "connected". Best-effort + off the connect path; never blocks.
            surfacePairPublishOutcome(gw)
            return gw
        }
    }

    /**
     * Re-read the group list from the engine after a create/join so a freshly
     * minted or joined group surfaces in [groups] (and the list screen) without
     * a reconnect. No-op when not connected; failures are swallowed exactly as
     * on the connect path. Safe to call from the UI scope.
     */
    suspend fun refreshGroups() {
        val gw = gateway ?: return
        loadGroups(gw)
    }

    /**
     * Remove a contact from the conversation list. Asks the engine to forget
     * the peer, then drops it from the local contact store so the row clears
     * even when the engine call fails (e.g. offline) -- the engine remove is
     * idempotent and best-effort, mirroring the desktop affordance. The local
     * delete is the user-visible effect and always runs.
     */
    suspend fun removeContact(agentIdHex: String) {
        removeContactVia(gateway, agentIdHex) { contacts.delete(agentIdHex) }
    }

    /**
     * Leave a group from the conversation list. Asks the engine to leave, then
     * refreshes the group list so the row disappears. The leave failure is
     * swallowed (mirrors [refreshGroups]); the refresh reconciles the list with
     * the engine's actual membership either way.
     */
    suspend fun leaveGroup(groupId: String) {
        leaveGroupVia(gateway, groupId) { refreshGroups() }
    }

    /**
     * Hydrate the thread for [convKey] from the engine's persisted vault so an
     * opened conversation shows its history immediately instead of waiting on
     * (or losing) it across a process kill. [convKey] is a
     * [ConversationStore.convKeyDm] or [ConversationStore.convKeyGroup] value.
     * Non-fatal + idempotent: the merge de-dups by message id, so re-opening a
     * thread does not double messages. No-op when not connected.
     */
    suspend fun hydrateConversation(convKey: String) {
        hydrateConversationVia(gateway, convKey, conversations)
    }

    /**
     * Roster of active members for [groupId] -- "who is in this group". Returns
     * the empty list (and logs) on any failure or when not connected, so the
     * member-list dialog degrades gracefully rather than crashing -- non-fatal,
     * mirroring [loadGroups]. The flags on each row are cosmetic; x0xd remains
     * the authority on every moderation call.
     */
    suspend fun groupMembers(groupId: String): List<GroupMemberFfi> {
        val gw = gateway ?: return emptyList()
        return try {
            gw.groupMembers(groupId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w("fetchit.chat", "groupMembers failed", e)
            emptyList()
        }
    }

    /**
     * Remove [agentIdHex] from [groupId], then refresh the group + roster.
     * x0xd is the authorization gate (admin+, refuses an owner-target, drives
     * the TreeKEM re-key); the [onError] callback surfaces the x0xd rejection
     * to the caller so an unauthorized attempt is shown, never silently
     * swallowed. Refresh runs regardless so the list reconciles with the
     * engine's actual membership.
     */
    suspend fun removeMember(
        groupId: String,
        agentIdHex: String,
        onError: (Throwable) -> Unit = {},
    ) {
        moderateVia(gateway, onError, { it.removeMember(groupId, agentIdHex) }) { refreshGroups() }
    }

    /**
     * Ban [agentIdHex] from [groupId] (removed and cannot rejoin), then refresh.
     * Same x0xd-gated contract as [removeMember]: surface the rejection.
     */
    suspend fun banMember(
        groupId: String,
        agentIdHex: String,
        onError: (Throwable) -> Unit = {},
    ) {
        moderateVia(gateway, onError, { it.banMember(groupId, agentIdHex) }) { refreshGroups() }
    }

    /**
     * Rename [groupId] to [newName], then refresh so the new title surfaces.
     * x0xd gates the rename to admin+; surface its rejection via [onError].
     */
    suspend fun renameGroup(
        groupId: String,
        newName: String,
        onError: (Throwable) -> Unit = {},
    ) {
        moderateVia(gateway, onError, { it.renameGroup(groupId, newName) }) { refreshGroups() }
    }

    /**
     * Load the agent's groups into [groups] and ensure each has a conversation
     * flow in [conversations] (keyed by [ConversationStore.convKeyGroup]) so the
     * list screen can render a row -- with title `name ?: groupId.take(8)` --
     * before any group message arrives. Mirrors desktop `loadGroups`. Failures
     * are swallowed: a group-list error must not break DM connect.
     */
    private suspend fun loadGroups(gw: ChatGateway) {
        val loaded = try {
            gw.listGroups()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w("fetchit.chat", "listGroups failed on connect", e)
            return
        }
        for (g in loaded) {
            // Touch the flow so a freshly-loaded group surfaces as an (empty)
            // conversation the list screen can render.
            val key = ConversationStore.convKeyGroup(g.groupId)
            conversations.messagesFor(key)
            // Hydrate the persisted transcript so the list shows a last-message
            // preview and the thread is non-empty on reopen. Non-fatal per
            // group: a hydrate failure must not break the group list.
            hydrateConversationVia(gw, key, conversations)
        }
        _groups.value = loaded
    }

    /**
     * Hydrate every known contact's DM thread from the persisted vault on
     * connect, so the list screen shows last-message previews and threads are
     * not empty on reopen. Non-fatal per contact, mirroring [loadGroups].
     * Groups are hydrated inside [loadGroups]; this covers the DM side.
     */
    private suspend fun hydrateContacts(gw: ChatGateway) {
        for (c in contacts.contacts.value) {
            hydrateConversationVia(gw, ConversationStore.convKeyDm(c.agentIdHex), conversations)
        }
    }

    /**
     * Start the engine outbox driver and project the current outbox snapshot
     * into [conversations]. Called once per connect, after the event pump is
     * live, so the snapshot can only duplicate live events -- and the upsert is
     * keyed by bubble id, so duplicates collapse onto one bubble.
     */
    private suspend fun startOutboxAndHydrate(gw: ChatGateway) {
        gw.startOutbox(displayNameOrDefault(appContext, gw.agentIdHex()))
        for (bubble in gw.outboxSnapshot()) {
            projectOutbox(conversations, bubble)
        }
    }

    /**
     * Poll the FFI-captured pair-record publish outcome shortly after connect
     * and surface a non-`ok` result. The publish runs async on connect (relay
     * HTTPS); on Android its `Err`/panic is otherwise silent -- the Rust `log`
     * facade does not bridge to logcat. Logs via `android.util.Log` (which DOES
     * reach logcat) and toasts a failure so a relay/TLS problem is visible
     * instead of a phantom connection. Best-effort; swallows its own errors.
     */
    private fun surfacePairPublishOutcome(gw: ChatGateway) {
        scope.launch {
            var outcome: String? = null
            var attempts = 0
            while (outcome == null && attempts < 10) {
                delay(1000)
                outcome = try {
                    gw.pairPublishOutcome()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    "error: ${e.message}"
                }
                attempts++
            }
            val result = outcome ?: "pending (no result after 10s)"
            android.util.Log.w("fetchit.chat", "pair-record publish outcome: $result")
            if (result != "ok") {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        appContext,
                        "Relay publish: $result",
                        Toast.LENGTH_LONG,
                    ).show()
                }
            }
        }
    }

    /**
     * Drop the relay connection and cancel the event pump.
     * Safe and idempotent when the gateway was never started.
     * [ensureGateway] can reconnect after this.
     */
    fun disconnect() {
        gateway?.disconnect()
        gateway = null
        pump?.cancel()
        pump = null
        // A deliberate teardown reads as clean even after an error stop, but
        // a controller that never connected stays IDLE.
        if (_pumpState.value != PumpState.IDLE) {
            _pumpState.value = PumpState.STOPPED_CLEAN
        }
    }

    companion object {

        /**
         * Default relay URL: the Cloudflare-fronted TLS endpoint (#114 cutover).
         * Use the `https://` scheme, NOT `wss://`: the relay client dial-upgrades
         * https->wss for the WebSocket, while pair-record / v2-card publishing POSTs
         * to this URL over HTTP -- a `wss://` value makes those POSTs fail (the HTTP
         * client rejects the wss scheme, which breaks card exchange). Empirically
         * confirmed on the soak fleet. Bare-IP `:8088` is CF-locked; clients must
         * use this. Region override is wired via the settings sheet in a later task.
         */
        const val DEFAULT_RELAY = "https://nyc-relay.etchit.io"

        /**
         * Drain [gw].[ChatGateway.nextEvent] in a loop, routing each event into
         * [convo] or [feed]. The loop exits cleanly when [nextEvent] returns
         * `null` (relay shut down) or throws (network error).
         *
         * Exposed as a companion function so tests can drive the pump with a
         * [io.etchit.fetchit.chat.FakeGateway] without constructing a full
         * [ChatController].
         *
         * @param htmlStripper Converts an HTML string to plain text. Defaults to
         *   [android.text.Html.fromHtml] (requires Android framework — not
         *   available in plain JUnit). Tests pass a regex-based stripper to
         *   keep them fast and hermetic.
         * @param onStopped Invoked exactly once when the loop exits: `true`
         *   when an unexpected error killed it (inbound delivery has halted;
         *   no reconnect in v1), `false` on a clean null shutdown. NOT invoked
         *   when the pump's Job is cancelled (deliberate teardown owns its own
         *   state).
         * @param logWarn Diagnostic sink for the error path. Defaults to
         *   logcat; tests inject a no-op to stay hermetic.
         */
        fun pumpEvents(
            gw: ChatGateway,
            convo: ConversationStore,
            feed: FeedStore,
            scope: CoroutineScope,
            htmlStripper: (String) -> String = { html ->
                android.text.Html.fromHtml(html, android.text.Html.FROM_HTML_MODE_LEGACY)
                    .toString()
                    .trim()
            },
            onStopped: (error: Boolean) -> Unit = {},
            logWarn: (String, Throwable) -> Unit = { msg, t ->
                android.util.Log.w("fetchit.chat", msg, t)
            },
        ): Job = scope.launch {
            while (true) {
                val ev = try {
                    gw.nextEvent()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    logWarn("event pump stopped on error", e)
                    onStopped(true)
                    return@launch
                } ?: break
                when (ev) {
                    is ChatEventFfi.Dm -> convo.append(
                        ConversationStore.convKeyDm(ev.fromAgentIdHex),
                        ChatMessage(
                            outbound = false,
                            body = ev.body,
                            sentAtMs = System.currentTimeMillis(),
                            messageId = ev.messageId,
                        ),
                    )
                    is ChatEventFfi.GroupMessage -> convo.append(
                        ConversationStore.convKeyGroup(ev.groupId),
                        ChatMessage(
                            outbound = false,
                            body = ev.body,
                            sentAtMs = System.currentTimeMillis(),
                            messageId = ev.messageId,
                            // Group bubbles attribute the sender; the UI shows a
                            // label off this (DMs leave it null).
                            senderAgentIdHex = ev.fromAgentIdHex,
                            // Sender's self-attached display name (rides the
                            // encrypted message); the label prefers it over the
                            // agent-id fallback.
                            senderName = ev.senderName,
                        ),
                    )
                    is ChatEventFfi.Receipt -> convo.markDelivered(ev.messageId)
                    is ChatEventFfi.PublicPost -> decodePost(ev, htmlStripper)?.let(feed::append)
                    is ChatEventFfi.Outbox -> projectOutbox(convo, ev.bubble)
                }
            }
            onStopped(false)
        }

        /**
         * Ask [gw] (if connected) to forget [agentIdHex], swallowing+logging any
         * failure, then run [dropLocal] to clear the local store. The local drop
         * is the user-visible effect and always runs, even when [gw] is `null`
         * (not connected) or the engine call fails (e.g. offline) — the engine
         * remove is best-effort and idempotent.
         *
         * Companion function so the swallow-then-drop seam is JVM-testable with a
         * [FakeGateway], mirroring [pumpEvents].
         */
        suspend fun removeContactVia(
            gw: ChatGateway?,
            agentIdHex: String,
            logWarn: (String, Throwable) -> Unit = { msg, t ->
                android.util.Log.w("fetchit.chat", msg, t)
            },
            dropLocal: suspend () -> Unit,
        ) {
            if (gw != null) {
                try {
                    gw.removeContact(agentIdHex)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    logWarn("removeContact failed", e)
                }
            }
            dropLocal()
        }

        /**
         * Ask [gw] to leave [groupId], swallowing+logging any failure, then run
         * [refresh] to reconcile the group list with the engine's membership.
         * No-op when [gw] is `null`. Companion function for the same JVM-test
         * reason as [removeContactVia].
         */
        suspend fun leaveGroupVia(
            gw: ChatGateway?,
            groupId: String,
            logWarn: (String, Throwable) -> Unit = { msg, t ->
                android.util.Log.w("fetchit.chat", msg, t)
            },
            refresh: suspend () -> Unit,
        ) {
            if (gw == null) return
            try {
                gw.leaveGroup(groupId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logWarn("leaveGroup failed", e)
            }
            refresh()
        }

        /**
         * Run an x0xd-gated moderation [action] (remove / ban / rename) against
         * [gw], then [refresh] the list. No-op when [gw] is `null`. Unlike the
         * remove/leave seams, a moderation failure is NOT silently swallowed:
         * x0xd is the sole authorization gate, so an unauthorized or rejected
         * call must reach the user. The failure is reported via [onError] (and
         * logged) BUT [refresh] still runs so the list reconciles with the
         * engine either way.
         *
         * Companion function so the report-then-refresh seam is JVM-testable
         * with a [FakeGateway], mirroring [removeContactVia] / [leaveGroupVia].
         */
        suspend fun moderateVia(
            gw: ChatGateway?,
            onError: (Throwable) -> Unit,
            action: suspend (ChatGateway) -> Unit,
            logWarn: (String, Throwable) -> Unit = { msg, t ->
                android.util.Log.w("fetchit.chat", msg, t)
            },
            refresh: suspend () -> Unit,
        ) {
            if (gw == null) return
            try {
                action(gw)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // x0xd is the authority -- surface its rejection, do not swallow.
                logWarn("group moderation failed", e)
                onError(e)
            }
            refresh()
        }

        /**
         * Parse a raw ActivityStreams [ChatEventFfi.PublicPost], extract
         * `object.content`, strip HTML to plain text, and return a [FeedPost].
         * Returns `null` for malformed JSON, missing content, or posts that
         * reduce to blank after stripping.
         *
         * Input is UNTRUSTED fediverse content — [htmlStripper] must sanitize
         * all markup before the result reaches the UI.
         */
        fun decodePost(
            ev: ChatEventFfi.PublicPost,
            htmlStripper: (String) -> String = { html ->
                android.text.Html.fromHtml(html, android.text.Html.FROM_HTML_MODE_LEGACY)
                    .toString()
                    .trim()
            },
        ): FeedPost? = runCatching {
            val json = JSONObject(String(ev.activityJson, Charsets.UTF_8))
            val content = json.optJSONObject("object")?.optString("content").orEmpty()
            val plain = htmlStripper(content)
            if (plain.isEmpty()) null else FeedPost(ev.verifiedActorUrl, plain, System.currentTimeMillis())
        }.getOrNull()

        /**
         * Map a persisted FFI transcript into [ChatMessage]s, keeping the
         * uniffi [ChatHistoryMessageFfi] type out of [ConversationStore].
         * Mirrors the live-event projection: an inbound entry carries the
         * group sender attribution; an outbound entry leaves those null, the
         * same shape the pump and [projectOutbox] produce, so a hydrated copy
         * de-dups cleanly against its live twin by [ChatMessage.messageId].
         *
         * A blank persisted `message_id` (legacy pre-id entries) becomes a null
         * [ChatMessage.messageId] so it reads as unmatchable, never as the
         * empty-string id.
         */
        fun historyToMessages(history: List<ChatHistoryMessageFfi>): List<ChatMessage> =
            history.map { h ->
                ChatMessage(
                    outbound = h.outbound,
                    body = h.body,
                    sentAtMs = h.sentAtMs.toLong(),
                    messageId = h.messageId.takeIf { it.isNotBlank() },
                    delivered = h.delivered,
                    // Sender attribution only on inbound entries (the group
                    // label reads off these); outbound + DM entries leave null,
                    // matching the live pump.
                    senderAgentIdHex = if (h.outbound) null else h.fromAgentIdHex,
                    senderName = if (h.outbound) null else h.senderName,
                )
            }

        /**
         * Hydrate the thread for [convKey] from the engine's persisted vault
         * via [gw], merging into [convo] (de-duped by message id). Non-fatal:
         * a missing gateway, a fetch failure, or an empty transcript leaves the
         * thread untouched and is logged, mirroring [loadGroups].
         *
         * Companion function so the fetch-then-merge seam is JVM-testable with
         * a [FakeGateway], mirroring [removeContactVia] / [projectOutbox].
         */
        suspend fun hydrateConversationVia(
            gw: ChatGateway?,
            convKey: String,
            convo: ConversationStore,
            logWarn: (String, Throwable) -> Unit = { msg, t ->
                android.util.Log.w("fetchit.chat", msg, t)
            },
        ) {
            if (gw == null) return
            val history = try {
                gw.conversationHistory(convKey)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logWarn("conversationHistory failed for $convKey", e)
                return
            }
            convo.mergeHistory(convKey, historyToMessages(history))
        }

        /**
         * Project an FFI outbox [bubble] into [convo], upserting by bubble id.
         * Maps the FFI status enum to the [ChatMessage] delivered/failed flags
         * so [ConversationStore] stays free of any uniffi types.
         */
        fun projectOutbox(convo: ConversationStore, bubble: OutboxBubbleFfi) {
            convo.upsertOutbox(
                peerAgentIdHex = bubble.peerAgentIdHex,
                outboxId = bubble.id,
                body = bubble.body,
                sentAtMs = bubble.enqueuedAtMs.toLong(),
                messageId = bubble.messageId,
                delivered = bubble.status == OutboxStatusFfi.DELIVERED,
                failed = bubble.status == OutboxStatusFfi.FAILED,
                lastError = bubble.lastError,
            )
        }
    }
}
