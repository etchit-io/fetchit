package io.etchit.fetchit.chat

import android.content.Context
import io.etchit.fetchit.SettingsStore
import android.widget.Toast
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
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
import uniffi.fetchit_ffi.MintOutcomeFfi
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

    private val feedPrefs =
        appContext.getSharedPreferences("fetchit_feed", Context.MODE_PRIVATE)

    /**
     * Fediverse posts (bridged + the user's own), persisted in plain prefs so
     * the feed survives a restart — own posts are never re-delivered to their
     * author, so an unpersisted feed silently loses them on process death.
     * Public content; plain prefs are fine (the [io.etchit.fetchit.BookmarkStore]
     * rationale).
     */
    val feed = FeedStore(
        load = { FeedSerde.decode(feedPrefs.getString(FEED_KEY, null)) },
        save = { posts -> feedPrefs.edit().putString(FEED_KEY, FeedSerde.encode(posts)).apply() },
    )

    private val _groups = MutableStateFlow<List<GroupFfi>>(emptyList())

    /**
     * Groups this agent belongs to, loaded on connect (mirrors desktop
     * `loadGroups`). The list screen renders these as conversation rows; their
     * threads live in [conversations] under [ConversationStore.convKeyGroup].
     */
    val groups: StateFlow<List<GroupFfi>> = _groups.asStateFlow()

    private val _fediThreads =
        MutableStateFlow<List<uniffi.fetchit_ffi.FediThreadSummaryFfi>>(emptyList())

    /**
     * Fediverse DM thread summaries, newest first — the fediverse rows in the
     * unified Chats list. Refreshed by [refreshFediThreads] (called on entering
     * the Chats tab, after an inbox sync). Empty when no handle is minted.
     */
    val fediThreads: StateFlow<List<uniffi.fetchit_ffi.FediThreadSummaryFfi>> =
        _fediThreads.asStateFlow()

    private val _personLinks =
        MutableStateFlow<List<uniffi.fetchit_ffi.FediPersonLinkFfi>>(emptyList())

    /**
     * Fediverse-person ↔ PQ-agent links, and pending go-private invites.
     * A `linked` entry means that fediverse thread is folded into its PQ
     * contact row (the fedi row is suppressed in the unified list);
     * `invited` (not yet linked) drives the pending-invite affordance.
     * Refreshed by [refreshPersonLinks]. Empty when no handle is minted.
     */
    val personLinks: StateFlow<List<uniffi.fetchit_ffi.FediPersonLinkFfi>> =
        _personLinks.asStateFlow()

    private val _pendingJoins = MutableStateFlow<List<String>>(emptyList())

    /** Group ids the engine is silently catching up (#297): the UI shows a
     * quiet syncing affordance on these instead of a dead conversation. */
    private val _reconnectingGroups = MutableStateFlow<Set<String>>(emptySet())
    val reconnectingGroups: StateFlow<Set<String>> = _reconnectingGroups.asStateFlow()

    /**
     * Group ids with a durable join still completing. The list screen draws
     * these as "joining…"; they clear themselves when the resume pump
     * ([startPendingJoinPump]) converges the join -- no user action needed.
     */
    val pendingJoins: StateFlow<List<String>> = _pendingJoins.asStateFlow()

    @Volatile private var gateway: ChatGateway? = null

    /**
     * Foreground/background mesh mode for the embedded x0x daemon -- the
     * data-bill guard (see [MeshPolicy]). Applies through the gateway when
     * one is connected; a failed flip is reported back so the policy keeps
     * retrying until the mode sticks (a wedged flip must not leak a
     * full-mesh daemon onto mobile data). No gateway counts as success:
     * the eventual connect seeds its initial mode from [MeshPolicy.active].
     */
    val meshPolicy: MeshPolicy = MeshPolicy(scope) { active ->
        try {
            gateway?.setMeshActive(active)
            true
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w("fetchit.chat", "mesh mode apply failed; will retry", e)
            false
        }
    }

    private var tripwireJob: Job? = null

    /**
     * Start the OS-level metered-data tripwire (see [DataTripwire]).
     * Samples Android's own per-app cumulative byte counter every minute
     * and attributes deltas to the current network class via [meteredNow].
     * A trip latches the mesh off through [MeshPolicy.onDataTripwire] and
     * notifies the user; an escalation (bytes still flowing while
     * quiesced) posts an urgent restart prompt -- automatic process
     * recycling is deliberately deferred until foreground-service restart
     * semantics are device-verified. Idempotent.
     */
    fun startDataTripwire(meteredNow: () -> Boolean) {
        if (tripwireJob != null) return
        val prefs =
            appContext.getSharedPreferences("data_tripwire", Context.MODE_PRIVATE)
        val restored =
            if (prefs.contains("epoch_day")) {
                DataTripwire.State(
                    epochDay = prefs.getLong("epoch_day", 0),
                    meteredBytes = prefs.getLong("metered_bytes", 0),
                    tripped = prefs.getBoolean("tripped", false),
                    escalated = prefs.getBoolean("escalated", false),
                )
            } else {
                null
            }
        val tripwire = DataTripwire(restored = restored)
        if (tripwire.tripped) meshPolicy.onDataTripwire(true)
        tripwireJob = scope.launch {
            val uid = android.os.Process.myUid()
            while (true) {
                val rx = android.net.TrafficStats.getUidRxBytes(uid)
                val tx = android.net.TrafficStats.getUidTxBytes(uid)
                // UNSUPPORTED (-1) on exotic kernels: fail open, the policy
                // still protects; the tripwire just cannot double-check it.
                if (rx >= 0 && tx >= 0) {
                    val day = System.currentTimeMillis() / DAY_MS
                    when (val v = tripwire.sample(day, rx + tx, meteredNow())) {
                        is DataTripwire.Verdict.Tripped -> {
                            android.util.Log.w(
                                "fetchit.chat",
                                "data tripwire TRIPPED: ${v.meteredBytesToday} metered bytes today",
                            )
                            meshPolicy.onDataTripwire(true)
                            postDataNotification(
                                "Mobile data protection on",
                                "fetch>it used ${v.meteredBytesToday / MB} MB of metered data " +
                                    "today, so peer-to-peer networking is paused. Messages " +
                                    "still arrive normally.",
                            )
                        }
                        is DataTripwire.Verdict.Escalated -> {
                            android.util.Log.e(
                                "fetchit.chat",
                                "data tripwire ESCALATED: ${v.meteredBytesToday} metered bytes " +
                                    "despite quiesce -- engine unreachable by policy",
                            )
                            meshPolicy.onDataTripwire(true)
                            postDataNotification(
                                "fetch>it needs a restart",
                                "The app kept using metered data (${v.meteredBytesToday / MB} MB " +
                                    "today) after protection engaged. Please close and reopen " +
                                    "fetch>it to stop it.",
                            )
                        }
                        DataTripwire.Verdict.DayReset -> meshPolicy.onDataTripwire(false)
                        DataTripwire.Verdict.None -> {}
                    }
                    val s = tripwire.stateSnapshot
                    prefs.edit()
                        .putLong("epoch_day", s.epochDay)
                        .putLong("metered_bytes", s.meteredBytes)
                        .putBoolean("tripped", s.tripped)
                        .putBoolean("escalated", s.escalated)
                        .apply()
                }
                delay(TRIPWIRE_SAMPLE_MS)
            }
        }
    }

    private fun postDataNotification(title: String, text: String) {
        try {
            val nm =
                appContext.getSystemService(Context.NOTIFICATION_SERVICE)
                    as android.app.NotificationManager
            nm.createNotificationChannel(
                android.app.NotificationChannel(
                    DATA_CHANNEL_ID,
                    "Data protection",
                    android.app.NotificationManager.IMPORTANCE_HIGH,
                ),
            )
            val notification =
                android.app.Notification.Builder(appContext, DATA_CHANNEL_ID)
                    .setSmallIcon(io.etchit.fetchit.R.drawable.ic_stat_chat)
                    .setContentTitle(title)
                    .setStyle(android.app.Notification.BigTextStyle().bigText(text))
                    .setContentText(text)
                    .build()
            nm.notify(DATA_NOTIFICATION_ID, notification)
        } catch (e: Exception) {
            // Notifications denied is survivable -- the mesh block already
            // protects the plan; the user just does not hear about it.
            android.util.Log.w("fetchit.chat", "data-protection notification failed", e)
        }
    }

    private var pump: Job? = null
    private var pendingJoinPump: Job? = null
    private val connectMutex = Mutex()

    private val _pumpState = MutableStateFlow(PumpState.IDLE)

    /** Observable pump lifecycle; see [PumpState] for the contract. */
    val pumpState: StateFlow<PumpState> = _pumpState.asStateFlow()

    private val _connecting = MutableStateFlow(false)

    /**
     * UI-facing chat connection status (the header dot): CONNECTED when the
     * pump is RUNNING, CONNECTING while an [ensureGateway] attempt is in flight
     * (the slow initial dial keeps the pump IDLE until it lands), OFFLINE
     * otherwise. Combines [pumpState] with the in-flight-connect flag via the
     * pure [chatConnectionStatus] mapping.
     */
    val connectionStatus: StateFlow<ChatConnectionStatus> =
        combine(_pumpState, _connecting) { pump, connecting ->
            chatConnectionStatus(pump, connecting)
        }.stateIn(scope, SharingStarted.Eagerly, ChatConnectionStatus.OFFLINE)

    /**
     * Notification tap: set by [io.etchit.fetchit.chat.notify.ChatForegroundService],
     * receives every inbound DM / group message from the pump. `null` (no
     * service / notifications off) drops the events — the UI stores are fed
     * directly by the pump either way.
     */
    @Volatile
    var inboundSink: ((io.etchit.fetchit.chat.notify.InboundNotify) -> Unit)? = null

    /**
     * Conversation key of the thread currently on screen, or `null`. The
     * notify policy suppresses notifications for it; the thread view keeps
     * this current on open/close.
     */
    @Volatile
    var visibleConvKey: String? = null

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
            // Signal the in-flight connect so the header dot reads "connecting…"
            // for the whole slow dial (the pump stays IDLE until the connect
            // lands) rather than "offline". Cleared in the finally whether the
            // connect succeeds, throws, or is cancelled.
            _connecting.value = true
            try {
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
                    // Background connects (boot receiver, notification
                    // service) must never join the public mesh just to
                    // leave it -- the policy's current mode decides.
                    meshPolicy.active,
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
                    onInbound = { inbound -> inboundSink?.invoke(inbound) },
                )
                // Durable-join resume pump: advance any pending join on a timer so a
                // join that could not converge now (owner offline) auto-completes
                // when the owner returns -- no user action, no re-spent invite.
                pendingJoinPump = startPendingJoinPump(gw)
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
            } finally {
                _connecting.value = false
            }
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
     * Re-read the pending-join set so a freshly-`Pending` join shows "joining…"
     * immediately, without waiting for the next pump tick. No-op when not
     * connected; a read failure leaves the set unchanged.
     */
    fun refreshPendingJoins() {
        val gw = gateway ?: return
        _pendingJoins.value = runCatching { gw.pendingJoins() }.getOrDefault(_pendingJoins.value)
    }

    /**
     * Launch the durable-join resume pump on the controller scope: every few
     * seconds advance any pending join one step and publish the still-pending
     * set. A join that could not converge at submit time (owner offline)
     * auto-completes here when the owner returns -- no user action, no re-spent
     * invite. When a group leaves the pending set (converged) the group list is
     * refreshed so it surfaces. A no-op tick when nothing is pending.
     */
    private fun startPendingJoinPump(gw: ChatGateway): Job = scope.launch {
        while (true) {
            val stillPending = try {
                gw.drivePendingJoins()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                android.util.Log.w("fetchit.chat", "pending-join pump tick failed", e)
                _pendingJoins.value
            }
            val converged = _pendingJoins.value.any { it !in stillPending }
            _pendingJoins.value = stillPending
            // Recovery status rides the same tick: cheap map read engine-side.
            _reconnectingGroups.value =
                runCatching { gw.reconnectingGroups().toSet() }
                    .getOrDefault(_reconnectingGroups.value)
            if (converged) {
                runCatching { refreshGroups() }
            }
            // 3s: fast enough that a returning owner converges the join within a
            // few seconds, cheap enough to idle-poll for the session's life.
            delay(3_000L)
        }
    }

    /**
     * The active minted fediverse @handle, or `null` when the user has not
     * opted in to public posting. Reads the local vault via the connected
     * gateway; `null` when chat isn't connected yet, so the onboarding prompt
     * shows until then.
     */
    fun fediActorStatus(): String? = gateway?.fediActorStatus()

    /**
     * Pull the current fediverse DM thread overview from the engine into
     * [fediThreads]. Quiet on failure (leaves the last value). No-op without a
     * connected gateway or a minted handle.
     */
    suspend fun refreshFediThreads() {
        val gw = gateway ?: return
        _fediThreads.value = runCatching { gw.fediThreadsOverview() }.getOrDefault(emptyList())
    }

    /**
     * Pull the current fediverse-person link table (linked + pending-invite)
     * from the engine into [personLinks]. Quiet on failure. No-op without a
     * connected gateway or a minted handle.
     */
    suspend fun refreshPersonLinks() {
        val gw = gateway ?: return
        _personLinks.value = runCatching { gw.fediPersonLinks() }.getOrDefault(emptyList())
    }

    /**
     * Opt in to public posting: mint + register the actor identity for
     * [handle]. Connects the gateway if needed. Directory-registration failure
     * is reported in the returned [MintOutcomeFfi], not thrown.
     */
    suspend fun fediMint(handle: String): MintOutcomeFfi = ensureGateway().fediMint(handle)

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
     * Leave a group from the conversation list -- self-removal only; the group
     * continues for everyone else. Refreshes the list against the engine's
     * actual membership, then rethrows a rejected leave so the caller can say
     * so. A sole admin (which a sole member always is) cannot leave: the
     * daemon rejects it and [deleteGroup] is the way out.
     */
    suspend fun leaveGroup(groupId: String) {
        leaveGroupVia(gateway, groupId) { refreshGroups() }
    }

    /**
     * Delete a group for everyone (terminal withdrawal commit), then refresh.
     * Admin-only -- the daemon authorizes and a refusal propagates.
     * Irreversible.
     */
    suspend fun deleteGroup(groupId: String) {
        deleteGroupVia(gateway, groupId) {
            // Record BEFORE the refresh: the daemon still lists the withdrawn
            // group as a tombstone, so the filter has to be in place for the
            // very refresh that follows the delete.
            SettingsStore(appContext).addDeletedGroup(groupId)
            refreshGroups()
        }
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
        val fetched = try {
            gw.listGroups()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w("fetchit.chat", "listGroups failed on connect", e)
            return
        }
        // x0xd keeps a keyless tombstone for a deleted (withdrawn) group and
        // still lists it, with no `withdrawn` field to read -- so a group we
        // deleted would keep its row forever. The delete is real server-side;
        // this only drops the tombstone from the list.
        val deleted = SettingsStore(appContext).deletedGroupIds()
        val loaded = if (deleted.isEmpty()) {
            fetched
        } else {
            fetched.filterNot { it.groupId in deleted }
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
     * Rebuild the gateway after the default network changed identity
     * (Wi-Fi to cellular, cellular to Wi-Fi, one Wi-Fi to another).
     *
     * An identity change kills established TCP flows, but the pump has no
     * in-loop reconnect in v1 and often keeps reading RUNNING against the
     * dead socket -- so [ensureGateway]'s fast path would happily return a
     * gateway that can neither send nor receive, and outbox sends queue
     * forever with no tick (caught on-device 2026-07-29: first meshless
     * foreground send after a Wi-Fi-off flip). Tear down unconditionally
     * and rebuild; the reconnect reads [MeshPolicy.active] fresh, so a
     * flip to mobile data comes back meshless and a flip to Wi-Fi comes
     * back meshless too until the policy's rise debounce promotes it.
     *
     * No-op when chat was never connected -- a network event must not
     * construct the runtime. Failures are logged and left for the next
     * recovery edge (another network change, foreground reconnect, or
     * nav-away+back); state after a failed rebuild is a clean disconnect.
     */
    suspend fun rebuildGatewayOnNetworkChange() {
        val gw = gateway ?: return
        // Reconnect ONLY the relay session in place. The full rebuild below
        // tears down the whole client -- engine, embedded daemon, pumps --
        // and a phone crossing networks repeatedly stacked engines until
        // Android's low-memory killer shot the process (2026-08-02). The
        // in-place swap verifies the fresh session live BEFORE draining
        // the old one, so a thrown error means nothing changed and the
        // full rebuild below is a safe fallback.
        try {
            gw.reconnectRelay()
            android.util.Log.i("fetchit.chat", "relay reconnected in place after network change")
            return
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w(
                "fetchit.chat",
                "in-place relay reconnect failed; falling back to full rebuild",
                e,
            )
        }
        disconnect()
        try {
            ensureGateway()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.w("fetchit.chat", "gateway rebuild after network change failed", e)
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
        pendingJoinPump?.cancel()
        pendingJoinPump = null
        _pendingJoins.value = emptyList()
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

        /** Prefs key holding the JSON-encoded persisted feed ([FeedSerde]). */
        private const val FEED_KEY = "feed_posts_v1"

        /** [DataTripwire] sampling cadence; coarse is fine against a 50MB budget. */
        private const val TRIPWIRE_SAMPLE_MS: Long = 60_000

        private const val DAY_MS: Long = 24 * 60 * 60 * 1000
        private const val MB: Long = 1024 * 1024
        private const val DATA_CHANNEL_ID = "data_protection"
        private const val DATA_NOTIFICATION_ID = 7401

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
            // Raw inbound-message tap for the notification layer: fired for
            // every Dm / GroupMessage BEFORE any notify policy — the sink
            // (ChatForegroundService) applies `shouldNotify` with the live
            // self/visible-conversation state the pump cannot see.
            //
            // Invoked ONLY through [notifySink], never directly: the sink is a
            // bystander and must not be able to kill delivery.
            onInbound: (io.etchit.fetchit.chat.notify.InboundNotify) -> Unit = {},
        ): Job = scope.launch {
            // The pump is the sole feed for the conversation stores, so an
            // exception escaping the notification sink stops inbound chat dead
            // until the app restarts — silently, which is the worst failure
            // this app can have. Contain it here: a broken notifier costs a
            // notification, never a message. (Shipped un-contained on
            // 2026-07-26; device stopped receiving after the first throw.)
            fun notifySink(inbound: io.etchit.fetchit.chat.notify.InboundNotify) {
                try {
                    onInbound(inbound)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    logWarn("inbound notify sink failed", e)
                }
            }
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
                    is ChatEventFfi.Dm -> {
                        convo.append(
                            ConversationStore.convKeyDm(ev.fromAgentIdHex),
                            ChatMessage(
                                outbound = false,
                                body = ev.body,
                                sentAtMs = System.currentTimeMillis(),
                                messageId = ev.messageId,
                            ),
                        )
                        notifySink(
                            io.etchit.fetchit.chat.notify.InboundNotify(
                                convKey = ConversationStore.convKeyDm(ev.fromAgentIdHex),
                                kind = io.etchit.fetchit.chat.notify.InboundKind.DM,
                                senderAgentIdHex = ev.fromAgentIdHex,
                                senderLabel = null,
                                body = ev.body,
                                messageId = ev.messageId.orEmpty(),
                            ),
                        )
                    }
                    is ChatEventFfi.GroupMessage -> {
                        convo.append(
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
                        notifySink(
                            io.etchit.fetchit.chat.notify.InboundNotify(
                                convKey = ConversationStore.convKeyGroup(ev.groupId),
                                kind = io.etchit.fetchit.chat.notify.InboundKind.GROUP,
                                senderAgentIdHex = ev.fromAgentIdHex,
                                senderLabel = ev.senderName,
                                body = ev.body,
                                messageId = ev.messageId.orEmpty(),
                            ),
                        )
                    }
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
            // Reconcile the list either way, then RETHROW a real failure. The
            // daemon rejects a last-admin leave (ADR-0016 409), and the row
            // legitimately stays -- so swallowing here made the caller report
            // "left <group>" over a group that never went anywhere.
            var failure: Exception? = null
            try {
                gw.leaveGroup(groupId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logWarn("leaveGroup failed", e)
                failure = e
            }
            refresh()
            failure?.let { throw it }
        }

        /**
         * Ask [gw] to delete [groupId] for everyone (terminal withdrawal),
         * then [refresh]. Unlike [leaveGroupVia] there is no swallow at all:
         * a delete that the daemon refused (e.g. `403` when not an admin)
         * must reach the user. No-op when [gw] is `null`.
         */
        suspend fun deleteGroupVia(
            gw: ChatGateway?,
            groupId: String,
            refresh: suspend () -> Unit,
        ) {
            if (gw == null) return
            gw.deleteGroup(groupId)
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
                    // matching the live pump. A blank persisted id is NOT an
                    // agent id — a fediverse sender has none — so it reads as
                    // "no attribution" rather than rendering a bare "agent-"
                    // label and a per-identity bubble stripe.
                    senderAgentIdHex = if (h.outbound) {
                        null
                    } else {
                        h.fromAgentIdHex.takeIf { it.isNotBlank() }
                    },
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
         *
         * A bubble carrying a [OutboxBubbleFfi.groupClientMessageId] is one
         * per-member fan-out copy of a queued GROUP message, not a DM —
         * upserting it by `peerAgentIdHex` would fabricate a phantom DM thread
         * with that member. Instead it backs the ONE message in the group
         * thread: the first copy to reach the relay flips that message's
         * delivery tick (honest "sent"); Sending/Failed copies leave the
         * queued clock in place while the engine outbox keeps retrying.
         */
        fun projectOutbox(convo: ConversationStore, bubble: OutboxBubbleFfi) {
            val groupAnchor = bubble.groupClientMessageId
            if (groupAnchor != null) {
                if (bubble.status == OutboxStatusFfi.DELIVERED) {
                    convo.markDelivered(groupAnchor)
                }
                return
            }
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
