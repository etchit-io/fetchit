package io.etchit.fetchit.chat

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi
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
        gateway?.let { return it }
        connectMutex.withLock {
            gateway?.let { return it }
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
            return gw
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

        /** Default relay URL. Region override is wired via the settings sheet in a later task. */
        const val DEFAULT_RELAY = "http://67.207.94.66:8088"

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
                        ev.fromAgentIdHex,
                        ChatMessage(
                            outbound = false,
                            body = ev.body,
                            sentAtMs = System.currentTimeMillis(),
                            messageId = ev.messageId,
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
