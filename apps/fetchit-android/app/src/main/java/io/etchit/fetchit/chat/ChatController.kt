package io.etchit.fetchit.chat

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONObject
import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi
import java.io.File

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

    /**
     * Returns the active [ChatGateway], connecting to [DEFAULT_RELAY] on first
     * call. Subsequent calls are cheap (cached). Thread-safe via `@Volatile`
     * read + coroutine suspension on the connect path.
     */
    suspend fun ensureGateway(): ChatGateway {
        gateway?.let { return it }
        val dataDir = File(appContext.filesDir, "chat").apply { mkdirs() }
        val client = ChatClient.connect(
            DEFAULT_RELAY,
            dataDir.absolutePath,
            ChatSecrets(appContext).vaultPass(),
        )
        val gw = FfiChatGateway(client)
        gateway = gw
        pump = pumpEvents(gw, conversations, feed, scope)
        return gw
    }

    /**
     * Drop the relay connection and cancel the event pump.
     * Safe to call when the gateway was never started (no-op).
     * [ensureGateway] can reconnect after this.
     */
    fun disconnect() {
        gateway?.disconnect()
        gateway = null
        pump?.cancel()
        pump = null
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
        ): Job = scope.launch {
            while (true) {
                val ev = runCatching { gw.nextEvent() }.getOrNull() ?: break
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
                }
            }
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
    }
}
