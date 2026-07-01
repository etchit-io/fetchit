# Android LIT P1 - 2-in-1 Shell (Browse + Chat) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a chat mode to the fetch>it Android viewer on the P0 `ChatClient` FFI: QR/URI pairing, 1:1 text DMs with receipt ticks, a pinned fediverse feed channel, and a one-tap mode switch, with zero clutter added to browse mode.

**Architecture:** The app stays single-activity, View-based, visibility-toggle (no fragments, no Compose). A `Mode` enum + `setMode()` in MainActivity swaps between the existing browse surfaces and one new `chatContainer`; chat's three screens (list / thread / add) live behind a `ChatModeView` orchestrator with its own back-stack. The FFI is wrapped behind a `ChatGateway` interface so the controller + stores are Robolectric-testable without a device or relay. Approved UX: DMs-only, text-only, copper chevron as the mode switch, fediverse read-feed as a pinned channel (Josh 2026-06-12).

**Tech Stack:** Kotlin, viewBinding, Material 1.12, kotlinx-coroutines, uniffi bindings (`uniffi.fetchit_ffi.ChatClient`), zxing-android-embedded (existing), JUnit4 + Robolectric 4.14 (existing test deps).

---

## Context for the implementer (read first)

- Worktree: `/home/josh/Desktop/etchit-fetchit/fetchit-android-lit` (branch `android-lit`). All paths below are relative to `apps/fetchit-android/`. Never run cargo in `/home/josh/Desktop/etchit-fetchit/fetchit`.
- Commits: DCO (`git commit -s`), conventional style, NO em-dashes in messages.
- The generated bindings (read them first): `app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt` defines `ChatClient.Companion.connect(relayUrl, dataDir, passphrase)` (suspend, throws `ChatFfiException`), `agentIdHex(): String`, `suspend pairShareUri(): String`, `suspend importPairUri(uri: String)`, `suspend sendDm(toAgentIdHex, body, senderName): String?`, `suspend nextEvent(): ChatEventFfi?`, `disconnect()`. `ChatEventFfi` is a sealed class: `Dm(fromAgentIdHex, body, messageId)`, `Receipt(messageId)`, `PublicPost(verifiedActorUrl, activityJson: ByteArray)`. `ChatFfiException.Invalid(reason)` / `.Network(reason)`.
- Patterns to mirror (read each before its task): `BookmarkStore.kt` (SharedPreferences + StateFlow + serde object), `FetchitApplication.kt` (`ensureConnected` cached-client pattern, `IdleDisconnect` observer), `MainActivity.kt` scanLauncher (lines ~201-218) + `onScanClicked` (~671), `QrShare.renderCardFor(address, label)`, `RenditionRenderer.clear()` visibility-toggle idiom, `themes.xml`/`colors.xml` (`copper #c9732b`, `ink #0a0a0a`, `bone #f5f2eb`; attrs `?attr/fetchitInk` etc.).
- Run unit tests: `./gradlew :app:testDebugUnitTest --tests '<pattern>'` from `apps/fetchit-android/`. Build: `./gradlew :app:assembleDebug`.
- Default relay for v1: `http://67.207.94.66:8088` (NYC), constant in `ChatController`; region override rides the existing settings sheet later, not in this plan.
- Strings are centralized in `res/values/strings.xml`; every user-visible literal goes there.

## File structure

| File | Responsibility |
|---|---|
| `app/src/main/java/io/etchit/fetchit/chat/ChatContact.kt` (new) | Contact data class + JSON serde object |
| `.../chat/ChatContactStore.kt` (new) | Persisted contacts (SharedPreferences + StateFlow), BookmarkStore mirror |
| `.../chat/ChatMessage.kt` (new) | In-memory message model (direction, body, ts, messageId, delivered) |
| `.../chat/ConversationStore.kt` (new) | In-memory per-peer message lists + receipt marking, StateFlow |
| `.../chat/ChatGateway.kt` (new) | Interface over the FFI surface + `FfiChatGateway` adapter |
| `.../chat/ChatSecrets.kt` (new) | One-time random vault passphrase in app-private prefs |
| `.../chat/ChatController.kt` (new) | Owns gateway lifecycle + event pump; routes events into stores |
| `.../chat/ChatModeView.kt` (new) | Chat screen orchestrator (list/thread/add) + chat back-stack |
| `.../FetchitApplication.kt` (modify) | Holds the singleton `ChatController` |
| `.../MainActivity.kt` (modify) | `Mode` enum, `setMode()`, switch buttons, per-mode back/refresh, x0x://pair deep link |
| `app/src/main/res/layout/activity_main.xml` (modify) | `modeChatButton`, `modeBrowseButton`, `chatContainer` + included chat layouts |
| `app/src/main/res/layout/view_chat_list.xml`, `view_chat_thread.xml`, `item_chat_contact.xml`, `item_chat_message.xml` (new) | Chat screens |
| `res/values/strings.xml` (modify) | All chat strings |
| Tests: `app/src/test/java/io/etchit/fetchit/chat/ChatContactStoreTest.kt`, `ConversationStoreTest.kt`, `ChatControllerTest.kt` (new) | Robolectric/JUnit |

---

### Task 1: ChatContact + ChatContactStore (persisted, observable)

**Files:** Create `chat/ChatContact.kt`, `chat/ChatContactStore.kt`, test `app/src/test/java/io/etchit/fetchit/chat/ChatContactStoreTest.kt`.

- [ ] **Step 1: Failing test** (Robolectric, mirror any existing store test style; if none exists this is the first):

```kotlin
package io.etchit.fetchit.chat

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ChatContactStoreTest {
    private fun store() = ChatContactStore(ApplicationProvider.getApplicationContext())

    @Test
    fun addPersistsAcrossInstances() {
        val a = store()
        a.add(ChatContact(agentIdHex = "a".repeat(64), displayName = "alice", addedAtMs = 1L))
        val b = store()
        assertEquals(1, b.contacts.value.size)
        assertEquals("alice", b.contacts.value.first().displayName)
    }

    @Test
    fun addDedupesOnAgentIdKeepingNewestName() {
        val s = store()
        s.add(ChatContact("b".repeat(64), "old", 1L))
        s.add(ChatContact("b".repeat(64), "new", 2L))
        assertEquals(1, s.contacts.value.size)
        assertEquals("new", s.contacts.value.first().displayName)
    }

    @Test
    fun deleteRemoves() {
        val s = store()
        s.add(ChatContact("c".repeat(64), "x", 1L))
        s.delete("c".repeat(64))
        assertTrue(s.contacts.value.isEmpty())
    }
}
```

- [ ] **Step 2:** Run `./gradlew :app:testDebugUnitTest --tests '*ChatContactStoreTest*'` from `apps/fetchit-android/`. Expected: compile FAIL (types missing). If `androidx.test.core` is not a test dep, add `testImplementation("androidx.test:core-ktx:1.6.1")`.

- [ ] **Step 3: Implement.** `ChatContact.kt`:

```kotlin
package io.etchit.fetchit.chat

import org.json.JSONArray
import org.json.JSONObject

/** A paired peer. agentIdHex is the stable identity key (lowercase 64-hex). */
data class ChatContact(
    val agentIdHex: String,
    val displayName: String,
    val addedAtMs: Long,
)

/** JSON serde for the contacts pref blob, versioned like BookmarkSerde. */
object ChatContactSerde {
    fun encode(list: List<ChatContact>): String {
        val arr = JSONArray()
        list.forEach { c ->
            arr.put(JSONObject().put("agent", c.agentIdHex).put("name", c.displayName).put("added", c.addedAtMs))
        }
        return arr.toString()
    }

    fun decode(raw: String?): List<ChatContact> {
        if (raw.isNullOrBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ChatContact(o.getString("agent"), o.getString("name"), o.optLong("added"))
            }
        }.getOrDefault(emptyList())
    }
}
```

`ChatContactStore.kt` (mirror BookmarkStore exactly: prefs name `"fetchit_contacts"`, key `"contacts_v1"`, `MutableStateFlow(load())`, `write()` persists then updates flow). `add` replaces any entry with the same `agentIdHex` (dedupe), sorted newest-first. `delete(agentIdHex)` filters. Include `rename(agentIdHex, newName)` (thread screen affordance later; cheap now).

- [ ] **Step 4:** Tests pass. **Step 5: Commit** `feat(android): ChatContact store (persisted, observable)`.

---

### Task 2: ConversationStore + ChatGateway + ChatSecrets + ChatController

**Files:** Create `chat/ChatMessage.kt`, `chat/ConversationStore.kt`, `chat/ChatGateway.kt`, `chat/ChatSecrets.kt`, `chat/ChatController.kt`; modify `FetchitApplication.kt`; tests `ConversationStoreTest.kt`, `ChatControllerTest.kt`.

- [ ] **Step 1: Failing tests.** `ConversationStoreTest.kt` (plain JUnit, no Robolectric needed):

```kotlin
package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConversationStoreTest {
    @Test
    fun appendThenReadBack() {
        val s = ConversationStore()
        s.append("a".repeat(64), ChatMessage(outbound = false, body = "hi", sentAtMs = 1L, messageId = "m1"))
        assertEquals("hi", s.messagesFor("a".repeat(64)).value.single().body)
    }

    @Test
    fun receiptMarksOutboundDelivered() {
        val s = ConversationStore()
        val peer = "b".repeat(64)
        s.append(peer, ChatMessage(outbound = true, body = "yo", sentAtMs = 1L, messageId = "m2"))
        s.markDelivered("m2")
        assertTrue(s.messagesFor(peer).value.single().delivered)
    }

    @Test
    fun unknownReceiptIsNoop() {
        val s = ConversationStore()
        s.markDelivered("nope")
    }
}
```

`ChatControllerTest.kt` (JUnit + kotlinx-coroutines-test; add `testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")` if absent) - uses a fake gateway:

```kotlin
package io.etchit.fetchit.chat

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.fetchit_ffi.ChatEventFfi

class FakeGateway : ChatGateway {
    val events = Channel<ChatEventFfi?>(capacity = 8)
    val sent = mutableListOf<Triple<String, String, String>>()
    override fun agentIdHex() = "f".repeat(64)
    override suspend fun pairShareUri() = "x0x://pair/${"f".repeat(64)}?r=relay"
    override suspend fun importPairUri(uri: String) {}
    override suspend fun sendDm(to: String, body: String, senderName: String): String? {
        sent += Triple(to, body, senderName); return "sent-1"
    }
    override suspend fun nextEvent(): ChatEventFfi? = events.receive()
    override fun disconnect() { events.trySend(null) }
}

class ChatControllerTest {
    @Test
    fun inboundDmLandsInConversation() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore())
        gw.events.send(ChatEventFfi.Dm("a".repeat(64), "hello", "m9"))
        gw.events.send(null) // pump exits on null
        pump.join()
        assertEquals("hello", convo.messagesFor("a".repeat(64)).value.single().body)
    }

    @Test
    fun receiptMarksDelivered() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        convo.append("a".repeat(64), ChatMessage(outbound = true, body = "x", sentAtMs = 1L, messageId = "m1"))
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore())
        gw.events.send(ChatEventFfi.Receipt("m1"))
        gw.events.send(null)
        pump.join()
        assertTrue(convo.messagesFor("a".repeat(64)).value.single().delivered)
    }

    @Test
    fun publicPostLandsInFeedAsPlainText() = runTest {
        val gw = FakeGateway()
        val feed = FeedStore()
        val pump = ChatController.pumpEvents(gw, ConversationStore(), feed)
        val activity = """{"object":{"content":"<p>hi <b>there</b></p>"}}""".toByteArray()
        gw.events.send(ChatEventFfi.PublicPost("https://m.example/u/x", activity))
        gw.events.send(null)
        pump.join()
        val post = feed.posts.value.single()
        assertEquals("hi there", post.body)
        assertEquals("https://m.example/u/x", post.actorUrl)
    }
}
```

- [ ] **Step 2:** Run both test classes. Expected: compile FAIL.

- [ ] **Step 3: Implement.**

`ChatMessage.kt`:
```kotlin
package io.etchit.fetchit.chat

/** One message in a 1:1 thread. In-memory only for v1 (mirrors desktop ephemerality). */
data class ChatMessage(
    val outbound: Boolean,
    val body: String,
    val sentAtMs: Long,
    val messageId: String?,
    val delivered: Boolean = false,
)

/** One bridged fediverse post, already reduced to plain text. */
data class FeedPost(val actorUrl: String, val body: String, val receivedAtMs: Long = 0L)
```

`ConversationStore.kt`: `private val byPeer = mutableMapOf<String, MutableStateFlow<List<ChatMessage>>>()` guarded by a lock; `messagesFor(peer): StateFlow<List<ChatMessage>>` (creates empty flow on demand); `append(peer, msg)`; `markDelivered(messageId)` scans all peers and copies the matching outbound message with `delivered = true`; `peersWithTraffic(): List<String>`. `FeedStore` in the same file: `MutableStateFlow<List<FeedPost>>`, `append(post)` capped at 200 newest.

`ChatGateway.kt`:
```kotlin
package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.ChatClient
import uniffi.fetchit_ffi.ChatEventFfi

/** Seam over the uniffi surface so controller + UI are testable without a relay. */
interface ChatGateway {
    fun agentIdHex(): String
    suspend fun pairShareUri(): String
    suspend fun importPairUri(uri: String)
    suspend fun sendDm(to: String, body: String, senderName: String): String?
    suspend fun nextEvent(): ChatEventFfi?
    fun disconnect()
}

class FfiChatGateway(private val inner: ChatClient) : ChatGateway {
    override fun agentIdHex() = inner.agentIdHex()
    override suspend fun pairShareUri() = inner.pairShareUri()
    override suspend fun importPairUri(uri: String) = inner.importPairUri(uri)
    override suspend fun sendDm(to: String, body: String, senderName: String) = inner.sendDm(to, body, senderName)
    override suspend fun nextEvent() = inner.nextEvent()
    override fun disconnect() = inner.disconnect()
}
```

`ChatSecrets.kt`: prefs `"fetchit_chat_secrets"`, key `"vault_pass_v1"`; on first read generate 32 bytes via `java.security.SecureRandom`, hex-encode, persist. Doc comment: app-private storage; Android Keystore wrapping is the designated follow-up; the vault itself is Argon2id-sealed by the Rust layer.

`ChatController.kt`:
```kotlin
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
 * Process-scoped chat runtime: caches the gateway (FetchitApplication
 * ensureConnected pattern), runs the event pump, owns the stores.
 */
class ChatController(private val appContext: Context, private val scope: CoroutineScope) {
    val contacts = ChatContactStore(appContext)
    val conversations = ConversationStore()
    val feed = FeedStore()

    @Volatile private var gateway: ChatGateway? = null
    private var pump: Job? = null

    suspend fun ensureGateway(): ChatGateway {
        gateway?.let { return it }
        val dataDir = File(appContext.filesDir, "chat").apply { mkdirs() }
        val client = ChatClient.connect(DEFAULT_RELAY, dataDir.absolutePath, ChatSecrets(appContext).vaultPass())
        val gw = FfiChatGateway(client)
        gateway = gw
        pump = pumpEvents(gw, conversations, feed, scope)
        return gw
    }

    fun disconnect() {
        gateway?.disconnect()
        gateway = null
        pump?.cancel()
        pump = null
    }

    companion object {
        const val DEFAULT_RELAY = "http://67.207.94.66:8088"

        /** Drain nextEvent() until it returns null; route each event. Exposed for tests. */
        fun pumpEvents(
            gw: ChatGateway,
            convo: ConversationStore,
            feed: FeedStore,
            scope: CoroutineScope = kotlinx.coroutines.GlobalScope,
        ): Job = scope.launch {
            while (true) {
                val ev = runCatching { gw.nextEvent() }.getOrNull() ?: break
                when (ev) {
                    is ChatEventFfi.Dm -> convo.append(
                        ev.fromAgentIdHex,
                        ChatMessage(outbound = false, body = ev.body, sentAtMs = System.currentTimeMillis(), messageId = ev.messageId),
                    )
                    is ChatEventFfi.Receipt -> convo.markDelivered(ev.messageId)
                    is ChatEventFfi.PublicPost -> decodePost(ev)?.let(feed::append)
                }
            }
        }

        /** UNTRUSTED input: parse activity JSON, take object.content, strip ALL tags to plain text. */
        fun decodePost(ev: ChatEventFfi.PublicPost): FeedPost? = runCatching {
            val json = JSONObject(String(ev.activityJson, Charsets.UTF_8))
            val content = json.optJSONObject("object")?.optString("content").orEmpty()
            val plain = android.text.Html.fromHtml(content, android.text.Html.FROM_HTML_MODE_LEGACY).toString().trim()
            if (plain.isEmpty()) null else FeedPost(ev.verifiedActorUrl, plain, System.currentTimeMillis())
        }.getOrNull()
    }
}
```
NOTE for the test: `Html.fromHtml` needs Robolectric, OR make `decodePost` accept an injectable `(String) -> String` html-stripper and default it; in plain-JUnit tests pass a regex stripper. Implementer picks the cleaner of the two; the test asserting `"hi there"` must pass without a device. The `GlobalScope` default is test-only convenience; production always passes the app scope - if clippy-equivalent (detekt absent) noise arises, require the scope parameter instead and update tests.

`FetchitApplication.kt`: add `val chatController: ChatController by lazy { ChatController(this, ProcessLifecycleOwner.get().lifecycleScope) }` (or an application-owned `CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)` if ProcessLifecycleOwner's scope is unavailable; match what compiles cleanly). Wire `IdleDisconnect`'s existing disconnect callback to ALSO call `chatController.disconnect()` only if chat was started (null-safe).

- [ ] **Step 4:** All Task-2 tests pass. **Step 5: Commit** `feat(android): chat controller, gateway seam, conversation + feed stores`.

---

### Task 3: Mode switch (layout + MainActivity integration)

**Files:** Modify `app/src/main/res/layout/activity_main.xml`, `MainActivity.kt`, `res/values/strings.xml`.

- [ ] **Step 1: Layout.** In `activity_main.xml`:
  (a) Add to the browse top bar, left of `scanButton` (same size/style as the existing glyph buttons): a `modeChatButton` (`TextView`/`Button` matching `scanButton`'s style verbatim) with `android:text="@string/mode_chat_glyph"`.
  (b) Add `chatContainer`: a full-bleed `FrameLayout` sibling AFTER the SwipeRefreshLayout inside the CoordinatorLayout, `android:visibility="gone"`, background `?attr/fetchitInk`. Chat screens are inflated into it by `ChatModeView` (Task 4); this task only creates the empty container plus a chat top bar inside it: app label `TextView` ("chat") left, and `modeBrowseButton` top-right with `android:text="@string/mode_browse_glyph"` and `android:textColor="@color/copper"` (the brand chevron doing real work).
  (c) strings.xml: `<string name="mode_chat_glyph">✉</string>` (placeholder glyph, swap candidate on device review), `<string name="mode_browse_glyph">❯</string>` (❯ copper chevron), `<string name="chat_mode_label">chat</string>`.

- [ ] **Step 2: MainActivity.** Add:

```kotlin
private enum class Mode { BROWSE, CHAT }
private var currentMode = Mode.BROWSE

private fun setMode(mode: Mode) {
    if (mode == currentMode) return
    currentMode = mode
    val browse = mode == Mode.BROWSE
    binding.swipeRefresh.isEnabled = browse           // landmine: pull-to-refresh is browse-only
    binding.swipeRefresh.visibility = if (browse) View.VISIBLE else View.GONE
    binding.chatContainer.visibility = if (browse) View.GONE else View.VISIBLE
    if (!browse) chatModeView.onShown()               // Task 4; no-op stub in this task
}
```
(Adapt the SwipeRefreshLayout binding id to the actual one in the layout - read it.) Wire `modeChatButton.setOnClickListener { setMode(Mode.CHAT) }` and `modeBrowseButton.setOnClickListener { setMode(Mode.BROWSE) }` in `onCreate`. Back handling (landmine): in the existing `backCallback`, FIRST branch on mode - `if (currentMode == Mode.CHAT) { if (!chatModeView.onBack()) setMode(Mode.BROWSE); return }` (stub `chatModeView.onBack() = false` this task), then the existing browse back-stack logic unchanged. Persist nothing about mode in this task (last-used-mode persistence is Step 4 of Task 6).

- [ ] **Step 3:** `./gradlew :app:assembleDebug` compiles; manual smoke deferred to Task 7. A Robolectric test is impractical for visibility wiring here; correctness rides on Task 7's device checklist. **Step 4: Commit** `feat(android): two-mode shell, chevron switch, per-mode back handling`.

---

### Task 4: Chat screens - conversation list + add contact + empty-state onboarding

**Files:** Create `chat/ChatModeView.kt`, `res/layout/view_chat_list.xml`, `res/layout/item_chat_contact.xml`; modify `MainActivity.kt` (instantiate), `strings.xml`.

- [ ] **Step 1: Layouts.** `view_chat_list.xml`: vertical LinearLayout - RecyclerView (`chatContactList`, 1f weight) + a Material extended FAB or bottom-right button `addContactButton` (`@string/chat_add_contact` = "add contact"). `item_chat_contact.xml`: horizontal row, monospace short-id `TextView` (first 8 hex + "…"), display name `TextView` (bone), last-message preview `TextView` (ash, single line, ellipsize). Empty state (when no contacts): a centered vertical block inside `view_chat_list.xml` (`chatEmptyState`): an `ImageView` (`chatPairQr`) for the QR card, a `TextView` `@string/chat_empty_hint` = "scan a friend's code, or share yours", and two buttons: `sharePairButton` ("share my code"), `scanPairButton` ("scan a code"). The pinned **Fediverse channel** is row zero of the list adapter whenever the feed has posts OR always (decide: always, label `@string/chat_feed_title` = "fediverse", ash-colored glyph row) - tapping opens the feed thread (Task 5).

- [ ] **Step 2: `ChatModeView.kt`.** A class owning `chatContainer`: inflates list/thread views lazily, holds `screenStack: ArrayDeque<Screen>` (`sealed class Screen { List; Thread(peer); Feed }`), `onBack(): Boolean` pops (returns false when stack is at List), `onShown()` triggers `ensureGateway()` via `lifecycleScope.launch` with a connecting state on the empty view (`@string/chat_connecting` = "connecting…"; on `ChatFfiException` show Snackbar with `.reason` and a retry button). Wire:
  - contact list adapter observing `controller.contacts.contacts` + `controller.conversations` flows (`repeatOnLifecycle` or `lifecycleScope.launch { flow.collect { adapter.submit(...) } }` - match the app's existing collect idiom; if none exists, use `lifecycleScope.launch` + `flowWithLifecycle`).
  - `sharePairButton`: `launch { val uri = gateway.pairShareUri(); QrShare-style render }` - reuse `QrShare.renderCardFor(uri, label = "fetch>it chat")` into `chatPairQr` ImageView, plus a long-press copy of the raw URI (`ClipboardManager`, Snackbar `@string/chat_uri_copied` = "copied"). On publish failure (`ChatFfiException.Network` - the prod-404 case until the relay redeploy) show the honest error Snackbar, never a URI.
  - `scanPairButton`: reuse the EXISTING scanLauncher pattern but route results: if scanned text starts with `x0x://pair/` call `importPairUri`, then prompt for a display name (MaterialAlertDialog with one EditText, default "peer-<first 6 hex>") and `contacts.add(...)`, then open the Thread screen. MainActivity's existing scanLauncher callback gains the `x0x://pair/` branch BEFORE the autonomi parse (deep-link landmine: keep autonomi routing untouched).
  - `addContactButton`: dialog with paste field accepting `x0x://pair/...` URIs - same import path as scan.

- [ ] **Step 3:** Compile + commit `feat(android): chat list, QR pair onboarding, add-contact flows`.

---

### Task 5: Thread view - bubbles, send box, ticks, browse bridge

**Files:** Create `res/layout/view_chat_thread.xml`, `res/layout/item_chat_message.xml`; extend `ChatModeView.kt`; `strings.xml`.

- [ ] **Step 1: Layouts.** `view_chat_thread.xml`: header row (back glyph `threadBackButton` "‹", peer name, short id), RecyclerView `messageList` (stackFromEnd), send row (EditText `messageInput` + send button `sendButton` text `@string/chat_send_glyph` = "➤" copper). `item_chat_message.xml`: a single `TextView` bubble (maxWidth ~80%, rounded bg drawable: outbound = copper-tinted `#33c9732b` right-aligned, inbound = `ink_3` left-aligned - two background drawables `bg_bubble_out.xml`/`bg_bubble_in.xml` with 16dp corner radius) + a tiny meta `TextView` (time + tick: "✓" when `delivered`, nothing otherwise, ash color).

- [ ] **Step 2: Wiring in `ChatModeView`.** Thread screen for `peer`: adapter observes `conversations.messagesFor(peer)`; send: `launch { val id = gateway.sendDm(peer, body, senderName = displayNameOrDefault()); conversations.append(peer, ChatMessage(outbound = true, body, now, id)) }` with the input cleared optimistically and restored on `ChatFfiException` (Snackbar with reason). `displayNameOrDefault()`: SettingsStore gains `chatDisplayName()` defaulting to `"agent-" + gateway.agentIdHex().take(6)` (add `saveChatDisplayName`; surface in the existing settings sheet as one EditText row labeled `@string/chat_display_name` = "chat display name"). **Browse bridge:** linkify `autonomi://[0-9a-f]{64}` in inbound bubbles (Linkify custom pattern or clickable span); tap → `setMode(Mode.BROWSE)` + `loadAddress(...)` via a callback MainActivity passes into ChatModeView (`onOpenAutonomi: (String) -> Unit`).
  The **Feed screen** (`Screen.Feed`): same thread layout, no send row (hide it), adapter over `feed.posts` rendering `actorUrl` as the meta line and `body` as inbound-style bubbles. Strictly plain text (the store already stripped HTML).

- [ ] **Step 3:** Compile + commit `feat(android): thread view with receipt ticks, feed channel, autonomi browse bridge`.

---

### Task 6: Deep link, last-mode persistence, settings row

**Files:** Modify `MainActivity.kt` (`handleViewIntent`), `AndroidManifest.xml`, `SettingsStore.kt`, `strings.xml`.

- [ ] **Step 1:** Manifest: add to MainActivity's existing deep-link intent-filter set a new `<intent-filter>` with `<data android:scheme="x0x" android:host="pair" .../>` (mirror the autonomi filter shape; VIEW + BROWSABLE + DEFAULT).
- [ ] **Step 2:** `handleViewIntent`: BEFORE the autonomi branch, `if (uri.scheme == "x0x" && uri.host == "pair") { setMode(Mode.CHAT); chatModeView.importFromUri(uri.toString()); return }` where `importFromUri` runs the Task-4 import flow (connect first if needed).
- [ ] **Step 3:** `SettingsStore`: `lastMode()/saveLastMode(...)` (string pref "mode", values "browse"/"chat", default "chat" ONLY on true first run when no pref exists AND no bookmarks exist - otherwise "browse"; rationale: brief says first run opens Chat whose empty state is onboarding, but existing users with bookmarks should keep waking in browse). `onCreate` applies it; `setMode` persists it.
- [ ] **Step 4:** Compile + commit `feat(android): x0x pair deep link, last-mode persistence, chat display name setting`.

---

### Task 7: Build, lint, device smoke checklist

- [ ] **Step 1:** `./gradlew :app:testDebugUnitTest` - all unit tests green. `./gradlew :app:lintDebug 2>&1 | tail -20` - no NEW errors vs the pre-P1 baseline (run lint on the parent commit if unsure what is pre-existing).
- [ ] **Step 2:** `./gradlew :app:assembleDebug` - APK builds. Report APK size vs the last release (the 38M .so will dominate; expected ~40-45M APK).
- [ ] **Step 3:** Write the device-smoke checklist to `docs/superpowers/plans/2026-06-12-p1-device-smoke.md` (for Josh's phone, two-device pairing happens with the desktop as the second peer): install via `adb install -r`; cold-open lands in chat empty state with QR card or honest "publish failed" note (pre-redeploy state); chevron flips to browse, browse unchanged end-to-end (fetch a known address); flip back retains chat state; back gesture: thread→list→browse; share-code long-press copies; paste-import a desktop pair URI; DM round-trip desktop↔phone with ticks; autonomi:// link in a DM opens browse; rotation does not lose mode or thread.
- [ ] **Step 4:** Commit `chore(android): P1 gates + device smoke checklist`, then run the full repo gates from the worktree root (`cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace 2>&1 | tail -3; echo EXIT:${PIPESTATUS[0]}`) to confirm nothing Rust-side drifted, and push the branch.

## Deferred (explicitly NOT in this plan)
Foreground service for background receive (specialUse FGS: needs Play declaration; lands as its own plan once the in-foreground loop is device-proven - a deliberate deviation from the brief's P1 line, flagged to Josh), message-history persistence, image attachments, presence, contact-list FFI accessor (Kotlin store suffices for v1), relay region picker UI, fediverse publishing.

Shipped as same-day fast-follows after this plan: branded QR card for pair URIs (Task 4 review M1) and the share-from-browse "send in chat" bridge (the brief's "only if cheap, else first fast-follow").
