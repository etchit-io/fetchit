package io.etchit.fetchit.chat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.text.SpannableString
import android.text.Spanned
import android.text.format.DateUtils
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.TextView
import androidx.lifecycle.LifecycleOwner
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import io.etchit.fetchit.QrShare
import io.etchit.fetchit.R
import io.etchit.fetchit.SettingsStore

import io.etchit.fetchit.fetchitApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.fetchit_ffi.ChatFfiException
import uniffi.fetchit_ffi.GroupFfi
import uniffi.fetchit_ffi.GroupMemberFfi
import uniffi.fetchit_ffi.JoinOutcomeFfi
import uniffi.fetchit_ffi.LinkOfferPreviewFfi
import uniffi.fetchit_ffi.LookupFfi
import uniffi.fetchit_ffi.LookupKindFfi
import uniffi.fetchit_ffi.MintRegistrationFfi
import uniffi.fetchit_ffi.enrollConfirmedDevice
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Orchestrates the chat screens (list / thread / feed) and owns the
 * chat back-stack within [container].
 *
 * The persistent chat top bar lives directly in [container]; all screen
 * inflation and swapping happens exclusively inside [slot] (chatScreenSlot),
 * so the top bar is never destroyed by removeAllViews() calls.
 *
 * @param context the host Activity context
 * @param container the chatContainer FrameLayout from activity_main.xml
 * @param controller the process-scoped [ChatController]
 * @param lifecycleScope the Activity's lifecycleScope for flow collection
 * @param lifecycleOwner the Activity's lifecycle owner
 * @param onLaunchScanner invoked when the user taps "scan a code"; caller
 *   launches the ZXing scanner and routes results to [importFromUri]
 * @param onOpenAutonomi invoked when a thread link taps an autonomi address;
 *   caller switches to browse mode and loads it (Task 5 wires this)
 */
class ChatModeView(
    private val context: Context,
    private val container: FrameLayout,
    private val controller: ChatController,
    private val lifecycleScope: CoroutineScope,
    private val lifecycleOwner: LifecycleOwner,
    private val onLaunchScanner: () -> Unit,
    private val onOpenAutonomi: (String) -> Unit = {},
) {

    // The dedicated screen-swap surface inside chatContainer.
    // All inflate/add/removeAllViews operations target this slot,
    // leaving the persistent top bar untouched.
    private val slot: FrameLayout =
        container.findViewById(R.id.chatScreenSlot)

    private sealed class Screen {
        // The three tab roots (bottom-nav). Roots never stack on each other.
        data object Chats : Screen()
        data object People : Screen()
        data object Feed : Screen()

        // Pushed screens — the tab bar hides while any of these is open.
        data class Thread(val peer: String) : Screen()
        data class GroupThread(val groupId: String) : Screen()
        data class FediThread(val handle: String) : Screen()
    }

    private val screenStack = ArrayDeque<Screen>()

    // The messaging tab bar, resolved from the persistent chat container.
    private val tabBar: com.google.android.material.bottomnavigation.BottomNavigationView =
        container.findViewById(R.id.chatTabBar)

    // wireTabs() attaches the selection listener exactly once.
    private var tabsWired = false

    // Lazily-inflated list view.
    private var listView: View? = null

    // Cached thread view — re-bound per peer rather than re-inflated.
    private var threadView: View? = null

    // Cached group-thread view — re-bound per group, mirrors threadView.
    private var groupThreadView: View? = null

    // Cached feed view.
    private var feedView: View? = null

    // Job for the active thread message-flow collector; cancelled on screen switch.
    private var threadCollectJob: Job? = null

    // Job for the feed post-flow collector; cancelled on screen switch.
    private var feedCollectJob: Job? = null

    // Jobs for the list-screen flow collectors (contacts+groups + pump state).
    // Launched exactly once behind the listView==null guard; stored here so
    // any future re-inflation path must cancel them first.
    private var listContactsJob: Job? = null
    private var listPumpStateJob: Job? = null
    private var listConnStatusJob: Job? = null
    private var linkConfirmJob: Job? = null

    /** Contact agent ids present at the time the list first loaded (the
     *  baseline). A NEW id appearing later, while a go-private invite is
     *  pending, is what triggers the human-confirmed "Same person?" link. */
    private val seenContactIds = HashSet<String>()

    /** Contacts we've already surfaced the link-confirm prompt for (accepted
     *  OR declined) — so a decline doesn't re-nag on every list emission. The
     *  contact-overflow re-open path covers change-of-mind. */
    private val linkPromptedIds = HashSet<String>()

    // Job for the active DM send; cancelled wherever threadCollectJob is cancelled.
    private var sendJob: Job? = null

    private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())

    /** Draws the `autonomi://` content cards under message and post bodies.
     *  Lazy so a session that never renders a body never builds it; the state
     *  it reads is process-scoped, not per-screen, so a previewed address
     *  stays previewed across conversations. */
    private val addressCards by lazy {
        AddressCardBinder(
            context = context,
            scope = lifecycleScope,
            states = context.fetchitApp().addressCards,
            onOpen = onOpenAutonomi,
        )
    }

    /** Draft handed over by [composeFeedPost] (the reader's "post to feed"),
     *  consumed by the next bind of the feed compose row. */
    private var pendingFeedCompose: String? = null

    /** Decoded fediverse profile pictures, keyed by canonical `user@host`. */
    private val fediAvatars = FediAvatars(
        (AVATAR_TARGET_DP * context.resources.displayMetrics.density).toInt(),
    )

    // ── fediverse avatars ──────────────────────────────────────────────

    /**
     * Paint [label]'s fediverse profile picture into [target] as a circle,
     * or leave the row exactly as it was when there is nothing to paint.
     *
     * Purely additive: the caller has already bound its placeholder (the 🌐
     * rail glyph, a monogram, a plain text line), and this either replaces
     * nothing or adds a circle beside it. Bytes come from the engine's
     * SSRF-guarded cache; a miss quietly asks the engine to fetch in the
     * background, so the next bind of the same row can succeed.
     *
     * [cacheOnly] is the private-row contract: it routes to the engine's
     * side-effect-free read and takes its own single-flight lane, so a LIT
     * row can never cause a fediverse request — not directly, and not by way
     * of a re-check that lands on the fetching call. See
     * [ChatGateway.fediAvatarCached] for why that matters.
     */
    private fun bindFediAvatar(target: ImageView, label: String, cacheOnly: Boolean = false) {
        // Recycled holders must never show the previous row's face.
        target.setImageDrawable(null)
        target.visibility = View.GONE
        if (label.isBlank()) return
        val key = FediAvatars.key(label)
        target.tag = key

        fediAvatars.cached(label)?.let { showCircle(target, key, it); return }

        val now = System.currentTimeMillis()
        if (!fediAvatars.shouldQuery(label, now, cacheOnly)) return
        lifecycleScope.launch {
            try {
                // Read AND decode off the main thread: a 512 KiB image is
                // real work, and a scroll must not stutter for a face.
                val bmp = withContext(Dispatchers.IO) {
                    val bytes = runCatching {
                        val gw = controller.gateway()
                        if (cacheOnly) gw?.fediAvatarCached(label) else gw?.fediAvatar(label)
                    }.getOrNull()
                    fediAvatars.decodeAndCache(label, bytes, System.currentTimeMillis(), cacheOnly)
                } ?: return@launch
                showCircle(target, key, bmp)
            } finally {
                // A screen closed mid-fetch must not strand the label.
                fediAvatars.releaseQuery(label, cacheOnly)
            }
        }
    }

    /**
     * A GONE-by-default circular avatar slot sized for a People/Feed row,
     * already bound to [label]. Handed straight to `addView`.
     */
    private fun fediAvatarSlot(label: String, sizeDp: Int): ImageView {
        val density = context.resources.displayMetrics.density
        val px = (sizeDp * density).toInt()
        return ImageView(context).apply {
            layoutParams = LinearLayout.LayoutParams(px, px).apply {
                marginEnd = (8 * density).toInt()
            }
            scaleType = ImageView.ScaleType.CENTER_CROP
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            bindFediAvatar(this, label)
        }
    }

    /** Draw [bmp] circular, but only if [target] still belongs to [key]. */
    private fun showCircle(target: ImageView, key: String, bmp: android.graphics.Bitmap) {
        if (target.tag != key) return
        target.setImageDrawable(circleOf(bmp))
        target.visibility = View.VISIBLE
    }

    /**
     * Put [label]'s avatar inline, ahead of [target]'s text, as a compound
     * drawable.
     *
     * Feed posts render as bubbles whose author line is a plain `TextView`;
     * a compound drawable adds the face without restructuring the message
     * row (and without disturbing the sender label's own show/hide logic).
     */
    private fun bindFediAvatarInline(target: TextView, label: String, sizeDp: Int) {
        target.setCompoundDrawablesRelative(null, null, null, null)
        if (label.isBlank()) return
        val key = FediAvatars.key(label)
        target.setTag(R.id.messageSender, key)

        fediAvatars.cached(label)?.let { showInline(target, key, it, sizeDp); return }

        val now = System.currentTimeMillis()
        if (!fediAvatars.shouldQuery(label, now)) return
        lifecycleScope.launch {
            try {
                val bmp = withContext(Dispatchers.IO) {
                    val bytes = runCatching { controller.gateway()?.fediAvatar(label) }.getOrNull()
                    fediAvatars.decodeAndCache(label, bytes, System.currentTimeMillis())
                } ?: return@launch
                showInline(target, key, bmp, sizeDp)
            } finally {
                fediAvatars.releaseQuery(label)
            }
        }
    }

    private fun showInline(target: TextView, key: String, bmp: android.graphics.Bitmap, sizeDp: Int) {
        if (target.getTag(R.id.messageSender) != key) return
        val density = context.resources.displayMetrics.density
        val px = (sizeDp * density).toInt()
        val round = circleOf(bmp)
        round.setBounds(0, 0, px, px)
        target.setCompoundDrawablesRelative(round, null, null, null)
        target.compoundDrawablePadding = (6 * density).toInt()
    }

    private fun circleOf(bmp: android.graphics.Bitmap) =
        androidx.core.graphics.drawable.RoundedBitmapDrawableFactory
            .create(context.resources, bmp)
            .apply { isCircular = true }

    // ── public entry points ────────────────────────────────────────────

    /**
     * Called each time the user switches into chat mode.
     * Ensures the list screen is shown and kicks off [ensureGateway].
     */
    fun onShown() {
        if (!tabsWired) {
            wireTabs()
            tabsWired = true
        }
        val tabId = tabIdFor(SettingsStore(context).lastChatTab())
        // Selecting the item fires the listener → showRoot. If that tab is
        // already selected (re-entry), drive the root directly so the screen
        // still renders.
        if (tabBar.selectedItemId == tabId) {
            showRoot(rootFor(tabId))
        } else {
            tabBar.selectedItemId = tabId
        }
        lifecycleScope.launch {
            runCatching { connectWithFeedback() }
            // Populate the fediverse rows once connected (the Chats collector
            // observes controller.fediThreads). Person-links drive which fedi
            // rows fold into a 🔒 contact row.
            controller.refreshFediThreads()
            controller.refreshPersonLinks()
        }
    }

    /**
     * Sync inbound fediverse DMs from the bridge, then refresh the thread
     * overview so new correspondents surface in the Chats list. Uses the
     * live gateway if present; a no-op without a minted handle. Quiet on
     * failure.
     */
    private fun refreshChatsFediThreads() {
        if (controller.fediActorStatus() == null) return
        lifecycleScope.launch {
            runCatching { controller.gateway()?.fediSyncInbox() }
            controller.refreshFediThreads()
        }
    }

    /** Attach the bottom-nav selection listener (once). */
    private fun wireTabs() {
        tabBar.setOnItemSelectedListener { item ->
            val (root, name) = when (item.itemId) {
                R.id.tabPeople -> Screen.People to "people"
                R.id.tabFeed -> Screen.Feed to "feed"
                else -> Screen.Chats to "chats"
            }
            SettingsStore(context).saveLastChatTab(name)
            showRoot(root)
            true
        }
    }

    /** Show a tab root: reset the back-stack to just this root. */
    private fun showRoot(root: Screen) {
        screenStack.clear()
        showScreen(root, pushToStack = true)
    }

    private fun tabIdFor(name: String): Int = when (name) {
        "people" -> R.id.tabPeople
        "feed" -> R.id.tabFeed
        else -> R.id.tabChats
    }

    private fun rootFor(itemId: Int): Screen = when (itemId) {
        R.id.tabPeople -> Screen.People
        R.id.tabFeed -> Screen.Feed
        else -> Screen.Chats
    }

    /**
     * Called by the Activity's back callback while in chat mode.
     * @return true if the back press was consumed (popped a sub-screen),
     *         false if the caller should return to browse.
     */
    fun onBack(): Boolean {
        if (screenStack.size <= 1) return false
        screenStack.removeLastOrNull()
        val prev = screenStack.lastOrNull() ?: Screen.Chats
        showScreen(prev, pushToStack = false)
        return true
    }

    /**
     * Initiate a pair import from a scanned or deep-linked URI.
     * Runs the full connect-and-import flow then prompts for a display name.
     *
     * Always resets to the list screen first so that a deep link arriving
     * while a thread is open does not stack the new import over the existing
     * thread (which would make back return to the previous thread rather than
     * the list).
     */
    fun importFromUri(uri: String) {
        val agentId = ChatUris.pairUriAgentId(uri) ?: run {
            snackbar(context.getString(R.string.chat_invalid_pair_uri))
            return
        }
        // Normalize the screen stack to the list before launching the import
        // coroutine so mid-session deep links land cleanly.
        showList()
        lifecycleScope.launch {
            runCatching { connectWithFeedback() }.onFailure { return@launch }
            val gw = controller.gateway() ?: run {
                snackbar(context.getString(R.string.chat_connect_failed_generic))
                return@launch
            }
            // Lowercase before the FFI: the Rust importPairUri requires lowercase
            // hex in the path. The precheck (ChatUris.pairUriAgentId) normalizes
            // for validation, but the raw uri can still carry uppercase hex from a
            // hand-typed or third-party QR; the relay hint is a URL so lowercasing
            // the whole uri is safe.
            runCatching { gw.importPairUri(uri.trim().lowercase()) }.onFailure { e ->
                snackbar(userFacingError(e, "importPairUri", R.string.chat_error_invalid))
                return@launch
            }
            promptDisplayName(agentId)
        }
    }

    /**
     * Existing-device side of "link a device" (M6.4): the user scanned (or
     * tapped) another device's `fetchit://link/v1/…` offer. Connect, fetch the
     * offer preview, and -- only if it has not expired -- ask the human to
     * confirm the short code matches the OTHER device's screen before
     * enrolling. The code comparison IS the security step, so an expired offer
     * never reaches a confirm dialog; the user is told to ask for a fresh one.
     *
     * Resets to the list screen first (same reason as [importFromUri]) so a
     * mid-session scan / deep link lands cleanly rather than stacking over an
     * open thread.
     */
    fun linkDeviceFromUri(uri: String) {
        if (!ChatUris.isLinkUri(uri)) {
            snackbar(context.getString(R.string.chat_link_invalid_uri))
            return
        }
        showList()
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrNull() ?: return@launch
            val preview = runCatching { gw.previewLinkOffer(uri.trim()) }.getOrElse { e ->
                snackbar(userFacingError(e, "previewLinkOffer", R.string.chat_link_preview_failed))
                return@launch
            }
            if (preview.expired) {
                showLinkExpiredDialog()
            } else {
                confirmLinkDevice(uri.trim(), preview)
            }
        }
    }

    /**
     * The confirm step: show the new device's short code prominently and make
     * the security bargain explicit -- only tap Link if this code matches the
     * one on the OTHER device's screen. The abbreviated agent id is shown as a
     * secondary reassurance. Tapping Link runs [enrollLinkedDevice].
     */
    private fun confirmLinkDevice(uri: String, preview: LinkOfferPreviewFfi) {
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_link_confirm_title))
            .setMessage(
                context.getString(
                    R.string.chat_link_confirm_message,
                    preview.shortCode,
                    "${preview.agentIdHex.take(8)}…",
                ),
            )
            .setPositiveButton(context.getString(R.string.chat_link_confirm_button)) { _, _ ->
                enrollLinkedDevice(uri)
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    /** An expired offer cannot be confirmed -- tell the user to ask for a fresh one. */
    private fun showLinkExpiredDialog() {
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_link_expired_title))
            .setMessage(context.getString(R.string.chat_link_expired_message))
            .setPositiveButton(context.getString(R.string.action_close), null)
            .show()
    }

    /**
     * Enroll the confirmed device. Runs the top-level [enrollConfirmedDevice]
     * FFI (not a gateway call -- it works off the on-disk account vault, no live
     * connection needed) against the SAME chat data dir + auto-managed vault
     * passphrase the controller connects with, publishing the account roster at
     * the next revision. The vault read is pushed off the main thread per
     * [ChatSecrets.vaultPass].
     *
     * `devicesGroupAdmitted` is the M6.6 stub (always false today): the device
     * is on the account roster now, but the live devices-group sync channel
     * lands later -- so success copy says linked-and-syncing rather than a bare
     * "done".
     */
    private fun enrollLinkedDevice(uri: String) {
        lifecycleScope.launch {
            val dataDir = File(context.filesDir, "chat").absolutePath
            val passphrase = withContext(Dispatchers.IO) { ChatSecrets(context).vaultPass() }
            val outcome = runCatching {
                enrollConfirmedDevice(dataDir, passphrase, uri, ChatController.DEFAULT_RELAY)
            }.getOrElse { e ->
                snackbar(userFacingError(e, "enrollConfirmedDevice", R.string.chat_link_enroll_failed))
                return@launch
            }
            val msg = if (outcome.devicesGroupAdmitted) {
                context.getString(R.string.chat_link_enrolled)
            } else {
                context.getString(R.string.chat_link_enrolled_syncing)
            }
            snackbar(msg)
        }
    }

    // ── screen navigation ──────────────────────────────────────────────

    private fun showList() {
        showRoot(Screen.Chats)
        tabBar.selectedItemId = R.id.tabChats
    }

    /** Open the DM thread for [agentIdHex]. */
    fun openThread(agentIdHex: String) {
        showScreen(Screen.Thread(agentIdHex), pushToStack = true)
    }

    /** Open the group thread for [groupId]. */
    fun openGroupThread(groupId: String) {
        showScreen(Screen.GroupThread(groupId), pushToStack = true)
    }

    /**
     * Open the feed with [text] waiting in the composer — the public half of
     * the reader's share-out. When there is no `@handle` yet the feed shows
     * the mint card instead of a compose row, so the draft is held until a
     * successful mint re-binds the composer and it lands there.
     */
    fun composeFeedPost(text: String) {
        // Tab first: selecting it fires the nav listener, which re-shows the
        // root and rebuilds the compose row. Handing over the draft after
        // that means the composer that receives it is the one on screen.
        tabBar.selectedItemId = R.id.tabFeed
        pendingFeedCompose = text
        showRoot(Screen.Feed)
    }

    /**
     * Open the thread for a [ConversationStore] conversation key — the
     * reverse of the key derivation, used by notification taps
     * ([io.etchit.fetchit.chat.notify.MessageNotifier]).
     */
    fun openConversationByKey(key: String) {
        if (key.startsWith("g:")) {
            openGroupThread(key.removePrefix("g:"))
        } else {
            openThread(key)
        }
    }

    private fun showScreen(screen: Screen, pushToStack: Boolean) {
        if (pushToStack) {
            if (screenStack.lastOrNull() != screen) screenStack.addLast(screen)
        }
        // Every navigation (open AND back-pop) lands here, so this is the
        // one place the notify policy's on-screen-conversation state stays
        // correct. Opening a thread also clears its pending notification.
        controller.visibleConvKey = when (screen) {
            is Screen.Thread -> ConversationStore.convKeyDm(screen.peer)
            is Screen.GroupThread -> ConversationStore.convKeyGroup(screen.groupId)
            else -> null
        }
        controller.visibleConvKey?.let {
            io.etchit.fetchit.chat.notify.MessageNotifier(context).cancel(it)
        }
        // The tab bar shows on the three roots and hides inside any thread.
        val isRoot = screen is Screen.Chats || screen is Screen.People || screen is Screen.Feed
        tabBar.visibility = if (isRoot) View.VISIBLE else View.GONE
        when (screen) {
            is Screen.Chats -> {
                // Cancel sub-screen collectors on return to list.
                threadCollectJob?.cancel()
                threadCollectJob = null
                sendJob?.cancel()
                sendJob = null
                feedCollectJob?.cancel()
                feedCollectJob = null
                if (listView == null) {
                    slot.removeAllViews()
                    inflateListScreen()
                } else {
                    // Re-attach the cached list view without re-inflating or
                    // launching duplicate collectors. listContactsJob and
                    // listPumpStateJob are live for the ChatModeView lifetime;
                    // any future re-inflation path must cancel them first.
                    if (listView!!.parent == null) {
                        slot.removeAllViews()
                        slot.addView(listView)
                    }
                    // State the cached view can't know changed elsewhere: the
                    // fediverse onboarding copy flips once a handle is minted
                    // (which happens on the feed screen).
                    listView?.let { bindOnboardFediCopy(it) }
                }
                refreshChatsFediThreads()
                // The cached list view keeps ONE collector for the whole
                // ChatModeView lifetime, so arriving here is the moment to
                // re-read the private rows' badges from the engine's durable
                // read marks: a message that landed while the user was on
                // another tab is counted, not merely what this process saw.
                lifecycleScope.launch { controller.refreshAllUnread() }
            }
            is Screen.People -> {
                threadCollectJob?.cancel()
                threadCollectJob = null
                sendJob?.cancel()
                sendJob = null
                feedCollectJob?.cancel()
                feedCollectJob = null
                slot.removeAllViews()
                bindPeopleScreen()
            }
            is Screen.Thread -> {
                // Cancel any running feed collector; thread gets its own fresh one.
                feedCollectJob?.cancel()
                feedCollectJob = null
                // Cancel any collector and in-flight send for the PREVIOUS peer
                // before binding the new one.
                threadCollectJob?.cancel()
                threadCollectJob = null
                sendJob?.cancel()
                sendJob = null
                slot.removeAllViews()
                bindThreadScreen(screen.peer)
            }
            is Screen.GroupThread -> {
                // Same teardown as a DM thread: a group thread reuses the
                // thread view + the threadCollect/send jobs, so the previous
                // screen's collector and in-flight send must be cancelled first.
                feedCollectJob?.cancel()
                feedCollectJob = null
                threadCollectJob?.cancel()
                threadCollectJob = null
                sendJob?.cancel()
                sendJob = null
                slot.removeAllViews()
                bindGroupThreadScreen(screen.groupId)
            }
            is Screen.Feed -> {
                // Cancel any running thread collector and in-flight send.
                threadCollectJob?.cancel()
                threadCollectJob = null
                sendJob?.cancel()
                sendJob = null
                feedCollectJob?.cancel()
                feedCollectJob = null
                slot.removeAllViews()
                bindFeedScreen()
            }
            is Screen.FediThread -> {
                // Same teardown discipline as the other threads.
                feedCollectJob?.cancel()
                feedCollectJob = null
                threadCollectJob?.cancel()
                threadCollectJob = null
                sendJob?.cancel()
                sendJob = null
                slot.removeAllViews()
                bindFediThreadScreen(screen.handle)
            }
        }
    }

    // ── list screen ────────────────────────────────────────────────────

    private fun inflateListScreen() {
        val view = LayoutInflater.from(context)
            .inflate(R.layout.view_chat_list, slot, false)
        slot.addView(view)
        listView = view

        val rv = view.findViewById<RecyclerView>(R.id.chatContactList)
        val emptyState = view.findViewById<View>(R.id.chatEmptyState)
        val lostBanner = view.findViewById<TextView>(R.id.chatConnectionLostBanner)
        val addBtn = view.findViewById<View>(R.id.addContactButton)
        val identityBadge = view.findViewById<View>(R.id.chatIdentityBadge)
        val identityAvatar = view.findViewById<TextView>(R.id.chatIdentityAvatar)
        val identityName = view.findViewById<TextView>(R.id.chatIdentityName)
        val connStatus = view.findViewById<TextView>(R.id.chatConnectionStatus)
        val addPersonBtn = view.findViewById<View>(R.id.onboardAddPersonButton)
        val createGroupBtn = view.findViewById<View>(R.id.onboardCreateGroupButton)
        val fediverseBtn = view.findViewById<View>(R.id.onboardFediverseButton)

        // Own-identity header badge: the user sees themselves by name +
        // initials avatar on the self (copper) hue, never the 64-hex. Tapping
        // it opens the share-my-code card. The display name resolves from the
        // connected gateway when available, else from the saved setting (no
        // connection needed); "You"/"?" before any name is set.
        bindIdentityBadge(identityAvatar, identityName)
        identityBadge.setOnClickListener { onIdentityBadgeTap(identityAvatar, identityName) }

        // Adapter: one unified list — groups, private contacts, and fediverse
        // threads, newest activity first (buildChatRows). No pinned rows.
        val adapter = ContactListAdapter(
            onFediTap = { label -> openFediThread(label) },
            onContactTap = { contact -> openThread(contact.agentIdHex) },
            onGroupTap = { group -> openGroupThread(group.groupId) },
            onRemoveContact = { anchor, contact -> showContactRowMenu(anchor, contact) },
            onLeaveGroup = { anchor, group -> showGroupRowMenu(anchor, group) },
        )
        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = adapter

        // Observe contacts + groups + fediverse threads together. Any of the
        // three populates the list; the empty-state onboarding shows only when
        // all three are empty. A fediverse thread with zero private contacts
        // still renders (closes the unseen-correspondent gap).
        listContactsJob = lifecycleScope.launch {
            combine(
                controller.contacts.contacts,
                controller.groups,
                controller.fediThreads,
                controller.personLinks,
                controller.litUnread,
            ) { contacts, groups, fedi, links, unread ->
                // A fediverse thread whose person is linked to a PQ agent is
                // folded into that contact's 🔒 row, so suppress its globe row.
                val linkedLabels = links.filter { it.linked }.map { it.label }.toSet()
                // ...and that same contact row inherits the fediverse face.
                val labelByAgent = links
                    .mapNotNull { l -> l.agentIdHex?.let { it to l.label } }
                    .toMap()
                buildChatRows(
                    contacts = contacts,
                    groups = groups,
                    groupPreview = { key ->
                        controller.conversations.messagesFor(key).value.lastOrNull()
                            ?.let { it.body to it.sentAtMs }
                    },
                    contactPreview = { key ->
                        controller.conversations.messagesFor(key).value.lastOrNull()
                            ?.let { it.body to it.sentAtMs }
                    },
                    fediThreads = fedi,
                    linkedFediLabels = linkedLabels,
                    litUnread = unread,
                    linkedFediLabelByAgent = labelByAgent,
                )
            }
                .collect { rows ->
                    val empty = rows.isEmpty()
                    rv.visibility = if (empty) View.GONE else View.VISIBLE
                    emptyState.visibility = if (empty) View.VISIBLE else View.GONE
                    // The FAB duplicates the onboarding buttons on the empty
                    // state, so it only shows once the list has content.
                    addBtn.visibility = if (empty) View.GONE else View.VISIBLE
                    adapter.submit(rows)
                }
        }

        // Observe pump state to drive the persistent offline-reassurance
        // banner. It stays up the whole time the connection is down
        // (STOPPED_ERROR) and clears itself the moment the pump is RUNNING
        // again — there is no one-time toast. The copy reassures that queued
        // messages are saved; the durable outbox resends them on the next
        // connect (a reconnect happens on the next chat-mode entry, which
        // calls ensureGateway and flips the pump back to RUNNING).
        applyOfflineBannerTone(lostBanner)
        listPumpStateJob = lifecycleScope.launch {
            controller.pumpState.collect { state ->
                lostBanner.visibility =
                    if (state == PumpState.STOPPED_ERROR) View.VISIBLE else View.GONE
            }
        }

        // Live connection dot in the identity header: connected / connecting… /
        // offline. StateFlow replays its current value to this collector on
        // subscribe, so the dot paints immediately on entering the list screen.
        listConnStatusJob = lifecycleScope.launch {
            controller.connectionStatus.collect { status ->
                renderConnectionStatus(connStatus, status)
            }
        }

        // Detect a newly-imported PQ contact while a go-private invite is
        // pending, and offer the human-confirmed "Same person?" link. Never
        // automatic: the pair link crossed the open fediverse, so anyone who
        // saw it could import it — the user is the trust anchor.
        linkConfirmJob = lifecycleScope.launch {
            controller.contacts.contacts.collect { contacts ->
                val firstSnapshot = seenContactIds.isEmpty()
                val fresh = contacts.filter {
                    it.agentIdHex !in seenContactIds && it.agentIdHex !in linkPromptedIds
                }
                seenContactIds.addAll(contacts.map { it.agentIdHex })
                // The first emission just establishes the baseline — contacts
                // that already existed when the list opened never prompt.
                if (firstSnapshot) return@collect
                for (contact in fresh) {
                    val pending = runCatching { controller.gateway()?.fediPendingInvites() }
                        .getOrNull().orEmpty()
                    if (pending.isEmpty()) break
                    linkPromptedIds.add(contact.agentIdHex)
                    promptLinkConfirm(contact, pending)
                }
            }
        }

        // Onboarding primary action: add your first person.
        addPersonBtn.setOnClickListener { showAddContactDialog() }

        // Onboarding secondary action: create a group.
        createGroupBtn.setOnClickListener { showNewGroupDialog() }

        // Onboarding: open the fediverse (get an @handle + see public posts).
        // The one first-run action needing no contacts, so it lives here in the
        // empty state, not only in the pinned list row — which the empty state
        // hides along with the rest of the (empty) contact list.
        // No handle yet → send them to People (the mint card lives there);
        // once minted → the Feed tab (public posts).
        fediverseBtn.setOnClickListener {
            tabBar.selectedItemId =
                if (controller.fediActorStatus() == null) R.id.tabPeople else R.id.tabFeed
        }
        bindOnboardFediCopy(view)

        // FAB: a popup with the list-level actions -- add a contact, start a
        // new group, join one from an invite link, or scan a code (the scan
        // affordance re-homed here now the identity badge owns share-my-code).
        addBtn.setOnClickListener { showNewChatSheet() }
    }

    /**
     * Point the empty-state's fediverse copy at the user's actual state:
     * before a handle exists the button invites ("Get your @handle"); after,
     * that invite would be a stale lie, so it flips to the destination ("See
     * public posts") and the body drops the get-a-handle nudge. Re-run on
     * every return to the list — minting happens on the feed screen this very
     * button leads to, and the list view is cached, not re-inflated.
     */
    private fun bindOnboardFediCopy(view: View) {
        val minted = controller.fediActorStatus() != null
        view.findViewById<TextView>(R.id.onboardFediverseButton)?.setText(
            if (minted) R.string.chat_onboard_fediverse_minted else R.string.chat_onboard_fediverse,
        )
        view.findViewById<TextView>(R.id.onboardBodyText)?.setText(
            if (minted) R.string.chat_onboard_body_minted else R.string.chat_onboard_body,
        )
    }

    /**
     * Paint the own-identity header badge: the user's initials avatar on the
     * self (copper) hue plus their display name — never the raw 64-hex
     * (grandma-UI rule 1: the user sees themselves by name). The full code
     * stays one tap away via the share card the badge opens.
     *
     * The name resolves from the connected gateway's agent id when one is
     * available, else from the saved chat display name (no connection
     * required). Before any name is set the badge reads "You" with a "?"
     * avatar, mirroring desktop's empty-name fallback.
     */
    private fun bindIdentityBadge(avatar: TextView, name: TextView) {
        // Read the SAVED name only -- never displayNameOrDefault, whose
        // agent-<hex> fallback would leak the very hex this badge exists to
        // hide (grandma rule 1: the user sees themselves by name). When no
        // name is set yet, invite them to add one rather than dead-end on "?".
        val saved = SettingsStore(context).chatDisplayName()
        if (saved.isBlank()) {
            name.text = context.getString(R.string.chat_identity_add_name)
            avatar.text = "+"
        } else {
            name.text = saved
            avatar.text = IdentityColor.initials(saved)
        }
        // Self hue is copper — the same OVAL background the avatar gets
        // everywhere. Set in code so the circle isn't a static drawable.
        avatar.background = android.graphics.drawable.GradientDrawable().apply {
            shape = android.graphics.drawable.GradientDrawable.OVAL
            setColor(SELF_HUE)
        }
    }

    /**
     * Tap on the identity badge: when no display name is set yet, invite the
     * user to add one (the most useful first action — and it stops the badge
     * dead-ending on "?"); once a name exists, the badge shares the user's
     * code, mirroring desktop where the badge opens the share card.
     */
    private fun onIdentityBadgeTap(avatar: TextView, name: TextView) {
        if (SettingsStore(context).chatDisplayName().isBlank()) {
            promptSetMyName(avatar, name)
        } else {
            lifecycleScope.launch { onShareMyCodeClicked() }
        }
    }

    /**
     * Prompt for the user's own display name — the name people see on the
     * messages they send (persisted via [SettingsStore.saveChatDisplayName],
     * the same value [displayNameOrDefault] feeds into every outbound send).
     * Re-binds the badge so it reflects the new name immediately.
     */
    private fun promptSetMyName(avatar: TextView, name: TextView) {
        val editText = EditText(context).apply {
            setText(SettingsStore(context).chatDisplayName())
            hint = context.getString(R.string.chat_identity_name_hint)
            setSelection(text.length)
        }
        val layout = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(editText)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_identity_name_title))
            .setMessage(context.getString(R.string.chat_identity_name_message))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_identity_name_save)) { _, _ ->
                SettingsStore(context).saveChatDisplayName(editText.text.toString())
                bindIdentityBadge(avatar, name)
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    /**
     * Opt-in fediverse mint dialog: pick a public @handle, validate it
     * client-side ([fediHandleError], mirroring desktop's rule), then mint +
     * register via [ChatController.fediMint]. Invalid input keeps the dialog
     * open with an inline error. On success [onMinted] refreshes the hub with
     * the new handle and the directory outcome is surfaced honestly
     * (registered vs pending).
     *
     * A name already held by someone else ([takenHandle]) is a dead end no
     * retry can clear, so it keeps the dialog open on the same inline-error
     * path as invalid input — edit the name, tap create again.
     * [takenName] reopens the dialog on a conflict the engine recorded in an
     * earlier session, field seeded and error shown, so a restart never loses
     * the reason.
     */
    private fun showFediMintDialog(takenName: String? = null, onMinted: (String) -> Unit) {
        val editText = EditText(context).apply {
            hint = context.getString(R.string.fedi_mint_handle_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            maxLines = 1
            filters = arrayOf(android.text.InputFilter.LengthFilter(64))
            if (takenName != null) {
                setText(takenName)
                setSelection(text.length)
                error = context.getString(R.string.fedi_mint_name_taken, takenName)
            }
        }
        val layout = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(editText)
        }
        val dialog = MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.fedi_mint_title))
            .setMessage(context.getString(R.string.fedi_mint_message))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.fedi_mint_create), null)
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .create()
        // Positive handler set after show() so an invalid handle keeps the
        // dialog open (an inline error) instead of dismissing.
        dialog.setOnShowListener {
            val createBtn = dialog.getButton(android.content.DialogInterface.BUTTON_POSITIVE)
            createBtn.setOnClickListener {
                val err = fediHandleError(editText.text.toString())
                if (err != null) {
                    editText.error = context.getString(fediHandleErrorMessage(err))
                    return@setOnClickListener
                }
                val handle = editText.text.toString().trim().lowercase()
                createBtn.isEnabled = false
                lifecycleScope.launch {
                    runCatching { controller.fediMint(handle) }
                        .onSuccess { outcome ->
                            val taken = takenHandle(outcome.registration)
                            if (taken != null) {
                                // Nothing was claimed, so the hub must not be
                                // told a handle exists — edit and try again.
                                createBtn.isEnabled = true
                                editText.error =
                                    context.getString(R.string.fedi_mint_name_taken, taken)
                                editText.setSelection(editText.text.length)
                                return@onSuccess
                            }
                            dialog.dismiss()
                            onMinted(handle)
                            snackbar(
                                context.getString(
                                    if (outcome.registration is MintRegistrationFfi.Registered) {
                                        R.string.fedi_mint_done
                                    } else {
                                        R.string.fedi_mint_done_pending
                                    },
                                    handle,
                                ),
                            )
                        }
                        .onFailure { e ->
                            createBtn.isEnabled = true
                            snackbar(userFacingError(e, "fediMint", R.string.fedi_mint_failed))
                        }
                }
            }
        }
        dialog.show()
    }

    private fun fediHandleErrorMessage(err: FediHandleError): Int = when (err) {
        FediHandleError.EMPTY -> R.string.fedi_handle_err_empty
        FediHandleError.TOO_LONG -> R.string.fedi_handle_err_long
        FediHandleError.INVALID_CHARS -> R.string.fedi_handle_err_chars
    }

    /**
     * Header subtitle on the fediverse hub: the user's `@handle@etchit.io` when
     * minted (ash), else a tappable "create your @handle" prompt (copper) that
     * opens the opt-in mint dialog and re-renders itself on a successful mint.
     * [onMinted] fires after a successful mint so the caller can reveal the
     * affordances a handle unlocks (the feed's compose row) without leaving
     * the screen.
     */
    private fun renderFediHubHeader(shortId: TextView, onMinted: () -> Unit = {}) {
        val handle = controller.fediActorStatus()
        if (handle != null) {
            // The minted @name is a door to the social graph — the chevron +
            // copper make it READ as tappable (an unmarked tap target failed
            // device testing: "I see nothing new").
            shortId.text =
                context.getString(R.string.fedi_hub_handle_tappable, handle)
            shortId.setTextColor(themeColor(R.attr.fetchitCopper))
            shortId.contentDescription = context.getString(R.string.fedi_people_desc)
            shortId.setOnClickListener { showFediPeopleSheet(handle) }
        } else {
            shortId.text = context.getString(R.string.fedi_hub_join)
            shortId.setTextColor(themeColor(R.attr.fetchitCopper))
            shortId.setOnClickListener {
                // A name the directory refused reopens the dialog on itself,
                // so the user picks up where the conflict left them even after
                // a restart.
                showFediMintDialog(controller.fediMintConflictHandle()) {
                    renderFediHubHeader(shortId, onMinted)
                    onMinted()
                }
            }
        }
    }

    /**
     * "Your fediverse" sheet — the social-graph surface a social app owes
     * its user: who you follow (with message / unfollow / block per row),
     * who follows you, and who you've blocked (with unblock). Opened by
     * tapping your @name in the feed header. Lists load live; every
     * action re-renders the sheet so state is never stale on screen.
     */
    private fun showFediPeopleSheet(handle: String) {
        val dialog = com.google.android.material.bottomsheet.BottomSheetDialog(context)
        val px16 = (16 * context.resources.displayMetrics.density).toInt()
        val px8 = px16 / 2
        val root = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(px16, px16, px16, px16)
        }
        val scroller = android.widget.ScrollView(context).apply { addView(root) }

        fun header(text: String) = TextView(context).apply {
            this.text = text
            textSize = 13f
            setTextColor(themeColor(R.attr.fetchitCopper))
            setPadding(0, px16, 0, px8)
        }
        fun line(text: String) = TextView(context).apply {
            this.text = text
            textSize = 14f
            setPadding(0, px8, 0, px8)
        }

        root.addView(TextView(context).apply {
            text = context.getString(R.string.fedi_people_title)
            textSize = 18f
        })
        root.addView(line(context.getString(R.string.fedi_hub_handle, handle)))
        root.addView(android.widget.Button(context).apply {
            text = context.getString(R.string.fedi_people_find)
            setOnClickListener {
                dialog.dismiss()
                showAddContactDialog()
            }
        })

        val followingHeader = header(context.getString(R.string.fedi_people_following, "…"))
        root.addView(followingHeader)
        val followingBox = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        root.addView(followingBox)

        root.addView(header(context.getString(R.string.fedi_people_followers)))
        root.addView(line(context.getString(R.string.fedi_people_followers_empty)))

        val blockedHeader = header(context.getString(R.string.fedi_people_blocked))
        root.addView(blockedHeader)
        val blockedBox = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        root.addView(blockedBox)

        fun renderBlocked() {
            blockedBox.removeAllViews()
            val blocked = blockStore.blocked()
            blockedHeader.visibility = if (blocked.isEmpty()) View.GONE else View.VISIBLE
            blocked.forEach { b ->
                val row = android.widget.LinearLayout(context).apply {
                    orientation = android.widget.LinearLayout.HORIZONTAL
                    gravity = android.view.Gravity.CENTER_VERTICAL
                }
                row.addView(TextView(context).apply {
                    text = context.getString(R.string.fedi_handle_at, b)
                    textSize = 14f
                    layoutParams = android.widget.LinearLayout.LayoutParams(
                        0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f,
                    )
                })
                row.addView(android.widget.Button(context, null, android.R.attr.borderlessButtonStyle).apply {
                    text = context.getString(R.string.fedi_unblock)
                    setOnClickListener {
                        blockStore.unblock(b)
                        snackbar(context.getString(R.string.fedi_unblocked, b))
                        renderBlocked()
                    }
                })
                blockedBox.addView(row)
            }
        }
        renderBlocked()

        fun renderFollowing(entries: List<uniffi.fetchit_ffi.FediFollowingFfi>) {
            followingBox.removeAllViews()
            followingHeader.text =
                context.getString(R.string.fedi_people_following, entries.size.toString())
            if (entries.isEmpty()) {
                followingBox.addView(line(context.getString(R.string.fedi_people_following_empty)))
                return
            }
            entries.forEach { e ->
                val atHandle = "@${e.label}"
                val row = android.widget.LinearLayout(context).apply {
                    orientation = android.widget.LinearLayout.HORIZONTAL
                    gravity = android.view.Gravity.CENTER_VERTICAL
                }
                row.addView(fediAvatarSlot(e.label, PEOPLE_AVATAR_DP))
                row.addView(TextView(context).apply {
                    text = if (e.state == "accepted") {
                        atHandle
                    } else {
                        context.getString(R.string.fedi_following_pending_row, atHandle)
                    }
                    textSize = 14f
                    layoutParams = android.widget.LinearLayout.LayoutParams(
                        0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f,
                    )
                })
                row.addView(android.widget.Button(context, null, android.R.attr.borderlessButtonStyle).apply {
                    text = context.getString(R.string.chat_fedi_dm)
                    setOnClickListener {
                        dialog.dismiss()
                        openFediThread(atHandle)
                    }
                })
                row.addView(android.widget.ImageButton(context, null, android.R.attr.borderlessButtonStyle).apply {
                    setImageResource(android.R.drawable.ic_menu_more)
                    contentDescription = context.getString(R.string.fedi_row_more)
                    setOnClickListener { anchor ->
                        PopupMenu(context, anchor).apply {
                            menu.add(context.getString(R.string.fedi_unfollow))
                            menu.add(context.getString(R.string.fedi_block))
                            setOnMenuItemClickListener { item ->
                                when (item.title) {
                                    context.getString(R.string.fedi_unfollow) ->
                                        unfollowFedi(e.targetActorUrl, atHandle) { dialog.dismiss() }
                                    context.getString(R.string.fedi_block) -> {
                                        blockStore.block(atHandle)
                                        snackbar(context.getString(R.string.fedi_blocked, atHandle))
                                        renderBlocked()
                                    }
                                }
                                true
                            }
                            show()
                        }
                    }
                })
                followingBox.addView(row)
            }
        }

        dialog.setContentView(scroller)
        dialog.show()

        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse {
                followingBox.addView(line(context.getString(R.string.chat_connect_failed_generic)))
                return@launch
            }
            runCatching { gw.fediFollowing() }.fold(
                onSuccess = { renderFollowing(it) },
                onFailure = {
                    followingBox.addView(
                        line(userFacingError(it, "fediFollowing", R.string.fedi_people_load_failed)),
                    )
                },
            )
        }
    }

    /**
     * Unfollow with feedback: the device retracts the follow and the
     * directory record drops; the local following memory is cleared so
     * lookup cards stop showing "following ✓".
     */
    private fun unfollowFedi(targetActorUrl: String, atHandle: String, onDone: () -> Unit = {}) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse { return@launch }
            runCatching { gw.fediUnfollow(targetActorUrl) }.fold(
                onSuccess = {
                    followStore.forget(atHandle)
                    snackbar(context.getString(R.string.fedi_unfollowed, atHandle))
                    onDone()
                },
                onFailure = { e ->
                    snackbar(userFacingError(e, "fediUnfollow", R.string.fedi_unfollow_failed))
                },
            )
        }
    }

    /**
     * Popup menu off the list FAB: add a DM contact, create a new group, join
     * a group from a pasted invite, or scan a code. Each entry opens its own
     * dialog (or the scanner), mirroring [showAddContactDialog].
     */
    /**
     * The "+ New chat" bottom sheet: one field for a name or a pasted link,
     * a scan option, group actions, and quick-tap rows for people you already
     * know. One place to start any conversation.
     */
    private fun showNewChatSheet() {
        val dialog = com.google.android.material.bottomsheet.BottomSheetDialog(context)
        val px16 = (16 * context.resources.displayMetrics.density).toInt()
        val px8 = px16 / 2
        val root = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(px16, px16, px16, px16)
        }

        root.addView(TextView(context).apply {
            text = context.getString(R.string.chat_new_chat_fab)
            textSize = 18f
            setTextColor(themeColor(R.attr.fetchitBone))
            setPadding(0, 0, 0, px8)
        })

        fun action(label: String, run: () -> Unit) = android.widget.Button(
            context,
            null,
            android.R.attr.borderlessButtonStyle,
        ).apply {
            text = label
            gravity = android.view.Gravity.START or android.view.Gravity.CENTER_VERTICAL
            setOnClickListener {
                dialog.dismiss()
                run()
            }
        }

        root.addView(action(context.getString(R.string.chat_new_chat_type)) { showAddContactDialog() })
        root.addView(action(context.getString(R.string.chat_scan_a_code)) { onLaunchScanner() })
        root.addView(action(context.getString(R.string.chat_new_group)) { showNewGroupDialog() })
        root.addView(action(context.getString(R.string.chat_join_group)) { showJoinGroupDialog() })

        // Quick-tap: people you already have a private contact with.
        val contacts = controller.contacts.contacts.value
        if (contacts.isNotEmpty()) {
            root.addView(TextView(context).apply {
                text = context.getString(R.string.people_contacts_header)
                textSize = 13f
                setTextColor(themeColor(R.attr.fetchitCopper))
                setPadding(0, px16, 0, px8)
            })
            contacts.forEach { c ->
                root.addView(TextView(context).apply {
                    text = "🔒 ${c.displayName}"
                    textSize = 15f
                    setTextColor(themeColor(R.attr.fetchitBone))
                    setPadding(0, px8, 0, px8)
                    isClickable = true
                    setOnClickListener {
                        dialog.dismiss()
                        openThread(c.agentIdHex)
                    }
                })
            }
        }

        dialog.setContentView(android.widget.ScrollView(context).apply { addView(root) })
        dialog.show()
    }

    /**
     * Per-row overflow popup off a conversation row's "⋮" button. One
     * kind-aware destructive entry: "Remove this chat" for a contact, "Leave
     * this group" for a group ([rowRemoveLabel] picks the label). Selecting it
     * opens the confirm dialog. Mirrors desktop's per-row remove affordance.
     */
    private fun showContactRowMenu(anchor: View, contact: ChatContact) {
        val removeLabel = context.getString(rowRemoveLabel(isGroup = false))
        // Offer the "link to a fediverse person…" re-entry only while at least
        // one go-private invite is pending — the change-of-mind path after a
        // declined "Same person?" prompt.
        val pending = runCatching { controller.gateway()?.fediPendingInvites() }
            .getOrNull().orEmpty()
        val linkLabel = context.getString(R.string.link_confirm_reopen)
        PopupMenu(context, anchor).apply {
            if (pending.isNotEmpty()) menu.add(linkLabel)
            menu.add(removeLabel)
            setOnMenuItemClickListener { item ->
                when (item.title) {
                    linkLabel -> promptLinkConfirm(contact, pending)
                    else -> confirmRemoveContact(contact)
                }
                true
            }
            show()
        }
    }

    private fun showGroupRowMenu(anchor: View, group: GroupFfi) {
        val leaveLabel = context.getString(rowRemoveLabel(isGroup = true))
        // Delete is the only exit from a group you're the sole member of (a
        // last admin cannot leave). The daemon authorizes it; a non-admin is
        // told so rather than silently failing.
        val deleteLabel = context.getString(R.string.chat_delete_group)
        PopupMenu(context, anchor).apply {
            menu.add(leaveLabel)
            menu.add(deleteLabel)
            setOnMenuItemClickListener { item ->
                when (item.title) {
                    deleteLabel -> confirmDeleteGroup(group)
                    else -> confirmLeaveGroup(group)
                }
                true
            }
            show()
        }
    }

    /**
     * Confirm before deleting a group for everyone. Irreversible, so the copy
     * says so plainly and the destructive verb is the positive button.
     */
    private fun confirmDeleteGroup(group: GroupFfi) {
        val title = groupTitle(group, group.groupId)
        MaterialAlertDialogBuilder(context)
            .setTitle(R.string.chat_delete_group_title)
            .setMessage(context.getString(R.string.chat_delete_group_message, title))
            .setPositiveButton(R.string.chat_delete_group_confirm) { _, _ ->
                lifecycleScope.launch {
                    runCatching { controller.deleteGroup(group.groupId) }
                        .onSuccess {
                            snackbar(context.getString(R.string.chat_group_deleted, title))
                        }
                        .onFailure { e ->
                            Log.w(TAG, "deleteGroup: ${ffiReason(e)}", e)
                            snackbar(
                                context.getString(R.string.chat_group_delete_failed, title),
                            )
                        }
                }
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    /**
     * Offer to link a fediverse person to a newly-appeared PQ [contact]. One
     * pending invite → straight to the confirm card; several → a picker first
     * (the security copy names the chosen handle either way). Declining is a
     * no-op; the contact overflow re-opens this flow later.
     */
    private fun promptLinkConfirm(contact: ChatContact, pending: List<String>) {
        when {
            pending.isEmpty() -> Unit
            pending.size == 1 -> confirmLinkPerson(contact, pending.first())
            else -> MaterialAlertDialogBuilder(context)
                .setTitle(R.string.link_confirm_title)
                .setItems(pending.toTypedArray()) { _, which ->
                    confirmLinkPerson(contact, pending[which])
                }
                .setNegativeButton(R.string.link_confirm_no, null)
                .show()
        }
    }

    /** The human-confirmed link card. The body names both the invited handle
     *  and the new contact, and warns that anyone who saw the invite link
     *  could impersonate them — the user is the trust anchor. */
    private fun confirmLinkPerson(contact: ChatContact, handle: String) {
        val contactName = contact.displayName.ifBlank { "${contact.agentIdHex.take(8)}…" }
        MaterialAlertDialogBuilder(context)
            .setTitle(R.string.link_confirm_title)
            .setMessage(context.getString(R.string.link_confirm_body, handle, contactName))
            .setPositiveButton(R.string.link_confirm_yes) { _, _ ->
                linkPerson(handle, contact.agentIdHex)
            }
            .setNegativeButton(R.string.link_confirm_no, null)
            .show()
    }

    /** Commit a fediverse↔PQ link (local only, never published), then refresh
     *  so the fedi row folds into the contact's 🔒 row. */
    private fun linkPerson(handle: String, agentIdHex: String) {
        lifecycleScope.launch {
            val gw = controller.gateway() ?: return@launch
            runCatching { gw.fediLinkPerson(handle, agentIdHex) }.onFailure {
                Log.w(TAG, "fediLinkPerson: ${ffiReason(it)}", it)
                snackbar(context.getString(R.string.chat_error_generic))
                return@launch
            }
            controller.refreshPersonLinks()
            controller.refreshFediThreads()
        }
    }

    /**
     * Confirm before removing a contact: destructive verb as the positive
     * button, cancel as negative. On confirm the controller forgets the peer
     * and drops it from the local store so the row clears. Mirrors desktop's
     * confirm-before-remove.
     */
    private fun confirmRemoveContact(contact: ChatContact) {
        val name = contact.displayName.ifBlank { "${contact.agentIdHex.take(8)}…" }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_remove_chat_title))
            .setMessage(context.getString(R.string.chat_remove_chat_message, name))
            .setPositiveButton(context.getString(R.string.chat_remove_chat_confirm)) { _, _ ->
                lifecycleScope.launch {
                    runCatching { controller.removeContact(contact.agentIdHex) }
                        .onSuccess { snackbar(context.getString(R.string.chat_contact_removed, name)) }
                        .onFailure { e ->
                            snackbar(userFacingError(e, "removeContact", R.string.chat_error_generic))
                        }
                }
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    /**
     * Confirm before leaving a group: destructive verb as the positive button,
     * cancel as negative. On confirm the controller leaves and refreshes the
     * group list so the row disappears.
     */
    private fun confirmLeaveGroup(group: GroupFfi) {
        val title = groupTitle(group, group.groupId)
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_leave_group_title))
            .setMessage(context.getString(R.string.chat_leave_group_message, title))
            .setPositiveButton(context.getString(R.string.chat_leave_group_confirm)) { _, _ ->
                lifecycleScope.launch {
                    runCatching { controller.leaveGroup(group.groupId) }
                        .onSuccess { snackbar(context.getString(R.string.chat_group_left, title)) }
                        .onFailure { e ->
                            // The daemon rejects a last-admin leave (ADR-0016)
                            // and the row correctly stays -- so name the real
                            // reason and point at the way out, rather than
                            // reporting a leave that never happened.
                            Log.w(TAG, "leaveGroup: ${ffiReason(e)}", e)
                            val res = if (isLastAdminRejection(e)) {
                                R.string.chat_group_leave_last_admin
                            } else {
                                R.string.chat_group_leave_failed
                            }
                            snackbar(context.getString(res, title))
                        }
                }
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    /**
     * Open the group member list ("who is in this group") for [groupId]. Loads
     * the roster, resolves the viewer's own role, and builds one row per
     * active member into a scrollable column inside a MaterialAlertDialog.
     *
     * Moderation is COSMETIC here: each row taps into a detail sheet whose
     * Remove/Ban actions appear only when the viewer's role permits, but x0xd
     * is the sole authorization gate. Any moderation call that x0xd rejects
     * surfaces its error via a Snackbar — never silently swallowed.
     *
     * Two members can share a resolved display name (re-key ghosts); their
     * labels are disambiguated with a short agent-id suffix before rendering.
     */
    private fun showGroupMembersDialog(groupId: String) {
        lifecycleScope.launch {
            val members = controller.groupMembers(groupId)
            val myHex = controller.gateway()?.agentIdHex()
            val myRole = members.firstOrNull { it.agentIdHex == myHex }?.role
            val viewerCanModerate = canModerate(myRole)

            // Resolve each member's name (wire → saved contact → short id), then
            // disambiguate any same-name collisions so identical rows are
            // distinguishable. Labels stay aligned to `members` by index.
            val resolved = members.map { m ->
                val savedContactName = controller.contacts.contacts.value
                    .firstOrNull { it.agentIdHex == m.agentIdHex }?.displayName
                m.agentIdHex to memberDisplayName(m.displayName, savedContactName, m.agentIdHex)
            }
            val labels = disambiguateMemberLabels(resolved)

            val density = context.resources.displayMetrics.density
            val pad = (16 * density).toInt()
            val column = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(pad, (8 * density).toInt(), pad, 0)
            }
            members.forEachIndexed { i, m ->
                column.addView(memberRow(groupId, m, labels[i], myHex, viewerCanModerate))
            }
            val scroll = android.widget.ScrollView(context).apply { addView(column) }

            val membersDialog = MaterialAlertDialogBuilder(context)
                .setTitle(context.getString(R.string.chat_members_title))
                .setView(scroll)
                .setNegativeButton(context.getString(R.string.action_close), null)
            // Mint + share a fresh invite. Owner/admin only (cosmetic gate --
            // x0xd authorizes invite generation). Invites are single-use per
            // joiner, so this is the only path to grow a private group past its
            // first invitee from the UI.
            if (viewerCanModerate) {
                membersDialog.setNeutralButton(
                    context.getString(R.string.chat_group_invite_someone),
                ) { _, _ -> showGroupInvitePicker(groupId) }
            }
            membersDialog.show()
        }
    }

    /**
     * Build one member row: a tinted circular avatar, the pre-disambiguated
     * display [name] (with " (you)" for self), and an optional owner/admin
     * chip. The whole row is tappable and opens [showMemberDetailSheet]; there
     * is no per-row overflow — moderation lives in the detail sheet, so the tap
     * is never a dead gesture.
     */
    private fun memberRow(
        groupId: String,
        member: GroupMemberFfi,
        name: String,
        myHex: String?,
        viewerCanModerate: Boolean,
    ): View {
        val density = context.resources.displayMetrics.density
        val isSelf = member.agentIdHex == myHex

        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            val v = (8 * density).toInt()
            setPadding(0, v, 0, v)
            isClickable = true
            isFocusable = true
            setBackgroundResource(selectableItemBackground())
            setOnClickListener {
                showMemberDetailSheet(groupId, member, name, isSelf, viewerCanModerate)
            }
        }

        // Tinted circular avatar with the identity initial.
        val avatarSize = (36 * density).toInt()
        val avatar = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(avatarSize, avatarSize)
            gravity = android.view.Gravity.CENTER
            text = IdentityColor.initials(name)
            setTextColor(0xFFFFFFFF.toInt())
            background = android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.OVAL
                setColor(IdentityColor.stripeColor(member.agentIdHex))
            }
        }
        row.addView(avatar)

        val label = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f,
            ).apply { marginStart = (12 * density).toInt() }
            text = if (isSelf) context.getString(R.string.chat_member_you, name) else name
            setTextColor(themeColor(R.attr.fetchitBone))
            textSize = 15f
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        row.addView(label)

        memberRoleTag(member.role)?.let { tag ->
            row.addView(TextView(context).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply { marginStart = (8 * density).toInt() }
                text = tag
                setTextColor(themeColor(R.attr.fetchitAsh))
                textSize = 11f
            })
        }

        return row
    }

    /**
     * Resolve the platform attr `?attr/selectableItemBackground` to a drawable
     * res id so a member row gets the standard touch ripple. Falls back to 0
     * (no background) if the attr can't be resolved.
     */
    private fun selectableItemBackground(): Int {
        val tv = android.util.TypedValue()
        return if (context.theme.resolveAttribute(
                android.R.attr.selectableItemBackground, tv, true,
            )
        ) {
            tv.resourceId
        } else {
            0
        }
    }

    /**
     * Member detail / action sheet, opened by tapping any member row. Shows the
     * tinted avatar + initials, the disambiguated [name], the owner/admin role
     * tag (if any), and a short agent-id. Always offers **Copy ID**; for an
     * owner/admin viewer on a non-owner, non-self target it also offers
     * **Remove** and **Ban** (reusing the existing destructive confirm flows).
     *
     * Moderation gating here is COSMETIC — it reuses [canModerateMember] only to
     * hide controls that x0xd would reject; x0xd is the sole authorization gate
     * and any rejection surfaces via a Snackbar.
     */
    private fun showMemberDetailSheet(
        groupId: String,
        member: GroupMemberFfi,
        name: String,
        isSelf: Boolean,
        viewerCanModerate: Boolean,
    ) {
        val density = context.resources.displayMetrics.density
        val pad = (20 * density).toInt()

        val header = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(pad, (16 * density).toInt(), pad, 0)
        }

        val avatarSize = (44 * density).toInt()
        header.addView(
            TextView(context).apply {
                layoutParams = LinearLayout.LayoutParams(avatarSize, avatarSize)
                gravity = android.view.Gravity.CENTER
                text = IdentityColor.initials(name)
                setTextColor(0xFFFFFFFF.toInt())
                background = android.graphics.drawable.GradientDrawable().apply {
                    shape = android.graphics.drawable.GradientDrawable.OVAL
                    setColor(IdentityColor.stripeColor(member.agentIdHex))
                }
            },
        )

        val nameColumn = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f,
            ).apply { marginStart = (14 * density).toInt() }
        }
        nameColumn.addView(
            TextView(context).apply {
                text = if (isSelf) context.getString(R.string.chat_member_you, name) else name
                setTextColor(themeColor(R.attr.fetchitBone))
                textSize = 17f
                maxLines = 2
                ellipsize = android.text.TextUtils.TruncateAt.END
            },
        )
        memberRoleTag(member.role)?.let { tag ->
            nameColumn.addView(
                TextView(context).apply {
                    text = tag
                    setTextColor(themeColor(R.attr.fetchitAsh))
                    textSize = 12f
                },
            )
        }
        // Short agent-id: first 8 hex + ellipsis. The full id is on Copy ID.
        nameColumn.addView(
            TextView(context).apply {
                text = "${member.agentIdHex.take(8)}…"
                setTextColor(themeColor(R.attr.fetchitAsh))
                textSize = 12f
            },
        )
        header.addView(nameColumn)

        val sheet = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            addView(header)
        }

        val dialog = MaterialAlertDialogBuilder(context)
            .setView(sheet)
            .setNegativeButton(context.getString(R.string.action_close), null)
            .create()

        // Actions render as full-width tappable rows inside the sheet (a custom
        // view can't share the dialog with a setItems list, and there are only
        // three button slots). Each row dismisses the sheet, then acts.
        fun actionRow(labelRes: Int, destructive: Boolean, onTap: () -> Unit): View =
            TextView(context).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                )
                text = context.getString(labelRes)
                textSize = 16f
                setTextColor(
                    if (destructive) themeColor(R.attr.fetchitCopper) else themeColor(R.attr.fetchitBone),
                )
                setPadding(pad, (14 * density).toInt(), pad, (14 * density).toInt())
                isClickable = true
                isFocusable = true
                setBackgroundResource(selectableItemBackground())
                setOnClickListener {
                    dialog.dismiss()
                    onTap()
                }
            }

        sheet.addView(android.view.View(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, (12 * density).toInt(),
            )
        })

        sheet.addView(
            actionRow(R.string.chat_member_copy_id, destructive = false) {
                copyToClipboard(member.agentIdHex)
                snackbar(context.getString(R.string.chat_member_id_copied))
            },
        )

        // Moderation lives here now (was the per-row overflow). Cosmetic gate;
        // x0xd authorizes the call and rejections surface via Snackbar.
        if (canModerateMember(viewerCanModerate, isSelf, member.isOwner)) {
            sheet.addView(
                actionRow(R.string.chat_member_remove, destructive = true) {
                    confirmRemoveMember(groupId, member, name)
                },
            )
            sheet.addView(
                actionRow(R.string.chat_member_ban, destructive = true) {
                    confirmBanMember(groupId, member, name)
                },
            )
        }
        dialog.show()
    }

    private fun confirmRemoveMember(groupId: String, member: GroupMemberFfi, name: String) {
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_member_remove_title))
            .setMessage(context.getString(R.string.chat_member_remove_message, name))
            .setPositiveButton(context.getString(R.string.chat_member_remove_confirm)) { _, _ ->
                lifecycleScope.launch {
                    controller.removeMember(groupId, member.agentIdHex) { e ->
                        snackbar(userFacingError(e, "removeMember", R.string.chat_moderation_failed))
                    }
                }
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    private fun confirmBanMember(groupId: String, member: GroupMemberFfi, name: String) {
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_member_ban_title))
            .setMessage(context.getString(R.string.chat_member_ban_message, name))
            .setPositiveButton(context.getString(R.string.chat_member_ban_confirm)) { _, _ ->
                lifecycleScope.launch {
                    controller.banMember(groupId, member.agentIdHex) { e ->
                        snackbar(userFacingError(e, "banMember", R.string.chat_moderation_failed))
                    }
                }
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    /**
     * Prompt to rename [groupId]. Admin-gated tap target (the group title);
     * x0xd authorizes the actual rename, so a rejection surfaces via Snackbar.
     * Mirrors [promptSetMyName]'s dialog shape.
     */
    private fun promptRenameGroup(groupId: String) {
        val current = controller.groups.value.firstOrNull { it.groupId == groupId }
        val editText = EditText(context).apply {
            setText(groupTitle(current, groupId))
            hint = context.getString(R.string.chat_group_rename_hint)
            setSelection(text.length)
        }
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(editText)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_group_rename_title))
            .setMessage(context.getString(R.string.chat_group_rename_message))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_group_rename_save)) { _, _ ->
                val newName = editText.text.toString().trim()
                if (newName.isEmpty()) return@setPositiveButton
                lifecycleScope.launch {
                    controller.renameGroup(groupId, newName) { e ->
                        snackbar(userFacingError(e, "renameGroup", R.string.chat_moderation_failed))
                    }
                }
            }
            .setNegativeButton(context.getString(R.string.action_cancel), null)
            .show()
    }

    private suspend fun onShareMyCodeClicked() {
        val gw = runCatching { connectWithFeedback() }.getOrNull() ?: return
        val uri = runCatching { gw.pairShareUri() }.getOrElse { e ->
            snackbar(userFacingError(e, "pairShareUri"))
            return
        }
        showPairQrDialog(uri)
    }

    /**
     * Show the local pairing code in a dismissible modal: the branded QR card,
     * a copy-link action, and close. Replaces the older inline-on-the-list QR,
     * which had no dismiss control, persisted across navigation, and let a
     * system back from the list fall through to browse instead of closing the
     * code. Android back now dismisses the dialog, not chat.
     */
    private fun showPairQrDialog(uri: String) {
        val label = context.getString(R.string.chat_pair_card_label)
        val bitmap = QrShare.renderCardForUri(uri, label)
        val image = ImageView(context).apply {
            adjustViewBounds = true
            bitmap?.let { setImageBitmap(it) }
            contentDescription = context.getString(R.string.chat_pair_qr_desc)
            val pad = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_share_my_code))
            .setView(image)
            .setPositiveButton(context.getString(R.string.chat_pair_copy_link)) { _, _ ->
                copyToClipboard(uri)
                snackbar(context.getString(R.string.chat_uri_copied))
            }
            .setNegativeButton(context.getString(R.string.action_close), null)
            .show()
    }

    /**
     * "Add someone" — one field, two intents. Type a fediverse @name to look
     * them up (then choose to message privately, post-quantum), or paste an
     * `x0x://` / `fetchit://share` link to add them straight away.
     * [classifyAddContactInput] decides which. Nothing here dead-ends: an empty
     * box nudges, a name that resolves to nobody shows a friendly "no one found"
     * card, and only a link goes to the import path.
     */
    private fun showAddContactDialog() {
        val editText = EditText(context).apply {
            hint = context.getString(R.string.chat_add_someone_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val layout = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(editText)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_add_someone_title))
            .setMessage(context.getString(R.string.chat_add_someone_message))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_add_someone_find)) { _, _ ->
                when (val input = classifyAddContactInput(editText.text.toString())) {
                    // A pasted link routes by kind: group invites join the
                    // group, anything else goes to the pair-import path (which
                    // owns its own validation + friendly errors). One box,
                    // right thing — the onboarding empty state hides the FAB,
                    // so this is a first-run user's only paste target.
                    is AddContactInput.PairUri ->
                        if (ChatUris.isInviteUri(input.raw)) {
                            joinGroupThen(input.raw)
                        } else {
                            importFromUri(input.raw)
                        }
                    is AddContactInput.FediHandle -> findByHandle(input.handle)
                    AddContactInput.Empty ->
                        snackbar(context.getString(R.string.chat_add_someone_empty))
                }
            }
            .setNegativeButton(context.getString(R.string.action_close), null)
            .show()
    }

    /**
     * Look up a fediverse handle and present a contact card. Connects first (the
     * lookup hits the directory + the person's relay), then routes the result to
     * [showLookupResultDialog]. A malformed handle or a transport failure lands
     * as a warm Snackbar, never a raw error.
     */
    private fun findByHandle(handle: String) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse { return@launch }
            runCatching { gw.fediLookup(handle) }.fold(
                onSuccess = { showLookupResultDialog(it) },
                onFailure = { e ->
                    snackbar(userFacingError(e, "fediLookup", R.string.chat_find_failed))
                },
            )
        }
    }

    /**
     * Present a fediverse lookup result as a plain-language card. Verified shows
     * a "message privately" action (post-quantum DM); public-only found the
     * account but couldn't confirm the person, so it explains that warmly with
     * no dead-end action; not-found nudges to check the spelling. A verified
     * handle that changed hands carries an extra heads-up line.
     */
    private fun showLookupResultDialog(lookup: LookupFfi) {
        val builder = MaterialAlertDialogBuilder(context)
        // A blocked account's card offers exactly one path: unblock.
        if (blockStore.isBlocked(lookup.handle)) {
            builder.setTitle(lookup.handle)
                .setMessage(context.getString(R.string.fedi_lookup_blocked_body))
                .setPositiveButton(context.getString(R.string.fedi_unblock)) { _, _ ->
                    blockStore.unblock(lookup.handle)
                    snackbar(context.getString(R.string.fedi_unblocked, lookup.handle))
                    showLookupResultDialog(lookup)
                }
                .setNegativeButton(context.getString(R.string.action_close), null)
                .show()
            return
        }
        // Device-local memory of sent follows: the card keeps showing
        // "following ✓" long after the confirmation snackbar is gone.
        // The button stays tappable — re-following is idempotent.
        val following = followStore.isFollowing(lookup.handle)
        val followLabel = context.getString(
            if (following) R.string.chat_fedi_following_badge else R.string.chat_fedi_follow,
        )
        when (lookup.kind) {
            LookupKindFfi.VERIFIED -> {
                val body = StringBuilder(context.getString(R.string.chat_lookup_verified_body))
                if (lookup.previousAgentIdHex != null) {
                    body.append("\n\n").append(context.getString(R.string.chat_lookup_changed_hands))
                }
                if (following) {
                    body.append("\n\n").append(context.getString(R.string.chat_lookup_following_line))
                }
                builder.setTitle(lookup.handle)
                    .setMessage(body.toString())
                    .setPositiveButton(context.getString(R.string.chat_lookup_message_privately)) { _, _ ->
                        messagePrivately(lookup)
                    }
                    .setNeutralButton(followLabel) { _, _ ->
                        followFedi(lookup.handle)
                    }
                    .setNegativeButton(context.getString(R.string.action_close), null)
            }
            LookupKindFfi.PUBLIC_ONLY -> {
                val body = StringBuilder(context.getString(R.string.chat_lookup_public_only_body))
                if (following) {
                    body.append("\n\n").append(context.getString(R.string.chat_lookup_following_line))
                }
                // Message is the primary action: leading with the caveat text
                // plus a buried button read as "you can't message them" in
                // device testing. The card must open doors, not close them.
                builder.setTitle(lookup.handle)
                    .setMessage(body.toString())
                    .setPositiveButton(context.getString(R.string.chat_fedi_dm)) { _, _ ->
                        openFediThread(lookup.handle)
                    }
                    .setNeutralButton(followLabel) { _, _ ->
                        followFedi(lookup.handle)
                    }
                    .setNegativeButton(context.getString(R.string.action_close), null)
            }
            LookupKindFfi.NOT_FOUND ->
                builder.setTitle(context.getString(R.string.chat_lookup_not_found_title))
                    .setMessage(context.getString(R.string.chat_lookup_not_found_body, lookup.handle))
                    .setPositiveButton(context.getString(R.string.action_close), null)
        }
        builder.show()
    }

    /**
     * Follow a fediverse account by handle: the device signs + delivers a
     * `Follow` and the bridge records it pending. Requires a minted handle —
     * a clear snackbar nudges to mint one first if not. The remote `Accept`
     * arrives later (standard follow-request UX), so success here means "your
     * follow is on its way", not "they accepted".
     */
    private fun followFedi(handle: String) {
        if (!requireMintedHandle()) return
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse {
                retrySnackbar(context.getString(R.string.chat_connect_failed_generic)) {
                    followFedi(handle)
                }
                return@launch
            }
            runCatching { gw.fediFollow(handle) }.fold(
                onSuccess = { report ->
                    // delivered=false means the remote inbox never got the
                    // Follow — the engine's follow-state sync re-asserts it.
                    android.util.Log.w(
                        "FediFollow",
                        "follow $handle: delivered=${report.delivered} recorded=${report.recorded}",
                    )
                    followStore.recordFollow(handle)
                    val msg = if (report.recorded) {
                        context.getString(R.string.chat_fedi_follow_sent, handle)
                    } else {
                        context.getString(R.string.chat_fedi_follow_pending, handle)
                    }
                    snackbar(msg)
                },
                onFailure = { e ->
                    retrySnackbar(userFacingError(e, "fediFollow", R.string.chat_fedi_follow_failed)) {
                        followFedi(handle)
                    }
                },
            )
        }
    }

    /**
     * Gate a fediverse action on having a minted \@handle, explaining in
     * plain language what to do when there isn't one. Returns whether the
     * action may proceed. Without this gate the engine's rejection surfaces
     * as a generic failure — misleading when the real fix is "mint first".
     */
    private fun requireMintedHandle(): Boolean {
        if (controller.fediActorStatus() != null) return true
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_fedi_needs_handle_title))
            .setMessage(context.getString(R.string.chat_fedi_needs_handle_body))
            .setPositiveButton(context.getString(R.string.action_close), null)
            .show()
        return false
    }

    /**
     * Failure snackbar with a "retry" action — a failed outcome must offer
     * the path forward, never dead-end on a vanished message.
     */
    private fun retrySnackbar(msg: String, retry: () -> Unit) {
        Snackbar.make(container, msg, Snackbar.LENGTH_LONG)
            .setAction(context.getString(R.string.action_retry)) { retry() }
            .show()
    }

    /**
     * Turn a verified lookup into a private conversation: import the contact
     * from its v3 share URI (the engine fetches + verifies the profile record),
     * register it under the handle's name so the thread reads "alice" not a hex
     * id, and open the DM. The share URI + agent id exist only on a verified
     * result, so both are guarded.
     */
    private fun messagePrivately(lookup: LookupFfi) {
        val shareUri = lookup.shareUri ?: return
        val agentId = lookup.agentIdHex ?: return
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse { return@launch }
            runCatching { gw.importPairUri(shareUri.trim()) }.onFailure { e ->
                snackbar(userFacingError(e, "importPairUri", R.string.chat_error_invalid))
                return@launch
            }
            // We already know who they are (their handle), so name the contact
            // automatically and skip the "name this contact" prompt — straight
            // into the chat. Idempotent: re-finding an existing contact just
            // reopens their thread.
            if (controller.contacts.contacts.value.none { it.agentIdHex == agentId }) {
                controller.contacts.add(
                    ChatContact(
                        agentIdHex = agentId,
                        displayName = contactNameFromHandle(lookup.handle),
                        addedAtMs = System.currentTimeMillis(),
                    ),
                )
            }
            openThread(agentId)
        }
    }

    // ── group create / join ────────────────────────────────────────────

    /**
     * Dialog to create a group: a name input + a private/public toggle that
     * defaults to private (PQ MLS). On create, opens the new group's thread
     * and offers to share its invite via the existing clipboard path. Mirrors
     * [showAddContactDialog].
     */
    private fun showNewGroupDialog() {
        val nameInput = EditText(context).apply {
            hint = context.getString(R.string.chat_new_group_name_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_CAP_WORDS
        }
        // Default private: groups are PQ MLS unless the user opts into a public
        // room. Checked == private, matching the engine's create_private path.
        val privateToggle = CheckBox(context).apply {
            text = context.getString(R.string.chat_new_group_private_label)
            isChecked = true
        }
        val layout = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(nameInput)
            addView(privateToggle)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_new_group_title))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_new_group_create)) { _, _ ->
                val name = nameInput.text.toString().trim()
                if (name.isEmpty()) {
                    snackbar(context.getString(R.string.chat_new_group_name_hint))
                    return@setPositiveButton
                }
                createGroupThen(name, private = privateToggle.isChecked)
            }
            .setNegativeButton(context.getString(R.string.action_close), null)
            .show()
    }

    /**
     * Dialog to join a group from a pasted `x0x://invite/…` link. Validates
     * the prefix client-side ([ChatUris.isInviteUri]) before handing the raw
     * uri to the engine. Mirrors [showAddContactDialog].
     */
    private fun showJoinGroupDialog() {
        val editText = EditText(context).apply {
            hint = context.getString(R.string.chat_join_group_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val layout = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(editText)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_join_group_title))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_join_group_join)) { _, _ ->
                val raw = editText.text.toString().trim()
                if (!ChatUris.isInviteUri(raw)) {
                    snackbar(context.getString(R.string.chat_invalid_invite_uri))
                    return@setPositiveButton
                }
                joinGroupThen(raw)
            }
            .setNegativeButton(context.getString(R.string.action_close), null)
            .show()
    }

    /**
     * Connect, create the group under the local display name, refresh the
     * group list, open its thread, and offer to share the fresh invite.
     */
    private fun createGroupThen(name: String, private: Boolean) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrNull() ?: return@launch
            val senderName = displayNameOrDefault(gw)
            val group = runCatching { gw.createGroup(name, senderName, private) }.getOrElse { e ->
                snackbar(userFacingError(e, "createGroup", R.string.chat_group_create_failed))
                return@launch
            }
            controller.refreshGroups()
            snackbar(context.getString(R.string.chat_group_created, groupTitle(group, group.groupId)))
            openGroupThread(group.groupId)
            offerShareInvite(group.groupId)
        }
    }

    /**
     * Connect, join via the invite uri under the local display name, refresh
     * the group list, and open the joined group's thread.
     */
    private fun joinGroupThen(inviteUri: String) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrNull() ?: return@launch
            val senderName = displayNameOrDefault(gw)
            // Durable join: a genuinely bad invite still errors, but an owner
            // being offline now returns Pending (a resumable intent), NOT a
            // failure -- so the join is never wasted and never shows the scary
            // "couldn't join" error just because the owner is asleep.
            val outcome = runCatching { gw.joinGroupDurable(inviteUri, senderName) }.getOrElse { e ->
                snackbar(userFacingError(e, "joinGroup", R.string.chat_group_join_failed))
                return@launch
            }
            controller.refreshGroups()
            when (outcome) {
                is JoinOutcomeFfi.Converged -> {
                    snackbar(
                        context.getString(
                            R.string.chat_group_joined,
                            groupTitle(outcome.group, outcome.group.groupId),
                        ),
                    )
                    openGroupThread(outcome.group.groupId)
                }
                is JoinOutcomeFfi.Pending -> {
                    // Owner not reachable yet: the record is durable and the
                    // controller's resume pump completes it with no user action.
                    // Surface "joining…" and let the list show it converge.
                    controller.refreshPendingJoins()
                    snackbar(context.getString(R.string.chat_group_join_pending))
                }
            }
        }
    }

    /**
     * Offer to share a fresh single-use invite for [groupId]: mint one via
     * the gateway and copy it to the clipboard, the existing share path for
     * chat URIs (the same clipboard route the pair-QR long-press uses). x0xd
     * group invites are single-use, so the snackbar action mints a FRESH
     * invite for the NEXT member (it re-offers, so the owner repeats once per
     * invitee) -- this is how a group grows past two members. A QR card is
     * not produced -- [QrShare] cards are scoped to `autonomi://` /
     * `x0x://pair/` payloads, and an invite blob is neither.
     */
    private fun offerShareInvite(groupId: String) {
        val gw = controller.gateway() ?: return
        lifecycleScope.launch {
            val invite = runCatching { gw.groupInvite(groupId) }.getOrNull() ?: return@launch
            copyToClipboard(invite)
            Snackbar.make(container, context.getString(R.string.chat_group_share_invite), Snackbar.LENGTH_LONG)
                .setAction(context.getString(R.string.chat_group_new_invite)) {
                    offerShareInvite(groupId)
                }
                .show()
        }
    }

    /**
     * Pick who to invite to a private group: your People — PQ contacts (🔒)
     * first, fediverse follows (🌐) below — or copy a link to share with
     * anyone. A PQ contact is invited over the existing PQ DM rail; a
     * fediverse-only person gets a FRESH single-use invite over a fedi DM.
     */
    private fun showGroupInvitePicker(groupId: String) {
        lifecycleScope.launch {
            val gw = controller.gateway() ?: return@launch
            val groupTitle = groupTitle(controller.groups.value.find { it.groupId == groupId }, groupId)
            val contacts = controller.contacts.contacts.value
            val follows = runCatching { gw.fediFollowing() }.getOrNull().orEmpty()

            val labels = ArrayList<String>()
            val actions = ArrayList<() -> Unit>()
            contacts.forEach { c ->
                val name = c.displayName.ifBlank { "${c.agentIdHex.take(8)}…" }
                labels.add("🔒 $name")
                actions.add { inviteContactToGroup(groupId, groupTitle, c, name) }
            }
            follows.forEach { f ->
                labels.add("🌐 ${f.label}")
                actions.add { inviteFediToGroup(groupId, groupTitle, f.label) }
            }
            labels.add(context.getString(R.string.group_invite_copy_link))
            actions.add { offerShareInvite(groupId) }

            MaterialAlertDialogBuilder(context)
                .setTitle(R.string.chat_group_invite_someone)
                .setItems(labels.toTypedArray()) { _, which -> actions[which]() }
                .setNegativeButton(context.getString(R.string.action_close), null)
                .show()
        }
    }

    /** Invite a PQ contact to the group over the existing private DM rail:
     *  mint a fresh single-use invite and DM it. When the contact is already
     *  in the roster (they reinstalled or moved phones — keys gone, roster
     *  entry left behind), x0xd would refuse to stage their Welcome, so the
     *  invite is preceded by a confirmed membership RESET (remove → re-key →
     *  fresh invite); see [reinviteDecision]. */
    private fun inviteContactToGroup(
        groupId: String,
        groupTitle: String,
        contact: ChatContact,
        name: String,
    ) {
        lifecycleScope.launch {
            when (reinviteDecision(controller.groupMembers(groupId), contact.agentIdHex)) {
                ReinviteDecision.INVITE -> mintAndDmInvite(groupId, groupTitle, contact, name)
                ReinviteDecision.ALREADY_OWNER ->
                    snackbar(context.getString(R.string.group_reinvite_owner, name))
                ReinviteDecision.CONFIRM_RESET -> MaterialAlertDialogBuilder(context)
                    .setTitle(context.getString(R.string.group_reinvite_title, name))
                    .setMessage(context.getString(R.string.group_reinvite_message, name))
                    .setPositiveButton(R.string.group_reinvite_confirm) { _, _ ->
                        lifecycleScope.launch { resetAndReinvite(groupId, groupTitle, contact, name) }
                    }
                    .setNegativeButton(context.getString(R.string.action_close), null)
                    .show()
            }
        }
    }

    /** The confirmed reset: remove the stale membership (x0xd drives the
     *  re-key that reseals the group without them), then invite normally.
     *  Removal is admin-gated daemon-side — a rejection surfaces and aborts. */
    private suspend fun resetAndReinvite(
        groupId: String,
        groupTitle: String,
        contact: ChatContact,
        name: String,
    ) {
        var removed = true
        controller.removeMember(groupId, contact.agentIdHex) {
            removed = false
            snackbar(context.getString(R.string.group_reinvite_reset_failed, name))
        }
        if (removed) mintAndDmInvite(groupId, groupTitle, contact, name)
    }

    /** Mint a fresh single-use invite for [groupId] and DM it to [contact]. */
    private suspend fun mintAndDmInvite(
        groupId: String,
        groupTitle: String,
        contact: ChatContact,
        name: String,
    ) {
        val gw = controller.gateway() ?: return
        val invite = runCatching { gw.groupInvite(groupId) }.getOrNull() ?: run {
            snackbar(context.getString(R.string.group_invite_send_failed, name))
            return
        }
        val senderName = displayNameOrDefault(gw)
        val body = context.getString(R.string.group_invite_dm, senderName, groupTitle, invite)
        runCatching { gw.enqueueDm(contact.agentIdHex, body, senderName) }.fold(
            onSuccess = { snackbar(context.getString(R.string.group_invite_sent, name)) },
            onFailure = {
                Log.w(TAG, "enqueueDm(group-invite): ${ffiReason(it)}", it)
                snackbar(context.getString(R.string.group_invite_send_failed, name))
            },
        )
    }

    /** Invite a fediverse-only person to the group: mint a FRESH single-use
     *  invite (never reuse) and send it over a fedi DM with the install nudge. */
    private fun inviteFediToGroup(groupId: String, groupTitle: String, handle: String) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse {
                snackbar(context.getString(R.string.group_invite_send_failed, handle))
                return@launch
            }
            val invite = runCatching { gw.groupInvite(groupId) }.getOrNull() ?: run {
                snackbar(context.getString(R.string.group_invite_send_failed, handle))
                return@launch
            }
            val senderName = displayNameOrDefault(gw)
            val body = context.getString(R.string.group_invite_dm, senderName, groupTitle, invite)
            val report = runCatching { gw.fediDm(handle, body) }.getOrElse {
                Log.w(TAG, "fediDm(group-invite): ${ffiReason(it)}", it)
                snackbar(context.getString(R.string.group_invite_send_failed, handle))
                return@launch
            }
            if (report.delivered) {
                snackbar(context.getString(R.string.group_invite_sent, handle))
            } else {
                snackbar(context.getString(R.string.group_invite_send_failed, handle))
            }
        }
    }

    // ── thread screen ──────────────────────────────────────────────────

    private fun bindThreadScreen(peer: String) {
        val view = threadView ?: LayoutInflater.from(context)
            .inflate(R.layout.view_chat_thread, slot, false)
            .also { threadView = it }

        slot.addView(view)

        val contact = controller.contacts.contacts.value.find { it.agentIdHex == peer }
        val displayName = contact?.displayName ?: "peer-${peer.take(6)}"

        view.findViewById<TextView>(R.id.threadPeerName).text = displayName
        view.findViewById<TextView>(R.id.threadPeerShortId).text = "${peer.take(8)}…"
        view.findViewById<View>(R.id.threadBackButton).setOnClickListener { onBack() }
        view.findViewById<View>(R.id.threadSendRow).visibility = View.VISIBLE
        // A DM has no member list; hide the (shared-layout) members button and
        // detach any group-thread rename listener a recycled view might carry.
        view.findViewById<ImageButton>(R.id.threadMembersButton).visibility = View.GONE
        view.findViewById<TextView>(R.id.threadPeerName).setOnClickListener(null)

        val rv = view.findViewById<RecyclerView>(R.id.messageList)
        val lm = LinearLayoutManager(context).apply { stackFromEnd = true }
        rv.layoutManager = lm
        val adapter = MessageAdapter(onOpenAutonomi, onRetry = { retryOutbox() })
        rv.adapter = adapter

        val messageInput = view.findViewById<EditText>(R.id.messageInput)
        val sendButton = view.findViewById<View>(R.id.sendButton)
        bindSendEnabled(messageInput, sendButton)
        sendButton.setOnClickListener {
            val body = messageInput.text.toString().trim()
            if (body.isEmpty()) return@setOnClickListener
            messageInput.text.clear()
            sendJob?.cancel()
            sendJob = lifecycleScope.launch {
                val gw = controller.gateway() ?: run {
                    // Only restore text if this thread is still the active screen.
                    if (screenStack.lastOrNull() == Screen.Thread(peer)) {
                        messageInput.setText(body)
                    }
                    snackbar(context.getString(R.string.chat_not_connected))
                    return@launch
                }
                val senderName = displayNameOrDefault(gw)
                // Enqueue into the durable outbox: the optimistic Sending bubble
                // and its Delivered/Failed transitions arrive as Outbox events
                // through the pump, so there is no local append here.
                runCatching { gw.enqueueDm(peer, body, senderName) }.onFailure { e ->
                    // Only restore text if this thread is still the active screen.
                    if (screenStack.lastOrNull() == Screen.Thread(peer)) {
                        messageInput.setText(body)
                    }
                    snackbar(userFacingError(e, "enqueueDm", R.string.thread_send_failed))
                }
            }
        }

        // If this person is linked to a fediverse handle, the thread is a
        // merged (🔒) thread: their fediverse history folds in above the
        // private messages, and the open-fediverse fallback is offered while
        // the private rail is down. Resolved once (local reverse lookup).
        val linkedLabel = runCatching { controller.gateway()?.fediLinkedLabelForAgent(peer) }
            .getOrNull()

        // Fallback offer (§7.6): honest banner + ONE explicit, labeled action.
        // Never an automatic downgrade — a silent switch would make the 🔒 a
        // lie. Only meaningful on a linked thread.
        val fallbackBanner = view.findViewById<View>(R.id.threadFallbackBanner)
        if (linkedLabel != null) {
            view.findViewById<TextView>(R.id.threadFallbackText).text =
                context.getString(R.string.thread_fallback_banner, displayName)
            view.findViewById<View>(R.id.threadFallbackAction).setOnClickListener {
                openFediThread(linkedLabel)
            }
        } else {
            fallbackBanner.visibility = View.GONE
        }

        // Collect messages for this peer; job cancelled on screen switch.
        threadCollectJob = lifecycleScope.launch {
            // Hydrate the persisted transcript before/as the thread renders so a
            // reopened DM is not empty after a process kill. Idempotent (de-duped
            // by message id) and non-fatal.
            controller.hydrateConversation(ConversationStore.convKeyDm(peer))
            // Merged-thread history: the linked person's fediverse messages
            // (read-only) above a two-line divider, then the private messages.
            val fediRows: List<MessageRow> = if (linkedLabel != null) {
                val fkey = ConversationStore.convKeyFedi(linkedLabel)
                controller.hydrateConversation(fkey)
                // The merged thread shows this person's fediverse history
                // here, so reading it here is reading it.
                controller.markFediThreadRead(linkedLabel)
                val fediMsgs = controller.conversations.messagesFor(fkey).value
                if (fediMsgs.isEmpty()) {
                    emptyList()
                } else {
                    dmRowsWithDays(fediMsgs) + listOf(
                        MessageRow.Divider(context.getString(R.string.thread_divider_fedi)),
                        MessageRow.Divider(context.getString(R.string.thread_divider_pq)),
                    )
                }
            } else {
                emptyList()
            }
            // Show the offered fallback only while the pump is down; it clears
            // on RUNNING. Child coroutine — cancelled with threadCollectJob.
            if (linkedLabel != null) {
                launch {
                    controller.pumpState.collect { state ->
                        fallbackBanner.visibility =
                            if (state == PumpState.STOPPED_ERROR) View.VISIBLE else View.GONE
                    }
                }
            }
            controller.conversations.messagesFor(peer).collect { msgs ->
                val prevSize = adapter.itemCount
                // The composer sends ONLY PQ (enqueueDm above) — a lock on the
                // row means nothing typed here is ever plaintext. Fediverse
                // messaging to this person stays deliberately out of the way.
                val rows = fediRows + dmRowsWithDays(msgs)
                adapter.submitList(rows)
                // Scroll only when new messages arrive, not on receipt-tick rebinds.
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
                // Read AFTER the render, never before: the mark may only claim
                // what was actually put on screen. Fires on the first emission
                // (opening the thread) and on every message that lands while it
                // is still up, so the row never badges what the user is reading.
                controller.markConversationRead(ConversationStore.convKeyDm(peer))
            }
        }
    }

    // ── group thread screen ────────────────────────────────────────────

    /**
     * Bind the group thread for [groupId]. Mirrors [bindThreadScreen] but:
     * the title resolves from the loaded [GroupFfi] via [groupTitle] (a short
     * id fallback); send goes DIRECT through `sendGroupMessage` (no outbox for
     * groups in v1, matching desktop); and messages are read from the group
     * conversation key ([ConversationStore.convKeyGroup]). The [MessageAdapter]
     * is reused unchanged -- inbound group bubbles carry a sender label off
     * [ChatMessage.senderAgentIdHex].
     */
    private fun bindGroupThreadScreen(groupId: String) {
        val view = groupThreadView ?: LayoutInflater.from(context)
            .inflate(R.layout.view_chat_thread, slot, false)
            .also { groupThreadView = it }

        slot.addView(view)

        val group = controller.groups.value.find { it.groupId == groupId }
        val title = groupTitle(group, groupId)
        // A leading lock glyph signals a PQ-encrypted (private) group; public
        // rooms and unresolved-kind groups show the bare title.
        val titleText = if (group?.isPrivate == true) {
            "${context.getString(R.string.chat_group_lock_glyph)} $title"
        } else {
            title
        }

        val peerName = view.findViewById<TextView>(R.id.threadPeerName)
        peerName.text = titleText
        view.findViewById<TextView>(R.id.threadPeerShortId).text = "${groupId.take(8)}…"
        view.findViewById<View>(R.id.threadBackButton).setOnClickListener { onBack() }
        view.findViewById<View>(R.id.threadSendRow).visibility = View.VISIBLE

        // Group member list + moderation entry. Visible on a group thread only
        // (DM/feed headers hide it). The members button opens the roster dialog;
        // the title becomes a rename affordance once we know the viewer is admin+
        // (resolved async below — until then it is inert). All role checks here
        // are COSMETIC: x0xd is the sole authorization gate.
        val membersButton = view.findViewById<ImageButton>(R.id.threadMembersButton)
        membersButton.visibility = View.VISIBLE
        membersButton.setOnClickListener { showGroupMembersDialog(groupId) }
        // Resolve the viewer's own role from the roster, then enable the title-tap
        // rename only when they can moderate. Non-fatal: an empty/failed roster
        // leaves the title inert.
        lifecycleScope.launch {
            val roster = controller.groupMembers(groupId)
            val myHex = controller.gateway()?.agentIdHex()
            val myRole = roster.firstOrNull { it.agentIdHex == myHex }?.role
            if (canModerate(myRole)) {
                peerName.setOnClickListener { promptRenameGroup(groupId) }
            }
        }

        val rv = view.findViewById<RecyclerView>(R.id.messageList)
        val lm = LinearLayoutManager(context).apply { stackFromEnd = true }
        rv.layoutManager = lm
        // Group bubbles are peer-agnostic; retry is a DM-outbox affordance and
        // never fires for the direct group-send path, so it is a no-op here.
        val adapter = MessageAdapter(onOpenAutonomi, onRetry = {})
        rv.adapter = adapter

        val messageInput = view.findViewById<EditText>(R.id.messageInput)
        val sendButton = view.findViewById<View>(R.id.sendButton)
        bindSendEnabled(messageInput, sendButton)
        sendButton.setOnClickListener {
            val body = messageInput.text.toString().trim()
            if (body.isEmpty()) return@setOnClickListener
            messageInput.text.clear()
            sendJob?.cancel()
            sendJob = lifecycleScope.launch {
                val gw = controller.gateway() ?: run {
                    if (screenStack.lastOrNull() == Screen.GroupThread(groupId)) {
                        messageInput.setText(body)
                    }
                    snackbar(context.getString(R.string.chat_not_connected))
                    return@launch
                }
                val senderName = displayNameOrDefault(gw)
                // Direct send (no outbox for groups in v1): append the outbound
                // bubble locally so the sender sees it, mirroring desktop -- the
                // group receive path filters self-source, so there is no echo.
                runCatching { gw.sendGroupMessage(groupId, body, senderName) }
                    .onSuccess { messageId ->
                        controller.conversations.append(
                            ConversationStore.convKeyGroup(groupId),
                            ChatMessage(
                                outbound = true,
                                body = body,
                                sentAtMs = System.currentTimeMillis(),
                                messageId = messageId,
                            ),
                        )
                    }
                    .onFailure { e ->
                        if (screenStack.lastOrNull() == Screen.GroupThread(groupId)) {
                            messageInput.setText(body)
                        }
                        snackbar(userFacingError(e, "sendGroupMessage", R.string.thread_send_failed))
                    }
            }
        }

        // Collect messages for this group; job cancelled on screen switch.
        threadCollectJob = lifecycleScope.launch {
            // Hydrate the persisted transcript before/as the thread renders so a
            // reopened group is not empty after a process kill. Idempotent
            // (de-duped by message id) and non-fatal.
            controller.hydrateConversation(ConversationStore.convKeyGroup(groupId))
            controller.conversations.messagesFor(ConversationStore.convKeyGroup(groupId)).collect { msgs ->
                val prevSize = adapter.itemCount
                val rows = dmRowsWithDays(msgs)
                adapter.submitList(rows)
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
                // Read AFTER the render (see the DM thread): on open, and again
                // for every message that arrives while the group is on screen.
                controller.markConversationRead(ConversationStore.convKeyGroup(groupId))
            }
        }
    }

    // ── people screen ──────────────────────────────────────────────────

    // The People tab root: search, your private contacts, and the
    // fediverse social graph (following / followers / blocked).
    private fun bindPeopleScreen() {
        val px16 = (16 * context.resources.displayMetrics.density).toInt()
        val px8 = px16 / 2
        val root = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(px16, px8, px16, px16)
        }
        val scroller = android.widget.ScrollView(context).apply {
            addView(root)
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }

        fun header(text: String) = TextView(context).apply {
            this.text = text
            textSize = 13f
            setTextColor(themeColor(R.attr.fetchitCopper))
            setPadding(0, px16, 0, px8)
        }
        fun line(text: String) = TextView(context).apply {
            this.text = text
            textSize = 14f
            setTextColor(themeColor(R.attr.fetchitAsh))
            setPadding(0, px8, 0, px8)
        }

        // Search — one field for an @name or a pasted link (opens the unified
        // add-someone flow).
        root.addView(android.widget.Button(context).apply {
            text = context.getString(R.string.people_find_hint)
            setOnClickListener { showAddContactDialog() }
        })

        // No public @handle yet → invite to mint (following/followers need one).
        if (controller.fediActorStatus() == null) {
            root.addView(TextView(context).apply {
                text = context.getString(R.string.feed_mint_prompt)
                textSize = 15f
                setTextColor(themeColor(R.attr.fetchitCopper))
                setPadding(0, px16, 0, px8)
                isClickable = true
                setOnClickListener {
                    showFediMintDialog(controller.fediMintConflictHandle()) {
                        showRoot(Screen.People)
                    }
                }
            })
        }

        // Your private (PQ) contacts.
        root.addView(header(context.getString(R.string.people_contacts_header)))
        val contacts = controller.contacts.contacts.value
        if (contacts.isEmpty()) {
            root.addView(line(context.getString(R.string.people_contacts_empty)))
        } else {
            contacts.forEach { c ->
                root.addView(TextView(context).apply {
                    text = "🔒 ${c.displayName}"
                    textSize = 15f
                    setTextColor(themeColor(R.attr.fetchitBone))
                    setPadding(0, px8, 0, px8)
                    isClickable = true
                    setOnClickListener { openThread(c.agentIdHex) }
                })
            }
        }

        val followingHeader = header(context.getString(R.string.fedi_people_following, "…"))
        root.addView(followingHeader)
        val followingBox = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        root.addView(followingBox)

        val followersHeader = header(context.getString(R.string.fedi_people_followers))
        root.addView(followersHeader)
        val followersBox = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        root.addView(followersBox)

        val blockedHeader = header(context.getString(R.string.fedi_people_blocked))
        root.addView(blockedHeader)
        val blockedBox = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        root.addView(blockedBox)

        fun renderBlocked() {
            blockedBox.removeAllViews()
            val blocked = blockStore.blocked()
            blockedHeader.visibility = if (blocked.isEmpty()) View.GONE else View.VISIBLE
            blocked.forEach { b ->
                val row = android.widget.LinearLayout(context).apply {
                    orientation = android.widget.LinearLayout.HORIZONTAL
                    gravity = android.view.Gravity.CENTER_VERTICAL
                }
                row.addView(TextView(context).apply {
                    text = context.getString(R.string.fedi_handle_at, b)
                    textSize = 14f
                    setTextColor(themeColor(R.attr.fetchitBone))
                    layoutParams = android.widget.LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f,
                    )
                })
                row.addView(android.widget.Button(context, null, android.R.attr.borderlessButtonStyle).apply {
                    text = context.getString(R.string.fedi_unblock)
                    setOnClickListener {
                        blockStore.unblock(b)
                        snackbar(context.getString(R.string.fedi_unblocked, b))
                        renderBlocked()
                    }
                })
                blockedBox.addView(row)
            }
        }
        renderBlocked()

        fun renderFollowing(entries: List<uniffi.fetchit_ffi.FediFollowingFfi>) {
            followingBox.removeAllViews()
            followingHeader.text =
                context.getString(R.string.fedi_people_following, entries.size.toString())
            if (entries.isEmpty()) {
                followingBox.addView(line(context.getString(R.string.fedi_people_following_empty)))
                return
            }
            entries.forEach { e ->
                val atHandle = "@${e.label}"
                val row = android.widget.LinearLayout(context).apply {
                    orientation = android.widget.LinearLayout.HORIZONTAL
                    gravity = android.view.Gravity.CENTER_VERTICAL
                }
                row.addView(fediAvatarSlot(e.label, PEOPLE_AVATAR_DP))
                row.addView(TextView(context).apply {
                    text = if (e.state == "accepted") {
                        atHandle
                    } else {
                        context.getString(R.string.fedi_following_pending_row, atHandle)
                    }
                    textSize = 14f
                    setTextColor(themeColor(R.attr.fetchitBone))
                    layoutParams = android.widget.LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f,
                    )
                })
                row.addView(android.widget.Button(context, null, android.R.attr.borderlessButtonStyle).apply {
                    text = context.getString(R.string.chat_fedi_dm)
                    setOnClickListener { openFediThread(atHandle) }
                })
                row.addView(android.widget.ImageButton(context, null, android.R.attr.borderlessButtonStyle).apply {
                    setImageResource(android.R.drawable.ic_menu_more)
                    contentDescription = context.getString(R.string.fedi_row_more)
                    setOnClickListener { anchor ->
                        PopupMenu(context, anchor).apply {
                            menu.add(context.getString(R.string.fedi_unfollow))
                            menu.add(context.getString(R.string.fedi_block))
                            setOnMenuItemClickListener { item ->
                                when (item.title) {
                                    context.getString(R.string.fedi_unfollow) ->
                                        unfollowFedi(e.targetActorUrl, atHandle) { showRoot(Screen.People) }
                                    context.getString(R.string.fedi_block) -> {
                                        blockStore.block(atHandle)
                                        snackbar(context.getString(R.string.fedi_blocked, atHandle))
                                        renderBlocked()
                                    }
                                }
                                true
                            }
                            show()
                        }
                    }
                })
                followingBox.addView(row)
            }
        }

        slot.addView(scroller)

        if (controller.fediActorStatus() == null) {
            followingHeader.visibility = View.GONE
            followersHeader.visibility = View.GONE
            return
        }
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse {
                followingBox.addView(line(context.getString(R.string.chat_connect_failed_generic)))
                return@launch
            }
            runCatching { gw.fediFollowing() }.fold(
                onSuccess = { renderFollowing(it) },
                onFailure = {
                    followingBox.addView(
                        line(userFacingError(it, "fediFollowing", R.string.fedi_people_load_failed)),
                    )
                },
            )
            runCatching { gw.fediFollowers() }.fold(
                onSuccess = { followers ->
                    if (followers.isEmpty()) {
                        followersBox.addView(line(context.getString(R.string.fedi_people_followers_empty)))
                    } else {
                        followers.forEach { f ->
                            val row = android.widget.LinearLayout(context).apply {
                                orientation = android.widget.LinearLayout.HORIZONTAL
                                gravity = android.view.Gravity.CENTER_VERTICAL
                            }
                            row.addView(fediAvatarSlot(f, PEOPLE_AVATAR_DP))
                            row.addView(line(context.getString(R.string.fedi_handle_at, f)))
                            followersBox.addView(row)
                        }
                    }
                },
                onFailure = {
                    followersBox.addView(line(context.getString(R.string.fedi_people_followers_empty)))
                },
            )
        }
    }

    // ── feed screen ────────────────────────────────────────────────────

    private fun bindFeedScreen() {
        val view = feedView ?: LayoutInflater.from(context)
            .inflate(R.layout.view_feed, slot, false)
            .also { feedView = it }

        slot.addView(view)

        // Compose (or the mint card when there's no handle yet). The social
        // graph — find / follow / message — lives on the People tab now; Feed
        // is content only.
        bindFeedCompose(view)

        val rv = view.findViewById<RecyclerView>(R.id.feedList)
        rv.layoutManager = LinearLayoutManager(context).apply { stackFromEnd = true }
        val adapter = MessageAdapter(onOpenAutonomi, onRetry = {})
        rv.adapter = adapter

        feedCollectJob = lifecycleScope.launch {
            controller.feed.posts.collect { posts ->
                val prevSize = adapter.itemCount
                // Posts carry the published stamp (0 when the remote date
                // failed to parse), so undated posts simply sit under the
                // day above them rather than minting a header.
                val rows = rowsWithDays(
                    posts.filterNot { blockStore.isBlocked(it.actorUrl) },
                    { it.receivedAtMs },
                    { MessageRow.Post(it) },
                )
                adapter.submitList(rows)
                // Scroll only when new posts arrive, not on content-only updates.
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
            }
        }
        refreshPulledFeed()
    }

    /**
     * Pull the newest posts from followed accounts into the feed (merged +
     * de-duped by [FeedStore.mergeRemote]). Quiet on failure — the feed
     * simply stays as-is; a spinnerless refresh matches the screen's calm.
     * Runs on every feed open; repeat pulls are cheap no-ops thanks to
     * the merge de-dup.
     */
    private fun refreshPulledFeed() {
        if (controller.fediActorStatus() == null) return
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse { return@launch }
            runCatching { gw.fediFeed() }
                .onSuccess { posts ->
                    controller.feed.mergeRemote(
                        posts.map {
                            FeedPost(
                                actorUrl = it.authorLabel,
                                body = it.text,
                                receivedAtMs = parseIsoToMs(it.published),
                            )
                        },
                    )
                }
                .onFailure { android.util.Log.w(TAG, "fediFeed pull: ${ffiReason(it)}") }
        }
    }

    /** ISO-8601 → epoch ms, best-effort (0 sorts a stampless post oldest). */
    private fun parseIsoToMs(iso: String): Long =
        runCatching { java.time.Instant.parse(iso).toEpochMilli() }.getOrDefault(0L)

    // ── fediverse thread (plaintext rails) ─────────────────────────────

    /** Open the plaintext fediverse conversation with [handle]. */
    private fun openFediThread(handle: String) {
        if (!requireMintedHandle()) return
        showScreen(Screen.FediThread(handle), pushToStack = true)
    }

    /**
     * A conversation over ordinary fediverse rails, rendered from the
     * engine's durable thread store (hydrated via the `f:` conversation
     * key). Sends append an optimistic in-memory bubble and the engine
     * persists the message itself, so the thread survives process death
     * — in-memory-only persistence is how sent DMs used to vanish.
     * Replies land via [pullFediReplies]. The header carries the
     * not-encrypted contract permanently instead of a one-shot dialog.
     */
    private fun bindFediThreadScreen(handle: String) {
        val view = LayoutInflater.from(context)
            .inflate(R.layout.view_chat_thread, slot, false)
        slot.addView(view)
        val convKey = ConversationStore.convKeyFedi(handle)

        view.findViewById<TextView>(R.id.threadPeerName).text = handle
        bindFediAvatar(view.findViewById(R.id.threadPeerAvatar), handle)
        view.findViewById<TextView>(R.id.threadPeerShortId).apply {
            text = context.getString(R.string.chat_fedi_thread_sub)
            setTextColor(themeColor(R.attr.fetchitAsh))
            isClickable = false
            setOnClickListener(null)
        }
        view.findViewById<View>(R.id.threadBackButton).setOnClickListener { onBack() }
        view.findViewById<ImageButton>(R.id.threadMembersButton).visibility = View.GONE

        val rv = view.findViewById<RecyclerView>(R.id.messageList)
        rv.layoutManager = LinearLayoutManager(context).apply { stackFromEnd = true }
        val adapter = MessageAdapter(onOpenAutonomi, onRetry = {})
        rv.adapter = adapter

        val messageInput = view.findViewById<EditText>(R.id.messageInput)
        val sendButton = view.findViewById<View>(R.id.sendButton)
        view.findViewById<View>(R.id.threadSendRow).visibility = View.VISIBLE
        messageInput.hint = context.getString(R.string.chat_fedi_thread_hint, handle)
        bindSendEnabled(messageInput, sendButton)
        sendButton.setOnClickListener {
            val body = messageInput.text.toString().trim()
            if (body.isEmpty()) return@setOnClickListener
            messageInput.setText("")
            lifecycleScope.launch {
                val gw = runCatching { connectWithFeedback() }.getOrElse {
                    if (screenStack.lastOrNull() == Screen.FediThread(handle)) {
                        messageInput.setText(body)
                    }
                    return@launch
                }
                runCatching { gw.fediDm(handle, body) }.fold(
                    onSuccess = { report ->
                        // The bubble appearing in the thread IS the sent
                        // confirmation; only the degraded case speaks up.
                        controller.conversations.append(
                            convKey,
                            ChatMessage(
                                outbound = true,
                                body = body,
                                sentAtMs = System.currentTimeMillis(),
                                messageId = report.noteId,
                            ),
                        )
                        if (!report.delivered) {
                            snackbar(context.getString(R.string.chat_fedi_dm_pending, handle))
                        }
                    },
                    onFailure = { e ->
                        if (screenStack.lastOrNull() == Screen.FediThread(handle)) {
                            messageInput.setText(body)
                        }
                        snackbar(userFacingError(e, "fediDm", R.string.chat_fedi_dm_failed))
                    },
                )
            }
        }

        wireGoPrivateBar(view, handle)

        threadCollectJob = lifecycleScope.launch {
            controller.hydrateConversation(convKey)
            // Opening the thread IS reading it: clear the unread badge for
            // what is already on disk before the pull below adds more.
            controller.markFediThreadRead(handle)
            controller.conversations.messagesFor(convKey).collect { msgs ->
                val prevSize = adapter.itemCount
                val rows = dmRowsWithDays(msgs)
                adapter.submitList(rows)
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
            }
        }
        pullFediReplies(convKey, handle)
    }

    /** Resend is offered only after this cooldown, so a tap can't spam the
     *  recipient's inbox. The pair link is stable, so a resend is idempotent. */
    private val goPrivateResendCooldownMs = 24L * 60 * 60 * 1000

    /**
     * Show and drive the go-private strip on a fediverse thread. Reflects the
     * current per-person state (offer → invited/pending → linked) and never
     * auto-switches rails: escalation is always an explicit, confirmed tap.
     */
    private fun wireGoPrivateBar(view: View, handle: String) {
        view.findViewById<View>(R.id.fediGoPrivateBar).visibility = View.VISIBLE
        renderGoPrivateBar(view, handle)
    }

    private fun renderGoPrivateBar(view: View, handle: String) {
        val bar = view.findViewById<View>(R.id.fediGoPrivateBar)
        val label = view.findViewById<TextView>(R.id.fediGoPrivateLabel)
        val sub = view.findViewById<TextView>(R.id.fediGoPrivateSub)
        val resend = view.findViewById<TextView>(R.id.fediGoPrivateResend)
        lifecycleScope.launch {
            val link = runCatching { controller.gateway()?.fediPersonLinks() }
                .getOrNull()
                ?.firstOrNull { it.label.equals(handle, ignoreCase = true) }
            when {
                // Already linked (defensive — the row is normally folded away).
                link?.linked == true -> {
                    label.text = context.getString(R.string.go_private_linked)
                    sub.visibility = View.GONE
                    resend.visibility = View.GONE
                    bar.isClickable = false
                    bar.setOnClickListener(null)
                }
                // Invite delivered, not yet accepted: quiet pending status.
                link?.invited == true -> {
                    label.text = context.getString(R.string.go_private_pending)
                    sub.visibility = View.GONE
                    bar.isClickable = false
                    bar.setOnClickListener(null)
                    val invitedAt = link.invitedAtMs ?: 0L
                    val cooledDown =
                        System.currentTimeMillis() - invitedAt >= goPrivateResendCooldownMs
                    resend.visibility = if (cooledDown) View.VISIBLE else View.GONE
                    resend.setOnClickListener {
                        if (cooledDown) sendGoPrivateInvite(view, handle, resend = true)
                    }
                }
                // Fresh: the actionable offer.
                else -> {
                    label.text = context.getString(R.string.go_private_button)
                    sub.visibility = View.VISIBLE
                    resend.visibility = View.GONE
                    bar.isClickable = true
                    bar.setOnClickListener { confirmGoPrivate(view, handle) }
                }
            }
        }
    }

    /** The go-private confirmation card. The body states plainly that the
     *  invite itself travels the open fediverse. */
    private fun confirmGoPrivate(view: View, handle: String) {
        MaterialAlertDialogBuilder(context)
            .setTitle(R.string.go_private_title)
            .setMessage(context.getString(R.string.go_private_body, handle))
            .setPositiveButton(R.string.go_private_send) { _, _ ->
                sendGoPrivateInvite(view, handle, resend = false)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Publish a pair record and send the invite over the existing fediverse DM
     * rail. Pending state is recorded engine-side only when delivery succeeds
     * (handled in the FFI), so an unreachable inbox surfaces a retry and leaves
     * the offer intact rather than lying about a sent invite.
     */
    private fun sendGoPrivateInvite(view: View, handle: String, resend: Boolean) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse {
                snackbar(context.getString(R.string.go_private_send_failed, handle))
                return@launch
            }
            val name = displayNameOrDefault(gw)
            val report = runCatching { gw.fediGoPrivateInvite(handle, name) }.getOrElse {
                Log.w(TAG, "fediGoPrivateInvite: ${ffiReason(it)}", it)
                snackbar(context.getString(R.string.go_private_send_failed, handle))
                return@launch
            }
            if (report.delivered) {
                controller.refreshPersonLinks()
                if (screenStack.lastOrNull() == Screen.FediThread(handle)) {
                    renderGoPrivateBar(view, handle)
                }
            } else {
                snackbar(context.getString(R.string.go_private_send_failed, handle))
            }
        }
    }

    /**
     * Sync inbound fediverse replies from the bridge into the engine's
     * durable thread store, then re-hydrate this thread so anything new
     * renders. The engine owns the cursor and persists every pulled
     * message (each into its own sender's thread) and the cursor in one
     * atomic save — a process death can no longer lose a reply the
     * cursor already passed, which is how replies used to vanish.
     * Quiet on failure: the thread simply shows what it already has.
     *
     * Anything the pull lands in [handle]'s own thread is being read
     * right now — this screen is open on it — so the read mark advances
     * again afterwards and the row never carries a badge for messages
     * the user is looking at. Other senders' threads keep theirs.
     */
    private fun pullFediReplies(convKey: String, handle: String) {
        lifecycleScope.launch {
            val gw = runCatching { connectWithFeedback() }.getOrElse { return@launch }
            runCatching { gw.fediSyncInbox() }.getOrElse {
                android.util.Log.w(TAG, "fediSyncInbox: ${ffiReason(it)}")
                return@launch
            }
            controller.hydrateConversation(convKey)
            controller.markFediThreadRead(handle)
        }
    }

    /**
     * Wire the feed's compose row. Posting is public and needs a minted
     * @handle: with one, the send row appears with a "post publicly as @name"
     * hint (the public/non-PQ contract stated at the moment of typing) and
     * sends via [ChatGateway.fediPublish]; without one the row stays hidden —
     * the header carries the create-your-@handle prompt, and a successful mint
     * re-runs this binder so the row appears in place. A published post is
     * echoed into the local feed immediately (delivery to other servers is
     * best-effort and quiet); failure restores the draft with a warm note.
     */
    private fun bindFeedCompose(view: View) {
        val composeRow = view.findViewById<View>(R.id.feedComposeRow)
        val mintCard = view.findViewById<TextView>(R.id.feedMintCard)
        val handle = controller.fediActorStatus()
        if (handle == null) {
            // No public handle yet — offer to mint one instead of composing.
            composeRow.visibility = View.GONE
            mintCard.visibility = View.VISIBLE
            mintCard.setOnClickListener {
                // Seeded with a name the directory refused, so a conflict from
                // an earlier session reopens where it left off.
                showFediMintDialog(controller.fediMintConflictHandle()) {
                    bindFeedCompose(view)
                    refreshPulledFeed()
                }
            }
            return
        }
        mintCard.visibility = View.GONE
        composeRow.visibility = View.VISIBLE
        val messageInput = view.findViewById<EditText>(R.id.feedComposeInput)
        val sendButton = view.findViewById<View>(R.id.feedSendButton)
        messageInput.hint = context.getString(R.string.feed_compose_hint, handle)
        // A draft handed over by the reader's "post to feed": drop the caret
        // in front of the address so the first thing typed is the comment.
        pendingFeedCompose?.let { draft ->
            pendingFeedCompose = null
            messageInput.setText(draft)
            messageInput.setSelection(0)
            messageInput.requestFocus()
        }
        bindSendEnabled(messageInput, sendButton)
        sendButton.setOnClickListener {
            val body = messageInput.text.toString().trim()
            if (body.isEmpty()) return@setOnClickListener
            messageInput.setText("")
            lifecycleScope.launch {
                val gw = runCatching { connectWithFeedback() }.getOrElse {
                    if (screenStack.lastOrNull() == Screen.Feed) messageInput.setText(body)
                    return@launch
                }
                runCatching { gw.fediPublish(body, null) }
                    .onSuccess {
                        controller.feed.append(
                            FeedPost(
                                actorUrl = "@$handle@$HOME_INSTANCE",
                                body = body,
                                receivedAtMs = System.currentTimeMillis(),
                            ),
                        )
                        snackbar(context.getString(R.string.feed_posted))
                    }
                    .onFailure { e ->
                        if (screenStack.lastOrNull() == Screen.Feed) messageInput.setText(body)
                        snackbar(userFacingError(e, "fediPublish", R.string.feed_post_failed))
                    }
            }
        }
    }

    // ── gateway helpers ────────────────────────────────────────────────

    /**
     * Connect to the relay, showing UI feedback. Returns the gateway on
     * success. On failure shows a Snackbar with a plain user-facing message
     * (via [userFacingError]) + a retry action; the raw engine reason goes to
     * logcat, never to the screen.
     */
    /** Set once per view after the first self-heal registration pass runs. */
    private var fediEnsureDone = false
    private var fediSetupNagged = false
    private val followStore by lazy { FediFollowStore(context) }
    private val blockStore by lazy { FediBlockStore(context) }

    private suspend fun connectWithFeedback(): ChatGateway {
        showConnecting(true)
        val gateway = runCatching {
            controller.ensureGateway()
        }.onFailure { e ->
            showConnecting(false)
            val message = userFacingError(e, "ensureGateway", R.string.chat_connect_failed_generic)
            Snackbar.make(container, message, Snackbar.LENGTH_INDEFINITE)
                .setAction(context.getString(R.string.action_retry)) {
                    lifecycleScope.launch { connectWithFeedback() }
                }
                .show()
        }.getOrThrow()
        // Self-heal the fediverse actor registration once per session: a bridge
        // redeploy or a fresh device leaves the handle minted locally but absent
        // from the directory, which silently breaks follow/DM recording. Re-run
        // the idempotent register pass (reuses the existing identity) before the
        // caller's fedi action proceeds. Failures are non-fatal (stay pending).
        if (!fediEnsureDone && controller.fediActorStatus() != null) {
            fediEnsureDone = true
            runCatching { gateway.fediEnsureV2() }
                .onSuccess {
                    android.util.Log.w(
                        "FediSelfHeal",
                        "ensure: registration=${it.registration} upgraded=${it.upgraded} pending=${it.pending}",
                    )
                    when (val reg = it.registration) {
                        is MintRegistrationFfi.Registered -> {}
                        // The directory says the @name is someone else's. Retrying
                        // can only 409 again, so the loop stops here: the user is
                        // told once, and the engine now reports "no public handle"
                        // so the mint prompt comes back with the name to edit.
                        is MintRegistrationFfi.NameTaken -> if (!fediSetupNagged) {
                            fediSetupNagged = true
                            snackbar(
                                context.getString(R.string.chat_fedi_name_taken, reg.handle),
                            )
                        }
                        // Not registered yet: re-arm so the next connect retries,
                        // and tell the user once (quietly) that setup is ongoing.
                        is MintRegistrationFfi.Retrying -> {
                            fediEnsureDone = false
                            if (!fediSetupNagged) {
                                fediSetupNagged = true
                                snackbar(context.getString(R.string.chat_fedi_setup_pending))
                            }
                        }
                    }
                }
                .onFailure {
                    android.util.Log.w("FediSelfHeal", "ensure threw: ${it.message}")
                    fediEnsureDone = false
                }
        }
        showConnecting(false)
        return gateway
    }

    /**
     * Paint the header connection dot from [ChatController.connectionStatus]
     * in the brand palette (etchit-website/brand.html): connected on the brand
     * green (#6ab04c), connecting on the copper accent (#c9732b), offline on
     * the theme's rust. Green + copper are brand constants so the dot reads the
     * same warm green/orange across the dark/dim/light themes; only the offline
     * rust tracks the theme. The label carries the leading ● glyph so it
     * inherits the colour; the TalkBack description drops the glyph.
     */
    private fun renderConnectionStatus(view: TextView, status: ChatConnectionStatus) {
        val labelRes: Int
        val color: Int
        when (status) {
            ChatConnectionStatus.CONNECTED -> {
                labelRes = R.string.chat_conn_connected
                color = context.getColor(R.color.signal_green)
            }
            ChatConnectionStatus.CONNECTING -> {
                labelRes = R.string.chat_conn_connecting
                color = context.getColor(R.color.copper)
            }
            ChatConnectionStatus.OFFLINE -> {
                labelRes = R.string.chat_conn_offline
                color = themeColor(R.attr.fetchitRust)
            }
        }
        val label = context.getString(labelRes)
        view.text = label
        view.setTextColor(color)
        view.contentDescription = label.removePrefix("● ")
    }

    /**
     * Paint the offline-reassurance banner in the calm "warn" tone: a faint
     * copper-tinted fill behind bone text, matching the app's copper accent
     * rather than the old alarming dark-red pill. Warn (not info/ash) is the
     * only tone Android surfaces — the connection model exposes a single
     * down state (pump [PumpState.STOPPED_ERROR]); there is no in-pump
     * "reconnecting" phase to paint in the muted info tone (desktop's
     * `relay === "reconnecting"`). Resolved once at bind time from the active
     * theme so it tracks the dark/dim/light palettes.
     */
    private fun applyOfflineBannerTone(banner: TextView) {
        val copper = themeColor(R.attr.fetchitCopper)
        val bone = themeColor(R.attr.fetchitBone)
        // ~22% copper over the surface reads as a calm tint, not an alert.
        banner.setBackgroundColor((copper and 0x00FFFFFF) or (0x38 shl 24))
        banner.setTextColor(bone)
    }

    /** Resolve a theme color attribute against the host context's theme. */
    private fun themeColor(attr: Int): Int {
        val tv = android.util.TypedValue()
        context.theme.resolveAttribute(attr, tv, true)
        return tv.data
    }

    private fun showConnecting(visible: Boolean) {
        slot.post {
            val ct = (listView ?: slot).findViewById<TextView?>(R.id.chatConnectingText)
                ?: return@post
            ct.visibility = if (visible) View.VISIBLE else View.GONE
        }
    }

    // ── name-prompt + contact creation ────────────────────────────────

    private fun promptDisplayName(agentId: String) {
        val defaultName = "peer-${agentId.take(6)}"
        val editText = EditText(context).apply {
            setText(defaultName)
            selectAll()
        }
        val layout = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val px16 = (16 * context.resources.displayMetrics.density).toInt()
            setPadding(px16, 0, px16, 0)
            addView(editText)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.chat_contact_name_title))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_contact_name_save)) { _, _ ->
                val name = editText.text.toString().trim().ifEmpty { defaultName }
                controller.contacts.add(
                    ChatContact(
                        agentIdHex = agentId,
                        displayName = name,
                        addedAtMs = System.currentTimeMillis(),
                    ),
                )
                snackbar(context.getString(R.string.chat_contact_added, name))
                // Stub hook: Task 5 opens the thread here.
                openThread(agentId)
            }
            .setNegativeButton(context.getString(R.string.action_close), null)
            .show()
    }

    // ── misc helpers ───────────────────────────────────────────────────

    private fun snackbar(msg: String) {
        Snackbar.make(container, msg, Snackbar.LENGTH_LONG).show()
    }

    private fun copyToClipboard(text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("pair URI", text))
    }

    /**
     * Raw engine reason for an error, for **logcat only** — never shown to the
     * user. The on-screen copy comes from [userFacingError]; raw engine text
     * like "transport error" or "invalid key package" is meaningless and scary
     * to a non-technical user.
     */
    private fun ffiReason(e: Throwable): String = when (e) {
        is ChatFfiException.Invalid -> e.reason
        is ChatFfiException.Network -> e.reason
        else -> e.message.orEmpty()
    }

    /**
     * Map an engine error to a short, warm, plain-language Snackbar string and
     * log the raw reason to logcat for debugging. Only the on-screen text is
     * sanitized; the raw [ffiReason] always reaches `Log.w(TAG, ...)`.
     *
     * @param fallbackRes the path-specific friendly string shown for every
     *   non-connectivity failure (the send/group/mint/moderation paths pass
     *   their own "couldn't send"/"couldn't join"/"couldn't create your handle"
     *   copy). Only [ChatFfiException.Network] bypasses it, with a universal
     *   "check your internet" message; the pair-import path passes the
     *   "scan again" copy explicitly, so it stays scoped to code scanning.
     */
    private fun userFacingError(
        e: Throwable,
        where: String,
        fallbackRes: Int = R.string.chat_error_generic,
    ): String {
        Log.w(TAG, "$where: ${ffiReason(e)}", e)
        return when (e) {
            is ChatFfiException.Network ->
                context.getString(R.string.chat_connect_failed_generic)
            else -> context.getString(fallbackRes)
        }
    }

    private fun displayNameOrDefault(gw: ChatGateway): String =
        io.etchit.fetchit.chat.displayNameOrDefault(context, gw.agentIdHex())

    /**
     * Label for an inbound group message's sender: the sender's self-attached
     * [senderName] (which rides the encrypted message) when present, else a
     * known contact's display name, else a short `agent-<6hex>` form. Delegates
     * the precedence to [io.etchit.fetchit.chat.groupSenderLabel] so it stays
     * in lockstep with desktop's `notify.ts` ordering.
     */
    private fun groupSenderLabel(agentIdHex: String, senderName: String?): String {
        val contactName = controller.contacts.contacts.value
            .find { it.agentIdHex == agentIdHex }?.displayName
        return io.etchit.fetchit.chat.groupSenderLabel(senderName, contactName, agentIdHex)
    }

    /**
     * Enable the send button only while [input] holds non-blank text, so an
     * empty tap can't silently no-op; dim it when disabled for a clear
     * affordance.
     */
    private fun bindSendEnabled(input: EditText, button: View) {
        fun sync() {
            val on = input.text.isNotBlank()
            button.isEnabled = on
            button.alpha = if (on) 1f else 0.4f
        }
        sync()
        input.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) { sync() }
        })
    }

    /** Flush the outbox now, in response to a tap on a failed message bubble. */
    private fun retryOutbox() {
        val gw = controller.gateway() ?: run {
            snackbar(context.getString(R.string.chat_not_connected))
            return
        }
        gw.retryOutbox()
        snackbar(context.getString(R.string.chat_retrying))
    }

    // ── message adapter ───────────────────────────────────────────────

    private sealed class MessageRow {
        data class Dm(val msg: ChatMessage) : MessageRow()
        data class Post(val post: FeedPost) : MessageRow()

        /** A centered caption separating merged-thread sections (fediverse
         *  history above, post-quantum private messages below). */
        data class Divider(val text: String) : MessageRow()

        /** A centered caption naming the calendar day the messages below it
         *  arrived on. [dayStartMs] is local midnight — the stable identity,
         *  since [label] flips from a date to "Yesterday" to "Today". */
        data class DaySeparator(val dayStartMs: Long, val label: String) : MessageRow()
    }

    /**
     * Turn [items] into adapter rows, interleaving a day separator wherever
     * the calendar day changes (and above the first dated item, so an opened
     * thread shows its date context).
     *
     * Sections are separated independently — the merged thread's fediverse
     * history and its private messages each restart their own day run.
     */
    private fun <T> rowsWithDays(
        items: List<T>,
        stampMs: (T) -> Long,
        row: (T) -> MessageRow,
    ): List<MessageRow> {
        val breaks = dayBreaks(items.map(stampMs))
        if (breaks.isEmpty()) return items.map(row)
        val byIndex = breaks.associateBy { it.index }
        val rows = ArrayList<MessageRow>(items.size + breaks.size)
        items.forEachIndexed { i, item ->
            byIndex[i]?.let {
                rows.add(MessageRow.DaySeparator(it.dayStartMs, dayLabel(it.dayStartMs)))
            }
            rows.add(row(item))
        }
        return rows
    }

    private fun dmRowsWithDays(msgs: List<ChatMessage>): List<MessageRow> =
        rowsWithDays(msgs, { it.sentAtMs }, { MessageRow.Dm(it) })

    /** Localized name for a day-separator row: the near days get a word,
     *  everything older gets the platform's abbreviated weekday + date
     *  (which adds the year itself once the day is not in this one). */
    private fun dayLabel(dayStartMs: Long): String =
        when (dayLabelKind(dayStartMs, System.currentTimeMillis())) {
            DayLabelKind.TODAY -> context.getString(R.string.chat_day_today)
            DayLabelKind.YESTERDAY -> context.getString(R.string.chat_day_yesterday)
            DayLabelKind.DATE -> DateUtils.formatDateTime(
                context,
                dayStartMs,
                DateUtils.FORMAT_SHOW_DATE or
                    DateUtils.FORMAT_SHOW_WEEKDAY or
                    DateUtils.FORMAT_ABBREV_ALL,
            )
        }

    private val msgDiff = object : DiffUtil.ItemCallback<MessageRow>() {
        override fun areItemsTheSame(old: MessageRow, new: MessageRow): Boolean =
            when {
                old is MessageRow.Dm && new is MessageRow.Dm -> {
                    val o = old.msg
                    val n = new.msg
                    when {
                        o.outboxId != null || n.outboxId != null -> o.outboxId == n.outboxId
                        o.messageId != null -> o.messageId == n.messageId
                        else -> o.sentAtMs == n.sentAtMs && o.body == n.body
                    }
                }
                old is MessageRow.Post && new is MessageRow.Post ->
                    old.post.actorUrl == new.post.actorUrl &&
                        old.post.body == new.post.body
                old is MessageRow.Divider && new is MessageRow.Divider ->
                    old.text == new.text
                old is MessageRow.DaySeparator && new is MessageRow.DaySeparator ->
                    old.dayStartMs == new.dayStartMs
                else -> false
            }

        override fun areContentsTheSame(old: MessageRow, new: MessageRow): Boolean =
            old == new
    }

    private inner class MessageAdapter(
        private val onLinkTap: (String) -> Unit,
        private val onRetry: () -> Unit,
    ) : ListAdapter<MessageRow, RecyclerView.ViewHolder>(msgDiff) {

        override fun getItemViewType(position: Int): Int =
            when (getItem(position)) {
                is MessageRow.Divider -> VIEW_DIVIDER
                is MessageRow.DaySeparator -> VIEW_DAY
                else -> VIEW_MESSAGE
            }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val inflater = LayoutInflater.from(parent.context)
            return when (viewType) {
                VIEW_DIVIDER ->
                    DividerVH(inflater.inflate(R.layout.item_chat_divider, parent, false))
                VIEW_DAY ->
                    DayVH(inflater.inflate(R.layout.item_chat_day, parent, false))
                else -> VH(inflater.inflate(R.layout.item_chat_message, parent, false))
            }
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val row = getItem(position)) {
                is MessageRow.Dm -> {
                    // The previous message decides whether this is the first of a
                    // consecutive run from the same sender — desktop names a run
                    // once, not on every line (groupAttribution). A preceding
                    // divider is not a Dm, so the first PQ message still names
                    // its sender.
                    val prevSender = if (position > 0) {
                        (getItem(position - 1) as? MessageRow.Dm)?.msg?.senderAgentIdHex
                    } else {
                        null
                    }
                    (holder as VH).bindDm(row.msg, onLinkTap, prevSender)
                }
                is MessageRow.Post -> (holder as VH).bindPost(row.post)
                is MessageRow.Divider -> (holder as DividerVH).bind(row.text)
                is MessageRow.DaySeparator -> (holder as DayVH).bind(row.label)
            }
        }

        inner class DividerVH(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val caption: TextView = itemView.findViewById(R.id.dividerCaption)
            fun bind(text: String) {
                caption.text = text
            }
        }

        inner class DayVH(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val caption: TextView = itemView.findViewById(R.id.dayCaption)
            fun bind(text: String) {
                caption.text = text
            }
        }

        inner class VH(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val sender: TextView = itemView.findViewById(R.id.messageSender)
            private val bubbleFrame: LinearLayout = itemView.findViewById(R.id.messageBubbleFrame)
            private val bubble: TextView = itemView.findViewById(R.id.messageBubble)
            private val cards: LinearLayout = itemView.findViewById(R.id.messageCards)
            private val meta: TextView = itemView.findViewById(R.id.messageMeta)

            fun bindDm(
                msg: ChatMessage,
                onLinkTap: (String) -> Unit,
                prevSenderAgentIdHex: String?,
            ) {
                // A recycled feed row must not leak its author's face onto a
                // LIT message: LIT has no avatar concept.
                sender.setCompoundDrawablesRelative(null, null, null, null)
                sender.setTag(R.id.messageSender, null)
                if (msg.outbound) {
                    // Self keeps the copper out-bubble; the who-is-who accent is
                    // inbound-only, so no sender label or identity tint here.
                    sender.visibility = View.GONE
                    bubbleFrame.setBackgroundResource(R.drawable.bg_bubble_out)
                    (itemView as? LinearLayout)?.gravity = android.view.Gravity.END
                    bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    bubble.text = msg.body
                    // Send status: failed bubbles are tappable to retry the whole
                    // outbox; delivered show a tick; in-flight show plain time.
                    // It rides the same in-bubble meta line as the time so the
                    // two read as one group.
                    val status = when {
                        msg.failed -> " " + context.getString(R.string.chat_msg_failed_retry)
                        msg.delivered -> " ✓"
                        else -> ""
                    }
                    meta.text = "${timeFmt.format(Date(msg.sentAtMs))}$status"
                    if (msg.failed) {
                        itemView.setOnClickListener { onRetry() }
                    } else {
                        itemView.setOnClickListener(null)
                    }
                } else {
                    (itemView as? LinearLayout)?.gravity = android.view.Gravity.START
                    bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                    val time = timeFmt.format(Date(msg.sentAtMs))
                    val groupSender = msg.senderAgentIdHex
                    if (groupSender != null) {
                        // Group message: a per-identity left stripe + faint tint
                        // keyed off the sender's agent id, matching the avatar and
                        // (on desktop) the bubble accent — so "who is who" is
                        // scannable at a glance, pixel-for-pixel with desktop.
                        bubbleFrame.background = identityBubbleBackground(groupSender)
                        // Name the sender once at the top of a consecutive run, in
                        // their identity hue (desktop's groupAttribution + the
                        // chat-sender--id label color).
                        if (prevSenderAgentIdHex == groupSender) {
                            sender.visibility = View.GONE
                        } else {
                            sender.visibility = View.VISIBLE
                            sender.text = groupSenderLabel(groupSender, msg.senderName)
                            sender.setTextColor(IdentityColor.senderNameColor(groupSender))
                        }
                    } else {
                        // DM: the peer IS the thread, so no per-identity accent or
                        // sender label — the bare inbound bubble + time.
                        sender.visibility = View.GONE
                        bubbleFrame.setBackgroundResource(R.drawable.bg_bubble_in)
                    }
                    meta.text = time
                    // Linkify autonomi:// addresses in inbound text.
                    applyAutonomiLinkedText(bubble, msg.body, onLinkTap)
                    // Clear any retry listener left by a recycled outbound bubble.
                    itemView.setOnClickListener(null)
                }
                // A content card per address the body mentions, on both sides
                // of the conversation — what you shared is a thing, not a hex
                // string. Renders from the address alone; the preview fetch
                // only ever happens on a tap.
                addressCards.bind(cards, msg.body)
            }

            fun bindPost(post: FeedPost) {
                // Actor attribution from the relay-verified URL (never a
                // body-asserted actor), formatted as a readable @user@domain in
                // the fediverse (copper) hue.
                sender.visibility = View.VISIBLE
                val display = fediActorDisplay(post.actorUrl)
                sender.text = display
                sender.setTextColor(themeColor(R.attr.fetchitCopper))
                // `fediActorDisplay` renders "@user@host"; the engine keys
                // avatars on the bare canonical label.
                bindFediAvatarInline(sender, display, PEOPLE_AVATAR_DP)
                bubbleFrame.setBackgroundResource(R.drawable.bg_bubble_in)
                (itemView as? LinearLayout)?.gravity = android.view.Gravity.START
                bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                // Feed body is plain text (HTML stripped by the pump); linkify any
                // autonomi:// addresses so they open in the reader, like DM bubbles.
                applyAutonomiLinkedText(bubble, post.body, onLinkTap)
                addressCards.bind(cards, post.body)
                // Honesty badge: fediverse posts are public + non-PQ (mirrors desktop).
                meta.text = context.getString(R.string.chat_feed_post_public_badge)
            }

            /**
             * Set [bubble]'s text with any `autonomi://<addr>` occurrences turned
             * into tappable spans that open the address via [onLink]; plain text
             * (no movement method) when there are none. Shared by inbound DM/group
             * bubbles and fediverse feed posts.
             */
            private fun applyAutonomiLinkedText(
                bubble: TextView,
                body: String,
                onLink: (String) -> Unit,
            ) {
                val addresses = ChatUris.autonomiAddresses(body)
                if (addresses.isEmpty()) {
                    bubble.text = body
                    bubble.movementMethod = null
                    return
                }
                val spannable = SpannableString(body)
                addresses.forEach { addr ->
                    val fullLink = "autonomi://$addr"
                    var start = body.indexOf(fullLink)
                    while (start >= 0) {
                        val end = start + fullLink.length
                        spannable.setSpan(
                            object : ClickableSpan() {
                                override fun onClick(widget: View) {
                                    onLink(addr)
                                }
                            },
                            start,
                            end,
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                        )
                        start = body.indexOf(fullLink, end)
                    }
                }
                bubble.text = spannable
                bubble.movementMethod = LinkMovementMethod.getInstance()
            }

            /**
             * Inbound group-bubble background keyed off the sender's identity:
             * a rounded faint-tint fill with a 3dp left stripe in the identity
             * hue. Mirrors the desktop `.chat-row--in .chat-bubble--idN` rule
             * (`border-left: 3px solid HUE; background: HUE 10-12% over ink-2`).
             * Built per-bind rather than as eight static drawables so the tint
             * math stays in one place ([IdentityColor]) and tracks any palette
             * change in lockstep with desktop.
             */
            private fun identityBubbleBackground(agentIdHex: String): android.graphics.drawable.Drawable {
                val density = itemView.resources.displayMetrics.density
                val radius = 16f * density
                val stripe = (3f * density).toInt()
                // The accent is the full rounded bubble in the identity hue. The
                // fill covers it except for a `stripe`-wide left band, so only
                // that band of the hue shows through as the left border. The
                // fill's left corners are square (the accent's rounded corners
                // sit under them); its right corners stay rounded.
                val accent = android.graphics.drawable.GradientDrawable().apply {
                    shape = android.graphics.drawable.GradientDrawable.RECTANGLE
                    cornerRadius = radius
                    setColor(IdentityColor.stripeColor(agentIdHex))
                }
                val fill = android.graphics.drawable.GradientDrawable().apply {
                    shape = android.graphics.drawable.GradientDrawable.RECTANGLE
                    // top-left, top-right, bottom-right, bottom-left (x/y pairs).
                    cornerRadii = floatArrayOf(
                        0f, 0f, radius, radius, radius, radius, 0f, 0f,
                    )
                    setColor(IdentityColor.bubbleTint(agentIdHex))
                }
                val layers = android.graphics.drawable.LayerDrawable(arrayOf(accent, fill))
                layers.setLayerInset(1, stripe, 0, 0, 0)
                // Nested padding would hand the stripe inset back to the view as
                // padding, overwriting the bubble's own — stack mode keeps the
                // inset purely visual.
                layers.paddingMode = android.graphics.drawable.LayerDrawable.PADDING_MODE_STACK
                return layers
            }
        }

    }

    // ── contact list adapter ──────────────────────────────────────────

    private inner class ContactListAdapter(
        private val onFediTap: (String) -> Unit,
        private val onContactTap: (ChatContact) -> Unit,
        private val onGroupTap: (GroupFfi) -> Unit,
        private val onRemoveContact: (View, ChatContact) -> Unit,
        private val onLeaveGroup: (View, GroupFfi) -> Unit,
    ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

        private val TYPE_FEDI = 0
        private val TYPE_CONTACT = 1
        private val TYPE_GROUP = 2

        private var rows: kotlin.collections.List<ChatRow> = emptyList()

        /** Swap in a freshly-built, already-sorted unified row list. */
        fun submit(newRows: kotlin.collections.List<ChatRow>) {
            rows = newRows
            notifyDataSetChanged()
        }

        override fun getItemViewType(position: Int) = when (rows[position]) {
            is ChatRow.Fedi -> TYPE_FEDI
            is ChatRow.Group -> TYPE_GROUP
            is ChatRow.Contact -> TYPE_CONTACT
        }

        override fun getItemCount() = rows.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_chat_contact, parent, false)
            return when (viewType) {
                TYPE_FEDI -> FediViewHolder(v)
                TYPE_GROUP -> GroupViewHolder(v)
                else -> ContactViewHolder(v)
            }
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val row = rows[position]) {
                is ChatRow.Fedi -> (holder as FediViewHolder).bind(row.summary, onFediTap)
                is ChatRow.Group ->
                    (holder as GroupViewHolder)
                        .bind(row.group, row.preview, row.unread, onGroupTap, onLeaveGroup)
                is ChatRow.Contact ->
                    (holder as ContactViewHolder).bind(
                        row.contact,
                        row.preview,
                        row.unread,
                        row.fediLabel,
                        onContactTap,
                        onRemoveContact,
                    )
            }
        }
    }

    private inner class FediViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val avatar: ImageView = itemView.findViewById(R.id.contactAvatar)
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)
        private val unread: TextView = itemView.findViewById(R.id.contactUnreadBadge)
        private val more: ImageButton = itemView.findViewById(R.id.contactRowMore)

        fun bind(
            summary: uniffi.fetchit_ffi.FediThreadSummaryFfi,
            onTap: (String) -> Unit,
        ) {
            // A globe marks the open-fediverse (not-encrypted) rail. It stays
            // put whether or not a profile picture lands beside it.
            shortId.text = "🌐"
            bindFediAvatar(avatar, summary.label)
            name.text = summary.label
            preview.text = summary.lastBody
            // Unread messages from someone who has never been replied to are
            // the whole point of the row: without the badge a first contact
            // is just another quiet line in the list.
            bindUnreadBadge(unread, summary.unread.toInt())
            // Fediverse threads have no per-row overflow yet (block/unfollow
            // live on the profile card); detach any recycled listener.
            more.visibility = View.GONE
            more.setOnClickListener(null)
            itemView.setOnClickListener { onTap(summary.label) }
        }
    }

    /**
     * Paint (or hide) a conversation row's unread pill. Zero hides it, so
     * a read row is visually identical to how it was before badges
     * existed; big counts cap at "99+" so the row can't be pushed around.
     */
    private fun bindUnreadBadge(badge: TextView, count: Int) {
        if (count <= 0) {
            badge.visibility = View.GONE
            badge.contentDescription = null
            return
        }
        badge.visibility = View.VISIBLE
        badge.text =
            if (count > 99) context.getString(R.string.chat_unread_overflow) else count.toString()
        badge.contentDescription = context.getString(R.string.chat_unread_desc, count)
    }

    private inner class ContactViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val avatar: ImageView = itemView.findViewById(R.id.contactAvatar)
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)
        private val unread: TextView = itemView.findViewById(R.id.contactUnreadBadge)
        private val more: ImageButton = itemView.findViewById(R.id.contactRowMore)

        fun bind(
            contact: ChatContact,
            lastPreview: String,
            unreadCount: Int,
            fediLabel: String?,
            onTap: (ChatContact) -> Unit,
            onMore: (View, ChatContact) -> Unit,
        ) {
            // A lock marks a private (PQ) DM — matching the group lock and the
            // fediverse globe, and never the raw 64-hex (grandma rule 1).
            shortId.text = "🔒"
            // A person the user confirmed is the same human as a fediverse
            // account borrows that account's face. CACHE-ONLY: a private row
            // must never put a request on a fediverse server's access log.
            // Unlinked contacts (and a recycled holder) get the placeholder
            // back, which is what this row looked like before avatars.
            bindFediAvatar(avatar, fediLabel.orEmpty(), cacheOnly = true)
            name.text = contact.displayName
            preview.text = lastPreview
            bindUnreadBadge(unread, unreadCount)
            itemView.setOnClickListener { onTap(contact) }
            more.visibility = View.VISIBLE
            more.setOnClickListener { anchor -> onMore(anchor, contact) }
        }
    }

    private inner class GroupViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)
        private val unread: TextView = itemView.findViewById(R.id.contactUnreadBadge)
        private val more: ImageButton = itemView.findViewById(R.id.contactRowMore)

        fun bind(
            group: GroupFfi,
            lastPreview: String,
            unreadCount: Int,
            onTap: (GroupFfi) -> Unit,
            onMore: (View, GroupFfi) -> Unit,
        ) {
            // A lock glyph marks private (PQ) groups; public / unknown-kind
            // groups show a generic group glyph in the id slot.
            shortId.text =
                if (group.isPrivate == true) context.getString(R.string.chat_group_lock_glyph) else "#"
            name.text = groupTitle(group, group.groupId)
            preview.text = lastPreview
            bindUnreadBadge(unread, unreadCount)
            itemView.setOnClickListener { onTap(group) }
            more.visibility = View.VISIBLE
            more.setOnClickListener { anchor -> onMore(anchor, group) }
        }
    }

    private companion object {
        private const val TAG = "ChatModeView"

        // The self (outbound) hue — copper, matching the copper out-bubble and
        // the desktop self identity. Drawn behind the own-identity badge avatar.
        private const val SELF_HUE = 0xFFC9732B.toInt()

        // MessageAdapter view types: normal message bubble, merged-thread
        // section divider, calendar-day separator.
        private const val VIEW_MESSAGE = 0
        private const val VIEW_DIVIDER = 1
        private const val VIEW_DAY = 2

        // Target edge for a decoded avatar. Matches the 36dp row circle with
        // headroom for a denser thread/People row; inSampleSize only halves,
        // so decoding to this and letting the ImageView scale down beats
        // decoding per-surface.
        private const val AVATAR_TARGET_DP = 96

        // Avatar edge on the People rows and feed post rows — smaller than
        // the 36dp chat-list circle so a dense list stays scannable.
        private const val PEOPLE_AVATAR_DP = 28
    }
}
