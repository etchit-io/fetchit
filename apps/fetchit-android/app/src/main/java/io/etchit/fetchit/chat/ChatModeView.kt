package io.etchit.fetchit.chat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.text.SpannableString
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.LifecycleOwner
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import io.etchit.fetchit.R
import io.etchit.fetchit.SettingsStore
import io.etchit.fetchit.fetchitApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import uniffi.fetchit_ffi.ChatFfiException
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
        data object List : Screen()
        data class Thread(val peer: String) : Screen()
        data object Feed : Screen()
    }

    private val screenStack = ArrayDeque<Screen>()

    // Lazily-inflated list view.
    private var listView: View? = null

    // Cached thread view — re-bound per peer rather than re-inflated.
    private var threadView: View? = null

    // Cached feed view.
    private var feedView: View? = null

    // Job for the active thread message-flow collector; cancelled on screen switch.
    private var threadCollectJob: Job? = null

    // Job for the feed post-flow collector; cancelled on screen switch.
    private var feedCollectJob: Job? = null

    // Jobs for the two list-screen flow collectors (contacts + pump state).
    // Launched exactly once behind the listView==null guard; stored here so
    // any future re-inflation path must cancel them first.
    private var listContactsJob: Job? = null
    private var listPumpStateJob: Job? = null

    // Job for the active DM send; cancelled wherever threadCollectJob is cancelled.
    private var sendJob: Job? = null

    private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())

    private val settingsStore by lazy { SettingsStore(context) }

    // ── public entry points ────────────────────────────────────────────

    /**
     * Called each time the user switches into chat mode.
     * Ensures the list screen is shown and kicks off [ensureGateway].
     */
    fun onShown() {
        if (screenStack.isEmpty() || screenStack.last() !is Screen.List) {
            showList()
        }
        lifecycleScope.launch { connectWithFeedback() }
    }

    /**
     * Called by the Activity's back callback while in chat mode.
     * @return true if the back press was consumed (popped a sub-screen),
     *         false if the caller should return to browse.
     */
    fun onBack(): Boolean {
        if (screenStack.size <= 1) return false
        screenStack.removeLastOrNull()
        val prev = screenStack.lastOrNull() ?: Screen.List
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
            runCatching { gw.importPairUri(uri.trim()) }.onFailure { e ->
                val reason = (e as? ChatFfiException)?.let { ffiReason(it) } ?: e.message.orEmpty()
                snackbar(reason)
                return@launch
            }
            promptDisplayName(agentId)
        }
    }

    // ── screen navigation ──────────────────────────────────────────────

    private fun showList() {
        showScreen(Screen.List, pushToStack = true)
    }

    /** Open the DM thread for [agentIdHex]. */
    fun openThread(agentIdHex: String) {
        showScreen(Screen.Thread(agentIdHex), pushToStack = true)
    }

    private fun showScreen(screen: Screen, pushToStack: Boolean) {
        if (pushToStack) {
            if (screenStack.lastOrNull() != screen) screenStack.addLast(screen)
        }
        when (screen) {
            is Screen.List -> {
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
                }
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
        val qrImage = view.findViewById<ImageView>(R.id.chatPairQr)
        val connectingText = view.findViewById<TextView>(R.id.chatConnectingText)
        val lostBanner = view.findViewById<TextView>(R.id.chatConnectionLostBanner)
        val addBtn = view.findViewById<View>(R.id.addContactButton)
        val shareBtn = view.findViewById<View>(R.id.sharePairButton)
        val scanBtn = view.findViewById<View>(R.id.scanPairButton)

        // Adapter: pinned fediverse row at position 0, then contacts.
        val adapter = ContactListAdapter(
            onFeedTap = { showScreen(Screen.Feed, pushToStack = true) },
            onContactTap = { contact -> openThread(contact.agentIdHex) },
        )
        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = adapter

        // Observe contacts + last messages to drive list visibility.
        listContactsJob = lifecycleScope.launch {
            controller.contacts.contacts.collect { contacts ->
                val hasContacts = contacts.isNotEmpty()
                rv.visibility = if (hasContacts) View.VISIBLE else View.GONE
                emptyState.visibility = if (hasContacts) View.GONE else View.VISIBLE
                addBtn.visibility = if (hasContacts) View.VISIBLE else View.GONE
                if (hasContacts) {
                    adapter.submitContactList(contacts)
                }
            }
        }

        // Observe pump state to show connection-lost banner.
        listPumpStateJob = lifecycleScope.launch {
            controller.pumpState.collect { state ->
                lostBanner.visibility =
                    if (state == PumpState.STOPPED_ERROR) View.VISIBLE else View.GONE
            }
        }

        // Share my code button.
        shareBtn.setOnClickListener {
            lifecycleScope.launch { onShareMyCodeClicked(qrImage) }
        }
        qrImage.setOnLongClickListener {
            val gw = controller.gateway()
            if (gw == null) {
                snackbar(context.getString(R.string.chat_not_connected))
                return@setOnLongClickListener true
            }
            lifecycleScope.launch {
                runCatching { gw.pairShareUri() }.onSuccess { uri ->
                    copyToClipboard(uri)
                    snackbar(context.getString(R.string.chat_uri_copied))
                }.onFailure { e ->
                    val reason = (e as? ChatFfiException)?.let { ffiReason(it) } ?: e.message.orEmpty()
                    snackbar(reason)
                }
            }
            true
        }

        // Scan a code button: delegate to MainActivity's scanner.
        scanBtn.setOnClickListener { onLaunchScanner() }

        // Add contact FAB: paste dialog.
        addBtn.setOnClickListener { showAddContactDialog() }
    }

    private suspend fun onShareMyCodeClicked(qrImage: ImageView) {
        val gw = runCatching { connectWithFeedback() }.getOrNull() ?: return
        val uri = runCatching { gw.pairShareUri() }.getOrElse { e ->
            val reason = (e as? ChatFfiException)?.let { ffiReason(it) } ?: e.message.orEmpty()
            snackbar(reason)
            return
        }
        // Render the pair URI as a plain QR bitmap (not the branded card —
        // the card validator checks for 64-hex Autonomi addresses, which
        // x0x:// URIs are not). Use ZXing directly via a simple approach.
        val bitmap = runCatching { renderPairQr(uri) }.getOrNull()
        if (bitmap != null) {
            qrImage.setImageBitmap(bitmap)
            qrImage.visibility = View.VISIBLE
        }
    }

    private fun renderPairQr(uri: String): android.graphics.Bitmap? {
        val size = 480
        val hints = mapOf(
            com.google.zxing.EncodeHintType.ERROR_CORRECTION to
                com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M,
            com.google.zxing.EncodeHintType.MARGIN to 2,
        )
        val matrix = com.google.zxing.qrcode.QRCodeWriter()
            .encode(uri, com.google.zxing.BarcodeFormat.QR_CODE, size, size, hints)
        val pixels = IntArray(size * size)
        for (y in 0 until size) {
            for (x in 0 until size) {
                pixels[y * size + x] = if (matrix.get(x, y)) 0xFF0a0a0a.toInt() else 0xFFf5f2eb.toInt()
            }
        }
        return android.graphics.Bitmap.createBitmap(pixels, size, size, android.graphics.Bitmap.Config.ARGB_8888)
    }

    private fun showAddContactDialog() {
        val editText = EditText(context).apply {
            hint = context.getString(R.string.chat_paste_pair_uri_hint)
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
            .setTitle(context.getString(R.string.chat_add_contact_title))
            .setView(layout)
            .setPositiveButton(context.getString(R.string.chat_add_contact_import)) { _, _ ->
                val raw = editText.text.toString().trim()
                importFromUri(raw)
            }
            .setNegativeButton(context.getString(R.string.action_close), null)
            .show()
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

        val rv = view.findViewById<RecyclerView>(R.id.messageList)
        val lm = LinearLayoutManager(context).apply { stackFromEnd = true }
        rv.layoutManager = lm
        val adapter = MessageAdapter(onOpenAutonomi)
        rv.adapter = adapter

        val messageInput = view.findViewById<EditText>(R.id.messageInput)
        view.findViewById<View>(R.id.sendButton).setOnClickListener {
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
                val result = runCatching { gw.sendDm(peer, body, senderName) }
                result.onSuccess { msgId ->
                    controller.conversations.append(
                        peer,
                        ChatMessage(
                            outbound = true,
                            body = body,
                            sentAtMs = System.currentTimeMillis(),
                            messageId = msgId,
                        ),
                    )
                }.onFailure { e ->
                    // Only restore text if this thread is still the active screen.
                    if (screenStack.lastOrNull() == Screen.Thread(peer)) {
                        messageInput.setText(body)
                    }
                    val reason = (e as? ChatFfiException)?.let { ffiReason(it) } ?: e.message.orEmpty()
                    snackbar(context.getString(R.string.thread_send_failed, reason))
                }
            }
        }

        // Collect messages for this peer; job cancelled on screen switch.
        threadCollectJob = lifecycleScope.launch {
            controller.conversations.messagesFor(peer).collect { msgs ->
                val prevSize = adapter.itemCount
                val rows = msgs.map { MessageRow.Dm(it) }
                adapter.submitList(rows)
                // Scroll only when new messages arrive, not on receipt-tick rebinds.
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
            }
        }
    }

    // ── feed screen ────────────────────────────────────────────────────

    private fun bindFeedScreen() {
        val view = feedView ?: LayoutInflater.from(context)
            .inflate(R.layout.view_chat_thread, slot, false)
            .also { feedView = it }

        slot.addView(view)

        view.findViewById<TextView>(R.id.threadPeerName).text =
            context.getString(R.string.chat_feed_title)
        view.findViewById<TextView>(R.id.threadPeerShortId).text = ""
        view.findViewById<View>(R.id.threadBackButton).setOnClickListener { onBack() }
        // Feed is read-only — hide the send row.
        view.findViewById<View>(R.id.threadSendRow).visibility = View.GONE

        val rv = view.findViewById<RecyclerView>(R.id.messageList)
        val lm = LinearLayoutManager(context).apply { stackFromEnd = true }
        rv.layoutManager = lm
        val adapter = MessageAdapter(onOpenAutonomi)
        rv.adapter = adapter

        feedCollectJob = lifecycleScope.launch {
            controller.feed.posts.collect { posts ->
                val prevSize = adapter.itemCount
                val rows = posts.map { MessageRow.Post(it) }
                adapter.submitList(rows)
                // Scroll only when new posts arrive, not on content-only updates.
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
            }
        }
    }

    // ── gateway helpers ────────────────────────────────────────────────

    /**
     * Connect to the relay, showing UI feedback. Returns the gateway on
     * success. On [ChatFfiException] shows a Snackbar with the reason + a
     * retry action.
     */
    private suspend fun connectWithFeedback(): ChatGateway {
        showConnecting(true)
        return runCatching {
            controller.ensureGateway()
        }.onSuccess {
            showConnecting(false)
        }.onFailure { e ->
            showConnecting(false)
            val reason = (e as? ChatFfiException)?.let { ffiReason(it) } ?: e.message.orEmpty()
            Snackbar.make(container, reason, Snackbar.LENGTH_INDEFINITE)
                .setAction(context.getString(R.string.action_retry)) {
                    lifecycleScope.launch { connectWithFeedback() }
                }
                .show()
        }.getOrThrow()
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

    private fun ffiReason(e: ChatFfiException): String = when (e) {
        is ChatFfiException.Invalid -> e.reason
        is ChatFfiException.Network -> e.reason
    }

    /**
     * Returns the user's chosen display name, or falls back to
     * "agent-" + the first 6 hex chars of [gw]'s agent id when unset.
     */
    private fun displayNameOrDefault(gw: ChatGateway): String {
        val saved = settingsStore.chatDisplayName()
        if (saved.isNotEmpty()) return saved
        return "agent-${gw.agentIdHex().take(6)}"
    }

    // ── message adapter ───────────────────────────────────────────────

    private sealed class MessageRow {
        data class Dm(val msg: ChatMessage) : MessageRow()
        data class Post(val post: FeedPost) : MessageRow()
    }

    private val msgDiff = object : DiffUtil.ItemCallback<MessageRow>() {
        override fun areItemsTheSame(old: MessageRow, new: MessageRow): Boolean =
            when {
                old is MessageRow.Dm && new is MessageRow.Dm ->
                    if (old.msg.messageId != null) old.msg.messageId == new.msg.messageId
                    else old.msg.sentAtMs == new.msg.sentAtMs && old.msg.body == new.msg.body
                old is MessageRow.Post && new is MessageRow.Post ->
                    old.post.actorUrl == new.post.actorUrl &&
                        old.post.body == new.post.body
                else -> false
            }

        override fun areContentsTheSame(old: MessageRow, new: MessageRow): Boolean =
            old == new
    }

    private inner class MessageAdapter(
        private val onLinkTap: (String) -> Unit,
    ) : ListAdapter<MessageRow, MessageAdapter.VH>(msgDiff) {

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_chat_message, parent, false)
            return VH(v)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            when (val row = getItem(position)) {
                is MessageRow.Dm -> holder.bindDm(row.msg, onLinkTap)
                is MessageRow.Post -> holder.bindPost(row.post)
            }
        }

        inner class VH(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val bubble: TextView = itemView.findViewById(R.id.messageBubble)
            private val meta: TextView = itemView.findViewById(R.id.messageMeta)

            fun bindDm(msg: ChatMessage, onLinkTap: (String) -> Unit) {
                if (msg.outbound) {
                    bubble.setBackgroundResource(R.drawable.bg_bubble_out)
                    (bubble.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                        android.view.Gravity.END
                    (itemView.layoutParams as? RecyclerView.LayoutParams)?.let { _ ->
                        bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    }
                    (itemView as? LinearLayout)?.gravity = android.view.Gravity.END
                    bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    bubble.text = msg.body
                    val tick = if (msg.delivered) " ✓" else ""
                    meta.text = "${timeFmt.format(Date(msg.sentAtMs))}$tick"
                    meta.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    (meta.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                        android.view.Gravity.END
                } else {
                    bubble.setBackgroundResource(R.drawable.bg_bubble_in)
                    (itemView as? LinearLayout)?.gravity = android.view.Gravity.START
                    bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                    meta.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                    (meta.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                        android.view.Gravity.START
                    meta.text = timeFmt.format(Date(msg.sentAtMs))
                    // Linkify autonomi:// addresses in inbound text.
                    val addresses = ChatUris.autonomiAddresses(msg.body)
                    if (addresses.isEmpty()) {
                        bubble.text = msg.body
                        bubble.movementMethod = null
                    } else {
                        val spannable = SpannableString(msg.body)
                        addresses.forEach { addr ->
                            val fullLink = "autonomi://$addr"
                            var start = msg.body.indexOf(fullLink)
                            while (start >= 0) {
                                val end = start + fullLink.length
                                spannable.setSpan(
                                    object : ClickableSpan() {
                                        override fun onClick(widget: View) {
                                            onLinkTap(addr)
                                        }
                                    },
                                    start,
                                    end,
                                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                                )
                                start = msg.body.indexOf(fullLink, end)
                            }
                        }
                        bubble.text = spannable
                        bubble.movementMethod = LinkMovementMethod.getInstance()
                    }
                }
            }

            fun bindPost(post: FeedPost) {
                bubble.setBackgroundResource(R.drawable.bg_bubble_in)
                (itemView as? LinearLayout)?.gravity = android.view.Gravity.START
                bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                // Feed body is already plain text (HTML was stripped by the pump).
                bubble.text = post.body
                bubble.movementMethod = null
                meta.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                (meta.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                    android.view.Gravity.START
                meta.text = post.actorUrl
            }
        }

    }

    // ── contact list adapter ──────────────────────────────────────────

    /**
     * Row model for the contact list adapter.
     * Position 0 is always the pinned fediverse channel.
     */
    private sealed class Row {
        data object Fediverse : Row()
        data class Contact(val contact: ChatContact, val preview: String) : Row()
    }

    private inner class ContactListAdapter(
        private val onFeedTap: () -> Unit,
        private val onContactTap: (ChatContact) -> Unit,
    ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

        private val TYPE_FEED = 0
        private val TYPE_CONTACT = 1

        private val rows = mutableListOf<Row>(Row.Fediverse)

        fun submitContactList(contacts: kotlin.collections.List<ChatContact>) {
            rows.clear()
            rows.add(Row.Fediverse)
            contacts.forEach { c ->
                val preview = controller.conversations
                    .messagesFor(c.agentIdHex).value
                    .lastOrNull()?.body.orEmpty()
                rows.add(Row.Contact(c, preview))
            }
            notifyDataSetChanged()
        }

        override fun getItemViewType(position: Int) =
            if (rows[position] is Row.Fediverse) TYPE_FEED else TYPE_CONTACT

        override fun getItemCount() = rows.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            return if (viewType == TYPE_FEED) {
                val v = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_chat_contact, parent, false)
                FeedViewHolder(v)
            } else {
                val v = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_chat_contact, parent, false)
                ContactViewHolder(v)
            }
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val row = rows[position]) {
                is Row.Fediverse -> {
                    (holder as FeedViewHolder).bind(onFeedTap)
                }
                is Row.Contact -> {
                    (holder as ContactViewHolder).bind(row.contact, row.preview, onContactTap)
                }
            }
        }
    }

    private inner class FeedViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)

        fun bind(onTap: () -> Unit) {
            shortId.text = "✦"
            name.text = context.getString(R.string.chat_feed_title)
            preview.text = context.getString(R.string.chat_feed_subtitle)
            itemView.setOnClickListener { onTap() }
        }
    }

    private inner class ContactViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)

        fun bind(
            contact: ChatContact,
            lastPreview: String,
            onTap: (ChatContact) -> Unit,
        ) {
            shortId.text = "${contact.agentIdHex.take(8)}…"
            name.text = contact.displayName
            preview.text = lastPreview
            itemView.setOnClickListener { onTap(contact) }
        }
    }
}
