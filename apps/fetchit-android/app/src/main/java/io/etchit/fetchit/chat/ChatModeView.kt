package io.etchit.fetchit.chat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.lifecycle.LifecycleOwner
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import io.etchit.fetchit.R
import io.etchit.fetchit.fetchitApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import uniffi.fetchit_ffi.ChatFfiException

/**
 * Orchestrates the chat screens (list / thread / feed) and owns the
 * chat back-stack within [container].
 *
 * Screens inflate lazily into [container]; Task 5 fills in the thread
 * and feed renders. For now [Screen.Thread] and [Screen.Feed] are stubs.
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

    private sealed class Screen {
        data object List : Screen()
        data class Thread(val peer: String) : Screen()
        data object Feed : Screen()
    }

    private val screenStack = ArrayDeque<Screen>()

    // Lazily-inflated list view.
    private var listView: View? = null

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
     */
    fun importFromUri(uri: String) {
        val agentId = ChatUris.pairUriAgentId(uri) ?: run {
            snackbar(context.getString(R.string.chat_invalid_pair_uri))
            return
        }
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

    /**
     * Hook for Task 5 — open the DM thread for [agentIdHex].
     * Currently a labeled no-op so Task 5 has a clear seam to fill.
     */
    @Suppress("UNUSED_PARAMETER")
    fun openThread(agentIdHex: String) {
        // Task 5 fills this — push Screen.Thread(agentIdHex) and inflate the thread view.
    }

    private fun showScreen(screen: Screen, pushToStack: Boolean) {
        if (pushToStack) {
            if (screenStack.lastOrNull() != screen) screenStack.addLast(screen)
        }
        container.removeAllViews()
        when (screen) {
            is Screen.List -> inflateListScreen()
            is Screen.Thread -> inflateThreadStub(screen.peer)
            is Screen.Feed -> inflateFeedStub()
        }
    }

    // ── list screen ────────────────────────────────────────────────────

    private fun inflateListScreen() {
        val view = LayoutInflater.from(context)
            .inflate(R.layout.view_chat_list, container, true)
        listView = view

        val rv = container.findViewById<RecyclerView>(R.id.chatContactList)
        val emptyState = container.findViewById<View>(R.id.chatEmptyState)
        val qrImage = container.findViewById<ImageView>(R.id.chatPairQr)
        val connectingText = container.findViewById<TextView>(R.id.chatConnectingText)
        val lostBanner = container.findViewById<TextView>(R.id.chatConnectionLostBanner)
        val addBtn = container.findViewById<View>(R.id.addContactButton)
        val shareBtn = container.findViewById<View>(R.id.sharePairButton)
        val scanBtn = container.findViewById<View>(R.id.scanPairButton)

        // Adapter: pinned fediverse row at position 0, then contacts.
        val adapter = ContactListAdapter(
            onFeedTap = { showScreen(Screen.Feed, pushToStack = true) },
            onContactTap = { contact -> openThread(contact.agentIdHex) },
        )
        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = adapter

        // Observe contacts + last messages to drive list visibility.
        lifecycleScope.launch {
            controller.contacts.contacts.collect { contacts ->
                val hasContacts = contacts.isNotEmpty()
                rv.visibility = if (hasContacts) View.VISIBLE else View.GONE
                emptyState.visibility = if (hasContacts) View.GONE else View.VISIBLE
                if (hasContacts) {
                    adapter.submitContactList(contacts)
                }
            }
        }

        // Observe pump state to show connection-lost banner.
        lifecycleScope.launch {
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

    // ── stub screens (Task 5 fills) ────────────────────────────────────

    private fun inflateThreadStub(peer: String) {
        val tv = TextView(context).apply {
            text = "thread: ${peer.take(8)}…  (Task 5)"
            setTextColor(context.getColor(android.R.color.white))
            gravity = android.view.Gravity.CENTER
        }
        val frame = FrameLayout(context).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
            addView(tv)
        }
        container.addView(frame)
    }

    private fun inflateFeedStub() {
        val tv = TextView(context).apply {
            text = context.getString(R.string.chat_feed_title)
            setTextColor(context.getColor(android.R.color.white))
            gravity = android.view.Gravity.CENTER
        }
        val frame = FrameLayout(context).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
            addView(tv)
        }
        container.addView(frame)
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
        container.post {
            val ct = container.findViewById<TextView?>(R.id.chatConnectingText) ?: return@post
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

    // ── adapter ───────────────────────────────────────────────────────

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
