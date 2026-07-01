package io.etchit.fetchit.chat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.text.SpannableString
import android.text.Spanned
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import uniffi.fetchit_ffi.ChatFfiException
import uniffi.fetchit_ffi.GroupFfi
import uniffi.fetchit_ffi.GroupMemberFfi
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
        data class GroupThread(val groupId: String) : Screen()
        data object Feed : Screen()
    }

    private val screenStack = ArrayDeque<Screen>()

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

    // Job for the active DM send; cancelled wherever threadCollectJob is cancelled.
    private var sendJob: Job? = null

    private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())

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

    // ── screen navigation ──────────────────────────────────────────────

    private fun showList() {
        showScreen(Screen.List, pushToStack = true)
    }

    /** Open the DM thread for [agentIdHex]. */
    fun openThread(agentIdHex: String) {
        showScreen(Screen.Thread(agentIdHex), pushToStack = true)
    }

    /** Open the group thread for [groupId]. */
    fun openGroupThread(groupId: String) {
        showScreen(Screen.GroupThread(groupId), pushToStack = true)
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

        // Own-identity header badge: the user sees themselves by name +
        // initials avatar on the self (copper) hue, never the 64-hex. Tapping
        // it opens the share-my-code card. The display name resolves from the
        // connected gateway when available, else from the saved setting (no
        // connection needed); "You"/"?" before any name is set.
        bindIdentityBadge(identityAvatar, identityName)
        identityBadge.setOnClickListener { onIdentityBadgeTap(identityAvatar, identityName) }

        // Adapter: pinned fediverse row at position 0, then groups + contacts.
        val adapter = ContactListAdapter(
            onFeedTap = { showScreen(Screen.Feed, pushToStack = true) },
            onContactTap = { contact -> openThread(contact.agentIdHex) },
            onGroupTap = { group -> openGroupThread(group.groupId) },
            onRemoveContact = { anchor, contact -> showContactRowMenu(anchor, contact) },
            onLeaveGroup = { anchor, group -> showGroupRowMenu(anchor, group) },
        )
        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = adapter

        // Observe contacts + groups together: either populates the list, so
        // visibility tracks (contacts OR groups). The empty-state onboarding
        // only shows when there is neither a contact nor a group to render.
        listContactsJob = lifecycleScope.launch {
            controller.contacts.contacts
                .combine(controller.groups) { contacts, groups -> contacts to groups }
                .collect { (contacts, groups) ->
                    val onboarding = showChatOnboarding(contacts.size, groups.size)
                    rv.visibility = if (onboarding) View.GONE else View.VISIBLE
                    emptyState.visibility = if (onboarding) View.VISIBLE else View.GONE
                    // The FAB is a list-level affordance (it offers group
                    // create/join, reachable with zero contacts), so it stays
                    // visible whenever the list view is shown.
                    addBtn.visibility = View.VISIBLE
                    adapter.submit(groups, contacts)
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

        // Onboarding primary action: add your first person.
        addPersonBtn.setOnClickListener { showAddContactDialog() }

        // Onboarding secondary action: create a group.
        createGroupBtn.setOnClickListener { showNewGroupDialog() }

        // FAB: a popup with the list-level actions -- add a contact, start a
        // new group, join one from an invite link, or scan a code (the scan
        // affordance re-homed here now the identity badge owns share-my-code).
        addBtn.setOnClickListener { anchor -> showListActionsMenu(anchor) }
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
     */
    private fun showFediMintDialog(onMinted: (String) -> Unit) {
        val editText = EditText(context).apply {
            hint = context.getString(R.string.fedi_mint_handle_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            maxLines = 1
            filters = arrayOf(android.text.InputFilter.LengthFilter(64))
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
                            dialog.dismiss()
                            onMinted(handle)
                            snackbar(
                                context.getString(
                                    if (outcome.registered) R.string.fedi_mint_done
                                    else R.string.fedi_mint_done_pending,
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
     */
    private fun renderFediHubHeader(shortId: TextView) {
        val handle = controller.fediActorStatus()
        if (handle != null) {
            shortId.text = context.getString(R.string.fedi_hub_handle, handle)
            shortId.setTextColor(themeColor(R.attr.fetchitAsh))
            shortId.setOnClickListener(null)
            shortId.isClickable = false
        } else {
            shortId.text = context.getString(R.string.fedi_hub_join)
            shortId.setTextColor(themeColor(R.attr.fetchitCopper))
            shortId.setOnClickListener { showFediMintDialog { renderFediHubHeader(shortId) } }
        }
    }

    /**
     * Popup menu off the list FAB: add a DM contact, create a new group, join
     * a group from a pasted invite, or scan a code. Each entry opens its own
     * dialog (or the scanner), mirroring [showAddContactDialog].
     */
    private fun showListActionsMenu(anchor: View) {
        PopupMenu(context, anchor).apply {
            menu.add(context.getString(R.string.chat_add_contact))
            menu.add(context.getString(R.string.chat_new_group))
            menu.add(context.getString(R.string.chat_join_group))
            menu.add(context.getString(R.string.chat_scan_a_code))
            setOnMenuItemClickListener { item ->
                when (item.title) {
                    context.getString(R.string.chat_add_contact) -> showAddContactDialog()
                    context.getString(R.string.chat_new_group) -> showNewGroupDialog()
                    context.getString(R.string.chat_join_group) -> showJoinGroupDialog()
                    context.getString(R.string.chat_scan_a_code) -> onLaunchScanner()
                }
                true
            }
            show()
        }
    }

    /**
     * Per-row overflow popup off a conversation row's "⋮" button. One
     * kind-aware destructive entry: "Remove this chat" for a contact, "Leave
     * this group" for a group ([rowRemoveLabel] picks the label). Selecting it
     * opens the confirm dialog. Mirrors desktop's per-row remove affordance.
     */
    private fun showContactRowMenu(anchor: View, contact: ChatContact) {
        val label = context.getString(rowRemoveLabel(isGroup = false))
        PopupMenu(context, anchor).apply {
            menu.add(label)
            setOnMenuItemClickListener {
                confirmRemoveContact(contact)
                true
            }
            show()
        }
    }

    private fun showGroupRowMenu(anchor: View, group: GroupFfi) {
        val label = context.getString(rowRemoveLabel(isGroup = true))
        PopupMenu(context, anchor).apply {
            menu.add(label)
            setOnMenuItemClickListener {
                confirmLeaveGroup(group)
                true
            }
            show()
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
                lifecycleScope.launch { controller.removeContact(contact.agentIdHex) }
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
                lifecycleScope.launch { controller.leaveGroup(group.groupId) }
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
                ) { _, _ -> offerShareInvite(groupId) }
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
            val group = runCatching { gw.joinGroup(inviteUri, senderName) }.getOrElse { e ->
                snackbar(userFacingError(e, "joinGroup", R.string.chat_group_join_failed))
                return@launch
            }
            controller.refreshGroups()
            snackbar(context.getString(R.string.chat_group_joined, groupTitle(group, group.groupId)))
            openGroupThread(group.groupId)
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

        // Collect messages for this peer; job cancelled on screen switch.
        threadCollectJob = lifecycleScope.launch {
            // Hydrate the persisted transcript before/as the thread renders so a
            // reopened DM is not empty after a process kill. Idempotent (de-duped
            // by message id) and non-fatal.
            controller.hydrateConversation(ConversationStore.convKeyDm(peer))
            controller.conversations.messagesFor(peer).collect { msgs ->
                val prevSize = adapter.itemCount
                val rows = msgs.map { MessageRow.Dm(it) }
                adapter.submitList(rows)
                // Scroll only when new messages arrive, not on receipt-tick rebinds.
                if (rows.size > prevSize) rv.scrollToPosition(rows.size - 1)
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
                val rows = msgs.map { MessageRow.Dm(it) }
                adapter.submitList(rows)
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
        renderFediHubHeader(view.findViewById(R.id.threadPeerShortId))
        view.findViewById<View>(R.id.threadBackButton).setOnClickListener { onBack() }
        // Feed is read-only — hide the send row and the (group-only) members button.
        view.findViewById<View>(R.id.threadSendRow).visibility = View.GONE
        view.findViewById<ImageButton>(R.id.threadMembersButton).visibility = View.GONE

        val rv = view.findViewById<RecyclerView>(R.id.messageList)
        val lm = LinearLayoutManager(context).apply { stackFromEnd = true }
        rv.layoutManager = lm
        val adapter = MessageAdapter(onOpenAutonomi, onRetry = {})
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
     * success. On failure shows a Snackbar with a plain user-facing message
     * (via [userFacingError]) + a retry action; the raw engine reason goes to
     * logcat, never to the screen.
     */
    private suspend fun connectWithFeedback(): ChatGateway {
        showConnecting(true)
        return runCatching {
            controller.ensureGateway()
        }.onSuccess {
            showConnecting(false)
        }.onFailure { e ->
            showConnecting(false)
            val message = userFacingError(e, "ensureGateway", R.string.chat_connect_failed_generic)
            Snackbar.make(container, message, Snackbar.LENGTH_INDEFINITE)
                .setAction(context.getString(R.string.action_retry)) {
                    lifecycleScope.launch { connectWithFeedback() }
                }
                .show()
        }.getOrThrow()
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
                else -> false
            }

        override fun areContentsTheSame(old: MessageRow, new: MessageRow): Boolean =
            old == new
    }

    private inner class MessageAdapter(
        private val onLinkTap: (String) -> Unit,
        private val onRetry: () -> Unit,
    ) : ListAdapter<MessageRow, MessageAdapter.VH>(msgDiff) {

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_chat_message, parent, false)
            return VH(v)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            when (val row = getItem(position)) {
                is MessageRow.Dm -> {
                    // The previous message decides whether this is the first of a
                    // consecutive run from the same sender — desktop names a run
                    // once, not on every line (groupAttribution).
                    val prevSender = if (position > 0) {
                        (getItem(position - 1) as? MessageRow.Dm)?.msg?.senderAgentIdHex
                    } else {
                        null
                    }
                    holder.bindDm(row.msg, onLinkTap, prevSender)
                }
                is MessageRow.Post -> holder.bindPost(row.post)
            }
        }

        inner class VH(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val sender: TextView = itemView.findViewById(R.id.messageSender)
            private val bubble: TextView = itemView.findViewById(R.id.messageBubble)
            private val meta: TextView = itemView.findViewById(R.id.messageMeta)

            fun bindDm(
                msg: ChatMessage,
                onLinkTap: (String) -> Unit,
                prevSenderAgentIdHex: String?,
            ) {
                if (msg.outbound) {
                    // Self keeps the copper out-bubble; the who-is-who accent is
                    // inbound-only, so no sender label or identity tint here.
                    sender.visibility = View.GONE
                    bubble.setBackgroundResource(R.drawable.bg_bubble_out)
                    (bubble.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                        android.view.Gravity.END
                    (itemView.layoutParams as? RecyclerView.LayoutParams)?.let { _ ->
                        bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    }
                    (itemView as? LinearLayout)?.gravity = android.view.Gravity.END
                    bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    bubble.text = msg.body
                    // Send status: failed bubbles are tappable to retry the whole
                    // outbox; delivered show a tick; in-flight show plain time.
                    val status = when {
                        msg.failed -> " " + context.getString(R.string.chat_msg_failed_retry)
                        msg.delivered -> " ✓"
                        else -> ""
                    }
                    meta.text = "${timeFmt.format(Date(msg.sentAtMs))}$status"
                    meta.textAlignment = View.TEXT_ALIGNMENT_TEXT_END
                    (meta.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                        android.view.Gravity.END
                    if (msg.failed) {
                        itemView.setOnClickListener { onRetry() }
                    } else {
                        itemView.setOnClickListener(null)
                    }
                } else {
                    (itemView as? LinearLayout)?.gravity = android.view.Gravity.START
                    bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                    meta.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                    (meta.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                        android.view.Gravity.START
                    val time = timeFmt.format(Date(msg.sentAtMs))
                    val groupSender = msg.senderAgentIdHex
                    if (groupSender != null) {
                        // Group message: a per-identity left stripe + faint tint
                        // keyed off the sender's agent id, matching the avatar and
                        // (on desktop) the bubble accent — so "who is who" is
                        // scannable at a glance, pixel-for-pixel with desktop.
                        bubble.background = identityBubbleBackground(groupSender)
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
                        bubble.setBackgroundResource(R.drawable.bg_bubble_in)
                    }
                    meta.text = time
                    // Linkify autonomi:// addresses in inbound text.
                    applyAutonomiLinkedText(bubble, msg.body, onLinkTap)
                    // Clear any retry listener left by a recycled outbound bubble.
                    itemView.setOnClickListener(null)
                }
            }

            fun bindPost(post: FeedPost) {
                // Actor attribution from the relay-verified URL (never a
                // body-asserted actor), formatted as a readable @user@domain in
                // the fediverse (copper) hue.
                sender.visibility = View.VISIBLE
                sender.text = fediActorDisplay(post.actorUrl)
                sender.setTextColor(themeColor(R.attr.fetchitCopper))
                bubble.setBackgroundResource(R.drawable.bg_bubble_in)
                (itemView as? LinearLayout)?.gravity = android.view.Gravity.START
                bubble.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                // Feed body is plain text (HTML stripped by the pump); linkify any
                // autonomi:// addresses so they open in the reader, like DM bubbles.
                applyAutonomiLinkedText(bubble, post.body, onLinkTap)
                meta.textAlignment = View.TEXT_ALIGNMENT_TEXT_START
                (meta.layoutParams as? LinearLayout.LayoutParams)?.gravity =
                    android.view.Gravity.START
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
                return layers
            }
        }

    }

    // ── contact list adapter ──────────────────────────────────────────

    /**
     * Row model for the contact list adapter.
     * Position 0 is always the pinned fediverse channel; group rows render
     * above contacts.
     */
    private sealed class Row {
        data object Fediverse : Row()
        data class Group(val group: GroupFfi, val preview: String) : Row()
        data class Contact(val contact: ChatContact, val preview: String) : Row()
    }

    private inner class ContactListAdapter(
        private val onFeedTap: () -> Unit,
        private val onContactTap: (ChatContact) -> Unit,
        private val onGroupTap: (GroupFfi) -> Unit,
        private val onRemoveContact: (View, ChatContact) -> Unit,
        private val onLeaveGroup: (View, GroupFfi) -> Unit,
    ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

        private val TYPE_FEED = 0
        private val TYPE_CONTACT = 1
        private val TYPE_GROUP = 2

        private val rows = mutableListOf<Row>(Row.Fediverse)

        /**
         * Rebuild the list: pinned fediverse row, then [groups], then
         * [contacts]. Each row's preview is the last message body on that
         * conversation key (group keys are `g:`-prefixed; DM keys are bare).
         */
        fun submit(
            groups: kotlin.collections.List<GroupFfi>,
            contacts: kotlin.collections.List<ChatContact>,
        ) {
            rows.clear()
            rows.add(Row.Fediverse)
            groups.forEach { g ->
                val preview = controller.conversations
                    .messagesFor(ConversationStore.convKeyGroup(g.groupId)).value
                    .lastOrNull()?.body.orEmpty()
                rows.add(Row.Group(g, preview))
            }
            contacts.forEach { c ->
                val preview = controller.conversations
                    .messagesFor(ConversationStore.convKeyDm(c.agentIdHex)).value
                    .lastOrNull()?.body.orEmpty()
                rows.add(Row.Contact(c, preview))
            }
            notifyDataSetChanged()
        }

        override fun getItemViewType(position: Int) = when (rows[position]) {
            is Row.Fediverse -> TYPE_FEED
            is Row.Group -> TYPE_GROUP
            is Row.Contact -> TYPE_CONTACT
        }

        override fun getItemCount() = rows.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_chat_contact, parent, false)
            return when (viewType) {
                TYPE_FEED -> FeedViewHolder(v)
                TYPE_GROUP -> GroupViewHolder(v)
                else -> ContactViewHolder(v)
            }
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val row = rows[position]) {
                is Row.Fediverse -> (holder as FeedViewHolder).bind(onFeedTap)
                is Row.Group ->
                    (holder as GroupViewHolder).bind(row.group, row.preview, onGroupTap, onLeaveGroup)
                is Row.Contact ->
                    (holder as ContactViewHolder).bind(row.contact, row.preview, onContactTap, onRemoveContact)
            }
        }
    }

    private inner class FeedViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)
        private val more: ImageButton = itemView.findViewById(R.id.contactRowMore)

        fun bind(onTap: () -> Unit) {
            shortId.text = "✦"
            name.text = context.getString(R.string.chat_feed_title)
            preview.text = context.getString(R.string.chat_feed_subtitle)
            // The pinned fediverse row is not removable; hide its overflow and
            // detach the listener a recycled holder might still carry.
            more.visibility = View.GONE
            more.setOnClickListener(null)
            itemView.setOnClickListener { onTap() }
        }
    }

    private inner class ContactViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)
        private val more: ImageButton = itemView.findViewById(R.id.contactRowMore)

        fun bind(
            contact: ChatContact,
            lastPreview: String,
            onTap: (ChatContact) -> Unit,
            onMore: (View, ChatContact) -> Unit,
        ) {
            shortId.text = "${contact.agentIdHex.take(8)}…"
            name.text = contact.displayName
            preview.text = lastPreview
            itemView.setOnClickListener { onTap(contact) }
            more.visibility = View.VISIBLE
            more.setOnClickListener { anchor -> onMore(anchor, contact) }
        }
    }

    private inner class GroupViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val shortId: TextView = itemView.findViewById(R.id.contactShortId)
        private val name: TextView = itemView.findViewById(R.id.contactName)
        private val preview: TextView = itemView.findViewById(R.id.contactPreview)
        private val more: ImageButton = itemView.findViewById(R.id.contactRowMore)

        fun bind(
            group: GroupFfi,
            lastPreview: String,
            onTap: (GroupFfi) -> Unit,
            onMore: (View, GroupFfi) -> Unit,
        ) {
            // A lock glyph marks private (PQ) groups; public / unknown-kind
            // groups show a generic group glyph in the id slot.
            shortId.text =
                if (group.isPrivate == true) context.getString(R.string.chat_group_lock_glyph) else "#"
            name.text = groupTitle(group, group.groupId)
            preview.text = lastPreview
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
    }
}
