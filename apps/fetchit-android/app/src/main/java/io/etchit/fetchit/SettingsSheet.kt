package io.etchit.fetchit

import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.etchit.fetchit.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.fetchit_ffi.CreatedLinkOfferFfi
import uniffi.fetchit_ffi.defaultPeers

/**
 * Drives the settings views nested inside [`MainActivity`]'s
 * `CoordinatorLayout` bottom sheet.
 *
 * Live-paints the peer count from
 * [`FetchitApplication.peerCountTracker`]: ash when ≥ 1, red when 0.
 * Bootstrap-peers section starts collapsed.
 */
class SettingsSheet(
    private val binding: ActivityMainBinding,
    private val activity: AppCompatActivity,
    private val onLaunchScanner: () -> Unit,
    // The photo picker is registered on the activity (an activity-result
    // contract must be); this sheet only asks for it.
    private val onPickProfilePicture: () -> Unit = {},
    private val onRemoveProfilePicture: () -> Unit = {},
) {

    private val store = SettingsStore(activity)

    /** Wire button handlers + initial render. Call once in `onCreate`. */
    fun bind() {
        binding.peersEdit.setText(store.peers().joinToString("\n"))
        binding.savePeersButton.setOnClickListener { onSaveClicked() }
        binding.resetPeersButton.setOnClickListener { onResetClicked() }
        binding.refreshPeersButton.setOnClickListener { onRefreshClicked() }
        binding.peersHeader.setOnClickListener { togglePeersBody() }
        binding.backupRevealRow.setOnClickListener { revealRecoveryPhraseFlow(activity) }
        binding.backupRestoreRow.setOnClickListener { restoreRecoveryPhraseFlow(activity) }
        binding.aboutHeader.setOnClickListener { showAboutDialog(activity) }
        binding.settingsVersionText.text =
            activity.getString(R.string.settings_version, BuildConfig.VERSION_NAME)
        bindThemePicker()
        observePeerCount()
        bindChatDisplayName()
        bindProfilePicture()
        bindLinkDevice()
        bindChatKeepConnected()
    }

    private fun bindThemePicker() {
        val current = store.theme()
        val buttons = mapOf(
            Theme.Dark to binding.themeDarkButton,
            Theme.Dim to binding.themeDimButton,
            Theme.Light to binding.themeLightButton,
        )
        val copper = activity.themeColor(R.attr.fetchitCopper)
        val ink = activity.themeColor(R.attr.fetchitInk)
        val ink3 = activity.themeColor(R.attr.fetchitInk3)
        val ash = activity.themeColor(R.attr.fetchitAsh)
        buttons.forEach { (theme, btn) ->
            val selected = theme == current
            btn.backgroundTintList =
                android.content.res.ColorStateList.valueOf(if (selected) copper else ink3)
            btn.setTextColor(if (selected) ink else ash)
            btn.setOnClickListener {
                if (theme == store.theme()) return@setOnClickListener
                store.saveTheme(theme)
                activity.recreate()
            }
        }
    }

    /** Read the current saved peer list (delegates to the store). */
    fun savedPeers(): List<String> = store.peers()

    private fun observePeerCount() {
        activity.lifecycleScope.launch {
            activity.fetchitApp().peerCountTracker.flow.collectLatest { count ->
                renderPeerCount(count)
            }
        }
    }

    private fun renderPeerCount(count: Long?) {
        when {
            count == null -> {
                binding.peerCountText.text =
                    activity.getString(R.string.settings_peer_count_disconnected)
                binding.peerCountText.setTextColor(activity.themeColor(R.attr.fetchitAsh))
            }
            count == 0L -> {
                binding.peerCountText.text =
                    activity.getString(R.string.settings_peer_count_value, 0L)
                binding.peerCountText.setTextColor(activity.themeColor(R.attr.fetchitRust))
            }
            else -> {
                binding.peerCountText.text =
                    activity.getString(R.string.settings_peer_count_value, count)
                binding.peerCountText.setTextColor(activity.themeColor(R.attr.fetchitSignalOk))
            }
        }
    }

    private fun togglePeersBody() {
        val showing = binding.peersBody.visibility == View.VISIBLE
        binding.peersBody.visibility = if (showing) View.GONE else View.VISIBLE
        binding.peersHeader.text = activity.getString(
            if (showing) R.string.settings_peers_header_collapsed
            else R.string.settings_peers_header_expanded,
        )
    }

    private fun onSaveClicked() {
        val entered = binding.peersEdit.text.toString()
            .lines().map { it.trim() }.filter { it.isNotEmpty() }
        store.savePeers(entered)
        // Drop the cached client so the next fetch reconnects with
        // the freshly-saved peer list.
        activity.fetchitApp().disconnect()
        toast(R.string.settings_saved)
    }

    private fun onResetClicked() {
        store.savePeers(emptyList())
        binding.peersEdit.setText(defaultPeers().joinToString("\n"))
        activity.fetchitApp().disconnect()
        toast(R.string.settings_reset)
    }

    private fun onRefreshClicked() {
        binding.refreshPeersButton.isEnabled = false
        toastStr(activity.getString(R.string.settings_refresh_peers_running))
        activity.lifecycleScope.launch {
            val result = runCatching { withContext(Dispatchers.IO) { BootstrapPeersUpstream.fetch() } }
            binding.refreshPeersButton.isEnabled = true
            result.fold(
                onSuccess = { upstream ->
                    val current = store.peers()
                    if (upstream == current) {
                        toastStr(activity.getString(R.string.settings_refresh_peers_current, upstream.size))
                    } else {
                        store.savePeers(upstream)
                        binding.peersEdit.setText(upstream.joinToString("\n"))
                        activity.fetchitApp().disconnect()
                        toastStr(activity.getString(R.string.settings_refresh_peers_updated, upstream.size))
                    }
                },
                onFailure = { e ->
                    toastStr(activity.getString(R.string.settings_refresh_peers_failed, e.message ?: e.javaClass.simpleName))
                },
            )
        }
    }

    private fun bindChatDisplayName() {
        binding.chatDisplayNameEdit.setText(store.chatDisplayName())
        binding.chatDisplayNameEdit.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == android.view.inputmethod.EditorInfo.IME_ACTION_DONE) {
                store.saveChatDisplayName(binding.chatDisplayNameEdit.text.toString())
                toast(R.string.chat_display_name_saved)
                true
            } else {
                false
            }
        }
        binding.chatDisplayNameEdit.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) {
                store.saveChatDisplayName(binding.chatDisplayNameEdit.text.toString())
            }
        }
    }

    /**
     * Wire the profile-picture row, directly under the display name — the
     * two together are "how people see me".
     *
     * The picture is published on the fediverse actor document, so both
     * buttons hand off to the activity, which owns the picker contract and
     * the engine calls.
     */
    private fun bindProfilePicture() {
        binding.profilePictureSetButton.setOnClickListener { onPickProfilePicture() }
        binding.profilePictureRemoveButton.setOnClickListener { onRemoveProfilePicture() }
    }

    /**
     * Wire the "link a device" section (M6.4). Two entry points:
     *  - "show my code": THIS device wants to be linked — mint + publish a link
     *    offer and show its QR + confirm code ([showLinkThisDeviceCode], flow A).
     *  - "scan a code": THIS device links another — launch the shared scanner;
     *    its sniff routes a scanned `fetchit://link/…` into the existing-device
     *    preview→confirm→enroll path ([ChatModeView.linkDeviceFromUri], flow B).
     */
    private fun bindLinkDevice() {
        binding.linkShowCodeButton.setOnClickListener { showLinkThisDeviceCode() }
        binding.linkScanCodeButton.setOnClickListener { onLaunchScanner() }
    }

    /**
     * Flow A: mint a link offer from this device's own identity and show it.
     * Connects the chat client (needed to publish the offer to the relay), then
     * renders the QR pointer + the human-comparable confirm code. A connect or
     * publish failure surfaces as a plain toast — the raw reason never reaches
     * the user.
     */
    private fun showLinkThisDeviceCode() {
        val controller = activity.fetchitApp().chatController
        activity.lifecycleScope.launch {
            val gw = runCatching { controller.ensureGateway() }.getOrElse {
                toast(R.string.chat_link_connect_failed)
                return@launch
            }
            // 600 s (10 min) offer window: long enough to walk to the other
            // device, short enough that a stale QR stops working on its own.
            val offer = runCatching { gw.createLinkOffer(600uL) }.getOrElse {
                toast(R.string.chat_link_offer_failed)
                return@launch
            }
            showLinkOfferDialog(offer)
        }
    }

    /**
     * The offer dialog: a scannable QR of the `fetchit://link/…` pointer above
     * a LARGE copper confirm code. The code is the security anchor — the caption
     * tells the user to scan on the other device and only proceed when the same
     * code shows on both screens.
     */
    private fun showLinkOfferDialog(offer: CreatedLinkOfferFfi) {
        val density = activity.resources.displayMetrics.density
        val pad = (20 * density).toInt()
        val column = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(pad, pad, pad, pad)
        }

        val qrSize = (240 * density).toInt()
        QrBitmap.renderQrWithLogo(offer.uri)?.let { bmp ->
            column.addView(
                ImageView(activity).apply {
                    setImageBitmap(bmp)
                    contentDescription = activity.getString(R.string.chat_link_qr_desc)
                    layoutParams = LinearLayout.LayoutParams(qrSize, qrSize)
                },
            )
        }

        // The short code is the security anchor: large, mono, copper, spaced so
        // it is trivially comparable against the other device across a table.
        column.addView(
            TextView(activity).apply {
                text = offer.shortCode
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                textSize = 26f
                letterSpacing = 0.12f
                gravity = Gravity.CENTER
                setTextColor(activity.themeColor(R.attr.fetchitCopper))
                setPadding(0, (16 * density).toInt(), 0, 0)
            },
        )

        column.addView(
            TextView(activity).apply {
                text = activity.getString(R.string.chat_link_show_code_caption)
                gravity = Gravity.CENTER
                setTextColor(activity.themeColor(R.attr.fetchitAsh))
                textSize = 13f
                setPadding(0, (12 * density).toInt(), 0, 0)
            },
        )

        MaterialAlertDialogBuilder(activity)
            .setTitle(activity.getString(R.string.chat_link_show_code_title))
            .setView(column)
            .setPositiveButton(activity.getString(R.string.action_close), null)
            .show()
    }

    private fun bindChatKeepConnected() {
        // Set the initial state before attaching the listener so opening
        // Settings does not fire a spurious toast.
        binding.chatKeepConnectedSwitch.isChecked = store.chatKeepConnected()
        binding.chatKeepConnectedSwitch.setOnCheckedChangeListener { _, isChecked ->
            store.saveChatKeepConnected(isChecked)
            toast(
                if (isChecked) R.string.settings_chat_keepalive_on
                else R.string.settings_chat_keepalive_off,
            )
        }
    }

    private fun toast(@androidx.annotation.StringRes msg: Int) {
        Toast.makeText(activity, msg, Toast.LENGTH_SHORT).show()
    }

    private fun toastStr(msg: String) {
        Toast.makeText(activity, msg, Toast.LENGTH_SHORT).show()
    }
}
