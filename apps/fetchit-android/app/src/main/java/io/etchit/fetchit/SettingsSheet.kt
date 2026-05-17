package io.etchit.fetchit

import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import io.etchit.fetchit.databinding.ActivityMainBinding
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import uniffi.fetchit_ffi.defaultPeers

/**
 * Drives the settings views nested inside [`MainActivity`]'s
 * `CoordinatorLayout` bottom sheet.
 *
 * Live-paints the peer count from
 * [`FetchitApplication.peerCountTracker`]: ash when ≥ 1, red when 0
 * (matches etchit's "honest dip" rule). Bootstrap-peers section starts
 * collapsed — most users never touch it.
 */
class SettingsSheet(
    private val binding: ActivityMainBinding,
    private val activity: AppCompatActivity,
) {

    private val store = SettingsStore(activity)

    /** Wire button handlers + initial render. Call once in `onCreate`. */
    fun bind() {
        binding.peersEdit.setText(store.peers().joinToString("\n"))
        binding.savePeersButton.setOnClickListener { onSaveClicked() }
        binding.resetPeersButton.setOnClickListener { onResetClicked() }
        binding.peersHeader.setOnClickListener { togglePeersBody() }
        binding.settingsVersionText.text =
            activity.getString(R.string.settings_version, BuildConfig.VERSION_NAME)
        bindThemePicker()
        observePeerCount()
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

    private fun toast(@androidx.annotation.StringRes msg: Int) {
        Toast.makeText(activity, msg, Toast.LENGTH_SHORT).show()
    }
}
