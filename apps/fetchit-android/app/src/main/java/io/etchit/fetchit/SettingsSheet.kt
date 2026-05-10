package io.etchit.fetchit

import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
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
        observePeerCount()
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
                binding.peerCountText.setTextColor(color(R.color.ash))
            }
            count == 0L -> {
                binding.peerCountText.text =
                    activity.getString(R.string.settings_peer_count_value, 0L)
                binding.peerCountText.setTextColor(color(R.color.status_red))
            }
            else -> {
                binding.peerCountText.text =
                    activity.getString(R.string.settings_peer_count_value, count)
                binding.peerCountText.setTextColor(color(R.color.status_green))
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

    private fun color(@androidx.annotation.ColorRes id: Int): Int =
        ContextCompat.getColor(activity, id)

    private fun toast(@androidx.annotation.StringRes msg: Int) {
        Toast.makeText(activity, msg, Toast.LENGTH_SHORT).show()
    }
}
