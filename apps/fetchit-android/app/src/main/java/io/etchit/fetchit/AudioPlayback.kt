package io.etchit.fetchit

import android.content.Context
import android.util.Log
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.ByteArrayDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.ui.PlayerView

/**
 * Owns a single [`ExoPlayer`] backed by an in-memory byte array.
 *
 * Playback reads straight from the in-memory `ByteArray` via Media3's
 * [`ByteArrayDataSource`] — the audio path writes no temp file of its
 * own. (The raw fetched bytes may already sit in the app's content
 * cache from the fetch; the playback layer itself adds nothing.)
 *
 * Standard media controls (play/pause, seek, time, ±15s skip) are
 * rendered by Media3's [`PlayerView`]; this class doesn't draw any UI
 * — it just attaches to whatever view the renderer hands it.
 */
@UnstableApi
class AudioPlayback(private val context: Context) {

    private var player: ExoPlayer? = null

    /**
     * Begin playback of `bytes`. Replaces any in-flight playback.
     * `onError` fires on the main thread for terminal errors.
     */
    fun play(bytes: ByteArray, onError: (String) -> Unit = {}) {
        release()
        val newPlayer = ExoPlayer.Builder(context).build().apply {
            val factory = DataSource.Factory { ByteArrayDataSource(bytes) }
            val mediaItem = MediaItem.fromUri("data:bytes")
            val source = ProgressiveMediaSource.Factory(factory)
                .createMediaSource(mediaItem)
            setMediaSource(source)
            prepare()
            playWhenReady = true
            addListener(object : Player.Listener {
                override fun onPlayerError(error: PlaybackException) {
                    Log.e(TAG, "ExoPlayer error", error)
                    onError(error.message ?: error.toString())
                }
            })
        }
        player = newPlayer
    }

    /** Hand the [`PlayerView`] this player so it renders controls. */
    fun attachTo(playerView: PlayerView) {
        playerView.player = player
    }

    /** Stop and release. Idempotent. Detaches from any [`PlayerView`]. */
    fun release() {
        player?.release()
        player = null
    }

    private companion object {
        const val TAG = "fetchit.audio"
    }
}
