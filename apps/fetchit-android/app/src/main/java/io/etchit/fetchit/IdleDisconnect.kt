package io.etchit.fetchit

import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner

/**
 * Disconnects the shared `Client` after the app has been in the
 * background for [`IDLE_GRACE_MS`]. Lets the user pop in/out without
 * paying a fresh bootstrap on every return, while ensuring the QUIC +
 * DHT chatter stops when the phone goes in the pocket. Reconnect
 * happens lazily on the next fetch via
 * [`FetchitApplication.ensureConnected`].
 *
 * Registered on the **process** lifecycle (not an Activity's), so
 * `onStop` fires only when *every* activity in the app is backgrounded
 * — config-change re-creates and quick fragment swaps don't trip it.
 */
class IdleDisconnect(private val onIdle: () -> Unit) : DefaultLifecycleObserver {

    private val handler = Handler(Looper.getMainLooper())
    private val disconnectTask = Runnable {
        Log.i(TAG, "idle timeout — disconnecting client to save battery")
        onIdle()
    }

    override fun onStart(owner: LifecycleOwner) {
        // App foregrounded — cancel any pending disconnect so the
        // user's next fetch finds the client warm.
        handler.removeCallbacks(disconnectTask)
    }

    override fun onStop(owner: LifecycleOwner) {
        // App backgrounded — schedule disconnect after the grace
        // period. Cancelled if onStart fires first.
        handler.removeCallbacks(disconnectTask)
        handler.postDelayed(disconnectTask, IDLE_GRACE_MS)
    }

    private companion object {
        const val TAG = "fetchit.idle"
        const val IDLE_GRACE_MS = 60_000L
    }
}
