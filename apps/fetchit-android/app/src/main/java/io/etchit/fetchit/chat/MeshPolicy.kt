package io.etchit.fetchit.chat

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Foreground/background mesh policy for the embedded x0x daemon.
 *
 * Full public-mesh citizenship costs gigabytes per day (129GB in July 2026
 * on one test phone), so the daemon only meshes while the app is actually in
 * the foreground. Backgrounding schedules a debounced drop -- quick app
 * switches must not churn the daemon -- and returning to the foreground
 * cancels it. Message delivery is unaffected by the drop: inbound rides the
 * relay connection, which is what the notification service consumes; the
 * mesh only accelerates direct P2P and native gossip groups while the user
 * is looking at the app.
 *
 * [active] is also the initial mode a fresh `ChatClient.connect` should be
 * given, so a connect that happens in the background (boot receiver,
 * notification service) never joins the mesh just to leave it.
 *
 * Transitions call [apply] on [scope]; a failed apply is the caller's to log
 * -- state still advances, and the next lifecycle transition re-converges.
 */
class MeshPolicy(
    private val scope: CoroutineScope,
    private val debounceMs: Long = DEBOUNCE_MS,
    private val apply: suspend (Boolean) -> Unit,
) {
    /** Current desired mesh mode; `false` until the first foreground. */
    @Volatile
    var active: Boolean = false
        private set

    private var pendingDrop: Job? = null

    /** App is visible: cancel any pending drop and go full mesh. */
    @Synchronized
    fun onForeground() {
        pendingDrop?.cancel()
        pendingDrop = null
        if (active) return
        active = true
        scope.launch { apply(true) }
    }

    /** App left the foreground: drop the mesh after the debounce. */
    @Synchronized
    fun onBackground() {
        if (!active) return
        if (pendingDrop?.isActive == true) return
        pendingDrop = scope.launch {
            delay(debounceMs)
            commitDrop()
        }
    }

    @Synchronized
    private fun commitDrop() {
        if (!active) return
        active = false
        pendingDrop = null
        scope.launch { apply(false) }
    }

    companion object {
        /** Long enough to absorb app switches, short enough to cap the bill. */
        const val DEBOUNCE_MS: Long = 120_000
    }
}
