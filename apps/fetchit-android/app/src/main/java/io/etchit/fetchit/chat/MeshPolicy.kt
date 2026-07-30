package io.etchit.fetchit.chat

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Mesh policy for the embedded x0x daemon: mesh only while the app is in
 * the foreground AND the default network is unmetered Wi-Fi/Ethernet.
 *
 * Full public-mesh citizenship costs gigabytes per hour (129GB in July 2026
 * on one test phone, all booked as "foreground" because the notification
 * service keeps the process alive), and even leaf mode cannot refuse
 * inbound gossip pushes -- the wire has no PRUNE frame. So on a metered
 * network the phone never meshes at all: delivery rides the relay, which
 * is what the notification path uses anyway.
 *
 * Transition timing is asymmetric by design:
 * - backgrounding drops the mesh after [DROP_DEBOUNCE_MS] (quick app
 *   switches must not churn the daemon);
 * - the network turning metered drops it immediately (every second on
 *   mobile data bills);
 * - the network turning unmetered rejoins after [RISE_DEBOUNCE_MS] (a
 *   flapping Wi-Fi connection must not churn the daemon either);
 * - opening the app on a good network joins immediately.
 *
 * Until the first [onNetworkChanged] verdict the policy fails safe: an
 * unknown network is treated as metered.
 *
 * [active] is also the initial mode a fresh `ChatClient.connect` should be
 * given, so a connect that happens in the background (boot receiver,
 * notification service) never joins the mesh just to leave it.
 *
 * Transitions call [apply] on [scope]; a failed apply is the caller's to log
 * -- state still advances, and the next transition re-converges.
 */
class MeshPolicy(
    private val scope: CoroutineScope,
    private val dropDebounceMs: Long = DROP_DEBOUNCE_MS,
    private val riseDebounceMs: Long = RISE_DEBOUNCE_MS,
    private val apply: suspend (Boolean) -> Unit,
) {
    /** Currently-applied mesh mode; `false` until foreground + good network. */
    @Volatile
    var active: Boolean = false
        private set

    private var foreground = false
    private var networkAllowsMesh = false
    private var pending: Job? = null

    /** App is visible. Joins immediately if the network already allows it. */
    @Synchronized
    fun onForeground() {
        foreground = true
        reevaluate(delayMs = 0)
    }

    /** App left the foreground: drop the mesh after the drop debounce. */
    @Synchronized
    fun onBackground() {
        foreground = false
        reevaluate(delayMs = dropDebounceMs)
    }

    /**
     * Default-network verdict from the connectivity monitor. Losing an
     * unmetered network commits immediately; gaining one is debounced.
     */
    @Synchronized
    fun onNetworkChanged(allowsMesh: Boolean) {
        if (networkAllowsMesh == allowsMesh) return
        networkAllowsMesh = allowsMesh
        reevaluate(delayMs = if (allowsMesh) riseDebounceMs else 0)
    }

    /**
     * Converge toward `foreground && networkAllowsMesh`. Any change of
     * inputs cancels an in-flight transition: the commit re-derives the
     * desired state at fire time, so a stale timer can never apply a mode
     * the inputs no longer want.
     */
    private fun reevaluate(delayMs: Long) {
        pending?.cancel()
        pending = null
        if ((foreground && networkAllowsMesh) == active) return
        if (delayMs == 0L) {
            commit()
        } else {
            pending = scope.launch {
                delay(delayMs)
                commit()
            }
        }
    }

    @Synchronized
    private fun commit() {
        pending = null
        val desired = foreground && networkAllowsMesh
        if (desired == active) return
        active = desired
        scope.launch { apply(desired) }
    }

    companion object {
        /** Long enough to absorb app switches, short enough to cap the bill. */
        const val DROP_DEBOUNCE_MS: Long = 120_000

        /** Long enough to ride out Wi-Fi flap, short enough to feel prompt. */
        const val RISE_DEBOUNCE_MS: Long = 15_000
    }
}
