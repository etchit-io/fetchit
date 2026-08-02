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
 * Transitions call [apply] on [scope]; `apply` reports success. A FAILED
 * apply is retried on [retryBackoffMs] until the mode sticks or the inputs
 * move on. Waiting for the next transition instead is not enough: a phone
 * sitting in a pocket on cellular fires no lifecycle or connectivity events
 * for hours, so one failed "mesh off" flip used to leak a full-mesh daemon
 * onto mobile data all night (the multi-GB/day burn of early Aug 2026).
 */
class MeshPolicy(
    private val scope: CoroutineScope,
    private val dropDebounceMs: Long = DROP_DEBOUNCE_MS,
    private val riseDebounceMs: Long = RISE_DEBOUNCE_MS,
    private val retryBackoffMs: Long = RETRY_BACKOFF_MS,
    private val apply: suspend (Boolean) -> Boolean,
) {
    /** Desired mesh mode; `false` until foreground + good network. */
    @Volatile
    var active: Boolean = false
        private set

    /**
     * Mode last confirmed applied. Starts equal to [active] because a fresh
     * connect seeds its initial mode from [active]. Diverges from [active]
     * only while an apply has failed and a retry is owed.
     */
    private var applied: Boolean = false

    /**
     * Mode an apply coroutine is currently carrying, `null` when none. Keeps
     * duplicate same-direction transitions from re-launching the apply while
     * the first one is still in flight ([applied] only advances on
     * completion).
     */
    private var inFlight: Boolean? = null

    private var foreground = false
    private var networkAllowsMesh = false

    /** Pending debounced commit OR pending failure retry; at most one. */
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
     * the inputs no longer want. `applied != active` keeps the state
     * "dirty" so a canceled retry is replaced by a fresh commit rather
     * than silently dropped.
     */
    private fun reevaluate(delayMs: Long) {
        pending?.cancel()
        pending = null
        if ((foreground && networkAllowsMesh) == active && converging()) return
        if (delayMs == 0L) {
            commit()
        } else {
            pending = scope.launch {
                delay(delayMs)
                commit()
            }
        }
    }

    /** The daemon already matches [active], or an apply that will is in flight. */
    private fun converging(): Boolean = applied == active || inFlight == active

    @Synchronized
    private fun commit() {
        pending = null
        val desired = foreground && networkAllowsMesh
        if (desired == active && converging()) return
        active = desired
        inFlight = desired
        scope.launch { onApplyResult(desired, apply(desired)) }
    }

    /**
     * Book the apply outcome. Success records [applied] (a same-mode
     * re-apply is a cheap engine no-op, so a stale success self-corrects
     * on the next commit). Failure schedules a retry unless the inputs
     * already moved on (a newer transition owns convergence) or one is
     * already queued.
     */
    @Synchronized
    private fun onApplyResult(desired: Boolean, ok: Boolean) {
        if (inFlight == desired) inFlight = null
        if (ok) {
            applied = desired
            return
        }
        if (desired != active || pending != null) return
        pending = scope.launch {
            delay(retryBackoffMs)
            commit()
        }
    }

    companion object {
        /** Long enough to absorb app switches, short enough to cap the bill. */
        const val DROP_DEBOUNCE_MS: Long = 120_000

        /** Long enough to ride out Wi-Fi flap, short enough to feel prompt. */
        const val RISE_DEBOUNCE_MS: Long = 15_000

        /**
         * Retry cadence after a failed apply. Short enough that a leaked
         * full-mesh daemon on mobile data is corrected in about a minute,
         * long enough not to hammer a wedged engine.
         */
        const val RETRY_BACKOFF_MS: Long = 60_000
    }
}
