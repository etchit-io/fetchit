package io.etchit.fetchit

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import uniffi.fetchit_ffi.Client

/**
 * Polls [`Client.peerCount`] periodically and exposes the latest value
 * as a [`StateFlow`].
 *
 * Mirrors etchit's pattern (15s interval, 5s per-query timeout).
 * Peer count drifts at runtime (DHT churn, NAT, bootstrap-driven
 * discovery); the live value — including 0 — is surfaced instead of
 * a binary connected/disconnected label.
 *
 * Owned by [`FetchitApplication`]; lives for the process. Idempotent
 * `start()` so on-demand callers don't spawn duplicate jobs.
 */
class PeerCountTracker(
    private val clientProvider: () -> Client?,
) {

    private val _flow = MutableStateFlow<Long?>(null)

    /** `null` while no client exists or every recent poll has timed out. */
    val flow: StateFlow<Long?> = _flow.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    /** Begin polling. Idempotent. */
    fun start() {
        if (job?.isActive == true) return
        job = scope.launch {
            while (isActive) {
                _flow.value = readOnce()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private suspend fun readOnce(): Long? {
        val client = clientProvider() ?: return null
        return try {
            withTimeout(QUERY_TIMEOUT_MS) { client.peerCount().toLong() }
        } catch (_: Exception) {
            // Timeout or transient FFI failure: retain the previous
            // value instead of overwriting with null.
            _flow.value
        }
    }

    private companion object {
        const val POLL_INTERVAL_MS = 15_000L
        const val QUERY_TIMEOUT_MS = 5_000L
    }
}
