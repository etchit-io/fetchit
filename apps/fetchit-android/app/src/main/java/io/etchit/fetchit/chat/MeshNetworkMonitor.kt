package io.etchit.fetchit.chat

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/**
 * Tracks whether the device's default network is one [MeshPolicy] may mesh
 * on: unmetered Wi-Fi or Ethernet. Mobile data (and metered Wi-Fi, e.g. a
 * phone hotspot) never qualifies -- mesh traffic on a metered plan is what
 * produced the 129GB July 2026 bill.
 *
 * Thin adapter over [ConnectivityManager]: the transition logic (debounces,
 * fail-safe default) lives in [MeshPolicy], which is where the unit tests
 * are. [start] seeds synchronously from the current default network before
 * registering the callback, so the first lifecycle event never races an
 * unknown verdict.
 */
class MeshNetworkMonitor(context: Context) {

    private val connectivity =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE)
            as ConnectivityManager

    /** Latest verdict; `false` until [start]. */
    @Volatile
    var latest: Boolean = false
        private set

    private var onChange: ((Boolean) -> Unit)? = null
    private var onDefaultNetworkChanged: (() -> Unit)? = null
    private var lastNetwork: Network? = null

    /**
     * Seed from the current default network, then follow it for the life of
     * the process. Callbacks fire on a connectivity handler thread; the
     * consumers ([MeshPolicy], the gateway rebuild) are thread-safe.
     *
     * [onDefaultNetworkChanged] fires when the default network's IDENTITY
     * changes (Wi-Fi to cellular, cellular to Wi-Fi, one Wi-Fi to another)
     * -- distinct from the mesh verdict, which can survive such a change.
     * Any identity change kills established TCP flows, and the relay
     * WebSocket has no in-pump reconnect in v1, so the shell must rebuild
     * the gateway or sends queue forever against a dead socket. The initial
     * network at [start] is a seed, not a change.
     */
    fun start(onChange: (Boolean) -> Unit, onDefaultNetworkChanged: (() -> Unit)? = null) {
        this.onChange = onChange
        this.onDefaultNetworkChanged = onDefaultNetworkChanged
        lastNetwork = connectivity.activeNetwork
        update(allowsMesh(lastNetwork?.let(connectivity::getNetworkCapabilities)))
        connectivity.registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                // Identity is tracked from onCapabilitiesChanged, not
                // onAvailable: Android delivers onAvailable(new) BEFORE the
                // new network's capabilities, and the identity-change
                // consumer reads the mesh verdict when it fires. Ordering
                // verdict-then-identity here means a Wi-Fi -> cellular flip
                // can never rebuild the gateway with a stale "unmetered"
                // verdict and join the mesh on mobile data.
                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) {
                    update(allowsMesh(capabilities))
                    trackIdentity(network)
                }

                override fun onLost(network: Network) = update(false)
            },
        )
    }

    @Synchronized
    private fun trackIdentity(network: Network) {
        if (network == lastNetwork) return
        val first = lastNetwork == null
        lastNetwork = network
        // A change FROM a known network is a real handover; the first
        // network ever seen (seed was null because start() ran before any
        // network was up) is not.
        if (!first) onDefaultNetworkChanged?.invoke()
    }

    @Synchronized
    private fun update(value: Boolean) {
        if (latest == value) return
        latest = value
        onChange?.invoke(value)
    }

    private companion object {
        fun allowsMesh(capabilities: NetworkCapabilities?): Boolean {
            val caps = capabilities ?: return false
            val wifiLike =
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
            return wifiLike && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        }
    }
}
