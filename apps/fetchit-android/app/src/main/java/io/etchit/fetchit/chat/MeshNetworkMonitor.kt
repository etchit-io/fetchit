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

    /**
     * Seed from the current default network, then follow it for the life of
     * the process. [onChange] fires on a connectivity handler thread; the
     * consumer ([MeshPolicy]) is thread-safe.
     */
    fun start(onChange: (Boolean) -> Unit) {
        this.onChange = onChange
        update(allowsMesh(connectivity.activeNetwork?.let(connectivity::getNetworkCapabilities)))
        connectivity.registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) = update(allowsMesh(capabilities))

                override fun onLost(network: Network) = update(false)
            },
        )
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
