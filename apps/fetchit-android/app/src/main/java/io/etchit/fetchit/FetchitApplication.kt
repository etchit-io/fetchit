package io.etchit.fetchit

import android.app.Application
import android.content.Context
import androidx.lifecycle.ProcessLifecycleOwner
import uniffi.fetchit_ffi.Client
import uniffi.fetchit_ffi.setDataHome
import uniffi.fetchit_ffi.setupLogger

/**
 * Bootstraps the FFI side of fetch/it and owns the process-scoped
 * [`Client`].
 *
 * Why the Client lives here, not in [`MainActivity`]: it's a heavy
 * resource (DHT bootstrap, QUIC connections), and other surfaces —
 * [`SettingsActivity`] for peer count, future Tauri/web embeds — need
 * to share it. The Activity is just one consumer.
 *
 * `ant-core`'s internal `data_dir()` resolution calls `home_dir().unwrap()`
 * on Linux when `XDG_DATA_HOME` is missing. Android sets neither `HOME`
 * nor `XDG_DATA_HOME` by default, so the unwrap panics with
 * `HomeDirNotFound` the first time anything in the FFI builds a Client.
 * Pointing both at the app-private files dir before any FFI call avoids
 * the panic. Same workaround etchit-android uses.
 */
class FetchitApplication : Application() {

    private var cached: Client? = null

    /** Live peer-count gauge. Polls every 15s once started. */
    val peerCountTracker: PeerCountTracker by lazy { PeerCountTracker { cached } }

    override fun onCreate() {
        super.onCreate()
        setDataHome(filesDir.absolutePath)
        setupLogger()
        peerCountTracker.start()
        ProcessLifecycleOwner.get().lifecycle.addObserver(IdleDisconnect(this))
    }

    /** Returns the connected client; constructs it on first call. */
    suspend fun ensureConnected(peers: List<String>): Client {
        cached?.let { return it }
        val client = Client.connect(peers)
        cached = client
        return client
    }

    /** `null` if not yet connected. Cheap; no network call. */
    fun client(): Client? = cached

    /**
     * Drop the cached [`Client`]. The next [`ensureConnected`] call
     * rebuilds with whatever peers are then current. Used after
     * settings changes so a peer-list edit takes effect on next fetch.
     */
    fun disconnect() {
        cached = null
    }
}

/** Convenience accessor for activities and fragments. */
fun Context.fetchitApp(): FetchitApplication =
    applicationContext as FetchitApplication
