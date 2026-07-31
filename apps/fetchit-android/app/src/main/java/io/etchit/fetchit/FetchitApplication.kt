package io.etchit.fetchit

import android.app.Application
import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import io.etchit.fetchit.chat.ChatController
import io.etchit.fetchit.chat.MeshNetworkMonitor
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import uniffi.fetchit_ffi.Client
import uniffi.fetchit_ffi.setDataHome
import uniffi.fetchit_ffi.setupLogger

/**
 * Bootstraps the FFI side of fetch>it and owns the process-scoped
 * [`Client`].
 *
 * Why the Client lives here, not in [`MainActivity`]: it's a heavy
 * resource (DHT bootstrap, QUIC connections), and other surfaces --
 * [`SettingsSheet`] for peer count, future Tauri/web embeds -- need
 * to share it. The Activity is just one consumer.
 *
 * `ant-core`'s internal `data_dir()` resolution calls `home_dir().unwrap()`
 * on Linux when `XDG_DATA_HOME` is missing. Android sets neither `HOME`
 * nor `XDG_DATA_HOME` by default, so the unwrap panics with
 * `HomeDirNotFound` the first time anything in the FFI builds a Client.
 * Pointing both at the app-private files dir before any FFI call avoids
 * the panic. Same workaround etchit-android uses.
 */
open class FetchitApplication : Application() {

    private var cached: Client? = null

    /**
     * Application-owned scope for coroutines that must outlive any single
     * activity (the chat event pump, for example). [SupervisorJob] ensures
     * one failing child does not cancel siblings.
     */
    val appScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /**
     * Backing field for [chatController]. `null` until first access so
     * idle-disconnect callbacks can check [_chatController] directly and skip
     * disconnecting chat if it was never started.
     */
    private var _chatController: ChatController? = null

    /**
     * Process-scoped chat runtime. Lazily constructed on first access so
     * the Autonomi browse path pays no initialisation cost if the user
     * never opens the chat mode.
     *
     * Lifecycle callbacks use [_chatController] (the nullable backing field)
     * to avoid inadvertently constructing the controller from a background event.
     */
    val chatController: ChatController
        get() =
            _chatController
                ?: ChatController(this, appScope).also {
                    _chatController = it
                    // Seed the network half of the mesh policy at construction:
                    // the monitor has been following the default network since
                    // onCreate, and a controller born on mobile data must not
                    // mesh on its first foreground.
                    it.meshPolicy.onNetworkChanged(meshNetworkMonitor.latest)
                }

    /** Process-lifetime tracker of whether the default network may mesh. */
    val meshNetworkMonitor: MeshNetworkMonitor by lazy { MeshNetworkMonitor(this) }

    /** Live peer-count gauge. Polls every 15s once started. */
    val peerCountTracker: PeerCountTracker by lazy { PeerCountTracker { cached } }

    /**
     * Disk-backed cache of fetched bytes, keyed by address. Both
     * top-level navigations (MainActivity) and SPA subresources
     * (HtmlView) consult this before going to the Autonomi network.
     * Lives in `filesDir` (persistent across app restarts) rather
     * than `cacheDir` so we keep the offline-replay guarantee.
     */
    val bytesCache: BytesCache by lazy {
        BytesCache(File(filesDir, "autonomi_cache"))
    }

    override fun onCreate() {
        super.onCreate()
        bootstrapFfi()
        peerCountTracker.start()
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            IdleDisconnect(::disconnectAll, ::reconnectChatIfActive),
        )
        // Mesh-mode lifecycle: mesh only while the app is visible AND the
        // network is unmetered Wi-Fi/Ethernet (129GB/July was one phone
        // doing mesh duty on mobile data around the clock). The monitor
        // pushes network verdicts through the nullable backing field so a
        // network change never constructs a controller; a controller built
        // later seeds itself from the monitor in the getter above.
        meshNetworkMonitor.start(
            onChange = { allowed ->
                _chatController?.meshPolicy?.onNetworkChanged(allowed)
            },
            // A default-network identity change (Wi-Fi <-> cellular, Wi-Fi
            // roam) kills the relay WebSocket under a pump that has no
            // in-loop reconnect, so sends queue forever against a dead
            // socket. Rebuild the gateway; the monitor orders this AFTER
            // the mesh verdict, so the reconnect sees the new network's
            // mode. Backing-field guard as everywhere: a network event
            // never constructs the chat runtime.
            onDefaultNetworkChanged = {
                val controller = _chatController ?: return@start
                appScope.launch {
                    try {
                        controller.rebuildGatewayOnNetworkChange()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        android.util.Log.w("fetchit.chat", "network-change gateway rebuild failed", e)
                    }
                }
            },
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) {
                    chatController.meshPolicy.onForeground()
                }

                override fun onStop(owner: LifecycleOwner) {
                    _chatController?.meshPolicy?.onBackground()
                }
            },
        )
    }

    /**
     * Initialise the native FFI side: point `ant-core`'s data dir at the
     * app-private files dir, then start the logger. Overridable so test
     * builds can stub it — there is no `.so` off-device.
     */
    protected open fun bootstrapFfi() {
        setDataHome(filesDir.absolutePath)
        setupLogger()
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

    /**
     * Called by [IdleDisconnect] on app backgrounding after the idle grace
     * period. Always disconnects the Autonomi browse client (its reconnect is
     * a cheap per-fetch lazy bootstrap). Only tears the chat gateway down when
     * the user has opted out of [SettingsStore.chatKeepConnected].
     *
     * Chat holds a relay/QUIC connection that is slow to re-establish on
     * mobile networks, so dropping it every idle period forces a costly
     * reconnect on return and briefly fails sends mid-reconnect. The default
     * ([chatKeepConnected] == true) keeps chat warm across backgrounding so
     * messaging stays instant; the battery-saving opt-out restores the old
     * disconnect-on-idle behaviour.
     *
     * The `_chatController` nullable check is intentional: accessing
     * [chatController] here would construct the controller, defeating the
     * lazy-init contract and wasting resources on users who never open chat.
     */
    private fun disconnectAll() {
        disconnect()
        if (!SettingsStore(this).chatKeepConnected()) {
            _chatController?.disconnect()
        }
    }

    /**
     * Rehydrate the chat runtime when the app returns to the foreground.
     * Paired with [disconnectAll]: once the idle grace period tears the
     * chat client down, a return to an already-open chat screen would
     * otherwise show empty group and conversation surfaces until a full
     * relaunch, because there is no in-pump reconnect and Activity resume
     * does not reconnect. Reconnecting here refills them.
     *
     * Guards on the [_chatController] nullable backing field, never the
     * [chatController] getter: a foreground event must not construct the
     * chat runtime for users who never opened chat (mirrors [disconnectAll]).
     * A no-op when chat is already live: [ChatController.ensureGateway]
     * fast-paths a running pump and the group reload is a cheap local read.
     */
    private fun reconnectChatIfActive() {
        val controller = _chatController ?: return
        appScope.launch {
            try {
                controller.ensureGateway()
                controller.refreshGroups()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                android.util.Log.w("fetchit.chat", "foreground chat reconnect failed", e)
            }
        }
    }
}

/** Convenience accessor for activities and fragments. */
fun Context.fetchitApp(): FetchitApplication =
    applicationContext as FetchitApplication
