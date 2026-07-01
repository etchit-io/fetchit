package io.etchit.fetchit

import android.app.Application
import android.os.Looper
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.TimeUnit

/**
 * Unit tests for [IdleDisconnect]. Robolectric-run so the main-thread
 * `Looper` can be advanced without real wall-clock waits; the disconnect
 * action is a recording lambda, so the scheduled task body is observed
 * directly.
 *
 * `application = Application::class` keeps Robolectric off the manifest's
 * `FetchitApplication`, whose `onCreate` calls the `fetchit_ffi` native
 * library — absent on the host JVM.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class IdleDisconnectTest {

    private val graceMs = 60_000L

    // IdleDisconnect ignores the LifecycleOwner argument; a bare
    // registry-backed owner is a sufficient stand-in.
    private val owner: LifecycleOwner = object : LifecycleOwner {
        override val lifecycle: Lifecycle = LifecycleRegistry(this)
    }

    private fun mainLooper() = shadowOf(Looper.getMainLooper())

    @Test
    fun onStop_schedules_a_disconnect_after_the_grace_period() {
        var disconnects = 0
        val idle = IdleDisconnect({ disconnects++ }, {})
        idle.onStop(owner)
        mainLooper().idleFor(graceMs - 1, TimeUnit.MILLISECONDS)
        assertEquals("must not fire before the grace period", 0, disconnects)
        mainLooper().idleFor(1, TimeUnit.MILLISECONDS)
        assertEquals("must fire once the grace period elapses", 1, disconnects)
    }

    @Test
    fun onStart_cancels_a_pending_disconnect() {
        var disconnects = 0
        val idle = IdleDisconnect({ disconnects++ }, {})
        idle.onStop(owner)
        idle.onStart(owner) // user returned before the grace period
        mainLooper().idleFor(graceMs * 2, TimeUnit.MILLISECONDS)
        assertEquals("a cancelled disconnect must not fire", 0, disconnects)
    }

    @Test
    fun background_foreground_background_reschedules_cleanly() {
        var disconnects = 0
        val idle = IdleDisconnect({ disconnects++ }, {})
        idle.onStop(owner)
        idle.onStart(owner) // cancels the first schedule
        idle.onStop(owner)  // schedules a fresh one
        mainLooper().idleFor(graceMs, TimeUnit.MILLISECONDS)
        assertEquals(1, disconnects)
    }

    @Test
    fun repeated_onStop_fires_the_disconnect_only_once() {
        var disconnects = 0
        val idle = IdleDisconnect({ disconnects++ }, {})
        idle.onStop(owner)
        idle.onStop(owner) // removeCallbacks then re-post — still a single task
        idle.onStop(owner)
        mainLooper().idleFor(graceMs, TimeUnit.MILLISECONDS)
        assertEquals(1, disconnects)
    }

    @Test
    fun onStart_on_a_clean_observer_is_harmless() {
        var disconnects = 0
        IdleDisconnect({ disconnects++ }, {}).onStart(owner) // nothing queued
        mainLooper().idleFor(graceMs * 2, TimeUnit.MILLISECONDS)
        assertEquals(0, disconnects)
    }

    @Test
    fun onStart_invokes_onForeground_so_a_returned_app_rehydrates() {
        var foregrounds = 0
        val idle = IdleDisconnect({ }, { foregrounds++ })
        idle.onStart(owner)
        assertEquals("onStart must fire onForeground to reconnect on return", 1, foregrounds)
    }
}
