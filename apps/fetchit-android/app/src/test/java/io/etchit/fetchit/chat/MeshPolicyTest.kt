package io.etchit.fetchit.chat

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The mesh policy is the phone's data-bill guard: full public-mesh duty
 * costs gigabytes per day (129GB in July 2026), so the embedded daemon may
 * only mesh while the app is in the foreground AND the network is unmetered
 * Wi-Fi/Ethernet. Backgrounding drops the mesh after a debounce (quick app
 * switches shouldn't churn the daemon); losing the Wi-Fi drops it
 * immediately (a metered network starts billing the instant it becomes the
 * default); regaining Wi-Fi rejoins after a short debounce so a flapping
 * connection doesn't churn the daemon. Messages keep arriving either way --
 * inbound rides the relay, which is what notifications use.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MeshPolicyTest {

    @Test
    fun `starts inactive and foreground alone does not activate the mesh`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }

        assertEquals(false, policy.active)
        policy.onForeground()
        advanceTimeBy(600_000)
        runCurrent()

        // No network verdict yet: fail safe, never mesh on an unknown network.
        assertEquals(emptyList<Boolean>(), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `foreground on unmetered wifi activates the mesh exactly once`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }

        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        policy.onForeground()
        runCurrent()

        assertEquals(listOf(true), applied)
        assertEquals(true, policy.active)
    }

    @Test
    fun `foreground on mobile data stays off the mesh`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }

        policy.onNetworkChanged(allowsMesh = false)
        policy.onForeground()
        advanceTimeBy(600_000)
        runCurrent()

        assertEquals(emptyList<Boolean>(), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `losing wifi mid-session drops the mesh immediately`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()

        policy.onNetworkChanged(allowsMesh = false)
        runCurrent()

        // No debounce: every second on a metered default network bills.
        assertEquals(listOf(true, false), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `regaining wifi while foreground rejoins after the rise debounce`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()
        policy.onNetworkChanged(allowsMesh = false)
        runCurrent()

        policy.onNetworkChanged(allowsMesh = true)
        advanceTimeBy(MeshPolicy.RISE_DEBOUNCE_MS - 1)
        runCurrent()
        assertEquals(listOf(true, false), applied)

        advanceTimeBy(2)
        runCurrent()
        assertEquals(listOf(true, false, true), applied)
        assertEquals(true, policy.active)
    }

    @Test
    fun `wifi flap within the rise debounce never touches the daemon`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = false)
        policy.onForeground()
        runCurrent()

        policy.onNetworkChanged(allowsMesh = true)
        advanceTimeBy(MeshPolicy.RISE_DEBOUNCE_MS - 1)
        policy.onNetworkChanged(allowsMesh = false)
        advanceTimeBy(600_000)
        runCurrent()

        assertEquals(emptyList<Boolean>(), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `background drops the mesh only after the debounce`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()

        policy.onBackground()
        advanceTimeBy(MeshPolicy.DROP_DEBOUNCE_MS - 1)
        runCurrent()
        assertEquals(listOf(true), applied)
        assertEquals(true, policy.active)

        advanceTimeBy(2)
        runCurrent()
        assertEquals(listOf(true, false), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `returning to foreground within the debounce cancels the drop`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()

        policy.onBackground()
        advanceTimeBy(MeshPolicy.DROP_DEBOUNCE_MS - 1)
        policy.onForeground()
        advanceTimeBy(600_000)
        runCurrent()

        // No drop fired, and the mesh was never redundantly re-activated.
        assertEquals(listOf(true), applied)
        assertEquals(true, policy.active)
    }

    @Test
    fun `losing wifi during a pending background drop commits it immediately`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()

        policy.onBackground()
        advanceTimeBy(10_000)
        policy.onNetworkChanged(allowsMesh = false)
        runCurrent()

        // The 120s grace is for app switches, not for burning mobile data.
        assertEquals(listOf(true, false), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `background while already inactive is a no-op`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }

        policy.onBackground()
        advanceTimeBy(600_000)
        runCurrent()

        assertEquals(emptyList<Boolean>(), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `network verdict changing during the rise debounce is re-checked at commit`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope) { applied += it; true }
        policy.onNetworkChanged(allowsMesh = false)
        policy.onForeground()
        runCurrent()

        policy.onNetworkChanged(allowsMesh = true)
        advanceTimeBy(MeshPolicy.RISE_DEBOUNCE_MS - 1)
        policy.onBackground()
        advanceTimeBy(600_000)
        runCurrent()

        // Backgrounded before the rise landed: the commit re-derives desired
        // state and declines to activate.
        assertEquals(emptyList<Boolean>(), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `failed apply retries on the backoff until it sticks`() = runTest {
        val applied = mutableListOf<Boolean>()
        var failures = 2
        val policy = MeshPolicy(backgroundScope) {
            applied += it
            failures-- <= 0
        }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()
        assertEquals(listOf(true), applied)

        advanceTimeBy(MeshPolicy.RETRY_BACKOFF_MS + 1)
        runCurrent()
        assertEquals(listOf(true, true), applied)

        advanceTimeBy(MeshPolicy.RETRY_BACKOFF_MS + 1)
        runCurrent()
        assertEquals(listOf(true, true, true), applied)

        // Third call succeeded: no further retries.
        advanceTimeBy(600_000)
        runCurrent()
        assertEquals(listOf(true, true, true), applied)
    }

    /**
     * The multi-GB burn case: leaving Wi-Fi wants the mesh OFF, the flip
     * fails (wedged engine), and no further lifecycle or connectivity event
     * arrives for hours. The policy must keep retrying on its own -- a
     * leaked full-mesh daemon on mobile data bills by the minute.
     */
    @Test
    fun `failed drop keeps retrying with no further input events`() = runTest {
        val applied = mutableListOf<Boolean>()
        var dropFailures = 1
        val policy = MeshPolicy(backgroundScope) {
            applied += it
            if (!it) dropFailures-- <= 0 else true
        }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()

        policy.onNetworkChanged(allowsMesh = false)
        runCurrent()
        // Drop applied and failed; nothing else will touch the policy.
        assertEquals(listOf(true, false), applied)

        advanceTimeBy(MeshPolicy.RETRY_BACKOFF_MS + 1)
        runCurrent()
        assertEquals(listOf(true, false, false), applied)
        assertEquals(false, policy.active)
    }

    @Test
    fun `input churn while a retry is owed still converges`() = runTest {
        val applied = mutableListOf<Boolean>()
        var dropFailures = 1
        val policy = MeshPolicy(backgroundScope) {
            applied += it
            if (!it) dropFailures-- <= 0 else true
        }
        policy.onNetworkChanged(allowsMesh = true)
        policy.onForeground()
        runCurrent()
        policy.onBackground()
        advanceTimeBy(MeshPolicy.DROP_DEBOUNCE_MS + 1)
        runCurrent()
        assertEquals(listOf(true, false), applied)

        // A second background event cancels the owed retry; the dirty
        // applied-state must schedule a replacement commit instead of
        // dropping convergence on the floor.
        policy.onBackground()
        advanceTimeBy(MeshPolicy.DROP_DEBOUNCE_MS + MeshPolicy.RETRY_BACKOFF_MS + 1)
        runCurrent()
        assertEquals(listOf(true, false, false), applied)
    }
}
