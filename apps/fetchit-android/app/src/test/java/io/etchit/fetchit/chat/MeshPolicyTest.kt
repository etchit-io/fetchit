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
 * only mesh while the app is actually in the foreground. Backgrounding
 * drops the mesh after a debounce (quick app switches shouldn't churn the
 * daemon); returning cancels the pending drop. Messages keep arriving
 * either way -- inbound rides the relay, which is what notifications use.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MeshPolicyTest {

    @Test
    fun `starts inactive and foreground activates the mesh exactly once`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope, debounceMs = 120_000) { applied += it }

        assertEquals(false, policy.active)
        policy.onForeground()
        policy.onForeground()
        runCurrent()

        assertEquals(listOf(true), applied)
        assertEquals(true, policy.active)
    }

    @Test
    fun `background drops the mesh only after the debounce`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope, debounceMs = 120_000) { applied += it }
        policy.onForeground()
        runCurrent()

        policy.onBackground()
        advanceTimeBy(119_999)
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
        val policy = MeshPolicy(backgroundScope, debounceMs = 120_000) { applied += it }
        policy.onForeground()
        runCurrent()

        policy.onBackground()
        advanceTimeBy(119_999)
        policy.onForeground()
        advanceTimeBy(600_000)
        runCurrent()

        // No drop fired, and the mesh was never redundantly re-activated.
        assertEquals(listOf(true), applied)
        assertEquals(true, policy.active)
    }

    @Test
    fun `background while already inactive is a no-op`() = runTest {
        val applied = mutableListOf<Boolean>()
        val policy = MeshPolicy(backgroundScope, debounceMs = 120_000) { applied += it }

        policy.onBackground()
        advanceTimeBy(600_000)
        runCurrent()

        assertEquals(emptyList<Boolean>(), applied)
        assertEquals(false, policy.active)
    }
}
