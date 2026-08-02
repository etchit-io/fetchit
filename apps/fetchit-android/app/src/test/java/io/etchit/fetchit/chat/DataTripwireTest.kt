package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The tripwire is the capped-plan user's last line of defense: it books the
 * OS's per-app cumulative byte counter against a daily metered budget, so a
 * bug class that defeats the mesh policy (July 2026: 129GB month; Aug 2026:
 * a zombie engine at 3-9GB/day on cellular) becomes a notification and a
 * latched-off mesh instead of a phone bill.
 */
class DataTripwireTest {

    private val mb = 1024L * 1024

    @Test
    fun `first sample is a baseline and books nothing`() {
        val tw = DataTripwire(tripBytes = 10 * mb)
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 500 * mb, metered = true))
        assertEquals(0, tw.stateSnapshot.meteredBytes)
    }

    @Test
    fun `metered deltas accumulate and trip at the budget`() {
        val tw = DataTripwire(tripBytes = 10 * mb)
        tw.sample(1, 0, metered = true)
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 4 * mb, metered = true))
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 9 * mb, metered = true))
        val verdict = tw.sample(1, 11 * mb, metered = true)
        assertTrue("crossing the budget must trip, got $verdict", verdict is DataTripwire.Verdict.Tripped)
        assertTrue(tw.tripped)
        // A trip fires once, not every sample after.
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 12 * mb, metered = true))
    }

    @Test
    fun `unmetered bytes never count toward the budget`() {
        val tw = DataTripwire(tripBytes = 10 * mb)
        tw.sample(1, 0, metered = false)
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 500 * mb, metered = false))
        assertEquals(0, tw.stateSnapshot.meteredBytes)
        // The Wi-Fi bytes moved the baseline: a later metered delta books
        // only its own bytes.
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 503 * mb, metered = true))
        assertEquals(3 * mb, tw.stateSnapshot.meteredBytes)
    }

    @Test
    fun `day rollover clears a trip and reports the reset`() {
        val tw = DataTripwire(tripBytes = 10 * mb)
        tw.sample(1, 0, metered = true)
        assertTrue(tw.sample(1, 11 * mb, metered = true) is DataTripwire.Verdict.Tripped)

        val verdict = tw.sample(2, 12 * mb, metered = true)
        assertEquals(
            "a tripped day rolling over must tell the caller to unblock the mesh",
            DataTripwire.Verdict.DayReset,
            verdict,
        )
        assertTrue(!tw.tripped)
        assertEquals(2, tw.stateSnapshot.epochDay)
    }

    @Test
    fun `day rollover without a trip is silent`() {
        val tw = DataTripwire(tripBytes = 10 * mb)
        tw.sample(1, 0, metered = true)
        tw.sample(1, 2 * mb, metered = true)
        assertEquals(DataTripwire.Verdict.None, tw.sample(2, 3 * mb, metered = true))
        // The delta spanning midnight books to the NEW day (one-sample
        // attribution error is the documented design); yesterday's bytes
        // are gone.
        assertEquals(1 * mb, tw.stateSnapshot.meteredBytes)
    }

    @Test
    fun `escalation fires once when bytes keep flowing past the trip`() {
        val tw = DataTripwire(tripBytes = 10 * mb, escalateBytes = 30 * mb)
        tw.sample(1, 0, metered = true)
        assertTrue(tw.sample(1, 11 * mb, metered = true) is DataTripwire.Verdict.Tripped)
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 20 * mb, metered = true))
        val verdict = tw.sample(1, 31 * mb, metered = true)
        assertTrue(
            "bytes flowing well past the trip mean the quiesce is not working; got $verdict",
            verdict is DataTripwire.Verdict.Escalated,
        )
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 40 * mb, metered = true))
    }

    @Test
    fun `a counter reset re-baselines instead of booking a negative delta`() {
        val tw = DataTripwire(tripBytes = 10 * mb)
        tw.sample(1, 500 * mb, metered = true)
        tw.sample(1, 505 * mb, metered = true)
        // Device rebooted: cumulative counter starts over near zero.
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 1 * mb, metered = true))
        assertEquals(5 * mb, tw.stateSnapshot.meteredBytes)
        // Counting resumes from the new baseline.
        tw.sample(1, 3 * mb, metered = true)
        assertEquals(7 * mb, tw.stateSnapshot.meteredBytes)
    }

    @Test
    fun `restored tripped state stays latched across a restart`() {
        val persisted =
            DataTripwire.State(epochDay = 1, meteredBytes = 60 * mb, tripped = true, escalated = false)
        val tw = DataTripwire(tripBytes = 50 * mb, restored = persisted)
        assertTrue(
            "an app restart must not forget that today's budget is spent",
            tw.tripped,
        )
        // Same day: no re-trip spam, bucket keeps growing.
        assertEquals(DataTripwire.Verdict.None, tw.sample(1, 100 * mb, metered = true))
    }
}
