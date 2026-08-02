package io.etchit.fetchit.chat

/**
 * Metered-data tripwire: the user's protection of last resort against the
 * app burning a capped mobile plan.
 *
 * Policy already keeps the mesh off on metered networks, and r11/r12 made
 * that state self-healing — but the July 2026 bill (129GB) and the Aug 2026
 * zombie-engine leak (3-9GB/day on cellular) both happened because a bug
 * class DEFEATED the policy. The tripwire therefore measures at the OS
 * level (the caller feeds it Android's own per-app cumulative byte counter,
 * which no in-app bug can dodge) and trips when a day's metered usage
 * crosses [tripBytes]: the caller forces the mesh quiet and tells the user.
 * If bytes KEEP flowing past [escalateBytes], something the policy cannot
 * reach is talking (a rogue engine) and the caller escalates — recycling
 * the process when backgrounded is the one guaranteed kill.
 *
 * Pure logic, no Android dependencies: the caller supplies the day index,
 * the cumulative counter, and the metered verdict, and persists [state]
 * across restarts. Counter resets (device reboot makes the cumulative
 * counter start over) are treated as a fresh baseline, never a negative
 * delta.
 */
class DataTripwire(
    private val tripBytes: Long = DEFAULT_TRIP_BYTES,
    private val escalateBytes: Long = DEFAULT_ESCALATE_BYTES,
    restored: State? = null,
) {
    /** Persisted snapshot: which day the bucket covers and what it holds. */
    data class State(
        /** Local-midnight day index the bucket belongs to. */
        val epochDay: Long,
        /** Bytes moved on metered networks during [epochDay]. */
        val meteredBytes: Long,
        /** Trip already fired for [epochDay]. */
        val tripped: Boolean,
        /** Escalation already fired for [epochDay]. */
        val escalated: Boolean,
    )

    /** What the caller must do after a sample. */
    sealed interface Verdict {
        /** Nothing to do. */
        data object None : Verdict

        /** A new day started: clear any mesh block from a previous trip. */
        data object DayReset : Verdict

        /** Daily metered budget crossed: quiet the mesh, notify the user. */
        data class Tripped(val meteredBytesToday: Long) : Verdict

        /**
         * Bytes kept flowing well past the trip: the policy's off-switch is
         * not reaching whatever is talking. Recycle the process when it is
         * safe (backgrounded); otherwise warn the user to restart.
         */
        data class Escalated(val meteredBytesToday: Long) : Verdict
    }

    private var state: State = restored ?: State(NO_DAY, 0, tripped = false, escalated = false)
    private var lastCumulative: Long = NO_BASELINE

    /** Current snapshot for persistence. */
    val stateSnapshot: State
        get() = state

    /** `true` while today's trip is latched (mesh must stay quiet). */
    val tripped: Boolean
        get() = state.tripped

    /**
     * Book one sample of the app's cumulative byte counter.
     *
     * [epochDay] is the caller's local day index; [cumulativeBytes] is
     * monotonic per boot (a smaller value than last time means the device
     * rebooted — re-baseline, count nothing); [metered] is whether the
     * ACTIVE network is metered right now. The delta since the previous
     * sample is attributed entirely to the current network class; at a
     * 60s cadence the attribution error across a network switch is one
     * sample, which is noise against a 50MB budget.
     */
    fun sample(epochDay: Long, cumulativeBytes: Long, metered: Boolean): Verdict {
        val dayChanged = state.epochDay != NO_DAY && state.epochDay != epochDay
        if (state.epochDay != epochDay) {
            val wasTripped = state.tripped
            state = State(epochDay, 0, tripped = false, escalated = false)
            if (dayChanged && wasTripped) {
                // Re-baseline below still runs; the caller unblocks the mesh.
                bookDelta(cumulativeBytes, metered)
                return Verdict.DayReset
            }
        }
        bookDelta(cumulativeBytes, metered)
        if (!state.escalated && state.meteredBytes >= escalateBytes) {
            state = state.copy(tripped = true, escalated = true)
            return Verdict.Escalated(state.meteredBytes)
        }
        if (!state.tripped && state.meteredBytes >= tripBytes) {
            state = state.copy(tripped = true)
            return Verdict.Tripped(state.meteredBytes)
        }
        return Verdict.None
    }

    private fun bookDelta(cumulativeBytes: Long, metered: Boolean) {
        val last = lastCumulative
        lastCumulative = cumulativeBytes
        if (last == NO_BASELINE || cumulativeBytes < last) return
        if (!metered) return
        state = state.copy(meteredBytes = state.meteredBytes + (cumulativeBytes - last))
    }

    companion object {
        /** Generous for a relay-routed messenger (a heavy day is single-digit MB). */
        const val DEFAULT_TRIP_BYTES: Long = 50L * 1024 * 1024

        /** Well past the trip: whatever is talking ignored the quiesce. */
        const val DEFAULT_ESCALATE_BYTES: Long = 150L * 1024 * 1024

        private const val NO_DAY: Long = Long.MIN_VALUE
        private const val NO_BASELINE: Long = Long.MIN_VALUE
    }
}
