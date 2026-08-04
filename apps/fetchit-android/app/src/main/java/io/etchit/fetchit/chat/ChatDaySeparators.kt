package io.etchit.fetchit.chat

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

/**
 * A calendar-day boundary in a thread: a day-separator row belongs
 * immediately *before* [index] in the source message list. [dayStartMs] is
 * local midnight of that day, so the label formats the day itself rather
 * than the first message's clock time.
 */
data class DayBreak(val index: Int, val dayStartMs: Long)

/** How a day-separator row names its day. */
enum class DayLabelKind { TODAY, YESTERDAY, DATE }

/**
 * Find every calendar-day boundary in [stampsMs] (epoch ms, thread order),
 * in the local [zone]. The first dated message always yields a break, so a
 * freshly opened thread shows its date context above the first bubble.
 *
 * A stamp of 0 (or negative) carries no date — an unknown stamp stays under
 * whichever day precedes it instead of minting a 1970 header. A thread with
 * no dated messages yields no breaks at all.
 */
fun dayBreaks(stampsMs: List<Long>, zone: ZoneId = ZoneId.systemDefault()): List<DayBreak> {
    val breaks = ArrayList<DayBreak>()
    var lastDay: LocalDate? = null
    stampsMs.forEachIndexed { index, ms ->
        if (ms <= 0L) return@forEachIndexed
        val day = localDate(ms, zone)
        if (day != lastDay) {
            breaks.add(DayBreak(index, day.atStartOfDay(zone).toInstant().toEpochMilli()))
            lastDay = day
        }
    }
    return breaks
}

/**
 * Classify [dayStartMs] relative to [nowMs] in the local [zone]. Only the
 * near days get a word; everything older is left to the platform date
 * formatter so it stays localized.
 */
fun dayLabelKind(
    dayStartMs: Long,
    nowMs: Long,
    zone: ZoneId = ZoneId.systemDefault(),
): DayLabelKind {
    val day = localDate(dayStartMs, zone)
    val today = localDate(nowMs, zone)
    return when (day) {
        today -> DayLabelKind.TODAY
        today.minusDays(1) -> DayLabelKind.YESTERDAY
        else -> DayLabelKind.DATE
    }
}

private fun localDate(ms: Long, zone: ZoneId): LocalDate =
    Instant.ofEpochMilli(ms).atZone(zone).toLocalDate()
