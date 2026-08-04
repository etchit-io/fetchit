package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId

class ChatDaySeparatorsTest {

    // A fixed zone keeps the boundaries deterministic wherever the suite runs.
    private val zone = ZoneId.of("America/New_York")

    private fun at(y: Int, m: Int, d: Int, h: Int, min: Int = 0): Long =
        LocalDateTime.of(y, m, d, h, min).atZone(zone).toInstant().toEpochMilli()

    private fun midnight(y: Int, m: Int, d: Int): Long =
        LocalDate.of(y, m, d).atStartOfDay(zone).toInstant().toEpochMilli()

    @Test
    fun firstMessageAlwaysGetsASeparator() {
        val breaks = dayBreaks(listOf(at(2026, 8, 4, 9)), zone)
        assertEquals(listOf(DayBreak(0, midnight(2026, 8, 4))), breaks)
    }

    @Test
    fun emptyThreadYieldsNoBreaks() {
        assertTrue(dayBreaks(emptyList(), zone).isEmpty())
    }

    @Test
    fun sameDayMessagesShareOneSeparator() {
        val breaks = dayBreaks(
            listOf(at(2026, 8, 4, 0, 1), at(2026, 8, 4, 12), at(2026, 8, 4, 23, 59)),
            zone,
        )
        assertEquals(listOf(DayBreak(0, midnight(2026, 8, 4))), breaks)
    }

    @Test
    fun crossingMidnightMintsASecondSeparator() {
        // 23:59 then 00:01 — nine minutes apart, but a different calendar day.
        val breaks = dayBreaks(
            listOf(at(2026, 8, 3, 23, 59), at(2026, 8, 4, 0, 1), at(2026, 8, 4, 8)),
            zone,
        )
        assertEquals(
            listOf(DayBreak(0, midnight(2026, 8, 3)), DayBreak(1, midnight(2026, 8, 4))),
            breaks,
        )
    }

    @Test
    fun everyDayChangeBreaksAcrossAMultiDayThread() {
        val breaks = dayBreaks(
            listOf(
                at(2026, 8, 1, 10),
                at(2026, 8, 1, 18),
                at(2026, 8, 2, 9),
                at(2026, 8, 4, 7),
            ),
            zone,
        )
        assertEquals(listOf(0, 2, 3), breaks.map { it.index })
        assertEquals(
            listOf(midnight(2026, 8, 1), midnight(2026, 8, 2), midnight(2026, 8, 4)),
            breaks.map { it.dayStartMs },
        )
    }

    @Test
    fun unknownStampNeverMintsAnEpochHeader() {
        // A 0 stamp carries no date: it stays under the day above it.
        val breaks = dayBreaks(listOf(at(2026, 8, 4, 9), 0L, at(2026, 8, 4, 11)), zone)
        assertEquals(listOf(DayBreak(0, midnight(2026, 8, 4))), breaks)
    }

    @Test
    fun leadingUnknownStampsAreSkippedNotDated() {
        val breaks = dayBreaks(listOf(0L, 0L, at(2026, 8, 4, 9)), zone)
        assertEquals(listOf(DayBreak(2, midnight(2026, 8, 4))), breaks)
    }

    @Test
    fun threadOfOnlyUnknownStampsGetsNoSeparator() {
        assertTrue(dayBreaks(listOf(0L, 0L, -1L), zone).isEmpty())
    }

    @Test
    fun dayStartIsLocalMidnightNotUtc() {
        // 00:30 local on Aug 4 is still Aug 3 in UTC — the separator must
        // name the local day, or a late-night message reads as yesterday.
        val breaks = dayBreaks(listOf(at(2026, 8, 4, 0, 30)), zone)
        assertEquals(midnight(2026, 8, 4), breaks.single().dayStartMs)
    }

    @Test
    fun labelKindNamesTodayAndYesterday() {
        val now = at(2026, 8, 4, 14)
        assertEquals(DayLabelKind.TODAY, dayLabelKind(midnight(2026, 8, 4), now, zone))
        assertEquals(DayLabelKind.YESTERDAY, dayLabelKind(midnight(2026, 8, 3), now, zone))
        assertEquals(DayLabelKind.DATE, dayLabelKind(midnight(2026, 8, 2), now, zone))
        assertEquals(DayLabelKind.DATE, dayLabelKind(midnight(2025, 8, 4), now, zone))
    }

    @Test
    fun todayHoldsRightUpToLocalMidnight() {
        // 23:59 today is still "Today"; one minute later is a new day.
        assertEquals(
            DayLabelKind.TODAY,
            dayLabelKind(midnight(2026, 8, 4), at(2026, 8, 4, 23, 59), zone),
        )
        assertEquals(
            DayLabelKind.YESTERDAY,
            dayLabelKind(midnight(2026, 8, 4), at(2026, 8, 5, 0, 1), zone),
        )
    }

    @Test
    fun yesterdayCrossesAMonthBoundary() {
        assertEquals(
            DayLabelKind.YESTERDAY,
            dayLabelKind(midnight(2026, 7, 31), at(2026, 8, 1, 10), zone),
        )
    }

    @Test
    fun dstSpringForwardStillSeparatesTwoDays() {
        // 2026-03-08 is the US spring-forward day (a 23-hour day): a naive
        // 24h-arithmetic split would fold the two days into one.
        val breaks = dayBreaks(listOf(at(2026, 3, 8, 12), at(2026, 3, 9, 11)), zone)
        assertEquals(listOf(0, 1), breaks.map { it.index })
        assertEquals(
            DayLabelKind.YESTERDAY,
            dayLabelKind(midnight(2026, 3, 8), at(2026, 3, 9, 11), zone),
        )
    }
}
