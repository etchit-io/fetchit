package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The report vocabulary is a cross-language contract: these strings are
 *  parsed by `fetchit_chat::report::parse_report_kind`, which rejects
 *  anything it does not know. A typo would only surface as a failed
 *  report at send time, after the person believed they had reported
 *  abuse — so it is pinned here instead. */
class FediReportReasonsTest {

    /** Exactly the kinds `parse_report_kind` accepts, minus `other`. */
    private val engineVocabulary = setOf(
        "csam",
        "violence_threat",
        "harassment",
        "spam",
        "doxxing",
        "abusive_content",
    )

    @Test
    fun every_offered_reason_is_a_kind_the_engine_parses() {
        FediReportReasons.OPTIONS.forEach {
            assertTrue("unknown wire kind ${it.wire}", engineVocabulary.contains(it.wire))
        }
    }

    @Test
    fun every_engine_kind_except_other_is_offered() {
        assertEquals(engineVocabulary, FediReportReasons.OPTIONS.map { it.wire }.toSet())
    }

    @Test
    fun wire_kinds_are_unique_so_a_radio_choice_is_unambiguous() {
        val wires = FediReportReasons.OPTIONS.map { it.wire }
        assertEquals(wires.size, wires.toSet().size)
    }

    @Test
    fun labels_are_distinct_so_two_rows_never_read_the_same() {
        val labels = FediReportReasons.OPTIONS.map { it.labelRes }
        assertEquals(labels.size, labels.toSet().size)
    }

    @Test
    fun the_most_severe_reason_is_the_shortest_reach() {
        assertEquals("csam", FediReportReasons.OPTIONS.first().wire)
    }

    @Test
    fun wire_at_maps_a_radio_id_to_its_kind_and_rejects_no_selection() {
        assertEquals("csam", FediReportReasons.wireAt(0))
        assertEquals(
            FediReportReasons.OPTIONS.last().wire,
            FediReportReasons.wireAt(FediReportReasons.OPTIONS.lastIndex),
        )
        // RadioGroup reports NO_ID (-1) when nothing is checked; the
        // dialog relies on that becoming null rather than a defaulted
        // report being sent on the reporter's behalf.
        assertNull(FediReportReasons.wireAt(-1))
        assertNull(FediReportReasons.wireAt(FediReportReasons.OPTIONS.size))
    }
}
