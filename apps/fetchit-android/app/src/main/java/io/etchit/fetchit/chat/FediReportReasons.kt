package io.etchit.fetchit.chat

import io.etchit.fetchit.R

/**
 * The abuse-report reasons offered in the UI, paired with the wire value
 * the engine expects.
 *
 * Split out of the view so the wire vocabulary is unit-testable: the
 * strings on the right must match `fetchit_chat::report::parse_report_kind`
 * exactly, and a typo there would be a report the service rejects at
 * send time with nothing catching it earlier.
 *
 * `other` is deliberately absent. It exists on the wire (a moderator
 * tool may need it) but offering "other" as a tap target produces
 * unactionable reports; a person who does not see their case here can
 * say so in the free-text comment under one of the named reasons.
 */
object FediReportReasons {

    /** One offered reason: the label resource, and the wire kind. */
    data class Reason(val labelRes: Int, val wire: String)

    /**
     * In display order — severity first, so the most urgent report is
     * the shortest reach.
     */
    val OPTIONS: List<Reason> = listOf(
        Reason(R.string.fedi_report_reason_csam, "csam"),
        Reason(R.string.fedi_report_reason_violence, "violence_threat"),
        Reason(R.string.fedi_report_reason_harassment, "harassment"),
        Reason(R.string.fedi_report_reason_doxxing, "doxxing"),
        Reason(R.string.fedi_report_reason_abusive, "abusive_content"),
        Reason(R.string.fedi_report_reason_spam, "spam"),
    )

    /** The wire kind at [index], or null when nothing is selected. */
    fun wireAt(index: Int): String? = OPTIONS.getOrNull(index)?.wire
}
