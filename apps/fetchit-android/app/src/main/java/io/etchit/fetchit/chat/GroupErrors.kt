package io.etchit.fetchit.chat

/**
 * Fragment of the ADR-0016 §3 last-admin REST errors. The daemon fixes both
 * strings verbatim ("...make another member an admin first" / "...before
 * leaving"), and this substring is common to both.
 */
private const val LAST_ADMIN_MARKER = "at least one admin"

/**
 * True when [error] is the daemon's ADR-0016 last-admin refusal.
 *
 * A live group must always keep one active admin, so the last admin's leave is
 * rejected with `409` — and a sole member is always the sole admin, meaning a
 * solo group can never be left, only deleted. The UI needs to tell those two
 * apart from a transport failure: one is a permanent rule with a specific way
 * out ("delete the group"), the other is worth retrying.
 *
 * Matches over the whole cause chain because the daemon's reason reaches us
 * wrapped in a uniffi `ChatFfiException`.
 */
fun isLastAdminRejection(error: Throwable): Boolean =
    generateSequence(error) { it.cause }
        .mapNotNull { it.message }
        .any { it.contains(LAST_ADMIN_MARKER, ignoreCase = true) }
