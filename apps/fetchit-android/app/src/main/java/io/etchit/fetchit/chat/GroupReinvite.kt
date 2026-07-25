package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.GroupMemberFfi

/** What inviting a contact to a group should do, given the current roster. */
enum class ReinviteDecision {
    /** Not in the roster: mint a fresh invite and DM it (the normal path). */
    INVITE,

    /**
     * Already listed as a member: confirm a membership RESET (remove, then a
     * fresh invite). x0xd refuses to stage a Welcome for an agent it still
     * lists as active, so a plain re-invite to someone who reinstalled or
     * moved phones — keys gone, roster entry left behind — fails silently as
     * "did not converge". Removing first drives the TreeKEM re-key that
     * reseals the group without them, which makes the fresh invite a normal
     * first join.
     */
    CONFIRM_RESET,

    /**
     * The target is the group OWNER: x0xd refuses an owner-target removal,
     * so a reset is impossible — and the owner is by definition already in.
     */
    ALREADY_OWNER,
}

/**
 * Classify inviting [targetAgentIdHex] against the [members] roster. Pure so
 * the three-way branch is JVM-testable; the caller owns the side effects
 * (dialog, removal, invite mint).
 */
fun reinviteDecision(members: List<GroupMemberFfi>, targetAgentIdHex: String): ReinviteDecision {
    val existing = members.find { it.agentIdHex == targetAgentIdHex } ?: return ReinviteDecision.INVITE
    return if (existing.isOwner) ReinviteDecision.ALREADY_OWNER else ReinviteDecision.CONFIRM_RESET
}
