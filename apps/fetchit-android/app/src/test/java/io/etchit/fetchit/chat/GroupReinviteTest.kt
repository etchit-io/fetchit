package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.fetchit_ffi.GroupMemberFfi

class GroupReinviteTest {

    private fun member(hex: String, role: String?) = GroupMemberFfi(
        agentIdHex = hex,
        displayName = null,
        role = role,
        isOwner = role == "owner",
        isAdmin = role == "owner" || role == "admin",
    )

    private val owner = member("aa".repeat(32), "owner")
    private val plain = member("bb".repeat(32), "member")

    @Test
    fun `absent from roster is a plain invite`() {
        assertEquals(
            ReinviteDecision.INVITE,
            reinviteDecision(listOf(owner, plain), "cc".repeat(32)),
        )
    }

    @Test
    fun `existing member needs the reset confirm`() {
        assertEquals(
            ReinviteDecision.CONFIRM_RESET,
            reinviteDecision(listOf(owner, plain), plain.agentIdHex),
        )
    }

    @Test
    fun `existing admin also needs the reset confirm`() {
        val admin = member("dd".repeat(32), "admin")
        assertEquals(
            ReinviteDecision.CONFIRM_RESET,
            reinviteDecision(listOf(owner, admin), admin.agentIdHex),
        )
    }

    @Test
    fun `the owner can never be reset`() {
        assertEquals(
            ReinviteDecision.ALREADY_OWNER,
            reinviteDecision(listOf(owner, plain), owner.agentIdHex),
        )
    }

    @Test
    fun `empty roster falls back to a plain invite`() {
        // groupMembers() degrades to emptyList() on any daemon failure; the
        // invite must still go out rather than being blocked on the roster.
        assertEquals(
            ReinviteDecision.INVITE,
            reinviteDecision(emptyList(), plain.agentIdHex),
        )
    }
}
