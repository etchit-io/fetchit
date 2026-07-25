package io.etchit.fetchit.chat

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GroupErrorsTest {

    @Test
    fun theDaemonsLastAdminSelfLeaveRefusalIsRecognised() {
        // Verbatim ADR-0016 §3 body, as captured off the device.
        val e = RuntimeException(
            "reason=daemon returned 409: {\"error\":\"a group must always have at " +
                "least one admin; make another member an admin before leaving\",\"ok\":false}",
        )
        assertTrue(isLastAdminRejection(e))
    }

    @Test
    fun theRefusalIsFoundThroughAWrappedCauseChain() {
        val cause = RuntimeException("a group must always have at least one admin; ...")
        assertTrue(isLastAdminRejection(IllegalStateException("leave failed", cause)))
    }

    @Test
    fun aTransportFailureIsNotALastAdminRefusal() {
        // Must stay retryable-looking: a different message, and a null message.
        assertFalse(isLastAdminRejection(RuntimeException("connection reset by peer")))
        assertFalse(isLastAdminRejection(RuntimeException()))
    }
}
