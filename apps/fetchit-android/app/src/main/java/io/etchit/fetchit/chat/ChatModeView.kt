package io.etchit.fetchit.chat

import android.widget.FrameLayout

/**
 * Orchestrates the chat screens (list / thread / add) and owns the chat
 * back-stack within the chat container.
 *
 * Task 4 fills this class with screen inflation, contact-list wiring,
 * QR pair onboarding, and the thread view. For now it is a minimal stub
 * so the two-mode shell in MainActivity compiles and the mode mechanics
 * are exercised end-to-end.
 *
 * @param container the chatContainer FrameLayout from activity_main.xml
 */
class ChatModeView(private val container: FrameLayout) {

    /** Called each time the user switches into chat mode. Task 4 uses
     *  this to trigger ensureGateway() and populate the screen. */
    fun onShown() {
        // Task 4 fills this.
    }

    /** Called by the activity's back callback while in chat mode.
     *  @return true if the back press was consumed (e.g. popped a chat
     *          sub-screen), false if the caller should return to browse. */
    fun onBack(): Boolean = false
}
