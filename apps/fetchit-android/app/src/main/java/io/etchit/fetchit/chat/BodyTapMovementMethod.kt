package io.etchit.fetchit.chat

import android.text.Spannable
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.view.MotionEvent
import android.widget.TextView

/**
 * [LinkMovementMethod] that also reports a tap on the plain body.
 *
 * A feed post's body is two affordances at once: the spans inside it
 * (an @-mention, an `autonomi://` address) open their own thing, and the
 * words around them open the conversation. An `OnClickListener` cannot
 * express that — `TextView.onTouchEvent` calls `View.onTouchEvent`
 * (which fires the click) BEFORE it runs the movement method, so a tap
 * on a mention would fire the span AND the listener. This is the one
 * place where the span under the finger is already known, so it is the
 * only place the two taps can honestly be told apart.
 *
 * Stateless apart from [onBodyTap], but instances are per-row rather
 * than shared: the callback closes over the post the row is bound to.
 */
class BodyTapMovementMethod(private val onBodyTap: () -> Unit) : LinkMovementMethod() {

    override fun onTouchEvent(
        widget: TextView,
        buffer: Spannable,
        event: MotionEvent,
    ): Boolean {
        // ACTION_UP is the tap. A scroll never reaches here as an UP —
        // the RecyclerView takes the gesture over and the child sees
        // ACTION_CANCEL — so this does not fire on a fling.
        if (event.actionMasked == MotionEvent.ACTION_UP &&
            clickableSpanUnder(widget, buffer, event) == null
        ) {
            onBodyTap()
            return true
        }
        return super.onTouchEvent(widget, buffer, event)
    }

    private companion object {

        /**
         * The [ClickableSpan] under the touch, or null when the finger
         * landed on plain text.
         *
         * Same hit test [LinkMovementMethod] itself uses, including the
         * horizontal bounds check: without it a tap in the empty space
         * past the end of a line resolves to the last character on that
         * line, so tapping beside a trailing mention would "hit" it.
         */
        fun clickableSpanUnder(
            widget: TextView,
            buffer: Spannable,
            event: MotionEvent,
        ): ClickableSpan? {
            val layout = widget.layout ?: return null
            val x = event.x.toInt() - widget.totalPaddingLeft + widget.scrollX
            val y = event.y.toInt() - widget.totalPaddingTop + widget.scrollY
            val line = layout.getLineForVertical(y)
            if (x < layout.getLineLeft(line) || x > layout.getLineRight(line)) return null
            val offset = layout.getOffsetForHorizontal(line, x.toFloat())
            return buffer.getSpans(offset, offset, ClickableSpan::class.java).firstOrNull()
        }
    }
}
