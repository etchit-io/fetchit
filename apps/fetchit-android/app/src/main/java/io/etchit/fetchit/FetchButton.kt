package io.etchit.fetchit

import android.annotation.SuppressLint
import android.content.Context
import android.util.AttributeSet
import android.view.MotionEvent
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.widget.FrameLayout

/**
 * The animated centerpiece "fetch>it" button. Wraps a `WebView` that
 * loads `assets/fetch-button.html` and exposes a small bridge:
 *
 *   * tap on the button (HTML side) → [`setOnTapListener`] callback
 *   * native [`setFetching`] → CSS class toggle on the button (ring
 *     sweeps, text fades, beagle runs)
 *
 * Why a `WebView`: the design ships as HTML/SVG/CSS animations, which
 * stay synchronised in one place. Re-implementing the leg-paired,
 * tail-wagging, dust-trailing beagle as Android `AnimatedVectorDrawable`
 * would multiply the maintenance surface for no gain. JavaScript is
 * enabled here (the button's state changes are driven from JS via a
 * small `Native` bridge), but the WebView is otherwise scoped tight:
 * one instance, transparent body, no DOM storage, no file or
 * content-provider access, `LOAD_NO_CACHE`, and it loads only the
 * one bundled asset — never remote content.
 */
@SuppressLint("SetJavaScriptEnabled")
class FetchButton @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : FrameLayout(context, attrs, defStyleAttr) {

    private val webView: WebView
    private var onTap: (() -> Unit)? = null

    init {
        webView = WebView(context).apply {
            // Transparent so the activity's ink background shows through.
            setBackgroundColor(0)
            isVerticalScrollBarEnabled = false
            isHorizontalScrollBarEnabled = false
            isScrollContainer = false
            overScrollMode = OVER_SCROLL_NEVER
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = false
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
            addJavascriptInterface(NativeBridge(), "Native")
            // Block long-press selection / context menus.
            setOnLongClickListener { true }
            isLongClickable = false
            loadUrl("file:///android_asset/fetch-button.html")
        }
        addView(
            webView,
            LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT),
        )
    }

    /** Set the click handler. Replaces any previous handler. */
    fun setOnTapListener(callback: (() -> Unit)?) {
        onTap = callback
    }

    /**
     * Toggle the in-flight animation. `true` while the network fetch
     * is running, `false` when it completes (success or error).
     */
    fun setFetching(fetching: Boolean) {
        post { webView.evaluateJavascript("window.setFetching($fetching)", null) }
    }

    /**
     * The WebView swallows touch events that don't hit the button —
     * intercept them so the host layout's other gestures (sheet drag,
     * etc.) still work outside the button's circular area.
     */
    override fun onInterceptTouchEvent(ev: MotionEvent?): Boolean = false

    private inner class NativeBridge {
        @JavascriptInterface
        fun onFetchTap() {
            // JS thread → main thread.
            post { onTap?.invoke() }
        }
    }
}
