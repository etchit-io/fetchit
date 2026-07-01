package io.etchit.fetchit

import android.content.Context
import android.view.Gravity
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog

/**
 * Display a `fetchit://import?…` URL as a scannable QR. Sibling of
 * [`showQrPreviewDialog`] for bookmark-list payloads — there's no
 * single 64-hex address to copy here, so the dialog skips the copy /
 * save actions and just shows the QR + a summary line ("N
 * bookmarks") + a close button.
 */
fun showBookmarkImportQrDialog(context: Context, url: String, summary: String) {
    val bitmap = QrBitmap.renderQrWithLogo(url, sizePx = 1024) ?: return

    val image = ImageView(context).apply {
        setImageBitmap(bitmap)
        adjustViewBounds = true
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        )
    }
    val summaryView = TextView(context).apply {
        text = summary
        gravity = Gravity.CENTER
        textSize = 16f
        val pad = dp(context, 8)
        setPadding(0, pad, 0, pad)
    }
    val container = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        val pad = dp(context, 16)
        setPadding(pad, pad, pad, pad)
        addView(image)
        addView(summaryView)
    }
    AlertDialog.Builder(context)
        .setView(container)
        .setPositiveButton(android.R.string.ok, null)
        .show()
}

private fun dp(context: Context, n: Int): Int =
    (n * context.resources.displayMetrics.density).toInt()
