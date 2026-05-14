package io.etchit.fetchit

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Render an `autonomi://<addr>` payload as a square QR with the brand `>`
 * glyph copper-stamped in the centre. Shared between the in-app preview
 * (see [`showQrPreviewDialog`]) and any future surfaces that want the same
 * artifact.
 *
 * Mark-design notes — kept in lockstep with `apps/fetchit-desktop/src/qr.ts`
 * per `docs/QR-SHARE.md`:
 *   - Error correction level H (~30%) so the ~16% centre occlusion is
 *     recoverable.
 *   - Centre logo: white rounded square ≈ 16% of the canvas side, copper
 *     `>` glyph in monospace bold filling ≈ 78% of the panel.
 *
 * `QrShare.kt` keeps its own inline QR + path-based `[>]` mark for the
 * share-as-image PNG card; this helper is the lighter-weight version for
 * direct on-screen display.
 */
object QrBitmap {
    private val INK = 0xFF1A1A1A.toInt()
    private val COPPER = 0xFFC9732B.toInt()

    fun renderQrWithLogo(payload: String, sizePx: Int = 720): Bitmap? = try {
        val matrix = QRCodeWriter().encode(
            payload,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            mapOf(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
                EncodeHintType.MARGIN to 2,
            ),
        )
        val pixels = IntArray(sizePx * sizePx)
        for (y in 0 until sizePx) {
            val row = y * sizePx
            for (x in 0 until sizePx) {
                pixels[row + x] = if (matrix.get(x, y)) INK else Color.WHITE
            }
        }
        val bitmap = Bitmap.createBitmap(pixels, sizePx, sizePx, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)

        val cx = sizePx / 2f
        val cy = sizePx / 2f
        val box = sizePx * 0.16f
        val half = box / 2f
        val rect = RectF(cx - half, cy - half, cx + half, cy + half)
        val r = box * 0.12f
        canvas.drawRoundRect(rect, r, r, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE })

        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            textSize = box * 0.78f
            color = COPPER
            textAlign = Paint.Align.CENTER
        }
        // Optical centre: textAlign=CENTER handles horizontal; vertical needs the
        // ascent/descent fixup so the glyph sits on the geometric centre, not the
        // baseline.
        val baseline = cy - (textPaint.descent() + textPaint.ascent()) / 2f
        canvas.drawText(">", cx, baseline, textPaint)
        bitmap
    } catch (_: Exception) {
        null
    }
}
