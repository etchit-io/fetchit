package io.etchit.fetchit

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import androidx.core.content.FileProvider
import androidx.core.graphics.PathParser
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import java.io.FileOutputStream

/**
 * Encode an Autonomi address as a small branded QR-code card (PNG) and
 * fire the system share sheet so the user can drop it into any
 * messenger / mail client / file manager.
 *
 * **Why QR**: Gmail / WhatsApp / SMS and most other messengers only
 * auto-linkify a small whitelist of URL schemes (`http`, `https`,
 * `mailto`, `tel`). `autonomi://<addr>` arrives as plain text — the
 * recipient can't tap to open. A QR lets them point their phone's
 * camera and have the system intent flow route to fetch>it without
 * any messenger cooperation. Aligns with the no-DNS / no-traditional-
 * internet ethos.
 *
 * **The card**: the QR carries the canonical payload (`autonomi://<64-hex>`,
 * so any Autonomi-aware client handles it), with the `[>]` mark in its
 * centre (the QR uses error-correction level H, which tolerates the
 * obscured modules), and the `fetch>it` wordmark + the address printed
 * below. Sized ~560 px wide — comfortably scannable off a phone screen,
 * but not the wall-filling 880 px square it used to be.
 */
object QrShare {

    /**
     * Build the branded QR card for `address` (and optional `label`)
     * and start the share-sheet activity. Returns `false` if the
     * address is invalid or rendering fails.
     */
    fun share(context: Context, address: String, label: String? = null): Boolean {
        if (!isValidAutonomiAddress(address)) return false
        val payload = "autonomi://$address"
        val card = renderCard(payload, address, label?.ifBlank { null }) ?: return false
        val file = writePng(context, address, card) ?: return false
        card.recycle()

        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file,
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "image/png"
            putExtra(Intent.EXTRA_STREAM, uri)
            // Subject + text fall back gracefully on apps that don't
            // attach images (Gmail uses subject; SMS may show the
            // text; image-aware apps ignore both and show the card).
            val title = label?.ifBlank { null } ?: "fetch>it"
            putExtra(Intent.EXTRA_SUBJECT, title)
            putExtra(
                Intent.EXTRA_TEXT,
                "$title\n\n$payload\n\n" +
                    "Scan with the camera if you have fetch>it installed.",
            )
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(
            Intent.createChooser(intent, context.getString(R.string.share_qr_title)),
        )
        return true
    }

    // ── colours (this card lives on white — dark text, copper accent) ──
    private val INK = 0xFF1A1A1A.toInt()      // near-black: QR modules + headings
    private val COPPER = 0xFFC9732B.toInt()   // brand copper
    private val ASH = 0xFF8A8A8A.toInt()      // dim text (address, tagline)
    private const val WHITE = Color.WHITE

    // ── layout (px) ─────────────────────────────────────────────────
    private const val QR_PX = 480       // the QR image itself
    private const val PAD = 40          // white margin around the QR (extra quiet zone)
    private const val CARD_W = QR_PX + PAD * 2   // 560

    /**
     * The `[>]` bracket-chevron mark, same path data as the launcher
     * icon foreground, in its 108×108 viewport. Bounding box ≈ x:30–78,
     * y:42–66 (so it's ~2:1, wider than tall).
     */
    private const val MARK_PATH =
        "M 30 42 L 42 42 L 42 46 L 34 46 L 34 62 L 42 62 L 42 66 L 30 66 Z " +
            "M 66 42 L 78 42 L 78 66 L 66 66 L 66 62 L 74 62 L 74 46 L 66 46 Z " +
            "M 46 42 L 52 42 L 62 54 L 52 66 L 46 66 L 56 54 Z"

    /** Render the full branded card. */
    private fun renderCard(payload: String, address: String, label: String?): Bitmap? = try {
        // — encode the QR —
        val matrix = QRCodeWriter().encode(
            payload,
            BarcodeFormat.QR_CODE,
            QR_PX,
            QR_PX,
            mapOf(
                // Level H so the centred logo's obscured modules are recoverable.
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
                EncodeHintType.MARGIN to 2,
            ),
        )
        val qrPixels = IntArray(QR_PX * QR_PX)
        for (y in 0 until QR_PX) {
            val row = y * QR_PX
            for (x in 0 until QR_PX) {
                qrPixels[row + x] = if (matrix.get(x, y)) INK else WHITE
            }
        }
        val qrBitmap = Bitmap.createBitmap(qrPixels, QR_PX, QR_PX, Bitmap.Config.ARGB_8888)

        // — text paints (measure first so we can size the card) —
        val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.DEFAULT_BOLD
            textSize = 44f
        }
        val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.DEFAULT_BOLD
            textSize = 22f
            color = INK
        }
        val addrPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.MONOSPACE
            textSize = 17f
            color = ASH
        }
        val tagPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.DEFAULT
            textSize = 16f
            color = ASH
        }
        val sibPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.DEFAULT
            textSize = 13f
            color = ASH
        }

        fun lineH(p: Paint): Float = p.fontMetrics.let { it.descent - it.ascent }

        // — vertical layout —
        val gAfterQr = 30f
        val gAfterRule = 26f
        val gAfterTitle = 14f   // wordmark → label (only used when there's a label)
        val gBeforeAddr = 14f   // (label or wordmark) → address
        val gAfterAddr = 26f    // address → tagline
        val gAfterTag = 8f      // tagline → sibling-app line

        var h = PAD.toFloat()
        val qrTop = h; h += QR_PX
        h += gAfterQr
        val ruleY = h; h += 2f
        h += gAfterRule
        val titleBaseTop = h; h += lineH(titlePaint)
        if (label != null) { h += gAfterTitle; h += lineH(labelPaint) }
        h += gBeforeAddr
        h += lineH(addrPaint)
        h += gAfterAddr
        h += lineH(tagPaint)
        h += gAfterTag
        h += lineH(sibPaint)
        h += PAD
        val cardH = h.toInt()

        val card = Bitmap.createBitmap(CARD_W, cardH, Bitmap.Config.ARGB_8888)
        val c = Canvas(card)
        c.drawColor(WHITE)

        // — the QR —
        c.drawBitmap(qrBitmap, PAD.toFloat(), qrTop, null)
        qrBitmap.recycle()

        // — centred logo: a white rounded pad + a thin copper outline + the [>] mark —
        val cx = PAD + QR_PX / 2f
        val cyQr = qrTop + QR_PX / 2f
        val padHalf = QR_PX * 0.155f          // white pad ≈ 31% of the QR side
        val padRect = RectF(cx - padHalf, cyQr - padHalf, cx + padHalf, cyQr + padHalf)
        val padR = padHalf * 0.28f
        c.drawRoundRect(padRect, padR, padR, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = WHITE })
        c.drawRoundRect(
            padRect, padR, padR,
            Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE
                strokeWidth = 2.5f
                color = COPPER
            },
        )
        // mark: scale the 108-viewport path so its 48-wide bbox fits ~78% of the pad width
        val markPath = PathParser.createPathFromPathData(MARK_PATH)
        val markScale = (padHalf * 2f * 0.78f) / 48f
        Matrix().apply {
            // bbox top-left in viewport coords is (30, 42); centre is (54, 54)
            postTranslate(-54f, -54f)
            postScale(markScale, markScale)
            postTranslate(cx, cyQr)
            markPath.transform(this)
        }
        c.drawPath(markPath, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = COPPER })

        // — copper hairline —
        c.drawRect(
            PAD * 3f, ruleY, CARD_W - PAD * 3f, ruleY + 2f,
            Paint().apply { color = COPPER },
        )

        // — wordmark: fetch · > · it (chevron in copper) —
        val wFetch = titlePaint.measureText("fetch")
        val wChev = titlePaint.measureText(">")
        val wIt = titlePaint.measureText("it")
        val wTotal = wFetch + wChev + wIt
        val titleBaseline = titleBaseTop - titlePaint.fontMetrics.ascent
        var x = (CARD_W - wTotal) / 2f
        titlePaint.color = INK; c.drawText("fetch", x, titleBaseline, titlePaint); x += wFetch
        titlePaint.color = COPPER; c.drawText(">", x, titleBaseline, titlePaint); x += wChev
        titlePaint.color = INK; c.drawText("it", x, titleBaseline, titlePaint)

        var y = titleBaseTop + lineH(titlePaint)

        // — optional label —
        if (label != null) {
            y += gAfterTitle
            val ellipsized = ellipsize(label, labelPaint, CARD_W - PAD * 2f)
            val lb = y - labelPaint.fontMetrics.ascent
            c.drawText(ellipsized, (CARD_W - labelPaint.measureText(ellipsized)) / 2f, lb, labelPaint)
            y += lineH(labelPaint)
        }
        y += gBeforeAddr

        // — abbreviated address (full one is in the QR) —
        val shortAddr = if (address.length > 18) {
            "autonomi://${address.take(8)}…${address.takeLast(6)}"
        } else {
            "autonomi://$address"
        }
        val ab = y - addrPaint.fontMetrics.ascent
        c.drawText(shortAddr, (CARD_W - addrPaint.measureText(shortAddr)) / 2f, ab, addrPaint)
        y += lineH(addrPaint)
        y += gAfterAddr

        // — tagline —
        val tag = "scan to open on the Autonomi network"
        val tb = y - tagPaint.fontMetrics.ascent
        c.drawText(tag, (CARD_W - tagPaint.measureText(tag)) / 2f, tb, tagPaint)
        y += lineH(tagPaint)
        y += gAfterTag

        // — companion app (brand-typographic wordmarks: fetch>it / etch/it) —
        val sib = "fetch>it reads it  ·  etch/it publishes it  —  etchit.io"
        val sibFit = ellipsize(sib, sibPaint, CARD_W - PAD.toFloat())
        val sb = y - sibPaint.fontMetrics.ascent
        c.drawText(sibFit, (CARD_W - sibPaint.measureText(sibFit)) / 2f, sb, sibPaint)

        card
    } catch (_: Exception) {
        null
    }

    /** Trim `s` with an ellipsis so `paint.measureText` fits within `maxW`. */
    private fun ellipsize(s: String, paint: Paint, maxW: Float): String {
        if (paint.measureText(s) <= maxW) return s
        var end = s.length
        while (end > 1 && paint.measureText(s.substring(0, end) + "…") > maxW) end--
        return s.substring(0, end) + "…"
    }

    /** Persist the bitmap into the FileProvider-shared `qr/` cache dir. */
    private fun writePng(context: Context, address: String, bitmap: Bitmap): File? = try {
        val dir = File(context.cacheDir, "qr").apply { mkdirs() }
        // Wipe stale entries so the share-cache doesn't grow unbounded.
        dir.listFiles()?.forEach { it.delete() }
        val short = address.take(8)
        val file = File(dir, "fetchit-$short.png")
        FileOutputStream(file).use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
        }
        file
    } catch (_: Exception) {
        null
    }
}
