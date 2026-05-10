package io.etchit.fetchit

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import androidx.core.content.FileProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import java.io.FileOutputStream

/**
 * Encode an Autonomi address as a QR-code PNG and fire the system
 * share sheet so the user can drop it into any messenger / mail
 * client / file manager.
 *
 * **Why QR**: Gmail / WhatsApp / SMS and most other messengers only
 * auto-linkify a small whitelist of URL schemes (`http`, `https`,
 * `mailto`, `tel`). `autonomi://<addr>` arrives as plain text — the
 * recipient can't tap to open. A QR lets them point their phone's
 * camera and have the system intent flow route to fetch>it without
 * any messenger cooperation. Aligns with the no-DNS / no-traditional-
 * internet ethos.
 *
 * The encoded payload is the canonical user-facing form
 * (`autonomi://<64-hex>`) so any other Autonomi-aware client can
 * also handle it.
 */
object QrShare {

    /**
     * Build a QR-code PNG for `address` and start the share-sheet
     * activity. Returns `false` if the address is invalid or the
     * encoder fails.
     */
    fun share(context: Context, address: String, label: String? = null): Boolean {
        if (!isValidAutonomiAddress(address)) return false
        val payload = "autonomi://$address"
        val bitmap = render(payload, SIZE_PX) ?: return false
        val file = writePng(context, address, bitmap) ?: return false
        bitmap.recycle()

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
            // text; image-aware apps ignore both and show the QR).
            val title = label?.ifBlank { null } ?: "fetch>it bookmark"
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

    /** Render a QR bitmap. Black foreground on white background. */
    private fun render(payload: String, sizePx: Int): Bitmap? = try {
        val matrix = QRCodeWriter().encode(
            payload,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            mapOf(
                // High error correction so a phone camera can still
                // decode through reflections / partial occlusion.
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
                EncodeHintType.MARGIN to 2,
            ),
        )
        Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.RGB_565).apply {
            for (y in 0 until sizePx) {
                for (x in 0 until sizePx) {
                    setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
                }
            }
        }
    } catch (_: Exception) {
        null
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

    /** 880px square: large enough for camera capture across rooms but
     *  still light to encode at runtime. */
    private const val SIZE_PX = 880
}
