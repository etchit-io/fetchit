package io.etchit.fetchit

import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileOutputStream

/**
 * Standard QR-share modal — the Android twin of the desktop `qrModal.ts`.
 * Same four actions everywhere across the suite (fetch>it + etch/it on
 * desktop and mobile): **Copy address**, **Copy autonomi://…**, **Save
 * image**, **Copy image**. Spec: `docs/QR-SHARE.md`.
 *
 * Two share-out actions ride alongside those four, both host-provided so the
 * bookmark surfaces that have no chat context simply don't show them.
 *
 * @param onOpenConversation when non-null a "share to chat" button is shown;
 *   after a successful send the Snackbar's "open" action invokes this with the
 *   conversation key so the caller can switch to chat mode and open the thread.
 * @param onPostToFeed when non-null a "post to feed" button is shown; it is
 *   invoked with the `autonomi://` URI so the caller can open the fediverse
 *   composer prefilled with it.
 */
fun showQrPreviewDialog(
    context: Context,
    address: String,
    label: String? = null,
    onOpenConversation: ((convKey: String) -> Unit)? = null,
    onPostToFeed: ((uri: String) -> Unit)? = null,
) {
    if (!isValidAutonomiAddress(address)) return

    val view = LayoutInflater.from(context).inflate(R.layout.dialog_qr_preview, null, false)
    val qrImage = view.findViewById<ImageView>(R.id.qr_image)
    val titleEdit = view.findViewById<EditText>(R.id.qr_title)
    val addrText = view.findViewById<TextView>(R.id.qr_address)
    val copyHex = view.findViewById<Button>(R.id.qr_copy_hex)
    val copyUrl = view.findViewById<Button>(R.id.qr_copy_url)
    val saveBtn = view.findViewById<Button>(R.id.qr_save_image)
    val copyImgBtn = view.findViewById<Button>(R.id.qr_copy_image)
    val sendInChatBtn = view.findViewById<Button>(R.id.qr_send_in_chat)
    val postToFeedBtn = view.findViewById<Button>(R.id.qr_post_to_feed)
    val closeBtn = view.findViewById<ImageButton>(R.id.qr_close)

    val payload = "autonomi://$address"
    titleEdit.setText(label?.trim().orEmpty())
    // Bare QR for the in-modal scan target. The export card (wordmark +
    // title + abbreviated address + footer) is regenerated at save /
    // copy time so the current EditText value lands on the artifact —
    // building it once at dialog open would strand whatever the user
    // types after.
    val previewBitmap = QrBitmap.renderQrWithLogo(payload, sizePx = 1024)
    qrImage.setImageBitmap(previewBitmap)
    addrText.text = abbreviateAddressForDisplay(address)

    fun currentExportBitmap(): Bitmap? {
        val typed = titleEdit.text?.toString()?.trim()
        val label = typed?.takeIf { it.isNotEmpty() }
        return QrShare.renderCardFor(address, label)
    }

    // Force the ShareDialog theme so the rendered card uses a fixed
    // palette and isn't affected by the host activity's theme.
    val dialog = Dialog(context, R.style.Theme_Fetchit_ShareDialog).apply {
        setContentView(view)
        window?.setLayout(MATCH_PARENT, MATCH_PARENT)
    }
    closeBtn.setOnClickListener { dialog.dismiss() }

    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val copied = context.getString(R.string.qr_preview_copied)
    val saved = context.getString(R.string.qr_preview_saved)
    val failed = context.getString(R.string.qr_preview_failed)

    copyHex.setOnClickListener {
        clipboard.setPrimaryClip(ClipData.newPlainText("Autonomi address", address))
        flashButton(copyHex, copied)
    }
    copyUrl.setOnClickListener {
        clipboard.setPrimaryClip(ClipData.newPlainText("Autonomi URL", payload))
        flashButton(copyUrl, copied)
    }
    saveBtn.setOnClickListener {
        val bmp = currentExportBitmap() ?: previewBitmap
        val ok = bmp?.let { saveQrToDownloads(context, address, it) } ?: false
        flashButton(saveBtn, if (ok) saved else failed)
        if (ok) {
            // Button flash is gone in <2s — surface the destination as a
            // toast that lingers so the user knows where to find the PNG.
            Toast.makeText(context, "Saved to Downloads · ${qrFilename(address)}", Toast.LENGTH_LONG).show()
        }
    }
    copyImgBtn.setOnClickListener {
        val bmp = currentExportBitmap() ?: previewBitmap
        val ok = bmp?.let { copyQrToClipboard(context, clipboard, address, it) } ?: false
        flashButton(copyImgBtn, if (ok) copied else failed)
    }

    if (onOpenConversation != null) {
        sendInChatBtn.visibility = View.VISIBLE
        sendInChatBtn.setOnClickListener {
            dialog.dismiss()
            showShareToChatDialog(context, address, view, onOpenConversation)
        }
    }

    if (onPostToFeed != null) {
        postToFeedBtn.visibility = View.VISIBLE
        postToFeedBtn.setOnClickListener {
            dialog.dismiss()
            onPostToFeed(payload)
        }
    }

    dialog.show()
}

private fun flashButton(btn: Button, msg: String) {
    val original = btn.text
    btn.text = msg
    btn.isEnabled = false
    Handler(Looper.getMainLooper()).postDelayed({
        btn.text = original
        btn.isEnabled = true
    }, 1100)
}

private fun qrFilename(address: String): String = "fetchit-${address.take(8)}.png"

/** Mirror of desktop `abbreviateAddress(..)` — keeps the modal address row
 *  to one line (8+…+8) so the new title row doesn't push the layout off
 *  short phones. Full hex still lives on the QR + clipboard buttons. */
private fun abbreviateAddressForDisplay(hex: String): String =
    if (hex.length <= 17) hex else "${hex.take(8)}…${hex.takeLast(8)}"

private fun saveQrToDownloads(context: Context, address: String, bitmap: Bitmap): Boolean = try {
    val resolver = context.contentResolver
    val values = ContentValues().apply {
        put(MediaStore.Downloads.DISPLAY_NAME, qrFilename(address))
        put(MediaStore.Downloads.MIME_TYPE, "image/png")
        put(MediaStore.Downloads.IS_PENDING, 1)
    }
    val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
        ?: throw RuntimeException("downloads insert returned null")
    resolver.openOutputStream(uri)?.use { out ->
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
    } ?: throw RuntimeException("openOutputStream returned null")
    values.clear()
    values.put(MediaStore.Downloads.IS_PENDING, 0)
    resolver.update(uri, values, null, null)
    true
} catch (_: Exception) {
    false
}

private fun copyQrToClipboard(context: Context, clipboard: ClipboardManager, address: String, bitmap: Bitmap): Boolean = try {
    val dir = File(context.cacheDir, "qr").apply { mkdirs() }
    // Wipe stale entries so the clipboard cache doesn't grow unbounded.
    dir.listFiles()?.forEach { it.delete() }
    val file = File(dir, qrFilename(address))
    FileOutputStream(file).use { out ->
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
    }
    val uri: Uri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.fileprovider",
        file,
    )
    val clip = ClipData.newUri(context.contentResolver, "QR image", uri)
    clipboard.setPrimaryClip(clip)
    true
} catch (_: Exception) {
    false
}
