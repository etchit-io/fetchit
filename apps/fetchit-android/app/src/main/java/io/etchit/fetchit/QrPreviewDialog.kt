package io.etchit.fetchit

import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.Button
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView

/**
 * Show the in-app QR preview modal — the Android twin of the desktop
 * `qrModal.ts`. Same layout philosophy: brand wordmark, QR with copper `>`
 * centre, the address selectable beneath it, four actions (copy hex / copy
 * URL / share-as-image / share-as-text), and an `etchit.io` footer so
 * screenshots of the dialog still advertise the project.
 *
 * "Share as image" delegates to [`QrShare.share`] (the existing branded
 * PNG card flow); "Share as text" fires `ACTION_SEND` with the raw
 * `autonomi://<addr>` payload. Both dismiss the dialog so the system
 * share sheet replaces it cleanly.
 *
 * Spec: `docs/QR-SHARE.md`.
 */
fun showQrPreviewDialog(context: Context, address: String, label: String? = null) {
    if (!isValidAutonomiAddress(address)) return

    val view = LayoutInflater.from(context).inflate(R.layout.dialog_qr_preview, null, false)
    val qrImage = view.findViewById<ImageView>(R.id.qr_image)
    val addrText = view.findViewById<TextView>(R.id.qr_address)
    val copyHex = view.findViewById<Button>(R.id.qr_copy_hex)
    val copyUrl = view.findViewById<Button>(R.id.qr_copy_url)
    val shareImage = view.findViewById<Button>(R.id.qr_share_image)
    val shareText = view.findViewById<Button>(R.id.qr_share_text)
    val closeBtn = view.findViewById<ImageButton>(R.id.qr_close)

    val payload = "autonomi://$address"
    qrImage.setImageBitmap(QrBitmap.renderQrWithLogo(payload, sizePx = 720))
    addrText.text = address

    // Full-screen, brand-fixed cream surface — the share artifact reads
    // identically regardless of which app theme is active, with no host
    // background bleeding around it.
    val dialog = Dialog(context, R.style.Theme_Fetchit_ShareDialog).apply {
        setContentView(view)
        window?.setLayout(MATCH_PARENT, MATCH_PARENT)
    }
    closeBtn.setOnClickListener { dialog.dismiss() }

    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val copied = context.getString(R.string.qr_preview_copied)

    copyHex.setOnClickListener {
        clipboard.setPrimaryClip(ClipData.newPlainText("Autonomi address", address))
        flashButton(copyHex, copied)
    }
    copyUrl.setOnClickListener {
        clipboard.setPrimaryClip(ClipData.newPlainText("Autonomi URL", payload))
        flashButton(copyUrl, copied)
    }
    shareImage.setOnClickListener {
        dialog.dismiss()
        QrShare.share(context, address, label)
    }
    shareText.setOnClickListener {
        dialog.dismiss()
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, payload)
            putExtra(Intent.EXTRA_SUBJECT, "fetch>it · $address")
        }
        context.startActivity(
            Intent.createChooser(intent, context.getString(R.string.action_share_label)),
        )
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
