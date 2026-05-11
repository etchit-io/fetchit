package io.etchit.fetchit

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Hand-off helpers for "open with…" and "save as…" on rendered bytes.
 *
 * Invoking another app via [`Intent.ACTION_VIEW`] needs a `content://`
 * URI, so the bytes are written to a temp file in `cacheDir/open_with/`
 * — scratch, not storage: wiped before each new write and reaped by
 * Android under cache pressure. (Raw fetched bytes are cached
 * separately by the fetch layer; "save as…" copies to a user-chosen
 * location via the system picker — fetch>it keeps no copy of it.)
 */
object BinaryActions {

    /** Subfolder of `cacheDir` used for `Intent.ACTION_VIEW` hand-offs. */
    private const val SUB = "open_with"

    /**
     * Stage `bytes` to a `content://` URI and fire
     * `Intent.ACTION_VIEW`. Returns `false` (with the chooser intent
     * unsent) if no installed app declares it can handle `mime` —
     * caller should surface a "no app installed" message.
     */
    fun openWith(
        context: Context,
        bytes: ByteArray,
        mime: String,
        suggestedName: String,
    ): Boolean {
        val uri = stage(context, bytes, suggestedName)
        val view = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(view, null)
        return try {
            context.startActivity(chooser)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    /**
     * Write `bytes` to the user-picked `Uri` (from
     * `ACTION_CREATE_DOCUMENT`). Returns a `Result` so the caller can
     * show success / failure UI.
     */
    fun saveTo(
        context: Context,
        uri: android.net.Uri,
        bytes: ByteArray,
    ): Result<Unit> = runCatching {
        context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            ?: error("could not open output stream for $uri")
    }

    private fun stage(context: Context, bytes: ByteArray, name: String): android.net.Uri {
        val dir = File(context.cacheDir, SUB).apply {
            // Wipe previous staged files so the cache doesn't grow.
            if (exists()) deleteRecursively()
            mkdirs()
        }
        val file = File(dir, name).apply { writeBytes(bytes) }
        return FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file,
        )
    }
}
