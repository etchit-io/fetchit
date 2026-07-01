package io.etchit.fetchit

import android.app.Dialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.view.LayoutInflater
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.Button
import android.widget.TextView

/** AGPL license, mirrored from the desktop About/License section. */
private const val AGPL_URL = "https://www.gnu.org/licenses/agpl-3.0.html"

/**
 * About / LIT Chat info screen (M1.2). Static honest-posture copy +
 * version + license, mirroring the desktop About checklist. Follows the
 * user's current theme (dark/dim/light) by constructing the dialog with
 * the active [Theme.Fetchit] style, so `?attr/fetchit*` resolve to the
 * chosen palette. Not an AP-identity surface: no fediverse handle is
 * shown or linked here (Decision 4).
 */
fun showAboutDialog(context: Context) {
    val themeRes = SettingsStore(context).theme().styleRes
    val view = LayoutInflater.from(context).inflate(R.layout.dialog_about, null, false)
    view.findViewById<TextView>(R.id.about_version).text =
        context.getString(R.string.settings_version, BuildConfig.VERSION_NAME)

    val dialog = Dialog(context, themeRes).apply {
        setContentView(view)
        window?.setLayout(MATCH_PARENT, MATCH_PARENT)
    }
    view.findViewById<TextView>(R.id.about_license_link).setOnClickListener {
        runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(AGPL_URL)))
        }
    }
    view.findViewById<Button>(R.id.about_close).setOnClickListener { dialog.dismiss() }
    dialog.show()
}
