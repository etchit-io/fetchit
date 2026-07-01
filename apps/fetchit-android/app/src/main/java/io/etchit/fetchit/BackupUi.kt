package io.etchit.fetchit

import android.app.KeyguardManager
import android.content.Context
import android.content.DialogInterface
import android.graphics.Typeface
import android.text.InputType
import android.util.Log
import android.view.Gravity
import android.view.WindowManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.etchit.fetchit.chat.ChatSecrets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.fetchit_ffi.restoreRecoveryPhrase
import uniffi.fetchit_ffi.revealRecoveryPhrase
import java.io.File

/**
 * Identity-backup surface for LIT Chat: reveal the 24-word BIP39 recovery
 * phrase (security-gated) and restore an identity from one.
 *
 * Security posture (all enforced here):
 * - The reveal is gated behind a device re-auth ([BiometricPrompt] with
 *   `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`); the phrase is read only inside
 *   `onAuthenticationSucceeded`. When no authenticator is enrolled the device
 *   lock is still required — an unsecured device gets an explicit warning and
 *   the phrase is shown only after the user confirms.
 * - The reveal dialog window carries `FLAG_SECURE` so the phrase can't be
 *   screenshotted or leak into the recents thumbnail.
 * - The phrase is never logged, persisted, copied to any store, or placed on
 *   the clipboard; it lives in the reveal dialog's view for exactly as long as
 *   that dialog is on screen and is scrubbed on dismiss.
 * - Restore needs no biometric: the typed phrase is itself the credential.
 *
 * Both FFI calls are blocking `@Throws` functions, so they run on
 * [Dispatchers.IO] inside `runCatching`; raw engine text is never surfaced.
 */

private const val TAG = "BackupUi"

/** Entry point for the "reveal recovery phrase" settings row. */
fun revealRecoveryPhraseFlow(activity: AppCompatActivity) {
    val secure = (activity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)
        ?.isDeviceSecure == true
    if (secure) {
        // A secured device ALWAYS goes through the OS re-auth prompt.
        // DEVICE_CREDENTIAL is allowed, so a PIN/pattern/password device
        // without biometrics still gets a real system gate — and androidx
        // handles the pre-API-30 credential fallback, sidestepping
        // canAuthenticate()'s unreliability on older API levels. Keying off
        // canAuthenticate here would let a secured-but-quirky device skip
        // the OS gate entirely.
        promptAuthThenReveal(
            activity,
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
    } else {
        // No screen lock at all: nothing to authenticate against. Warn that
        // the phrase is unprotected and reveal only on explicit confirm.
        MaterialAlertDialogBuilder(activity)
            .setTitle(activity.getString(R.string.backup_reveal_nolock_title))
            .setMessage(activity.getString(R.string.backup_reveal_nolock_message))
            .setPositiveButton(activity.getString(R.string.backup_reveal_nolock_action)) { _, _ ->
                revealAfterAuth(activity)
            }
            .setNegativeButton(activity.getString(R.string.action_cancel), null)
            .show()
    }
}

/** Present the system re-auth prompt; reveal only on success. */
private fun promptAuthThenReveal(activity: AppCompatActivity, authenticators: Int) {
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            revealAfterAuth(activity)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            // Treat user-initiated cancels as a silent no-op; only surface a
            // friendly note for genuine failures. Never reveal from here.
            val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                errorCode == BiometricPrompt.ERROR_CANCELED
            if (!cancelled) {
                toast(activity, R.string.backup_reveal_auth_failed)
            }
        }
    }
    val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(activity.getString(R.string.backup_reveal_auth_title))
        .setSubtitle(activity.getString(R.string.backup_reveal_auth_subtitle))
        .setAllowedAuthenticators(authenticators)
        .build()
    prompt.authenticate(info)
}

/**
 * Read the phrase off the main thread and route to the right dialog: the
 * legacy-identity notice when the vault has no recoverable seed, otherwise the
 * `FLAG_SECURE` reveal. Any engine error becomes a friendly toast.
 */
private fun revealAfterAuth(activity: AppCompatActivity) {
    activity.lifecycleScope.launch {
        val result = runCatching {
            withContext(Dispatchers.IO) {
                revealRecoveryPhrase(chatDataDir(activity), ChatSecrets(activity).vaultPass())
            }
        }
        result.fold(
            onSuccess = { phrase ->
                if (phrase == null) {
                    MaterialAlertDialogBuilder(activity)
                        .setTitle(activity.getString(R.string.backup_reveal_none_title))
                        .setMessage(activity.getString(R.string.backup_reveal_none_message))
                        .setPositiveButton(activity.getString(R.string.action_close), null)
                        .show()
                } else {
                    showPhraseDialog(activity, phrase)
                }
            },
            onFailure = { e ->
                // Class name only — never the reason text, and never the phrase.
                Log.w(TAG, "revealRecoveryPhrase failed: ${e.javaClass.simpleName}")
                toast(activity, R.string.backup_reveal_failed)
            },
        )
    }
}

/**
 * Show the 24 words in a screenshot-blocked dialog. The phrase lives only in
 * this view and is scrubbed the moment the dialog closes.
 */
private fun showPhraseDialog(activity: AppCompatActivity, phrase: String) {
    val density = activity.resources.displayMetrics.density
    val padH = (20 * density).toInt()
    val padV = (8 * density).toInt()

    val phraseView = TextView(activity).apply {
        text = phrase
        typeface = Typeface.MONOSPACE
        textSize = 16f
        setLineSpacing(0f, 1.35f)
        setTextColor(activity.themeColor(R.attr.fetchitBone))
        // Non-selectable: no long-press copy, so the secret can't reach the
        // clipboard. Paper is the intended backup medium.
        setTextIsSelectable(false)
    }
    val warnView = TextView(activity).apply {
        text = activity.getString(R.string.backup_reveal_warning)
        setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
        textSize = 13f
        setPadding(0, (18 * density).toInt(), 0, 0)
        setTextColor(activity.themeColor(R.attr.fetchitRust))
    }
    val column = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(padH, padV, padH, 0)
        addView(phraseView)
        addView(warnView)
    }
    val scroll = ScrollView(activity).apply { addView(column) }

    val dialog = MaterialAlertDialogBuilder(activity)
        .setTitle(activity.getString(R.string.backup_reveal_title))
        .setView(scroll)
        .setPositiveButton(activity.getString(R.string.backup_reveal_done), null)
        .create()
    // Scrub the words from the view hierarchy as soon as the dialog closes.
    dialog.setOnDismissListener { phraseView.text = "" }
    // FLAG_SECURE: block screenshots and keep the phrase out of the recents
    // thumbnail. Set on the dialog's own window before it is shown.
    dialog.window?.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE,
    )
    dialog.show()
}

/** Entry point for the "restore from phrase" settings row. */
fun restoreRecoveryPhraseFlow(activity: AppCompatActivity) {
    val density = activity.resources.displayMetrics.density
    val padH = (20 * density).toInt()
    val padV = (8 * density).toInt()

    val input = EditText(activity).apply {
        hint = activity.getString(R.string.backup_restore_hint)
        inputType = InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        setLines(3)
        gravity = Gravity.TOP or Gravity.START
        typeface = Typeface.MONOSPACE
        textSize = 15f
        setTextColor(activity.themeColor(R.attr.fetchitBone))
        setHintTextColor(activity.themeColor(R.attr.fetchitAsh))
    }
    val column = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(padH, padV, padH, 0)
        addView(input)
    }

    val dialog = MaterialAlertDialogBuilder(activity)
        .setTitle(activity.getString(R.string.backup_restore_title))
        .setMessage(activity.getString(R.string.backup_restore_message))
        .setView(column)
        .setPositiveButton(activity.getString(R.string.backup_restore_action), null)
        .setNegativeButton(activity.getString(R.string.action_cancel), null)
        .create()
    // Positive handler wired after show() so an invalid phrase reports inline
    // instead of dismissing the dialog.
    dialog.setOnShowListener {
        val restoreBtn = dialog.getButton(DialogInterface.BUTTON_POSITIVE)
        restoreBtn.setOnClickListener {
            val normalized = normalizeRecoveryPhrase(input.text.toString())
            if (normalized.isEmpty()) {
                input.error = activity.getString(R.string.backup_restore_empty)
                return@setOnClickListener
            }
            restoreBtn.isEnabled = false
            activity.lifecycleScope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        restoreRecoveryPhrase(
                            chatDataDir(activity),
                            ChatSecrets(activity).vaultPass(),
                            normalized,
                        )
                    }
                }
                result.fold(
                    onSuccess = {
                        dialog.dismiss()
                        toast(activity, R.string.backup_restore_done)
                    },
                    onFailure = { e ->
                        restoreBtn.isEnabled = true
                        // Class name only — never the reason text (which could
                        // echo input) and never the phrase.
                        Log.w(TAG, "restoreRecoveryPhrase failed: ${e.javaClass.simpleName}")
                        toast(activity, restoreErrorMessage(activity, e))
                    },
                )
            }
        }
    }
    dialog.show()
}

/**
 * Pick friendly copy for a restore failure by inspecting the engine reason in
 * memory only — distinguishing "phrase doesn't look right" from "you already
 * have an identity". The raw reason is never shown or logged.
 */
private fun restoreErrorMessage(context: Context, e: Throwable): String {
    val reason = e.message.orEmpty().lowercase()
    val alreadyHasIdentity = reason.contains("exist") || reason.contains("already")
    return context.getString(
        if (alreadyHasIdentity) R.string.backup_restore_err_exists
        else R.string.backup_restore_err_invalid,
    )
}

/** Same chat vault directory the connect path uses (mirrors ChatController). */
private fun chatDataDir(context: Context): String =
    File(context.filesDir, "chat").apply { mkdirs() }.absolutePath

private fun toast(context: Context, @StringRes msg: Int) {
    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
}

private fun toast(context: Context, msg: String) {
    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
}
