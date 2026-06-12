package io.etchit.fetchit.chat

import android.content.Context
import android.content.SharedPreferences
import java.security.SecureRandom

/**
 * Provides a stable, random vault passphrase for the chat FFI layer.
 *
 * On first access 32 bytes are drawn from [SecureRandom], hex-encoded,
 * and persisted in app-private [SharedPreferences]. Subsequent calls
 * return the same value for the lifetime of the app installation.
 *
 * Storage: app-private `SharedPreferences` (`MODE_PRIVATE`). The passphrase
 * is never written to logcat or included in crash reports.
 *
 * Security follow-up: wrap the stored value with an Android Keystore-backed
 * AES-GCM key so the passphrase is sealed at rest and requires biometric or
 * device-credential unlock to retrieve. The Rust layer already applies
 * Argon2id key-derivation on top, so the current arrangement is safe for v1
 * on a non-rooted device.
 */
class ChatSecrets(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Returns the vault passphrase for this installation. Generates and
     * persists a fresh random passphrase on the first call.
     *
     * Must not be called on the main thread (prefs read is fast but
     * is best kept off UI to avoid jank on first launch).
     */
    fun vaultPass(): String {
        prefs.getString(KEY, null)?.let { return it }
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hex = bytes.joinToString("") { "%02x".format(it) }
        prefs.edit().putString(KEY, hex).commit()
        return hex
    }

    private companion object {
        const val PREFS_NAME = "fetchit_chat_secrets"
        const val KEY = "vault_pass_v1"
    }
}
