package io.etchit.fetchit.chat.notify

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.etchit.fetchit.SettingsStore

/**
 * Restarts [ChatForegroundService] after a reboot when "keep chat connected"
 * is enabled, so messages resume without opening the app. Not direct-boot
 * aware on purpose: it runs after the user's first unlock, when the chat
 * vault's keystore material is available.
 */
class ChatBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!SettingsStore(context).chatKeepConnected()) return
        ContextCompat.startForegroundService(
            context,
            Intent(context, ChatForegroundService::class.java),
        )
    }
}
