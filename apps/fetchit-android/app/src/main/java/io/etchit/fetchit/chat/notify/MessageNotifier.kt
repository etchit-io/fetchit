package io.etchit.fetchit.chat.notify

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.Person
import io.etchit.fetchit.MainActivity
import io.etchit.fetchit.R

/**
 * Posts one notification per conversation for inbound chat messages, plus
 * the persistent minimum-importance entry the foreground service is
 * required to show. Content is sender + preview with
 * [NotificationCompat.VISIBILITY_PRIVATE], so the system's lock-screen
 * setting decides what shows while locked. Framework-thin: the
 * notify/suppress decision lives in [shouldNotify], label resolution with
 * the caller.
 */
class MessageNotifier(private val context: Context) {

    private val manager =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    /** Idempotent; Android ignores re-creation of an existing channel. */
    fun ensureChannels() {
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_MESSAGES,
                context.getString(R.string.notify_channel_messages),
                NotificationManager.IMPORTANCE_HIGH,
            ),
        )
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_BACKGROUND,
                context.getString(R.string.notify_channel_background),
                NotificationManager.IMPORTANCE_MIN,
            ),
        )
    }

    /**
     * Post (or replace) the notification for [inbound]'s conversation.
     * [conversationTitle] is the resolved thread name (contact / group
     * name); [senderLabel] the resolved author name shown on the message
     * line. Tapping deep-links into the conversation via
     * [MainActivity.EXTRA_OPEN_CONV_KEY].
     */
    fun post(inbound: InboundNotify, conversationTitle: String, senderLabel: String) {
        val tap = PendingIntent.getActivity(
            context,
            inbound.convKey.hashCode(),
            Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                putExtra(EXTRA_OPEN_CONV_KEY, inbound.convKey)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val sender = Person.Builder().setName(senderLabel).build()
        val style = NotificationCompat.MessagingStyle(sender)
            .setConversationTitle(if (inbound.kind == InboundKind.GROUP) conversationTitle else null)
            .setGroupConversation(inbound.kind == InboundKind.GROUP)
            .addMessage(inbound.body, System.currentTimeMillis(), sender)
        val notification = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_chat)
            .setStyle(style)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .build()
        manager.notify(TAG_MESSAGE, inbound.convKey.hashCode(), notification)
    }

    /** Clear the conversation's notification (called when it opens). */
    fun cancel(convKey: String) {
        manager.cancel(TAG_MESSAGE, convKey.hashCode())
    }

    /**
     * The persistent entry Android requires a foreground service to show.
     * Minimum importance: no sound, collapsed to the smallest form the
     * system allows.
     */
    fun serviceNotification(): Notification =
        NotificationCompat.Builder(context, CHANNEL_BACKGROUND)
            .setSmallIcon(R.drawable.ic_stat_chat)
            .setContentTitle(context.getString(R.string.notify_background_title))
            .setOngoing(true)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()

    companion object {
        const val CHANNEL_MESSAGES = "chat_messages"
        const val CHANNEL_BACKGROUND = "chat_background"

        /** [MainActivity] intent extra: conversation key to open on tap. */
        const val EXTRA_OPEN_CONV_KEY = "io.etchit.fetchit.OPEN_CONV_KEY"

        /** Notification tag so message ids can't collide with other surfaces. */
        private const val TAG_MESSAGE = "chat-msg"

        /** Stable id for the foreground-service notification. */
        const val SERVICE_NOTIFICATION_ID = 0x0F5
    }
}
