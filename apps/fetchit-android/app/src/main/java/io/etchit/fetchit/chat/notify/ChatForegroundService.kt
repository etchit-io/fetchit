package io.etchit.fetchit.chat.notify

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import io.etchit.fetchit.FetchitApplication
import io.etchit.fetchit.SettingsStore
import io.etchit.fetchit.chat.ConversationStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Foreground service that keeps the app-scoped [io.etchit.fetchit.chat.ChatController]
 * (and with it the in-process daemon + relay connection) alive while the UI
 * is backgrounded or closed, and raises message notifications off the pump's
 * inbound tap. The Signal-without-Play-Services model: no push dependency,
 * the cost is the persistent min-importance status entry Android requires.
 *
 * Enabled by the existing "keep chat connected" setting
 * ([SettingsStore.chatKeepConnected], default on); [io.etchit.fetchit.MainActivity]
 * starts it, [ChatBootReceiver] restarts it after a reboot. `START_STICKY`
 * so the system re-creates it after memory pressure kills the process.
 */
class ChatForegroundService : Service() {

    private lateinit var notifier: MessageNotifier
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        running = true
        notifier = MessageNotifier(this).also { it.ensureChannels() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val type = when {
            Build.VERSION.SDK_INT >= 34 -> ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING
            Build.VERSION.SDK_INT >= 29 -> ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            else -> 0
        }
        ServiceCompat.startForeground(
            this,
            MessageNotifier.SERVICE_NOTIFICATION_ID,
            notifier.serviceNotification(),
            type,
        )

        val controller = (application as FetchitApplication).chatController
        controller.inboundSink = { inbound -> onInbound(inbound) }
        // Ensure the gateway (and its event pump) is up; capped-backoff retry
        // so a boot-time race (network not yet routable) self-heals. Failure
        // never degrades the UI path -- the activity connects independently.
        scope.launch {
            var backoffMs = 2_000L
            while (true) {
                try {
                    controller.ensureGateway()
                    return@launch
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    android.util.Log.w("fetchit.chat", "background connect failed; retrying", e)
                }
                delay(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(60_000L)
            }
        }
        return START_STICKY
    }

    private fun onInbound(inbound: InboundNotify) {
        val controller = (application as FetchitApplication).chatController
        if (!SettingsStore(this).chatKeepConnected()) return
        val selfHex = controller.gateway()?.agentIdHex().orEmpty()
        if (!shouldNotify(inbound, selfHex, controller.visibleConvKey)) return

        val savedContactName = controller.contacts.contacts.value
            .firstOrNull { it.agentIdHex.equals(inbound.senderAgentIdHex, ignoreCase = true) }
            ?.displayName
        val sender = savedContactName
            ?: inbound.senderLabel
            ?: inbound.senderAgentIdHex.take(8)
        val title = when (inbound.kind) {
            InboundKind.DM -> sender
            InboundKind.GROUP ->
                controller.groups.value
                    .firstOrNull { ConversationStore.convKeyGroup(it.groupId) == inbound.convKey }
                    ?.name
                    ?: getString(io.etchit.fetchit.R.string.notify_group_fallback)
        }
        notifier.post(inbound, title, sender)
    }

    override fun onDestroy() {
        running = false
        (application as FetchitApplication).chatController.inboundSink = null
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        /**
         * Whether an instance is live. Start-callers check this first: on
         * 14+ the user may swipe the (dismissible) persistent notification
         * away, and a redundant `startForegroundService` on every app open
         * would re-post it — the "it keeps coming back" annoyance. One
         * process, one service; a plain flag is enough.
         */
        @Volatile
        var running: Boolean = false
            private set
    }
}
