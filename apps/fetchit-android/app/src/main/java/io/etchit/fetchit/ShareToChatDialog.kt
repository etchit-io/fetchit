package io.etchit.fetchit

import android.app.Activity
import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import io.etchit.fetchit.chat.ChatGateway
import io.etchit.fetchit.chat.ConversationStore
import io.etchit.fetchit.chat.displayNameOrDefault
import io.etchit.fetchit.chat.groupTitle
import kotlinx.coroutines.launch
import uniffi.fetchit_ffi.ChatFfiException

/**
 * "share to chat": pick one existing conversation — a private contact or a
 * group — optionally say something about the address, and send it. The
 * message body carries the plain `autonomi://` URI, which every fetch>it
 * client turns back into a content card, so what lands in the other person's
 * thread reads as the thing rather than 64 hex characters.
 *
 * @param anchor a view to hang failure feedback on if the host is not an
 *   Activity; an Activity-level anchor is preferred so in-flight Snackbars
 *   survive the share dialog closing.
 * @param onOpenConversation invoked with the conversation key from the "open"
 *   action on the sent Snackbar (see [ConversationStore.convKeyDm] /
 *   [ConversationStore.convKeyGroup]).
 */
fun showShareToChatDialog(
    context: Context,
    address: String,
    anchor: View,
    onOpenConversation: (convKey: String) -> Unit,
) {
    val controller = context.fetchitApp().chatController
    val contacts = controller.contacts.contacts.value
    val groups = controller.groups.value
    // Snackbars must outlive this dialog: the send is still in flight when it
    // closes, and a detached view swallows (or crashes on) the feedback.
    val feedbackAnchor = (context as? Activity)?.findViewById(android.R.id.content) ?: anchor
    if (contacts.isEmpty() && groups.isEmpty()) {
        Snackbar.make(
            feedbackAnchor,
            context.getString(R.string.share_no_contacts),
            Snackbar.LENGTH_LONG,
        ).show()
        return
    }

    val targets = ArrayList<ShareTarget>(contacts.size + groups.size)
    contacts.forEach { contact ->
        val name = contact.displayName.ifBlank { "${contact.agentIdHex.take(8)}…" }
        targets.add(
            ShareTarget("🔒 $name", ConversationStore.convKeyDm(contact.agentIdHex)) { gw, body, sender ->
                gw.enqueueDm(contact.agentIdHex, body, sender)
            },
        )
    }
    groups.forEach { group ->
        targets.add(
            ShareTarget(
                "👥 ${groupTitle(group, group.groupId)}",
                ConversationStore.convKeyGroup(group.groupId),
            ) { gw, body, sender ->
                gw.sendGroupMessage(group.groupId, body, sender)
            },
        )
    }

    val inflater = LayoutInflater.from(context)
    val view = inflater.inflate(R.layout.dialog_share_to_chat, null, false)
    val note = view.findViewById<EditText>(R.id.shareNote)
    val list = view.findViewById<LinearLayout>(R.id.shareTargets)
    val dialog = MaterialAlertDialogBuilder(context)
        .setTitle(R.string.share_pick_contact_title)
        .setView(view)
        .setNegativeButton(context.getString(R.string.action_close), null)
        .create()

    targets.forEach { target ->
        val row = inflater.inflate(R.layout.item_share_target, list, false) as TextView
        row.text = target.label
        row.setOnClickListener {
            // Picking IS sending — a second confirm step buys nothing here.
            dialog.dismiss()
            sendShare(context, feedbackAnchor, address, note.text.toString().trim(), target, onOpenConversation)
        }
        list.addView(row)
    }
    dialog.show()
}

/** One pickable conversation and how a message reaches it. */
private class ShareTarget(
    val label: String,
    val convKey: String,
    val send: suspend (gw: ChatGateway, body: String, senderName: String) -> Unit,
)

private fun sendShare(
    context: Context,
    anchor: View,
    address: String,
    note: String,
    target: ShareTarget,
    onOpenConversation: (convKey: String) -> Unit,
) {
    val scope = (context as? LifecycleOwner)?.lifecycleScope ?: return
    // The URI goes on its own line so the note reads as a note and the
    // receiving client's address extraction sees a free-standing token.
    val body = if (note.isEmpty()) "autonomi://$address" else "$note\nautonomi://$address"
    scope.launch {
        val controller = context.fetchitApp().chatController
        val gateway = runCatching { controller.ensureGateway() }.getOrElse { e ->
            Snackbar.make(anchor, shareFailureReason(e), Snackbar.LENGTH_LONG).show()
            return@launch
        }
        val senderName = displayNameOrDefault(context, gateway.agentIdHex())
        // Enqueued into the durable outbox; the optimistic bubble and its
        // Delivered / Failed state surface in the thread via the outbox event
        // projection, so nothing is appended locally here.
        runCatching { target.send(gateway, body, senderName) }
            .onSuccess {
                Snackbar.make(anchor, context.getString(R.string.share_sent_in_chat), Snackbar.LENGTH_LONG)
                    .setAction(context.getString(R.string.share_open_thread)) {
                        onOpenConversation(target.convKey)
                    }
                    .show()
            }
            .onFailure { e ->
                Snackbar.make(anchor, shareFailureReason(e), Snackbar.LENGTH_LONG).show()
            }
    }
}

private fun shareFailureReason(e: Throwable): String = when (e) {
    is ChatFfiException.Invalid -> e.reason
    is ChatFfiException.Network -> e.reason
    else -> e.message.orEmpty()
}
