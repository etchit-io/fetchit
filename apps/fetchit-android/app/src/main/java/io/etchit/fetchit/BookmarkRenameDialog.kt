package io.etchit.fetchit

import android.content.Context
import android.text.InputType
import android.view.WindowManager
import android.widget.EditText
import androidx.appcompat.app.AlertDialog

/**
 * Show the "name this bookmark" modal. Empty labels are rejected — the
 * spec is explicit that custom labels are required, not optional, so
 * the OK button stays disabled until the user types something.
 *
 * `prefill` is what's already in the input — empty for a fresh save,
 * the existing label for a rename. `hint` is the faded placeholder
 * shown when the input is empty (e.g. "name it…" on a fresh save).
 */
fun showBookmarkRenameDialog(
    context: Context,
    title: String,
    prefill: String = "",
    hint: String? = null,
    onConfirmed: (String) -> Unit,
) {
    val input = EditText(context).apply {
        inputType = InputType.TYPE_CLASS_TEXT
        setText(prefill)
        setSelection(prefill.length)
        hint?.let { this.hint = it }
    }

    val dialog = AlertDialog.Builder(context)
        .setTitle(title)
        .setView(input)
        .setPositiveButton(android.R.string.ok) { _, _ ->
            onConfirmed(input.text.toString().trim())
        }
        .setNegativeButton(android.R.string.cancel, null)
        .create()

    // Auto-show the soft keyboard so the user can type immediately.
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
    dialog.show()

    val ok = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
    ok.isEnabled = prefill.isNotBlank()
    input.addTextChangedListener(object : android.text.TextWatcher {
        override fun afterTextChanged(s: android.text.Editable?) {
            ok.isEnabled = !s.isNullOrBlank()
        }
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
    })
}
