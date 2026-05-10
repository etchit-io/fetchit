package io.etchit.fetchit

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

/**
 * Renders a list of [`Bookmark`]s in the [`BookmarkSheet`].
 *
 * Click → recall (fill the address bar, dismiss the sheet).
 * Long-press → context menu via [`onLongPress`] (rename / delete /
 * share — handled in the host fragment so this stays a pure binder).
 */
class BookmarkAdapter(
    private val onClick: (Bookmark) -> Unit,
    private val onLongPress: (Bookmark) -> Unit,
) : ListAdapter<Bookmark, BookmarkAdapter.ViewHolder>(Diff) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.bookmark_row, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val bookmark = getItem(position)
        holder.label.text = bookmark.label
        holder.address.text = bookmark.address
        holder.itemView.setOnClickListener { onClick(bookmark) }
        holder.itemView.setOnLongClickListener {
            onLongPress(bookmark)
            true
        }
    }

    class ViewHolder(itemView: android.view.View) : RecyclerView.ViewHolder(itemView) {
        val label: TextView = itemView.findViewById(R.id.bookmarkLabel)
        val address: TextView = itemView.findViewById(R.id.bookmarkAddress)
    }

    private object Diff : DiffUtil.ItemCallback<Bookmark>() {
        override fun areItemsTheSame(a: Bookmark, b: Bookmark) = a.id == b.id
        override fun areContentsTheSame(a: Bookmark, b: Bookmark) = a == b
    }
}
