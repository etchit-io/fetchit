package io.etchit.fetchit

import android.content.Context
import android.graphics.Bitmap
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.io.File

/**
 * Inline PDF renderer using Android's built-in [`PdfRenderer`].
 *
 * `PdfRenderer` requires a seekable file descriptor, so the bytes are
 * staged to a temp file in `cacheDir/pdf/`. The temp file is wiped on
 * each new [`load`] and on [`release`]. This is the same pattern
 * `BinaryActions.openWith` uses — keeps the spec §3 "no on-device
 * caching" rule honest by treating the temp as scratch, not storage.
 *
 * Pages render lazily as the user scrolls — `PdfRenderer.openPage(i)`
 * is called per-row. Bitmaps are rendered at the view's pixel width
 * for crisp output, recycled when the row scrolls off-screen.
 */
class PdfView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : RecyclerView(context, attrs, defStyleAttr) {

    private var pfd: ParcelFileDescriptor? = null
    private var renderer: PdfRenderer? = null
    private var stagedFile: File? = null

    init {
        layoutManager = LinearLayoutManager(context)
        setBackgroundColor(0)
    }

    fun load(bytes: ByteArray) {
        release()
        val dir = File(context.cacheDir, "pdf").apply {
            if (exists()) deleteRecursively()
            mkdirs()
        }
        val file = File(dir, "current.pdf").apply { writeBytes(bytes) }
        stagedFile = file
        val descriptor = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
        pfd = descriptor
        val r = PdfRenderer(descriptor)
        renderer = r
        adapter = PdfPageAdapter(r)
    }

    fun release() {
        adapter = null
        renderer?.close()
        renderer = null
        pfd?.close()
        pfd = null
        stagedFile?.delete()
        stagedFile = null
    }
}

/** One row per PDF page, bitmap rendered at view-width on bind. */
private class PdfPageAdapter(private val renderer: PdfRenderer) :
    RecyclerView.Adapter<PdfPageAdapter.PageHolder>() {

    override fun getItemCount(): Int = renderer.pageCount

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PageHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.pdf_page_row, parent, false)
        return PageHolder(view as ImageView)
    }

    override fun onBindViewHolder(holder: PageHolder, position: Int) {
        renderer.openPage(position).use { page ->
            val width = holder.itemView.width.takeIf { it > 0 }
                ?: holder.itemView.context.resources.displayMetrics.widthPixels
            val scale = width.toFloat() / page.width.toFloat()
            val height = (page.height * scale).toInt().coerceAtLeast(1)
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
            holder.image.setImageBitmap(bitmap)
        }
    }

    override fun onViewRecycled(holder: PageHolder) {
        super.onViewRecycled(holder)
        (holder.image.drawable as? android.graphics.drawable.BitmapDrawable)?.bitmap?.recycle()
        holder.image.setImageBitmap(null)
    }

    class PageHolder(val image: ImageView) : RecyclerView.ViewHolder(image)
}
