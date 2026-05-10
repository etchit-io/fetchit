package io.etchit.fetchit

import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import io.etchit.fetchit.databinding.BookmarkSheetBinding
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Slide-up sheet for the bookmark list. Mounted on tap of the ⭐
 * button. Hosts only the lifecycle, view binding, and launcher
 * registration — context menu lives in [`showBookmarkContextMenu`],
 * file IO in [`BookmarkFileIO`].
 */
class BookmarkSheet : BottomSheetDialogFragment() {

    /** What the host activity must provide for the sheet to function. */
    interface Host {
        val store: BookmarkStore

        /** Address currently in the input field, or empty. */
        fun currentAddressInput(): String

        /** Recall: fill the address bar with this bookmark's address. */
        fun recallAddress(address: String)
    }

    private val host: Host get() = requireActivity() as Host

    private var _binding: BookmarkSheetBinding? = null
    private val binding get() = _binding!!

    private lateinit var adapter: BookmarkAdapter

    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> uri?.let(::onExportPicked) }

    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(::onImportPicked) }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = BookmarkSheetBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = BookmarkAdapter(
            onClick = { host.recallAddress(it.address); dismiss() },
            onLongPress = { showBookmarkContextMenu(requireContext(), it, host.store) },
        )
        binding.bookmarkList.layoutManager = LinearLayoutManager(requireContext())
        binding.bookmarkList.adapter = adapter

        wireSaveCurrent()
        binding.exportButton.setOnClickListener {
            exportLauncher.launch("fetchit-bookmarks-${System.currentTimeMillis()}.json")
        }
        binding.importButton.setOnClickListener {
            importLauncher.launch(arrayOf("application/json"))
        }

        viewLifecycleOwner.lifecycleScope.launch {
            host.store.bookmarks.collectLatest { list ->
                adapter.submitList(list)
                renderEmptyState(list.isEmpty())
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun wireSaveCurrent() {
        val current = host.currentAddressInput()
        if (!isValidAutonomiAddress(current)) {
            binding.saveCurrentButton.visibility = View.GONE
            return
        }
        binding.saveCurrentButton.visibility = View.VISIBLE
        binding.saveCurrentButton.text =
            getString(R.string.bookmark_save_current_with_addr, current.take(8))
        binding.saveCurrentButton.setOnClickListener {
            showBookmarkRenameDialog(
                context = requireContext(),
                title = getString(R.string.bookmark_save_dialog_title),
                prefill = "",
                hint = getString(R.string.bookmark_name_hint),
            ) { label ->
                host.store.add(Bookmark.create(label = label, address = current))
            }
        }
    }

    private fun renderEmptyState(empty: Boolean) {
        binding.emptyState.visibility = if (empty) View.VISIBLE else View.GONE
        binding.bookmarkList.visibility = if (empty) View.GONE else View.VISIBLE
    }

    private fun onExportPicked(uri: Uri) {
        BookmarkFileIO.writeExport(requireContext(), uri, host.store.bookmarks.value)
            .onSuccess { toast(getString(R.string.bookmark_export_done)) }
            .onFailure { toast(getString(R.string.bookmark_export_failed, it.message)) }
    }

    private fun onImportPicked(uri: Uri) {
        BookmarkFileIO.readImport(requireContext(), uri)
            .onSuccess {
                host.store.mergeImport(it)
                toast(getString(R.string.bookmark_import_done, it.size))
            }
            .onFailure { toast(getString(R.string.bookmark_import_failed, it.message)) }
    }

    private fun toast(msg: String) =
        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
}
