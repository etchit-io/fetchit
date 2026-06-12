package io.etchit.fetchit

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.media3.common.util.UnstableApi
import com.google.android.material.snackbar.Snackbar
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.etchit.fetchit.chat.ChatModeView
import io.etchit.fetchit.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.fetchit_ffi.Client
import uniffi.fetchit_ffi.FetchitException
import uniffi.fetchit_ffi.RenditionFfi
import uniffi.fetchit_ffi.detect

/**
 * Single-Activity host for fetch>it.
 *
 * Orchestrates only — validation lives in [`isValidAutonomiAddress`],
 * rendering in [`RenditionRenderer`], audio + video in [`AudioPlayback`]
 * (Media3 ExoPlayer with built-in controls), persistent state in
 * [`BookmarkStore`] / [`SettingsStore`], the live peer-count gauge in
 * [`PeerCountTracker`], and the shared [`Client`] in
 * [`FetchitApplication`]. Hand-off to other apps lives in
 * [`BinaryActions`].
 */
@UnstableApi
class MainActivity : AppCompatActivity(), BookmarkSheet.Host {

    private lateinit var binding: ActivityMainBinding
    private lateinit var audio: AudioPlayback
    private lateinit var renderer: RenditionRenderer
    private lateinit var settingsSheet: SettingsSheet
    override lateinit var store: BookmarkStore

    /** Last successful (mime, bytes) — drives Open / Save buttons. */
    private var lastBinary: Pair<String, ByteArray>? = null

    /** Last fetched address — drives pull-to-refresh and Snackbar retry. */
    private var lastFetchAddr: String? = null

    /** True while in the immersive fullscreen layout (chrome hidden). */
    private var fullscreen = false

    /**
     * Addresses successfully fetched during this session, oldest first.
     * The system back gesture pops the top entry and re-fetches the new
     * top — same model as a browser's history stack. Cleared by
     * pull-to-clear.
     */
    private val backStack = ArrayDeque<String>()

    private enum class Mode { BROWSE, CHAT }
    private var currentMode = Mode.BROWSE
    private lateinit var chatModeView: ChatModeView

    /**
     * Switch between browse and chat modes.
     *
     * @param persist when true (the default for button-click switches) the
     *   chosen mode is written to [SettingsStore] so the app wakes into it
     *   next launch. Pass [persist] = false for deep-link entries — a
     *   crafted `x0x://pair/` URI must not permanently overwrite the user's
     *   chosen wake-up mode.
     */
    private fun setMode(mode: Mode, persist: Boolean = true) {
        if (mode == currentMode) return
        currentMode = mode
        if (persist) SettingsStore(this).saveLastMode(if (mode == Mode.BROWSE) "browse" else "chat")
        val browse = mode == Mode.BROWSE
        binding.swipeRefresh.isEnabled = browse
        binding.swipeRefresh.visibility = if (browse) View.VISIBLE else View.GONE
        binding.chatContainer.visibility = if (browse) View.GONE else View.VISIBLE
        // Settings sheet intrudes into the chat container — hide in chat, restore in browse.
        val sheetBehavior = com.google.android.material.bottomsheet.BottomSheetBehavior
            .from(binding.settingsSheet)
        if (browse) {
            binding.settingsSheet.visibility = View.VISIBLE
            sheetBehavior.state = com.google.android.material.bottomsheet.BottomSheetBehavior.STATE_COLLAPSED
        } else {
            sheetBehavior.state = com.google.android.material.bottomsheet.BottomSheetBehavior.STATE_COLLAPSED
            binding.settingsSheet.visibility = View.GONE
        }
        if (!browse) {
            // Chat mode always needs back enabled so the gesture returns to browse.
            backCallback.isEnabled = true
            chatModeView.onShown()
        } else {
            // Restore browse back-stack logic: only enabled when there is history.
            backCallback.isEnabled = backStack.size >= 2 || viewingArchiveEntry
        }
    }

    private val backCallback = object : OnBackPressedCallback(false) {
        override fun handleOnBackPressed() {
            // Chat mode: let chat consume the back press first; if it
            // doesn't (stack at root), flip back to browse.
            if (currentMode == Mode.CHAT) {
                if (!chatModeView.onBack()) setMode(Mode.BROWSE)
                return
            }
            // Inner-archive nav: viewing an entry preview, back returns
            // to the listing — no refetch, no address-stack change.
            val ctx = archiveContext
            if (viewingArchiveEntry && ctx != null) {
                viewingArchiveEntry = false
                renderer.showArchive(ctx.address, ctx.entries)
                lastFetchAddr = ctx.address
                isEnabled = backStack.size >= 2
                return
            }
            // Pop the current page; the *new* top is where we want to go.
            // Remove it too so doFetch's push will re-add cleanly without
            // a duplicate entry.
            backStack.removeLastOrNull()
            val prev = backStack.removeLastOrNull() ?: return
            binding.addressInput.setText(prev)
            binding.addressInput.setSelection(prev.length)
            lifecycleScope.launch { doFetch(prev) }
        }
    }

    /** Drives the timed status text under the fetch button. */
    private var statusJob: Job? = null

    /**
     * True once any fetch has succeeded this session. Selects between
     * the pre-first-connection status string set (mentions the bootstrap
     * warmup) and the steady-state set.
     */
    private var hasConnectedOnce = false

    private val saveLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri -> uri?.let(::onSavePicked) }

    /** Bytes waiting for the user to confirm a SAF destination — written
     *  on the matching launcher callback and cleared after. The save and
     *  open-with paths for archive entries / whole archives flow through
     *  here so the launcher result handler can recover the right bytes. */
    private var pendingArchiveSave: ByteArray? = null

    private val archiveSaveLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        val bytes = pendingArchiveSave
        pendingArchiveSave = null
        if (uri == null || bytes == null) return@registerForActivityResult
        BinaryActions.saveTo(this, uri, bytes)
            .onSuccess {
                Snackbar.make(binding.rootCoordinator, R.string.save_done, Snackbar.LENGTH_SHORT).show()
            }
            .onFailure { e ->
                Snackbar.make(
                    binding.rootCoordinator,
                    getString(R.string.save_failed, e.message),
                    Snackbar.LENGTH_LONG,
                ).show()
            }
    }

    /** State of the archive the user is currently navigating inside.
     *  Non-null whenever an archive's listing has been shown this fetch;
     *  preserved through entry previews so the back gesture can restore
     *  the listing without a network refetch. Cleared by `renderer.clear()`
     *  via the close button (`MainActivity.onClose`) or when a fresh
     *  address is fetched.                                              */
    private data class ArchiveContext(
        val address: String,
        val entries: List<uniffi.fetchit_ffi.ArchiveEntryFfi>,
    )
    private var archiveContext: ArchiveContext? = null

    /** True while showing an inner-entry preview inside an open archive
     *  — back press returns to the listing in that mode.                */
    private var viewingArchiveEntry = false

    /** Callbacks the ArchiveView uses to hand work back to the activity. */
    private val archiveCallbacks = object : ArchiveView.Callbacks {
        override fun onSaveArchive(address: String) {
            val bytes = fetchitApp().bytesCache.get(address) ?: return
            pendingArchiveSave = bytes
            archiveSaveLauncher.launch("fetchit-${address.take(8)}.zip")
        }

        override fun onEntryTap(address: String, entryPath: String) {
            val bytes = extractEntryOrToast(address, entryPath) ?: return
            val rendition = try {
                uniffi.fetchit_ffi.detect(bytes)
            } catch (e: Exception) {
                Log.w(TAG, "detect failed for $entryPath", e)
                Snackbar.make(
                    binding.rootCoordinator,
                    getString(R.string.archive_extract_failed, entryPath),
                    Snackbar.LENGTH_LONG,
                ).show()
                return
            }
            // Cache the entry bytes under a synthetic "address" so the
            // existing binary-actions / share paths can pick them up if
            // the rendition turns out to be OpaqueBinary.
            val syntheticAddr = "$address::$entryPath"
            lastFetchAddr = syntheticAddr
            viewingArchiveEntry = true
            backCallback.isEnabled = true
            renderer.render(rendition, syntheticAddr)
        }
    }

    private fun extractEntryOrToast(address: String, entryPath: String): ByteArray? {
        val archive = fetchitApp().bytesCache.get(address) ?: return null
        return try {
            uniffi.fetchit_ffi.extractArchiveEntry(archive, entryPath)
        } catch (e: Exception) {
            Log.w(TAG, "extract failed for $entryPath", e)
            Snackbar.make(
                binding.rootCoordinator,
                getString(R.string.archive_extract_failed, entryPath),
                Snackbar.LENGTH_LONG,
            ).show()
            null
        }
    }

    /**
     * In-app QR scanner. Powered by `zxing-android-embedded` — opens its
     * own scanner Activity, handles the camera permission prompt, returns
     * the decoded text. We accept anything `parseAutonomiInput` accepts
     * (raw 64-hex or `autonomi://<addr>` URL) and reject other QRs.
     */
    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val raw = result?.contents ?: return@registerForActivityResult
        val importPayload = parseBookmarkImportUrl(raw)
        if (importPayload != null) {
            handleBookmarkImport(importPayload)
            return@registerForActivityResult
        }
        // x0x://pair/ URIs go to the chat pairing flow BEFORE the autonomi check.
        // persist = false: scanning a pair QR must not permanently overwrite
        // the user's chosen wake-up mode (same policy as the deep-link path).
        if (io.etchit.fetchit.chat.ChatUris.isPairUri(raw)) {
            setMode(Mode.CHAT, persist = false)
            chatModeView.importFromUri(raw)
            return@registerForActivityResult
        }
        val parsed = parseAutonomiUrl(raw)
        if (parsed == null) {
            Snackbar.make(
                binding.rootCoordinator,
                R.string.scan_qr_not_autonomi,
                Snackbar.LENGTH_LONG,
            ).show()
            return@registerForActivityResult
        }
        loadAddress(parsed.address, parsed.query)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Apply the persisted theme BEFORE setContentView; Android resolves
        // theme attributes at inflation time, so a theme switch elsewhere
        // calls Activity.recreate() and lands here on the new choice.
        setTheme(SettingsStore(this).theme().styleRes)
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        audio = AudioPlayback(this)
        renderer = RenditionRenderer(binding, audio, ::onAudioError, archiveCallbacks)
        store = BookmarkStore(this)
        settingsSheet = SettingsSheet(binding, this).also { it.bind() }
        chatModeView = ChatModeView(
            context = this,
            container = binding.chatContainer,
            controller = fetchitApp().chatController,
            lifecycleScope = lifecycleScope,
            lifecycleOwner = this,
            onLaunchScanner = ::onScanClicked,
            onOpenAutonomi = { addr ->
                setMode(Mode.BROWSE)
                loadAddress(addr)
            },
        )

        binding.fetchButton.setOnTapListener { onFetchClicked() }
        binding.bookmarkButton.setOnClickListener {
            BookmarkSheet().show(supportFragmentManager, "bookmarks")
        }
        binding.scanButton.setOnClickListener { onScanClicked() }
        binding.modeChatButton.setOnClickListener { setMode(Mode.CHAT) }
        binding.modeBrowseButton.setOnClickListener { setMode(Mode.BROWSE) }
        binding.closeButton.setOnClickListener {
            archiveContext = null
            viewingArchiveEntry = false
            renderer.clear()
        }
        binding.epubView.setOnExit { renderer.clear() }
        binding.shareButton.setOnClickListener { onShareCurrentClicked() }
        binding.openWithButton.setOnClickListener { onOpenWithClicked() }
        binding.saveButton.setOnClickListener { onSaveClicked() }
        binding.addressInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                onFetchClicked()
                true
            } else false
        }
        // Hide the smart-paste chip the moment the user starts typing
        // their own address — the chip would be stale at that point.
        binding.addressInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                if (binding.pasteChip.visibility == View.VISIBLE) {
                    binding.pasteChip.visibility = View.GONE
                }
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        // Show the PlayerView's built-in fullscreen button and define
        // what fullscreen means for our chrome (hide everything but
        // the player + close).
        binding.playerView.setFullscreenButtonClickListener { isFullscreen ->
            applyFullscreen(isFullscreen)
        }

        // In-page autonomi:// links: tapping <a href="autonomi://addr">
        // inside a rendered SPA loads that address as a fresh fetch.
        binding.htmlView.setOnAutonomiNavigate { loadAddress(it) }
        binding.htmlView.setOnAutonomiBack(::navigateBack)

        // Restore the last-used mode (browse or chat). Applied before
        // handleViewIntent so a deep-link intent can override it.
        // setMode early-returns on BROWSE (the initial state) so this
        // only triggers a real switch when the persisted mode is "chat".
        val lastMode = SettingsStore(this).lastMode()
        if (lastMode == "chat") setMode(Mode.CHAT)

        // External entry: another app, a QR scanner, or a clicked link
        // routed an autonomi://<addr> intent at us — pick it up.
        handleViewIntent(intent)

        // Pull-down-from-top: full reset — clear the address input,
        // dismiss any rendition, restore the fetch button.
        binding.swipeRefresh.setColorSchemeColors(themeColor(R.attr.fetchitCopper))
        binding.swipeRefresh.setProgressBackgroundColorSchemeColor(themeColor(R.attr.fetchitInk3))
        binding.swipeRefresh.setOnRefreshListener { resetToIdle() }

        onBackPressedDispatcher.addCallback(this, backCallback)
    }

    override fun currentAddressInput(): String =
        binding.addressInput.text.toString().trim()

    override fun recallAddress(address: String) {
        binding.addressInput.setText(address)
        binding.addressInput.setSelection(address.length)
    }

    override fun onDestroy() {
        audio.release()
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        // Smart paste: every time we come to foreground, peek at the
        // clipboard. If it holds an Autonomi-shaped string and the user
        // hasn't already typed something / isn't in the middle of a
        // rendition, surface a one-tap chip so they don't have to
        // long-press → paste → tap-fetch.
        maybeOfferClipboardPaste()
    }

    private fun maybeOfferClipboardPaste() {
        // Only on the idle screen with an empty input.
        if (binding.addressInput.text.isNotEmpty()) return
        if (binding.fetchButton.visibility != View.VISIBLE) return

        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return
        if (!cm.hasPrimaryClip()) return
        val clip = cm.primaryClip ?: return
        if (clip.itemCount == 0) return
        val text = clip.getItemAt(0)?.coerceToText(this)?.toString() ?: return
        val parsed = parseAutonomiUrl(text) ?: return
        val addr = parsed.address

        // Truncated display so the chip stays readable on phones.
        val display = "autonomi://${addr.take(6)}…${addr.takeLast(4)}"
        binding.pasteChip.text = getString(R.string.paste_chip_label, display)
        binding.pasteChip.visibility = View.VISIBLE
        binding.pasteChip.setOnClickListener {
            binding.pasteChip.visibility = View.GONE
            binding.addressInput.setText(addr)
            binding.addressInput.setSelection(addr.length)
            lifecycleScope.launch { doFetch(addr, parsed.query) }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // singleTask + already-running activity gets new intents here
        // rather than via onCreate — must handle both for deep links.
        handleViewIntent(intent)
    }

    private fun handleViewIntent(intent: Intent?) {
        val uri = intent?.data ?: return
        // `fetchit://import?v=1&data=…` is the bookmark-import deep
        // link the desktop's QR-share emits. Route to the
        // confirmation dialog before anything else.
        if (uri.scheme == "fetchit" && uri.host == "import") {
            val parsed = parseBookmarkImportUrl(uri.toString()) ?: return
            handleBookmarkImport(parsed)
            return
        }
        // `x0x://pair/<agent-id>?r=<relay>` deep links: switch to chat
        // mode and hand the URI to ChatModeView which runs connect-first
        // import (Task 4 guarantees this). persist = false so a crafted
        // pair URI cannot permanently overwrite the user's wake-up mode.
        if (uri.scheme == "x0x" && uri.host == "pair") {
            setMode(Mode.CHAT, persist = false)
            chatModeView.importFromUri(uri.toString())
            return
        }
        if (uri.scheme != "autonomi") return
        // `autonomi://abc…` parses with `host = "abc…"`. Some senders
        // produce `autonomi:abc…` (opaque) which lands in
        // `schemeSpecificPart` — accept both shapes. Keep any `?query`
        // so it reaches the renderer.
        val host = uri.host
        val raw = if (host != null) {
            host + (uri.encodedQuery?.let { "?$it" } ?: "")
        } else {
            uri.schemeSpecificPart?.removePrefix("//") ?: return
        }
        val parsed = parseAutonomiUrl(raw) ?: return
        loadAddress(parsed.address, parsed.query)
    }

    /**
     * Show the import-confirmation dialog and, on positive, merge the
     * incoming bookmarks into [`BookmarkStore`]. De-duplication by
     * address is handled inside [`BookmarkStore.mergeImport`] —
     * existing bookmarks win on conflict so the user's chosen labels
     * survive a re-import.
     */
    private fun handleBookmarkImport(payload: BookmarkImport) {
        if (payload.bookmarks.isEmpty()) {
            Snackbar.make(
                binding.rootCoordinator,
                R.string.bookmark_import_empty,
                Snackbar.LENGTH_LONG,
            ).show()
            return
        }
        showBookmarkImportDialog(this, payload) { confirmed ->
            val bookmarks = confirmed.bookmarks.map {
                Bookmark.create(label = it.label.ifBlank { it.address }, address = it.address)
            }
            store.mergeImport(bookmarks)
            val added = bookmarks.size
            Snackbar.make(
                binding.rootCoordinator,
                resources.getQuantityString(
                    R.plurals.bookmark_import_added,
                    added,
                    added,
                ),
                Snackbar.LENGTH_SHORT,
            ).show()
        }
    }

    /** Populate the input and kick off a fetch. Used by deep links + in-page navigation. */
    private fun loadAddress(addr: String, query: String = "") {
        binding.addressInput.setText(addr)
        binding.addressInput.setSelection(addr.length)
        lifecycleScope.launch { doFetch(addr, query) }
    }

    private fun onFetchClicked() {
        val raw = binding.addressInput.text.toString()
        val parsed = parseAutonomiUrl(raw)
        if (parsed == null) {
            showValidationError(getString(R.string.error_invalid_address))
            return
        }
        val addr = parsed.address
        // Re-write the input in canonical form (drop the optional
        // `autonomi://` so the user sees what's actually being fetched).
        if (raw.trim() != addr) {
            binding.addressInput.setText(addr)
            binding.addressInput.setSelection(addr.length)
        }
        lifecycleScope.launch { doFetch(addr, parsed.query) }
    }

    private suspend fun doFetch(addr: String, query: String = "") {
        val app = fetchitApp()
        // Disk cache first — Autonomi addresses are immutable, so a hit
        // is always correct, even across app restarts. Cache-hit path
        // renders directly without clearing or toggling the in-flight
        // fetch chrome.
        val cached = withContext(Dispatchers.IO) { app.bytesCache.get(addr) }
        if (cached != null) {
            try {
                val rendition = withContext(Dispatchers.IO) { detect(cached) }
                afterRender(addr, rendition, cached, query)
                binding.swipeRefresh.isRefreshing = false
                return
            } catch (e: Exception) {
                // Corrupt/unsupported cache entry — fall through and
                // re-fetch from the network with the usual chrome.
                Log.w(TAG, "render from cache failed; refetching", e)
            }
        }
        setFetchInFlight(true)
        renderer.clear()
        lastBinary = null
        try {
            val (rendition, bytes) = withContext(Dispatchers.IO) {
                val client = ensureConnectedClient()
                val b = client.fetch(addr)
                app.bytesCache.put(addr, b)
                detect(b) to b
            }
            afterRender(addr, rendition, bytes, query)
        } catch (e: FetchitException) {
            showFetchError(addr, query, e.message ?: e.toString())
        } catch (e: Exception) {
            Log.e(TAG, "fetch failed", e)
            showFetchError(addr, query, e.message ?: e.toString())
        } finally {
            setFetchInFlight(false)
            binding.swipeRefresh.isRefreshing = false
        }
    }

    /** Common tail of a successful fetch: bind the rendition and record nav state. */
    private fun afterRender(addr: String, rendition: RenditionFfi, bytes: ByteArray, query: String = "") {
        lastBinary = null
        cacheBinaryHandle(rendition)
        // Archive-context bookkeeping: capture the listing when we land
        // on a pure Archive rendition so inner-entry previews can back
        // out to it without a refetch. EPUBs render via their own viewer
        // and don't expose a listing, so they don't open archive context.
        archiveContext = if (
            rendition is RenditionFfi.Archive &&
            !EpubBook.looksLikeEpub(rendition.entries.map { it.path })
        ) {
            ArchiveContext(addr, rendition.entries)
        } else {
            null
        }
        viewingArchiveEntry = false
        if (rendition is RenditionFfi.Archive && EpubBook.looksLikeEpub(rendition.entries.map { it.path })) {
            renderer.bindEpub(addr, bytes, rendition.entries)
        } else {
            renderer.render(rendition, addr, query)
        }
        hasConnectedOnce = true
        lastFetchAddr = addr
        // Push onto the nav stack — but skip if we're already viewing
        // this address (retry, swipe-down + same address, or an in-page
        // link to the current page).
        if (backStack.lastOrNull() != addr) {
            backStack.addLast(addr)
        }
        backCallback.isEnabled = backStack.size >= 2
    }

    /**
     * Handler for an in-page `autonomi://back` link: pop the nav stack,
     * same as a system back press. If there's nothing below the current
     * page (e.g. the user deep-linked straight to a spoke), it's a
     * no-op rather than exiting the app.
     */
    private fun navigateBack() {
        if (backStack.size >= 2) backCallback.handleOnBackPressed()
    }

    private fun resetToIdle() {
        binding.addressInput.setText("")
        renderer.clear()
        lastFetchAddr = null
        lastBinary = null
        backStack.clear()
        backCallback.isEnabled = false
        binding.swipeRefresh.isRefreshing = false
    }

    private suspend fun ensureConnectedClient(): Client {
        val app = fetchitApp()
        app.client()?.let { return it }
        val peers = settingsSheet.savedPeers()
        return withContext(Dispatchers.IO) { app.ensureConnected(peers) }
    }

    private fun setFetchInFlight(inFlight: Boolean) {
        binding.fetchButton.setFetching(inFlight)
        statusJob?.cancel()
        if (inFlight) {
            // Two-stage status: an initial delay before any text appears,
            // then a second timer swaps to the long-fetch string. The
            // string-set pair is selected by hasConnectedOnce.
            val short = if (hasConnectedOnce) R.string.status_fetching else R.string.status_connecting
            val long = if (hasConnectedOnce) R.string.status_still_fetching else R.string.status_first_connection
            statusJob = lifecycleScope.launch {
                delay(STATUS_INITIAL_DELAY_MS)
                binding.fetchStatus.setText(short)
                binding.fetchStatus.visibility = View.VISIBLE
                delay(STATUS_LONG_THRESHOLD_MS - STATUS_INITIAL_DELAY_MS)
                binding.fetchStatus.setText(long)
            }
        } else {
            binding.fetchStatus.visibility = View.GONE
            binding.fetchStatus.text = ""
        }
    }

    private fun onAudioError(msg: String) {
        showFetchError(currentAddressInput(), "", msg)
    }

    /**
     * Toggle the immersive-player layout: hide app chrome, expand the
     * player to fill, hide system bars. Tapping the fullscreen icon
     * again restores everything.
     */
    private fun applyFullscreen(on: Boolean) {
        fullscreen = on
        val chrome = if (on) View.GONE else View.VISIBLE
        binding.addressInput.visibility = chrome
        binding.bookmarkButton.visibility = chrome
        binding.kindText.visibility = chrome
        binding.closeButton.visibility = chrome
        if (currentMode == Mode.BROWSE) binding.settingsSheet.visibility = chrome

        val insets = WindowCompat.getInsetsController(window, window.decorView)
        if (on) {
            insets.hide(WindowInsetsCompat.Type.systemBars())
        } else {
            insets.show(WindowInsetsCompat.Type.systemBars())
        }
    }

    private fun cacheBinaryHandle(r: RenditionFfi) {
        lastBinary = when (r) {
            is RenditionFfi.OpaqueBinary -> r.mime to r.data
            else -> null
        }
    }

    private fun onOpenWithClicked() {
        val (mime, bytes) = lastBinary ?: return
        val ok = BinaryActions.openWith(this, bytes, mime, suggestedName(mime))
        if (!ok) {
            Snackbar.make(
                binding.rootCoordinator,
                getString(R.string.open_no_app, mime),
                Snackbar.LENGTH_LONG,
            ).show()
        }
    }

    private fun onSaveClicked() {
        val (_, _) = lastBinary ?: return
        saveLauncher.launch(suggestedName(lastBinary!!.first))
    }

    private fun onSavePicked(uri: android.net.Uri) {
        val (_, bytes) = lastBinary ?: return
        BinaryActions.saveTo(this, uri, bytes)
            .onSuccess {
                Snackbar.make(binding.rootCoordinator, R.string.save_done, Snackbar.LENGTH_SHORT).show()
            }
            .onFailure { e ->
                Snackbar.make(
                    binding.rootCoordinator,
                    getString(R.string.save_failed, e.message),
                    Snackbar.LENGTH_LONG,
                ).show()
            }
    }

    private fun suggestedName(mime: String): String {
        // Pull a sensible extension out of the mime; fall back to
        // .bin so the user always has a filename to confirm.
        val ext = android.webkit.MimeTypeMap.getSingleton()
            .getExtensionFromMimeType(mime) ?: "bin"
        val short = currentAddressInput().take(8).ifEmpty { "content" }
        return "fetchit-$short.$ext"
    }

    /** Bad input — Snackbar without retry, no state to persist. */
    private fun showValidationError(msg: String) {
        Snackbar.make(binding.rootCoordinator, msg, Snackbar.LENGTH_LONG).show()
        renderer.clear()
    }

    /**
     * Network/decode error — Snackbar with retry. Maps the underlying
     * (technical) `FetchitException` message to a human-friendly one
     * by string-matching known patterns. The technical detail still
     * lands in logcat for debugging.
     */
    private fun showFetchError(addr: String, query: String, msg: String) {
        renderer.clear()
        Log.w(TAG, "fetch error for $addr: $msg")
        val friendly = friendlyFetchError(msg)
        Snackbar.make(binding.rootCoordinator, friendly, Snackbar.LENGTH_INDEFINITE)
            .setAction(R.string.action_retry) {
                lifecycleScope.launch { doFetch(addr, query) }
            }
            .show()
    }

    private fun friendlyFetchError(msg: String): String {
        val lower = msg.lowercase()
        val resId = when {
            "no client connected" in lower || "503" in lower ->
                R.string.error_no_client
            "invalid autonomi address" in lower || "400" in lower ->
                R.string.error_invalid_address
            "chunk not found" in lower || "not found" in lower ||
                "404" in lower || "data_map_fetch" in lower ->
                R.string.error_not_found
            "timed out" in lower || "timeout" in lower ->
                R.string.error_timed_out
            else -> R.string.error_generic
        }
        return getString(resId)
    }

    /**
     * Launch the in-app QR scanner. ZXing handles the camera permission
     * prompt + viewfinder UI; result lands in [`scanLauncher`].
     */
    private fun onScanClicked() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt(getString(R.string.scan_qr_prompt))
            setBeepEnabled(false)
            // ZXing's bundled CaptureActivity declares sensorLandscape
            // in its manifest, which wins over setOrientationLocked.
            // Use our portrait-locked subclass instead.
            setCaptureActivity(PortraitCaptureActivity::class.java)
            setOrientationLocked(true)
        }
        scanLauncher.launch(options)
    }

    /**
     * Share the address currently displayed. Opens the in-app QR preview
     * modal (see `QrPreviewDialog.kt` / `docs/QR-SHARE.md`); from there the
     * user can copy the address, copy the `autonomi://` URL, share the
     * branded PNG card, or fall back to plain-text share. Visible only
     * while content is rendered (see [`RenditionRenderer`]).
     *
     * Passes [openThreadFromBrowse] so the dialog can surface the
     * "send in chat" action alongside the existing share affordances.
     */
    private fun onShareCurrentClicked() {
        val addr = lastFetchAddr ?: return
        showQrPreviewDialog(this, addr, onOpenThread = ::openThreadFromBrowse)
    }

    /**
     * Switch to chat mode and open the thread for [agentIdHex].
     * Used as the "open" callback from the browse-to-chat share bridge
     * (mirrors how [onOpenAutonomi] crosses the boundary in the other
     * direction).
     */
    private fun openThreadFromBrowse(agentIdHex: String) {
        setMode(Mode.CHAT)
        chatModeView.openThread(agentIdHex)
    }

    private companion object {
        const val TAG = "fetchit"
        /** Initial delay before any status text appears; fetches that
         *  finish below this duration display none. */
        const val STATUS_INITIAL_DELAY_MS = 1_500L
        /** Switch to the long-fetch string after this many ms. Set
         *  below the ~10s ant-core connect-warmup ceiling. */
        const val STATUS_LONG_THRESHOLD_MS = 8_000L
    }
}
