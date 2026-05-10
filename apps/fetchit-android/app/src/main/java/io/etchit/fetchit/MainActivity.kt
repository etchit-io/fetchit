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

    private val backCallback = object : OnBackPressedCallback(false) {
        override fun handleOnBackPressed() {
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

    private val saveLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri -> uri?.let(::onSavePicked) }

    /**
     * In-app QR scanner. Powered by `zxing-android-embedded` — opens its
     * own scanner Activity, handles the camera permission prompt, returns
     * the decoded text. We accept anything `parseAutonomiInput` accepts
     * (raw 64-hex or `autonomi://<addr>` URL) and reject other QRs.
     */
    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val raw = result?.contents ?: return@registerForActivityResult
        val addr = parseAutonomiInput(raw)
        if (addr == null) {
            Snackbar.make(
                binding.rootCoordinator,
                R.string.scan_qr_not_autonomi,
                Snackbar.LENGTH_LONG,
            ).show()
            return@registerForActivityResult
        }
        loadAddress(addr)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        audio = AudioPlayback(this)
        renderer = RenditionRenderer(binding, audio, ::onAudioError)
        store = BookmarkStore(this)
        settingsSheet = SettingsSheet(binding, this).also { it.bind() }

        binding.fetchButton.setOnTapListener { onFetchClicked() }
        binding.bookmarkButton.setOnClickListener {
            BookmarkSheet().show(supportFragmentManager, "bookmarks")
        }
        binding.scanButton.setOnClickListener { onScanClicked() }
        binding.closeButton.setOnClickListener { renderer.clear() }
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
        binding.htmlView.setOnAutonomiNavigate(::loadAddress)

        // External entry: another app, a QR scanner, or a clicked link
        // routed an autonomi://<addr> intent at us — pick it up.
        handleViewIntent(intent)

        // Pull-down-from-top: full reset to the idle screen — clear
        // the address input, dismiss any rendition, restore the fetch
        // button. Lighter than ✕ + manual address-clear.
        binding.swipeRefresh.setColorSchemeResources(R.color.copper)
        binding.swipeRefresh.setProgressBackgroundColorSchemeResource(R.color.ink_3)
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
        val addr = parseAutonomiInput(text) ?: return

        // Truncated display so the chip stays readable on phones.
        val display = "autonomi://${addr.take(6)}…${addr.takeLast(4)}"
        binding.pasteChip.text = getString(R.string.paste_chip_label, display)
        binding.pasteChip.visibility = View.VISIBLE
        binding.pasteChip.setOnClickListener {
            binding.pasteChip.visibility = View.GONE
            binding.addressInput.setText(addr)
            binding.addressInput.setSelection(addr.length)
            lifecycleScope.launch { doFetch(addr) }
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
        if (uri.scheme != "autonomi") return
        // `autonomi://abc…` parses with `host = "abc…"`. Some senders
        // produce `autonomi:abc…` (opaque) which lands in
        // `schemeSpecificPart` — accept both shapes.
        val raw = uri.host ?: uri.schemeSpecificPart?.removePrefix("//") ?: return
        val addr = parseAutonomiInput(raw) ?: return
        loadAddress(addr)
    }

    /** Populate the input and kick off a fetch. Used by deep links + in-page navigation. */
    private fun loadAddress(addr: String) {
        binding.addressInput.setText(addr)
        binding.addressInput.setSelection(addr.length)
        lifecycleScope.launch { doFetch(addr) }
    }

    private fun onFetchClicked() {
        val raw = binding.addressInput.text.toString()
        val addr = parseAutonomiInput(raw)
        if (addr == null) {
            showValidationError(getString(R.string.error_invalid_address))
            return
        }
        // Re-write the input in canonical form (drop the optional
        // `autonomi://` so the user sees what's actually being fetched).
        if (raw.trim() != addr) {
            binding.addressInput.setText(addr)
            binding.addressInput.setSelection(addr.length)
        }
        lifecycleScope.launch { doFetch(addr) }
    }

    private suspend fun doFetch(addr: String) {
        setFetchInFlight(true)
        renderer.clear()
        lastBinary = null
        try {
            val app = fetchitApp()
            val rendition = withContext(Dispatchers.IO) {
                // Disk cache first — Autonomi addresses are immutable,
                // so a cache hit is always correct. Skips network
                // entirely on subsequent fetches of the same address,
                // including across app restarts.
                val cached = app.bytesCache.get(addr)
                if (cached != null) {
                    detect(cached)
                } else {
                    val client = ensureConnectedClient()
                    val bytes = client.fetch(addr)
                    app.bytesCache.put(addr, bytes)
                    detect(bytes)
                }
            }
            cacheBinaryHandle(rendition)
            renderer.render(rendition)
            lastFetchAddr = addr
            // Push onto the nav stack — but skip if we're already
            // viewing this address (e.g. retry, swipe-down + same
            // address, or an in-page link to the current page).
            if (backStack.lastOrNull() != addr) {
                backStack.addLast(addr)
            }
            backCallback.isEnabled = backStack.size >= 2
        } catch (e: FetchitException) {
            showFetchError(addr, e.message ?: e.toString())
        } catch (e: Exception) {
            Log.e(TAG, "fetch failed", e)
            showFetchError(addr, e.message ?: e.toString())
        } finally {
            setFetchInFlight(false)
            binding.swipeRefresh.isRefreshing = false
        }
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
            // Two-stage status: a short "connecting…" appears after a
            // brief delay so quick cache hits don't flash text; the
            // longer "first connection takes a moment…" replaces it
            // if the bootstrap is dragging — sets honest expectations
            // instead of leaving the user staring at a spinner.
            statusJob = lifecycleScope.launch {
                delay(STATUS_INITIAL_DELAY_MS)
                binding.fetchStatus.setText(R.string.status_connecting)
                binding.fetchStatus.visibility = View.VISIBLE
                delay(STATUS_LONG_THRESHOLD_MS - STATUS_INITIAL_DELAY_MS)
                binding.fetchStatus.setText(R.string.status_first_connection)
            }
        } else {
            binding.fetchStatus.visibility = View.GONE
            binding.fetchStatus.text = ""
        }
    }

    private fun onAudioError(msg: String) {
        showFetchError(currentAddressInput(), msg)
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
        binding.settingsSheet.visibility = chrome

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
    private fun showFetchError(addr: String, msg: String) {
        renderer.clear()
        Log.w(TAG, "fetch error for $addr: $msg")
        val friendly = friendlyFetchError(msg)
        Snackbar.make(binding.rootCoordinator, friendly, Snackbar.LENGTH_INDEFINITE)
            .setAction(R.string.action_retry) {
                lifecycleScope.launch { doFetch(addr) }
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
     * Share the address currently displayed via the Android share-sheet.
     * Visible only while content is rendered (see [`RenditionRenderer`]).
     */
    private fun onShareCurrentClicked() {
        val addr = lastFetchAddr ?: return
        val url = "autonomi://$addr"
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, url)
            putExtra(Intent.EXTRA_SUBJECT, "fetch>it · $addr")
        }
        startActivity(
            Intent.createChooser(intent, getString(R.string.action_share_label)),
        )
    }

    private companion object {
        const val TAG = "fetchit"
        /** Wait this long before flashing any status text — keeps fast
         *  cache hits invisible (no flicker). */
        const val STATUS_INITIAL_DELAY_MS = 1_500L
        /** Switch from "connecting…" to the long-fetch reassurance after
         *  this many ms. ~10s is the typical bootstrap, so we want the
         *  user reassured a bit before that. */
        const val STATUS_LONG_THRESHOLD_MS = 8_000L
    }
}
