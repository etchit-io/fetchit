# Android LIT P1 - device smoke checklist

For Josh's phone. Pairing partner: the desktop app (chat branch) or a second phone. Install:

```bash
cd apps/fetchit-android
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Prereq already verified from this box: the daemonless client connects to prod NY and publishes pair records (both live smokes green post-redeploy), so every networked step below runs against real infrastructure.

## The checklist

1. **First run** (clear app data first, or fresh install): app opens in CHAT mode showing the empty state. Tap "share my code": either a QR appears (publish succeeded) or an honest error Snackbar with retry (no fake QR). Long-press the QR copies the raw `x0x://pair/` URI.
2. **Mode switch**: the copper `❯` flips to browse; browse is unchanged end to end (fetch a known address, render it, back-stack works, pull-to-refresh works). The `✉` flips back to chat with state intact. Settings sheet peek is absent in chat, present in browse.
3. **Existing-user wake**: kill the app, reopen: it wakes in the LAST USED mode. (A fresh install with bookmarks already present would wake in browse.)
4. **Pairing, desktop to phone**: on desktop, Share my card → copy the pointer URI → encode/scan or paste into the phone's add-contact dialog. Name dialog appears with a sensible default; CANCEL adds nothing; redo + save adds the contact and opens the thread.
5. **Pairing, phone to desktop**: scan the phone's QR with the desktop (or paste the copied URI). Desktop resolves and adds.
6. **DM round-trip**: phone → desktop and desktop → phone; messages appear within seconds; the outbound bubble gains a "✓" tick when the receipt lands.
7. **Receipt-tick scroll behavior**: in a thread with enough messages to scroll, scroll UP, have the peer send nothing while a receipt arrives for an old message: the view must NOT jump to the bottom.
8. **Browse bridge**: send the phone a DM containing `autonomi://<64-hex>` (a real address): it renders as a tappable link; tapping switches to browse and fetches it.
9. **Fediverse channel**: the pinned "fediverse" row opens the read-only feed (it may be empty; no send box must be visible).
10. **Deep link**: from another app (e.g. a notes app), open an `x0x://pair/...` link: the app opens INTO chat, shows the import flow; cancel it; kill + reopen the app: it must wake in whatever mode you last CHOSE, not chat-because-of-the-link.
11. **Back gesture**: thread → list → browse → (browse history) → home, in that order, no app exit from chat.
12. **Rotation**: rotate mid-thread: mode and thread survive.
13. **Connection-loss pill**: enable airplane mode mid-session, send a DM (expect an honest failure Snackbar, typed text restored). If the pump dies, the slim "connection lost" banner appears in chat.

## Known v1 shapes (not bugs)
- Plain palette QR (branded card variant is a queued polish item).
- Message history is in-memory: kill the app, history clears (contacts persist).
- No background receive yet (foreground only; FGS is the next plan).
- Re-entering chat shows a brief "connecting" flash (cheap reconnect check).
