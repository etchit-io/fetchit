# Android Private-Group Feature -- Device Smoke Test

**For:** Josh (on-device). **Branch:** `android-groups` @ `c496e2e` (assembleDebug green, 32M debug APK). **Validates:** the full Android private-group feature (create / join / send / receive) end-to-end against a real partner + relay -- the one thing the automated gates (239 unit tests + assembleDebug + compileDebugKotlin) cannot cover. On-device is the only outstanding gate before this merges to chat.

**Build + install:**
```
cd apps/fetchit-android && ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**Partner:** a desktop fetch>it (group chat is code-complete both directions on chat -- receive `d847353` + send `3c4a09d`) OR a second Android build. Both must reach the same relay.

## Steps

1. **Connect + DM no-regression:** launch the app, open chat, confirm it connects. Send/receive a DM first to confirm the in-process x0xd embed did not regress the daemonless DM path.
2. **Create (PQ private):** list FAB -> New group -> name it, leave "private (end-to-end encrypted)" CHECKED -> create. Expect: the group thread opens; the group appears in the list with a lock glyph.
3. **Invite:** in the group, share the invite (copies the `x0x://invite/...` URI to the clipboard). Send it to the desktop partner out-of-band.
4. **Join (desktop):** desktop joins the group via the invite.
5. **Desktop -> Android:** desktop sends a group message. Expect: Android receives + renders it in the group thread with a sender label (the desktop's display name, or `agent-<6hex>` fallback).
6. **Android -> Desktop:** Android composes + sends a group message. Expect: desktop receives + renders it; the Android bubble shows outbound.
7. **Bidirectional:** exchange several messages both ways. Expect: all decrypt + render; no crash; the embedded x0xd stays up.
8. **Card-less joiner (Option-B auto-resolve):** if the desktop joiner never DM-paired with the Android sender, confirm the message STILL decrypts (the engine lazy-resolves the sender's ML-DSA card from the relay; soak-proven on infra 2026-06-15).
9. **Lifecycle:** background + return -> reconnect -> group list/history still present. Disconnect (settings / account switch) -> the embedded x0xd shuts down with the client (no leaked process; `adb shell ps` shows none lingering).
10. **Public room (optional):** repeat 2-7 with "private" UNCHECKED (public room). Messages flow plaintext via the SignedPublic path -- `send_to_group` routes by group kind.

## Pass criteria
- Create + join + send + receive all work, both directions, on PQ (private) groups.
- DM path unaffected (no regression from the in-process x0xd embed).
- Lock glyph on private groups; sender labels render on inbound group messages.
- No crash; the embedded x0xd starts (identity keys under app storage, NOT `~/.x0x`) and shuts down cleanly with the client.

## Known v1 scope / non-blockers
- Group send is DIRECT (no outbox/retry for groups in v1 -- matches desktop). A failed send shows a snackbar + restores the text.
- Invite share is clipboard (the existing QR path only accepts pair/autonomi URIs; invite blobs are long base64). A QR-invite affordance is a possible fast-follow.
- The embedded x0xd binds an ephemeral QUIC gossip socket but on mobile NAT mostly relies on the relay bridge for MLS state; that is expected.

## If a step fails
- Capture `adb logcat | grep -iE "chat_ffi|x0xd|private.group|secure"` around the failure.
- "private_group_decrypt_failed" warns = the receive seam ran but decrypt/verify failed (sender card unresolved, or x0xd /secure/decrypt error) -- not a crash, message is dropped.
- App won't launch / x0xd won't start = check the identity-key path (must be under app files dir via the fork's `identity_dir`, x0x-fork `71ff5af`).
