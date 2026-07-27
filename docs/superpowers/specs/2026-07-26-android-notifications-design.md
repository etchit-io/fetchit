# Android Notifications — Design

**Date:** 2026-07-26 · **Approved:** Josh (chat) · **Branch:** `android-notifications`

## Goal

Incoming LIT chat messages (DMs + private groups) notify the user when the
app is backgrounded or closed, without any Google/push dependency.

## Decisions (Josh)

- **Architecture: foreground service.** The app keeps its own relay
  connection alive in a persistent service — the Signal-without-Play-Services
  model. Sovereign, works with today's relay; costs a small status-bar entry
  and battery. Push (FCM/UnifiedPush) can layer on later; the notifier is
  transport-agnostic.
- **Content: sender + preview**, `VISIBILITY_PRIVATE` so Android's own
  lock-screen setting governs what shows while locked.

## Scope

- IN: DMs, private-group messages (the two inbound `ChatEventFfi` arms).
- OUT (follow-ups): fedi DMs (poll-on-open today, not pump events), per-
  conversation mute, relay-only low-power background mode, push transports.

## Architecture

Today `FetchitApplication` owns a lazy app-scoped `ChatController`;
`ChatController.pumpEvents` (companion fn, injected deps, JVM-tested with a
`FakeGateway`) drains `ChatEventFfi` into the stores. `IdleDisconnect` tears
chat down when idle. There is no service and no notification code.

1. **Seam** — `pumpEvents` gains `onInbound: (InboundNotify) -> Unit = {}`,
   fired from the `Dm` and `GroupMessage` arms only. `InboundNotify` carries
   conversation key, kind, sender hex, sender label, body, message id.
   `shouldNotify(inbound, selfAgentHex, visibleConvKey)` is a pure function:
   never for self-authored messages, never for the conversation currently on
   screen.
2. **Notifier** — `MessageNotifier`: two channels ("Messages" high-importance,
   "Background connection" min-importance), one `MessagingStyle` notification
   per conversation keyed by conversation key, `cancel(convKey)` when a
   conversation opens. Content intent deep-links to the conversation.
3. **Service** — `ChatForegroundService` (`remoteMessaging` FGS type on 34+,
   `dataSync` below): `START_STICKY`, posts the persistent min-importance
   notification, ensures the controller gateway, registers the inbound sink.
   `ChatBootReceiver` starts it on boot when enabled. Settings toggle
   `backgroundChatEnabled` (default on); while enabled, `IdleDisconnect`
   skips the chat client.
4. **Prompts** — first enable asks `POST_NOTIFICATIONS` (13+) and offers the
   battery-optimization exemption (Samsung reliability).
5. **Locked vault** — if the service starts before the vault can decrypt, it
   posts a single "Unlock fetch>it to receive messages" notification instead
   of crash-looping.

## Error handling

Pump death → existing `onStopped` path; service observes and retries with
backoff. Service start failures degrade to today's behavior (no service, no
notifications) — never block the UI path.

## Testing

JVM: `shouldNotify` truth table; `pumpEvents` emission (extends existing
FakeGateway tests); notification content builder. Device: backgrounded and
app-killed receive, tap-through, clear-on-open, boot start.
