# Inbox key binding: the signer is not always the author

Record of the 2026-08 fediverse-inbox incident, the rule that replaced
the broken one, and the conditions under which forwarded activities
could ever be stored.

## The incident

`POST /actors/:handle/inbox` was refusing roughly 27% of real inbound
deliveries with `401 signature invalid`. Rejected senders retried for
days. Deliveries from fosstodon.org verified; a recurring minority from
mastodon.social, mastodon.online, chaos.social, phpc.social,
techhub.social and social.linux.pizza failed every single time.

Several plausible causes were killed by evidence before the real one
surfaced: the failing senders' actor documents were structurally
identical to the working one, the newer `/ap/users/<numeric>` actor form
was accepted, and the actor fetch itself always succeeded.

A packet capture correlating request headers with response status
settled it, with 100% correlation:

| `keyId` owner | `activity.actor` | Status |
|---|---|---|
| fosstodon.org/users/happyborg | mastodon.online/users/codechimp | 401 |
| fosstodon.org/users/happyborg | kanoa.de/users/dion | 401 |
| social.vivaldi.net/ap/users/… | same as `keyId` owner | 202 |
| mastodon.social/ap/users/… | same as `keyId` owner | 202 |

Signer equal to the activity's actor was accepted; signer different from
it was refused. Every rejected activity was a `Create(Note)` carrying
`Mention` tags — a thread reply.

## Root cause

The route derived its verification key from the activity's `actor`
field and never parsed the signature's `keyId` at all:

```rust
let Some(sender_url) = activity.get("actor").and_then(Value::as_str) else { … };
let sender = fetchit_fedi::lookup::fetch_remote_actor(&sender_actor_url).await …;
let Some(pubkey_pem) = sender.rsa_public_key_pem.as_deref() else { … };
verify_inbound_signature(&headers, &handle, pubkey_pem, &body, …)
```

HTTP Signatures makes `keyId` authoritative for key selection (RFC 9421
§3.2, draft-cavage §2.1.1). Taking the key from the payload instead
works only while the signer happens to be the author.

It is not, for forwarded activities. Mastodon forwards replies in
threads its users participate in: an account we follow forwards a reply
authored on a third instance, signing the POST with its own key while
`actor` still names the real author. Verifying the forwarder's signature
against the author's key can never succeed, so those deliveries were
mathematically guaranteed to 401 — forever, on every retry.

The diagnosis took weeks because every one of these failures rendered as
the same four words. `signature invalid` covered "wrong key", "wrong
wire format", "covered header we never rebuilt" and "actual forgery"
alike. The rejection log now carries the wire format, the declared
component list with per-component presence, the presented `keyId`, and
whether that `keyId`'s owner matches the activity's actor.

## The rule now

1. Parse `keyId` from the `Signature` header (draft-cavage) or the
   `keyid` parameter of `Signature-Input` (RFC 9421). No parseable
   `keyId` is `401 missing keyId`; an unparseable one is
   `401 keyId is not a url`. Both are decided before any network call.
2. Strip the `#fragment` and fetch the owner, SSRF-guarded, through
   `fetchit_fedi::lookup::fetch_remote_actor`. Verify the signature
   against that document's key. This establishes who DELIVERED the
   request.
3. Compare the authenticated signer to the activity's claimed `actor`.
   Equal means self-delivered: dispatch exactly as before, so every
   binding that worked before still works and means the same thing.
4. Different means forwarded. Acknowledge with `202 ignored (forwarded)`
   and drop the object unread.

Step 3's comparison is between canonical ids on both sides.
`fetch_remote_actor` re-fetches at any `id` that differs from the URL it
fetched, so an aliased `keyId` resolves to the account's real id before
the comparison. Mastodon serves one account at both `/users/<name>` and
`/ap/users/<numeric>`, so a same-host mismatch is resolved with one
authoritative fetch of the claimed actor rather than assumed hostile;
a cross-host mismatch needs no fetch. That resolution fails closed —
an unresolvable claimed actor counts as forwarded.

## Why forwarded objects are not stored

Nothing in a forwarded request authenticates the embedded object. The
forwarder proved only that it sent the bytes. Passing that object to
`handle_create` would let any peer holding a key fabricate a message
attributed to any actor, which is strictly worse than the bug being
fixed.

The considered alternative was to take the object's canonical `id`,
require its host to match the claimed actor's, and re-fetch the
authoritative copy from its origin. That was rejected for this change,
on three grounds:

- It has no effect on stored content. `is_direct_to` stores only notes
  addressed to us with no public and no followers audience. Forwarded
  replies are public thread content by construction — Mastodon forwards
  to the followers collection of the local thread participant — so the
  re-fetched authoritative copy is dropped by the same gate that drops
  the forwarded one. The fetch would run and its result be discarded.
- It adds an outbound fetch that any authenticated peer can aim at a
  host of its choosing, on a public inbox with no rate limit on that
  path. That is a real amplification surface bought for no gain.
- It cannot be tested hermetically. The SSRF guard refuses loopback, so
  the re-fetch would ship unexercised.

The honest position is the one implemented: we do not accept forwarded
replies, and we say so with a distinct status, a distinct log line and a
distinct counter rather than by conflating them with signature failures.

Reopening this is a product decision, not a bug fix. It becomes worth
doing when the client renders public thread context (not just DMs), at
which point the `is_direct_to` gate is no longer the thing discarding
the result. The two viable mechanisms are the origin re-fetch above, or
verifying the `RsaSignature2017` LD-Signature that Mastodon attaches to
forwarded activities — the latter needs JSON-LD URDNA2015
canonicalization, which is a large and historically bug-prone
dependency to take on.

## Denylist

The bridge holds no denylist; the M3/M4 denylist is consumed by the
owner device and by the relay-server's inbox. The positioning
requirement is satisfied structurally here: for self-delivered
activities the authenticated signer IS the author, so any author-level
gate downstream sees the authenticated identity; forwarded activities
never reach a handler at all.

## Counters

| Series | Meaning |
|---|---|
| `fetchit_bridge_inbox_signature_rejected_total` | 401s off the inbox |
| `fetchit_bridge_inbox_forwarded_ignored_total` | authenticated, signer ≠ author |
| `fetchit_bridge_inbox_actor_resolution_failed_total` | same-host actor unresolvable |

The deploy signal is the ratio moving: `signature_rejected` should
collapse toward zero while `forwarded_ignored` picks up the volume that
used to be 401s. If `signature_rejected` stays high, a second cause is
present and the new log fields name it.

## What production traffic still has to confirm

- That the residual `signature_rejected` volume is near zero. Any
  remainder is a different bug, and the wire format / declared component
  list in the log identifies which.
- Whether `actor_resolution_failed` is ever non-zero. It should be rare;
  a steady rate means some instance serves an actor alias that does not
  self-confirm, and the fail-closed choice is silently dropping it.
- Whether any forwarded activity would have passed `is_direct_to`. It
  should never happen, and the assumption underpinning the decision
  above rests on it.
