//! `ActivityPub` `Activity` types — `Create`, `Note`, `Follow`, and the
//! fetchit-side `PublicPost` envelope payload.
//!
//! Plan Stage 5.1 lands `PublicPost`; Stage 5.3 expands to `Follow`.

use serde::{Deserialize, Serialize};

/// A C=Public chat-layer post, ready to be wrapped into an `ActivityPub`
/// `Create { object: Note }` activity by Stage 5.2's
/// `Client::publish_public_post` and delivered through
/// [`crate::transport::FediverseTransport`].
///
/// URLs are carried as `String` rather than `url::Url` so the value
/// can pass through `fetchit_trust::canonicalize_url_value` before
/// any denylist check fires; the canonical-on-wire shape matches the
/// denylist manifest values from M4 Stage 4.1. Callers MUST
/// canonicalize before constructing.
///
/// `created_at_ms` is milliseconds-since-epoch in UTC; matches the
/// `ts_ms` convention used elsewhere in the chat layer and avoids
/// pulling a `chrono` dep into the fedi crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPost {
    /// Fediverse handle of the author in `@user@instance` form. Used
    /// by the outbound POST builder as the `actor` field; not
    /// authoritative for denylist purposes (the actor URL is).
    pub author_handle: String,

    /// Markdown body of the post. Rendered to HTML by the recipient's
    /// renderer; the outbound `Note.content` field gets the HTML form
    /// at delivery time.
    pub body_md: String,

    /// Authorship time in milliseconds-since-epoch (UTC).
    pub created_at_ms: u64,

    /// Canonical-form actor URL this post is replying to, when
    /// applicable. `None` for top-level posts.
    pub reply_to_actor_url: Option<String>,

    /// Fediverse handles mentioned in the post, in `@user@instance`
    /// form. Resolution to canonical actor URLs happens in Stage 5.2
    /// at publish-time via `WebFinger`; per-mention denylist gating
    /// fires after that resolution, not at this layer.
    pub mentions: Vec<String>,
}

/// The `ActivityStreams` public-audience magic URI. A value carrying this
/// in `to` is addressed to "the public" — every server treats it as a
/// world-readable post.
pub const PUBLIC_AUDIENCE: &str = "https://www.w3.org/ns/activitystreams#Public";

/// A `Mention` tag inside a [`Note`] — links a `@user@instance` handle
/// (`name`) to the canonical actor URL (`href`) it resolved to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mention {
    /// Always `"Mention"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Canonical actor URL the mention resolved to.
    pub href: String,
    /// Original `@user@instance` handle as written by the author.
    pub name: String,
}

/// An `ActivityStreams` `Note` — the object carried inside a [`CreateActivity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Object id — `<actor_url>/statuses/<created_at_ms>`.
    pub id: String,
    /// Always `"Note"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Authoring actor URL.
    #[serde(rename = "attributedTo")]
    pub attributed_to: String,
    /// HTML body (see [`markdown_body_to_html`] — XSS-safe escaping).
    pub content: String,
    /// RFC 3339 / ISO 8601 UTC timestamp (e.g. `2026-06-08T12:00:00Z`).
    pub published: String,
    /// Primary audience — `[PUBLIC_AUDIENCE]` for a public post.
    pub to: Vec<String>,
    /// Secondary audience — the resolved mention URLs.
    pub cc: Vec<String>,
    /// Object being replied to, when applicable. We carry the
    /// replied-to **actor** URL (the chat layer does not thread a
    /// status URL yet), so threading is approximate until a future
    /// stage carries the parent object id.
    #[serde(rename = "inReplyTo", skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// `Mention` tags — one per resolved mention.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tag: Vec<Mention>,
}

/// An `ActivityStreams` `Create` activity wrapping a [`Note`]. This is the
/// exact JSON shape `POSTed` to a recipient's inbox by
/// `fetchit_chat::Client::publish_public_post`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateActivity {
    /// JSON-LD `@context` — the activitystreams vocabulary URL.
    #[serde(rename = "@context")]
    pub context: String,
    /// Activity id — `<note id>/activity`.
    pub id: String,
    /// Always `"Create"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Authoring actor URL.
    pub actor: String,
    /// RFC 3339 UTC timestamp (mirrors the inner note's `published`).
    pub published: String,
    /// Primary audience — `[PUBLIC_AUDIENCE]`.
    pub to: Vec<String>,
    /// Secondary audience — the resolved mention URLs.
    pub cc: Vec<String>,
    /// The wrapped note.
    pub object: Note,
}

/// Wrap a [`PublicPost`] into the `Create { object: Note }` activity for
/// outbound delivery.
///
/// `actor_url` is the authoring actor's canonical URL.
/// `resolved_mentions` pairs each original `@user@instance` handle with
/// the canonical actor URL it resolved to (via `WebFinger`); they become
/// both `cc` entries and `Mention` tags. The post's `reply_to_actor_url`
/// is carried verbatim into the note's `inReplyTo` (see [`Note::in_reply_to`]).
///
/// Body markdown is rendered through [`markdown_body_to_html`], which
/// escapes all HTML metacharacters — no raw markup is ever emitted, so
/// the activity is XSS-safe by construction.
#[must_use]
pub fn build_create_note(
    post: &PublicPost,
    actor_url: &str,
    resolved_mentions: &[(String, url::Url)],
) -> CreateActivity {
    let published = format_rfc3339_utc(post.created_at_ms);
    let note_id = format!("{actor_url}/statuses/{}", post.created_at_ms);
    let activity_id = format!("{note_id}/activity");

    let cc: Vec<String> = resolved_mentions
        .iter()
        .map(|(_, url)| url.to_string())
        .collect();
    let tag: Vec<Mention> = resolved_mentions
        .iter()
        .map(|(handle, url)| Mention {
            kind: "Mention".to_owned(),
            href: url.to_string(),
            name: handle.clone(),
        })
        .collect();

    let note = Note {
        id: note_id,
        kind: "Note".to_owned(),
        attributed_to: actor_url.to_owned(),
        content: markdown_body_to_html(&post.body_md),
        published: published.clone(),
        to: vec![PUBLIC_AUDIENCE.to_owned()],
        cc: cc.clone(),
        in_reply_to: post.reply_to_actor_url.clone(),
        tag,
    };

    CreateActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: activity_id,
        kind: "Create".to_owned(),
        actor: actor_url.to_owned(),
        published,
        to: vec![PUBLIC_AUDIENCE.to_owned()],
        cc,
        object: note,
    }
}

/// Build a `Create { Note }` for a DIRECT fedi DM to a single recipient —
/// the `ActivityPub` visibility=direct shape (M7 P3). `to` carries only the
/// recipient (never [`PUBLIC_AUDIENCE`]), `cc` is empty, and a `Mention`
/// tag names the recipient so Mastodon threads it as a direct message.
///
/// This message is **not** end-to-end encrypted: the recipient's server —
/// and ours — can read it. The chat layer renders such DMs under a
/// persistent unencrypted-thread banner and never interleaves them with PQ
/// messages (the M7 P3 hard UX rule). Escalation to PQ chat is a separate,
/// user-consented action (P4).
///
/// Body markdown is rendered through [`markdown_body_to_html`], which
/// escapes all HTML metacharacters — no raw markup is ever emitted, so the
/// activity is XSS-safe by construction.
#[must_use]
pub fn build_direct_note(
    actor_url: &str,
    recipient_actor_url: &str,
    recipient_handle: &str,
    body_md: &str,
    created_at_ms: u64,
    reply_to_note_id: Option<&str>,
) -> CreateActivity {
    let published = format_rfc3339_utc(created_at_ms);
    let note_id = format!("{actor_url}/statuses/{created_at_ms}");
    let activity_id = format!("{note_id}/activity");
    let to = vec![recipient_actor_url.to_owned()];
    let tag = vec![Mention {
        kind: "Mention".to_owned(),
        href: recipient_actor_url.to_owned(),
        name: recipient_handle.to_owned(),
    }];

    let note = Note {
        id: note_id,
        kind: "Note".to_owned(),
        attributed_to: actor_url.to_owned(),
        content: markdown_body_to_html(body_md),
        published: published.clone(),
        to: to.clone(),
        cc: Vec::new(),
        in_reply_to: reply_to_note_id.map(str::to_owned),
        tag,
    };

    CreateActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: activity_id,
        kind: "Create".to_owned(),
        actor: actor_url.to_owned(),
        published,
        to,
        cc: Vec::new(),
        object: note,
    }
}

/// An `ActivityStreams` `Follow` activity (M7 P1). The exact JSON shape
/// `POSTed` to the target actor's inbox when one of our actors follows a
/// remote account, and the shape we parse back out of a verified inbound
/// `Follow` when a remote account follows us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowActivity {
    /// JSON-LD `@context` — the activitystreams vocabulary URL.
    #[serde(rename = "@context")]
    pub context: String,
    /// Activity id — `<actor_url>/follows/<unique>`; the inbound `Accept`
    /// is matched against this exact id, so it must be unique per request.
    pub id: String,
    /// Always `"Follow"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The following actor's URL (us, outbound; them, inbound).
    pub actor: String,
    /// The actor being followed.
    pub object: String,
}

/// An `Accept` (or `Reject`) wrapping the `Follow` it answers. Mastodon
/// echoes the full `Follow` object back; matching is done on
/// `object.id`, never on the sender's word alone — the HTTP-signature
/// gate has already bound the envelope to the accepting actor's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowResponseActivity {
    /// JSON-LD `@context`.
    #[serde(rename = "@context")]
    pub context: String,
    /// Activity id — `<actor_url>/accepts/<unique>`.
    pub id: String,
    /// `"Accept"` or `"Reject"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The actor answering the follow (the followee).
    pub actor: String,
    /// The `Follow` being answered, echoed in full.
    pub object: FollowActivity,
}

/// An `Undo` wrapping the `Follow` it retracts (unfollow, both
/// directions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoFollowActivity {
    /// JSON-LD `@context`.
    #[serde(rename = "@context")]
    pub context: String,
    /// Activity id — `<follow id>/undo`.
    pub id: String,
    /// Always `"Undo"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The actor retracting its follow.
    pub actor: String,
    /// The original `Follow`, echoed in full.
    pub object: FollowActivity,
}

/// Build the outbound `Follow` for `actor_url` → `target_actor_url`.
///
/// `unique` disambiguates the activity id (callers pass a timestamp or
/// counter); the returned activity's `id` is what the remote `Accept`
/// must echo, so persist it before delivery.
#[must_use]
pub fn build_follow(actor_url: &str, target_actor_url: &str, unique: u64) -> FollowActivity {
    FollowActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: format!("{actor_url}/follows/{unique}"),
        kind: "Follow".to_owned(),
        actor: actor_url.to_owned(),
        object: target_actor_url.to_owned(),
    }
}

/// Build the `Accept` answering a verified inbound `follow` on behalf of
/// `actor_url` (the followee — one of our actors).
#[must_use]
pub fn build_accept_follow(
    actor_url: &str,
    follow: &FollowActivity,
    unique: u64,
) -> FollowResponseActivity {
    FollowResponseActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: format!("{actor_url}/accepts/{unique}"),
        kind: "Accept".to_owned(),
        actor: actor_url.to_owned(),
        object: follow.clone(),
    }
}

/// Build the `Undo(Follow)` retracting `follow` (unfollow).
#[must_use]
pub fn build_undo_follow(actor_url: &str, follow: &FollowActivity) -> UndoFollowActivity {
    UndoFollowActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: format!("{}/undo", follow.id),
        kind: "Undo".to_owned(),
        actor: actor_url.to_owned(),
        object: follow.clone(),
    }
}

/// An `ActivityStreams` `Like` — a favourite of one post. `object` is
/// the target Note's URL, not an embedded object: that is the shape
/// Mastodon-family servers accept, and it keeps the activity a fixed
/// size regardless of what is being liked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LikeActivity {
    /// JSON-LD `@context` — the activitystreams vocabulary URL.
    #[serde(rename = "@context")]
    pub context: String,
    /// Activity id — `<actor_url>/likes/<unique>`; the `Undo` echoes it.
    pub id: String,
    /// Always `"Like"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The liking actor's URL (us, outbound).
    pub actor: String,
    /// URL of the post being liked.
    pub object: String,
}

/// An `Undo` wrapping the `Like` it retracts (unlike).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoLikeActivity {
    /// JSON-LD `@context`.
    #[serde(rename = "@context")]
    pub context: String,
    /// Activity id — `<like id>/undo`.
    pub id: String,
    /// Always `"Undo"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The actor retracting its like.
    pub actor: String,
    /// The original `Like`, echoed in full.
    pub object: LikeActivity,
}

/// Build the outbound `Like` for `actor_url` → `object_url`.
///
/// The activity id is derived from `object_url`'s hash rather than a
/// clock, so liking the same post twice mints the SAME id: a re-send
/// after a failed delivery is idempotent on the receiving server, and
/// [`build_undo_like`] can retract a like this device no longer has any
/// record of.
#[must_use]
pub fn build_like(actor_url: &str, object_url: &str) -> LikeActivity {
    LikeActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: format!("{actor_url}/likes/{}", stable_object_tag(object_url)),
        kind: "Like".to_owned(),
        actor: actor_url.to_owned(),
        object: object_url.to_owned(),
    }
}

/// Build the `Undo(Like)` retracting `like` (unlike).
#[must_use]
pub fn build_undo_like(actor_url: &str, like: &LikeActivity) -> UndoLikeActivity {
    UndoLikeActivity {
        context: "https://www.w3.org/ns/activitystreams".to_owned(),
        id: format!("{}/undo", like.id),
        kind: "Undo".to_owned(),
        actor: actor_url.to_owned(),
        object: like.clone(),
    }
}

/// A stable, URL-path-safe tag for `object_url`: the lowercase hex of
/// its FNV-1a 64 hash. Deterministic across devices and restarts, and
/// free of any character that would need escaping in an activity id.
///
/// Not a security primitive — a collision costs two posts one shared
/// like-activity id on our own server's namespace, nothing more — so a
/// dependency-free hash is the right size for the job.
fn stable_object_tag(object_url: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in object_url.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Render a post's markdown body to the HTML that goes in `Note.content`.
///
/// Intentionally minimal and **XSS-safe by construction**: every HTML
/// metacharacter is escaped and no raw markup is passed through, so a
/// hostile body cannot inject script into a recipient's renderer. Hard
/// line breaks become `<br>`; the whole body is wrapped in one `<p>`.
/// Rich markdown (bold, links, lists) is deferred to a later stage —
/// recipients see escaped plain text until then.
///
/// The one markup we *do* emit is an anchor per Autonomi address (see
/// [`linkify_autonomi_addresses`]) — the funnel that turns a mention of
/// a content address on Mastodon into a tappable link to the fetch>it
/// landing page. Anchors are synthesised from a hex-only match, never
/// passed through from the body, so the XSS-safe-by-construction claim
/// still holds.
#[must_use]
pub fn markdown_body_to_html(body: &str) -> String {
    let escaped = body
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    let linked = linkify_autonomi_addresses(&escaped);
    let with_breaks = linked.replace('\n', "<br>");
    format!("<p>{with_breaks}</p>")
}

/// Landing page an Autonomi address links to in an outbound public post.
/// The address rides in the fragment, so the hex never reaches the
/// server's logs and the page resolves it client-side.
const ADDRESS_LANDING_BASE: &str = "https://etchit.io/a/#";

/// Length of an Autonomi content address in hex characters.
const ADDRESS_HEX_LEN: usize = 64;

/// Is `b` a character that may not sit immediately beside an address
/// token? Mirrors the Android detector's `[0-9A-Za-z_]` lookaround, so a
/// 65-character hex run — or a 64-hex substring glued into a longer
/// identifier — never linkifies.
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Wrap every Autonomi address in `escaped` in an anchor to the fetch>it
/// landing page.
///
/// Token grammar mirrors `AutonomiRefs.kt` on Android — an optional
/// `autonomi://` scheme, an optional `0x`, then exactly 64 hex
/// characters, with no `[0-9A-Za-z_]` character
/// immediately adjacent on either side. The `href` carries the bare
/// lowercase hex; the anchor TEXT is the matched token verbatim, so a
/// fetch>it client reducing the HTML back to text with
/// [`crate::text::html_to_text`] recovers exactly what the author typed
/// and still renders its own content card.
///
/// Takes ALREADY-ESCAPED input: hex, `:` and `/` all survive escaping
/// unchanged, and every entity the escape pass emits ends in `;` (never
/// a token character), so matching after escaping sees the same token
/// boundaries as matching before it — while keeping the emitted anchor
/// out of the escaper's reach.
#[must_use]
pub fn linkify_autonomi_addresses(escaped: &str) -> String {
    let bytes = escaped.as_bytes();
    let mut out = String::with_capacity(escaped.len());
    let mut i = 0usize;
    while i < bytes.len() {
        // A token can only start where the previous byte is not a token
        // character (the lookbehind).
        let boundary_before = i == 0 || !is_token_char(bytes[i - 1]);
        if boundary_before {
            if let Some((end, hex)) = match_address(bytes, i) {
                out.push_str("<a href=\"");
                out.push_str(ADDRESS_LANDING_BASE);
                out.push_str(&hex);
                out.push_str("\">");
                out.push_str(&escaped[i..end]);
                out.push_str("</a>");
                i = end;
                continue;
            }
        }
        // Not a token start: copy this character and move on. `i` always
        // lands on a char boundary — every branch above advances past
        // ASCII only, and this one advances by a whole character.
        let ch_len = escaped[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&escaped[i..i + ch_len]);
        i += ch_len;
    }
    out
}

/// Try to match one address token at `start`. Returns the exclusive end
/// offset and the lowercase hex, or `None` when no token starts here.
fn match_address(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    /// Optional scheme prefix, matched ASCII-case-insensitively.
    const SCHEME: &[u8] = b"autonomi://";
    let mut i = start;
    if bytes.len() - i >= SCHEME.len() && bytes[i..i + SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        i += SCHEME.len();
    }
    // Optional `0x` prefix (the Autonomi app prefixes public addresses).
    if bytes.len() - i >= 2 && bytes[i] == b'0' && (bytes[i + 1] | 0x20) == b'x' {
        i += 2;
    }
    let hex_start = i;
    if bytes.len() - hex_start < ADDRESS_HEX_LEN {
        return None;
    }
    let hex_end = hex_start + ADDRESS_HEX_LEN;
    if !bytes[hex_start..hex_end].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    // The lookahead: a 65th hex character (or any other token character)
    // means this run is not a free-standing address.
    if bytes.get(hex_end).copied().is_some_and(is_token_char) {
        return None;
    }
    let hex = String::from_utf8(bytes[hex_start..hex_end].to_ascii_lowercase()).ok()?;
    Some((hex_end, hex))
}

/// Format milliseconds-since-epoch (UTC) as an RFC 3339 / ISO 8601
/// instant, e.g. `2026-06-08T12:00:00Z`. Dependency-free (no `chrono`
/// / `time`) — derives the civil date via Howard Hinnant's
/// `civil_from_days` algorithm.
#[must_use]
pub fn format_rfc3339_utc(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert a count of days since the Unix epoch to `(year, month, day)`
/// in the proleptic Gregorian calendar. Howard Hinnant's
/// `civil_from_days` (public domain), shifted from the 0000-03-01 era
/// origin to the 1970-01-01 epoch via the `719_468` offset. Kept in
/// `u64` throughout: `days` is derived from a `u64` millisecond count,
/// so it is always `>= 0` and every intermediate term stays
/// non-negative (no signed casts, no truncation).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample() -> PublicPost {
        PublicPost {
            author_handle: "@josh@etchit.io".to_owned(),
            body_md: "Hello fediverse.".to_owned(),
            created_at_ms: 1_780_876_000_000,
            reply_to_actor_url: Some("https://mastodon.example/users/alice".to_owned()),
            mentions: vec!["@alice@mastodon.example".to_owned()],
        }
    }

    #[test]
    fn public_post_serde_round_trip() {
        let p = sample();
        let json = serde_json::to_string(&p).unwrap();
        let back: PublicPost = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn public_post_top_level_has_no_reply_to() {
        let mut p = sample();
        p.reply_to_actor_url = None;
        p.mentions.clear();
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"reply_to_actor_url\":null"));
        let back: PublicPost = serde_json::from_str(&json).unwrap();
        assert!(back.reply_to_actor_url.is_none());
        assert!(back.mentions.is_empty());
    }

    #[test]
    fn format_rfc3339_utc_known_values() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // 1_700_000_000 s since epoch is a widely-cited instant.
        assert_eq!(
            format_rfc3339_utc(1_700_000_000_000),
            "2023-11-14T22:13:20Z"
        );
        // Sub-second millis are truncated, not rounded.
        assert_eq!(format_rfc3339_utc(999), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn markdown_body_to_html_escapes_and_breaks() {
        let html = markdown_body_to_html("a <script>&\"'\nb");
        assert_eq!(html, "<p>a &lt;script&gt;&amp;&quot;&#39;<br>b</p>");
        // No raw angle-bracketed tag survives the escape.
        assert!(!html.contains("<script>"));
    }

    // ---- funnel: autonomi addresses become links on Mastodon ----

    /// 64 hex characters, mixed case, so the lowercasing of the `href`
    /// is visible in the assertions.
    const ADDR: &str = "AbC1230000000000000000000000000000000000000000000000000000000def";
    const ADDR_LOWER: &str = "abc1230000000000000000000000000000000000000000000000000000000def";

    #[test]
    fn bare_address_linkifies_to_the_landing_page() {
        let html = markdown_body_to_html(&format!("read this {ADDR} now"));
        assert_eq!(
            html,
            format!(
                "<p>read this <a href=\"https://etchit.io/a/#{ADDR_LOWER}\">{ADDR}</a> now</p>"
            ),
        );
    }

    #[test]
    fn prefixed_forms_linkify_and_keep_their_text_verbatim() {
        for token in [
            format!("autonomi://{ADDR}"),
            format!("0x{ADDR}"),
            format!("autonomi://0x{ADDR}"),
            format!("AUTONOMI://{ADDR}"),
        ] {
            let html = markdown_body_to_html(&token);
            assert_eq!(
                html,
                format!("<p><a href=\"https://etchit.io/a/#{ADDR_LOWER}\">{token}</a></p>"),
                "token {token} must linkify with its original text",
            );
        }
    }

    #[test]
    fn adjacent_word_characters_never_linkify() {
        // A 65-hex run, a 63-hex run, and a 64-hex run glued into a
        // longer identifier: none is a free-standing address, so none
        // may sprout a link (mirrors AutonomiRefs.kt's lookarounds).
        for body in [
            format!("{ADDR}0"),
            format!("0{ADDR}"),
            ADDR[..63].to_owned(),
            format!("id_{ADDR}"),
            format!("{ADDR}_id"),
            format!("autonomi://{ADDR}f"),
        ] {
            let html = markdown_body_to_html(&body);
            assert!(
                !html.contains("<a href"),
                "{body} must not linkify, got {html}",
            );
        }
    }

    #[test]
    fn punctuation_around_a_token_still_leaves_it_free_standing() {
        for (body, expect_link) in [
            (format!("({ADDR})"), true),
            (format!("{ADDR}."), true),
            (format!("see:{ADDR}"), true),
            (format!("\"{ADDR}\""), true),
        ] {
            let html = markdown_body_to_html(&body);
            assert_eq!(
                html.contains("<a href"),
                expect_link,
                "body {body} produced {html}",
            );
        }
    }

    #[test]
    fn escaping_of_surrounding_text_is_unaffected() {
        // A `<` and an `&` beside the token still escape, and the entity
        // they produce (ending in `;`) does not glue itself to the token.
        let html = markdown_body_to_html(&format!("a<b & {ADDR} <end>"));
        assert!(html.starts_with("<p>a&lt;b &amp; <a href="), "got {html}");
        assert!(html.ends_with("</a> &lt;end&gt;</p>"), "got {html}");
        assert!(!html.contains("<end>"), "got {html}");
    }

    #[test]
    fn an_entity_immediately_before_a_token_does_not_block_the_link() {
        // `&`, `<`, `"` and `'` all escape to entities ending in `;`,
        // which is not a token character — the same boundary the raw
        // character had. Pin it so a future escape change that emits a
        // trailing word character is caught here.
        for lead in ['&', '<', '>', '"', '\''] {
            let html = markdown_body_to_html(&format!("{lead}{ADDR}"));
            assert!(html.contains("<a href"), "lead {lead:?} gave {html}");
        }
    }

    #[test]
    fn multiple_addresses_in_one_body_all_linkify() {
        let second = "f".repeat(64);
        let html = markdown_body_to_html(&format!("{ADDR} and {second}"));
        assert_eq!(html.matches("<a href").count(), 2, "got {html}");
        assert!(html.contains(&format!("https://etchit.io/a/#{second}")));
    }

    #[test]
    fn newlines_still_become_breaks_around_a_link() {
        let html = markdown_body_to_html(&format!("top\n{ADDR}\nbottom"));
        assert_eq!(
            html,
            format!(
                "<p>top<br><a href=\"https://etchit.io/a/#{ADDR_LOWER}\">{ADDR}</a><br>bottom</p>"
            ),
        );
    }

    #[test]
    fn non_ascii_bodies_survive_the_scan() {
        // The scanner indexes by byte, so a multi-byte character next to
        // a token must not split a char boundary (that would panic).
        let html = markdown_body_to_html(&format!("héllo — {ADDR} ✨"));
        assert!(html.contains("héllo — <a href="), "got {html}");
        assert!(html.ends_with("</a> ✨</p>"), "got {html}");
    }

    #[test]
    fn round_trip_through_html_to_text_recovers_the_original_token() {
        // fetch>it clients reduce wire HTML to text and grow their own
        // content card from the token, so the anchor must collapse back
        // to exactly what the author typed.
        for token in [
            ADDR.to_owned(),
            format!("autonomi://{ADDR}"),
            format!("0x{ADDR}"),
        ] {
            let body = format!("look: {token} !");
            let html = markdown_body_to_html(&body);
            assert_eq!(crate::text::html_to_text(&html), body, "token {token}");
        }
    }

    #[test]
    fn build_create_note_top_level_golden() {
        let post = PublicPost {
            author_handle: "@josh@etchit.io".to_owned(),
            body_md: "Hello fediverse.".to_owned(),
            created_at_ms: 1_700_000_000_000,
            reply_to_actor_url: None,
            mentions: vec![],
        };
        let activity = build_create_note(&post, "https://etchit.io/actors/josh", &[]);
        let json = serde_json::to_value(&activity).unwrap();

        assert_eq!(json["@context"], "https://www.w3.org/ns/activitystreams");
        assert_eq!(json["type"], "Create");
        assert_eq!(json["actor"], "https://etchit.io/actors/josh");
        assert_eq!(
            json["id"],
            "https://etchit.io/actors/josh/statuses/1700000000000/activity"
        );
        assert_eq!(json["to"][0], PUBLIC_AUDIENCE);
        let note = &json["object"];
        assert_eq!(note["type"], "Note");
        assert_eq!(
            note["id"],
            "https://etchit.io/actors/josh/statuses/1700000000000"
        );
        assert_eq!(note["attributedTo"], "https://etchit.io/actors/josh");
        assert_eq!(note["content"], "<p>Hello fediverse.</p>");
        assert_eq!(note["published"], "2023-11-14T22:13:20Z");
        // Empty audience + tag are omitted from the wire form.
        assert!(note.get("inReplyTo").is_none());
        assert!(note.get("tag").is_none());
        assert_eq!(note["cc"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn build_create_note_with_mentions_and_reply() {
        let post = PublicPost {
            author_handle: "@josh@etchit.io".to_owned(),
            body_md: "hi".to_owned(),
            created_at_ms: 1_700_000_000_000,
            reply_to_actor_url: Some("https://mastodon.example/users/alice".to_owned()),
            mentions: vec!["@alice@mastodon.example".to_owned()],
        };
        let resolved = vec![(
            "@alice@mastodon.example".to_owned(),
            url::Url::parse("https://mastodon.example/users/alice").unwrap(),
        )];
        let activity = build_create_note(&post, "https://etchit.io/actors/josh", &resolved);
        let json = serde_json::to_value(&activity).unwrap();
        let note = &json["object"];

        assert_eq!(note["inReplyTo"], "https://mastodon.example/users/alice");
        assert_eq!(json["cc"][0], "https://mastodon.example/users/alice");
        assert_eq!(note["cc"][0], "https://mastodon.example/users/alice");
        assert_eq!(note["tag"][0]["type"], "Mention");
        assert_eq!(
            note["tag"][0]["href"],
            "https://mastodon.example/users/alice"
        );
        assert_eq!(note["tag"][0]["name"], "@alice@mastodon.example");
    }

    #[test]
    fn build_direct_note_is_direct_visibility() {
        let activity = build_direct_note(
            "https://etchit.io/actors/josh",
            "https://fosstodon.org/users/happyborg",
            "@happyborg@fosstodon.org",
            "hey, want to move to private chat?",
            1_700_000_000_000,
            None,
        );
        let json = serde_json::to_value(&activity).unwrap();

        // Direct visibility: addressed only to the recipient, never Public,
        // and cc empty at both the activity and note level.
        assert_eq!(json["to"][0], "https://fosstodon.org/users/happyborg");
        assert!(!json["to"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == PUBLIC_AUDIENCE));
        assert_eq!(json["cc"].as_array().unwrap().len(), 0);
        let note = &json["object"];
        assert_eq!(note["to"][0], "https://fosstodon.org/users/happyborg");
        assert!(!note["to"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == PUBLIC_AUDIENCE));
        assert_eq!(note["cc"].as_array().unwrap().len(), 0);
        // The recipient is tagged so Mastodon threads it as a DM, and the
        // body is HTML-escaped through the shared markdown renderer.
        assert_eq!(note["tag"][0]["type"], "Mention");
        assert_eq!(
            note["tag"][0]["href"],
            "https://fosstodon.org/users/happyborg"
        );
        assert_eq!(note["tag"][0]["name"], "@happyborg@fosstodon.org");
        assert_eq!(note["content"], "<p>hey, want to move to private chat?</p>");
        assert_eq!(note["attributedTo"], "https://etchit.io/actors/josh");
    }

    #[test]
    fn build_direct_note_threads_under_reply_target() {
        // With a reply target, inReplyTo carries it so the recipient's
        // client nests the DM into the ongoing thread.
        let parent = "https://fosstodon.org/users/happyborg/statuses/999";
        let activity = build_direct_note(
            "https://etchit.io/actors/josh",
            "https://fosstodon.org/users/happyborg",
            "@happyborg@fosstodon.org",
            "replying in-thread",
            1_700_000_000_000,
            Some(parent),
        );
        let json = serde_json::to_value(&activity).unwrap();
        assert_eq!(json["object"]["inReplyTo"], parent);
    }

    #[test]
    fn build_direct_note_first_contact_has_no_reply_field() {
        // No reply target -> inReplyTo is omitted entirely (serde skips
        // None), so a first-contact DM is a clean standalone note.
        let activity = build_direct_note(
            "https://etchit.io/actors/josh",
            "https://fosstodon.org/users/happyborg",
            "@happyborg@fosstodon.org",
            "first hello",
            1_700_000_000_000,
            None,
        );
        let json = serde_json::to_value(&activity).unwrap();
        assert!(json["object"].get("inReplyTo").is_none());
    }

    #[test]
    fn build_direct_note_escapes_html_body() {
        let activity = build_direct_note(
            "https://etchit.io/actors/josh",
            "https://fosstodon.org/users/happyborg",
            "@happyborg@fosstodon.org",
            "<script>alert(1)</script>",
            1_700_000_000_000,
            None,
        );
        let json = serde_json::to_value(&activity).unwrap();
        assert!(!json["object"]["content"]
            .as_str()
            .unwrap()
            .contains("<script>"));
    }

    #[test]
    fn follow_round_trips_and_accept_echoes_id() {
        let me = "https://bridge.example/actors/josh";
        let them = "https://fosstodon.org/users/happyborg";
        let follow = build_follow(me, them, 1234);
        assert_eq!(follow.id, "https://bridge.example/actors/josh/follows/1234");

        // serde round-trip: the wire shape Mastodon sees
        let v = serde_json::to_value(&follow).unwrap();
        assert_eq!(v["type"], "Follow");
        assert_eq!(v["actor"], me);
        assert_eq!(v["object"], them);
        assert_eq!(v["@context"], "https://www.w3.org/ns/activitystreams");
        let back: FollowActivity = serde_json::from_value(v).unwrap();
        assert_eq!(back, follow);

        // Accept wraps the follow verbatim -- matching key is object.id
        let accept = build_accept_follow(them, &follow, 99);
        let av = serde_json::to_value(&accept).unwrap();
        assert_eq!(av["type"], "Accept");
        assert_eq!(av["actor"], them);
        assert_eq!(av["object"]["id"], follow.id);
        assert_eq!(av["object"]["type"], "Follow");
    }

    #[test]
    fn undo_wraps_the_original_follow() {
        let me = "https://bridge.example/actors/josh";
        let follow = build_follow(me, "https://fosstodon.org/users/happyborg", 7);
        let undo = build_undo_follow(me, &follow);
        let v = serde_json::to_value(&undo).unwrap();
        assert_eq!(v["type"], "Undo");
        assert_eq!(v["id"], format!("{}/undo", follow.id));
        assert_eq!(v["object"]["id"], follow.id);
        assert_eq!(
            v["object"]["object"],
            "https://fosstodon.org/users/happyborg"
        );
    }

    #[test]
    fn like_wire_shape_and_undo_echo() {
        let me = "https://bridge.example/actors/josh";
        let post = "https://fosstodon.org/@happyborg/12345";
        let like = build_like(me, post);

        let v = serde_json::to_value(&like).unwrap();
        assert_eq!(v["type"], "Like");
        assert_eq!(v["actor"], me);
        assert_eq!(v["object"], post, "object is the post URL, not the author");
        assert_eq!(v["@context"], "https://www.w3.org/ns/activitystreams");
        assert!(v["id"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{me}/likes/")));
        let back: LikeActivity = serde_json::from_value(v).unwrap();
        assert_eq!(back, like);

        let undo = build_undo_like(me, &like);
        let uv = serde_json::to_value(&undo).unwrap();
        assert_eq!(uv["type"], "Undo");
        assert_eq!(uv["id"], format!("{}/undo", like.id));
        assert_eq!(uv["object"]["id"], like.id);
        assert_eq!(uv["object"]["object"], post);
    }

    #[test]
    fn like_id_is_stable_per_post_and_distinct_across_posts() {
        // Re-liking the same post must mint the SAME id: a retry after a
        // failed delivery is then idempotent remotely, and an Undo can be
        // built from the object URL alone with no local like record.
        let me = "https://bridge.example/actors/josh";
        let a = build_like(me, "https://fosstodon.org/@happyborg/1");
        let again = build_like(me, "https://fosstodon.org/@happyborg/1");
        assert_eq!(a.id, again.id);
        let b = build_like(me, "https://fosstodon.org/@happyborg/2");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn like_id_is_path_safe_for_any_object_url() {
        // Object URLs carry slashes, query strings, and unicode; the id
        // segment they produce must stay a bare hex token.
        let me = "https://bridge.example/actors/josh";
        for url in [
            "https://h/@u/1?x=1&y=2#frag",
            "https://h/users/ünicode/statuses/9",
            "",
        ] {
            let id = build_like(me, url).id;
            let tag = id.rsplit('/').next().unwrap();
            assert_eq!(tag.len(), 16);
            assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn inbound_mastodon_follow_parses() {
        // Shape Mastodon actually delivers (no published, exact fields).
        let raw = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://fosstodon.org/8b3a92c0-1111-2222-3333-444455556666",
            "type": "Follow",
            "actor": "https://fosstodon.org/users/happyborg",
            "object": "https://bridge.example/actors/josh"
        });
        let f: FollowActivity = serde_json::from_value(raw).unwrap();
        assert_eq!(f.kind, "Follow");
        assert_eq!(f.actor, "https://fosstodon.org/users/happyborg");
    }
}
