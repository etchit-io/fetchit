//! Tolerant remote-actor lookup (M5.1, Component A).
//!
//! [`RemoteActor`] decodes ANY well-formed `ActivityPub` actor,
//! attestation present or not, so the desktop can render public-only
//! cards for vanilla fediverse accounts. This type is for CLIENT
//! lookup only: relay-side ingest keeps the strict
//! [`crate::actor::Actor`] decode (attestation required), and that
//! boundary is deliberate; widening relay ingest is M5.2 scope.

use crate::actor::{
    fetch_json_ld_at_url, is_actor_class_type, pinned_no_redirect_client, required_str,
    spki_pem_to_der, ActorError, FetchActorError, ACTOR_FETCH_TIMEOUT,
    PQ_ATTESTATION_V2_PROPERTY_URI,
};
use crate::attestation::ActorAttestationV2;
use serde_json::Value;
use std::time::{Duration, Instant};

/// A remote actor as seen by the lookup path. Every field beyond the
/// identity pair is optional; trust is established exclusively by
/// [`RemoteActor::verify_attestation_v2`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteActor {
    /// Canonical actor URL (`id`).
    pub id: url::Url,
    /// `inbox` endpoint — where Follow/Create/DM activities are posted.
    /// Mandatory per `ActivityPub` §4.1; every real actor serves one.
    pub inbox: url::Url,
    /// `preferredUsername` as served; the local part of the handle.
    pub preferred_username: String,
    /// `outbox` collection URL when served (every Mastodon-family actor
    /// has one; optional here so exotic actors still decode).
    pub outbox: Option<url::Url>,
    /// `publicKey.publicKeyPem` when served.
    pub rsa_public_key_pem: Option<String>,
    /// v2 attestation when served. Present-but-malformed is a decode
    /// error, never silently `None`.
    pub attestation_v2: Option<ActorAttestationV2>,
    /// The actor's avatar URL as served in `icon`, when present. Pure
    /// remote input: nothing here is validated at decode time —
    /// [`crate::avatar::fetch_avatar`] owns the https + SSRF + size +
    /// content-type gates. `None` for an actor with no usable icon.
    pub icon_url: Option<String>,
    /// `name` — the actor's chosen display name, when served. Remote
    /// text: renderers show it beside, never instead of, the handle.
    /// `None` when absent or served empty.
    pub name: Option<String>,
    /// `summary` — the actor's bio, as served. RAW remote HTML; callers
    /// reduce it with [`crate::text::html_to_text`] before display, the
    /// same contract as [`RemotePost::content_html`].
    pub summary: Option<String>,
}

/// A non-empty, trimmed string field off a remote document, or `None`.
/// A server that serves `"name": ""` means "no name", not "a name that
/// is blank" — collapsing both here keeps every caller's fallback logic
/// to one `is_none` check.
fn optional_str(value: &Value, key: &str) -> Option<String> {
    let s = value.get(key).and_then(Value::as_str)?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

impl RemoteActor {
    /// Decode from an actor JSON-LD document, tolerating absent
    /// attestation and public key.
    ///
    /// # Errors
    ///
    /// [`ActorError`] on missing `id`/`preferredUsername`, a non-actor
    /// `type`, a `publicKey.owner` that does not match `id`, or a
    /// malformed v2 attestation value.
    pub fn from_json_ld(value: &Value) -> Result<Self, ActorError> {
        // Same actor-class allowlist as the strict decode: a Note or
        // Activity object styled as an actor is rejected outright.
        if let Some(type_str) = value.get("type").and_then(Value::as_str) {
            if !is_actor_class_type(type_str) {
                return Err(ActorError::InvalidField {
                    name: "type".into(),
                    reason: format!(
                        "expected one of {{Person, Service, Application, Organization, Group}}; got {type_str:?}"
                    ),
                });
            }
        }
        let id_str = required_str(value, "id")?;
        let id: url::Url = id_str.parse().map_err(|e| ActorError::InvalidField {
            name: "id".into(),
            reason: format!("{e}"),
        })?;
        let inbox_str = required_str(value, "inbox")?;
        let inbox: url::Url = inbox_str.parse().map_err(|e| ActorError::InvalidField {
            name: "inbox".into(),
            reason: format!("{e}"),
        })?;
        let preferred_username = required_str(value, "preferredUsername")?.to_owned();
        let outbox = value
            .get("outbox")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok());
        let rsa_public_key_pem = match value.get("publicKey") {
            None => None,
            Some(pk) => {
                // Tolerant on missing owner, strict on present-but-wrong
                // (same rule as the strict decode).
                if let Some(owner) = pk.get("owner").and_then(Value::as_str) {
                    if owner != id_str {
                        return Err(ActorError::InvalidField {
                            name: "publicKey.owner".into(),
                            reason: format!("owner {owner:?} does not match Actor id {id_str:?}"),
                        });
                    }
                }
                pk.get("publicKeyPem")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }
        };
        let attestation_v2 = match value.get(PQ_ATTESTATION_V2_PROPERTY_URI) {
            None => None,
            Some(raw) => Some(
                serde_json::from_value::<ActorAttestationV2>(raw.clone())
                    .map_err(|e| ActorError::Attestation(format!("v2: {e}")))?,
            ),
        };
        let icon_url = crate::avatar::icon_url_from_actor_doc(value);
        Ok(Self {
            id,
            inbox,
            preferred_username,
            outbox,
            rsa_public_key_pem,
            attestation_v2,
            icon_url,
            name: optional_str(value, "name"),
            summary: optional_str(value, "summary"),
        })
    }

    /// Verify the v2 attestation, returning the derived agent id hex.
    /// Fails closed when either the attestation or the RSA key is
    /// absent; callers render the public-only card on any error.
    ///
    /// # Errors
    ///
    /// [`ActorError`] wrapping the attestation failure surface.
    pub fn verify_attestation_v2(&self) -> Result<String, ActorError> {
        let att = self
            .attestation_v2
            .as_ref()
            .ok_or_else(|| ActorError::Attestation("no v2 attestation on actor".into()))?;
        let pem = self
            .rsa_public_key_pem
            .as_deref()
            .ok_or_else(|| ActorError::MissingField {
                name: "publicKey.publicKeyPem".into(),
            })?;
        let spki_der = spki_pem_to_der(pem).map_err(|reason| ActorError::InvalidField {
            name: "publicKey.publicKeyPem".into(),
            reason,
        })?;
        Ok(crate::attestation::verify_binding_v2(
            &self.preferred_username,
            &self.id,
            &spki_der,
            att,
        )?)
    }
}

/// Fetch and tolerantly decode a remote actor. Same SSRF hardening as
/// [`crate::actor::fetch_actor`] (private-IP pre-flight, DNS pinning,
/// no redirects, body cap, timeout).
///
/// The returned document's `id` is BOUND to the URL it was fetched
/// from: an `id` differing from the fetch URL is trusted only after one
/// re-fetch AT the claimed id confirms the same claim (the Mastodon
/// rule). Without this, any host could serve a document impersonating
/// an actor it does not control, and every downstream sender binding —
/// inbox dispatch, the follow-request queue, follower fan-out records —
/// would be forgeable by a hostile instance.
///
/// # Errors
///
/// Same [`FetchActorError`] surface as the strict fetch, plus
/// [`FetchActorError::IdMismatch`] when the claimed id fails to
/// self-confirm.
pub async fn fetch_remote_actor(actor_url: &url::Url) -> Result<RemoteActor, FetchActorError> {
    let actor = fetch_remote_actor_once(actor_url).await?;
    if actor.id == *actor_url {
        return Ok(actor);
    }
    // Exactly one hop: the claimed id must serve a document naming
    // itself. The re-fetch rides the same SSRF-guarded client path.
    let claimed = actor.id.clone();
    let refetched = fetch_remote_actor_once(&claimed).await?;
    if refetched.id == claimed {
        Ok(refetched)
    } else {
        Err(FetchActorError::IdMismatch {
            fetched_from: actor_url.to_string(),
            claimed: refetched.id.to_string(),
        })
    }
}

async fn fetch_remote_actor_once(actor_url: &url::Url) -> Result<RemoteActor, FetchActorError> {
    let client = pinned_no_redirect_client(actor_url, ACTOR_FETCH_TIMEOUT).await?;
    let value = fetch_json_ld_at_url(&client, actor_url, ACTOR_FETCH_TIMEOUT).await?;
    RemoteActor::from_json_ld(&value).map_err(FetchActorError::Parse)
}

/// One `Mention` tag off a remote Note: the visible `@user@host` text
/// (`name`) and the actor URL it points at (`href`).
///
/// Both fields are remote-authored strings carried verbatim. `href` is
/// NOT validated here — a consumer that acts on it (profile fetch,
/// follow, DM) runs it back through the SSRF-guarded resolve + denylist
/// gate first, exactly as it would a handle the user typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MentionRef {
    /// The mention as written in the body, e.g. `@alice@mastodon.example`.
    pub name: String,
    /// Actor URL the mention resolved to on the authoring server.
    pub href: String,
}

/// Mentions retained per post. Beyond this the tail is dropped: a
/// hostile server can put thousands of `Mention` tags on one Note, and
/// a feed row renders a handful.
pub const MAX_MENTIONS_PER_POST: usize = 32;

/// One post from a remote actor's outbox, reduced to what a feed
/// renders. `content_html` is the wire HTML as served — callers strip
/// it with [`crate::text::html_to_text`] before display; it must never
/// reach a renderer raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePost {
    /// Author actor URL (`attributedTo`, falling back to the wrapping
    /// activity's `actor`).
    pub author_url: String,
    /// The Note's `content` — raw HTML off the wire.
    pub content_html: String,
    /// ISO-8601 `published` stamp as served (empty when absent). UTC
    /// ISO-8601 sorts lexicographically, so feeds can order on the
    /// string without a datetime parse.
    pub published: String,
    /// Human-facing URL of the post (`url`, falling back to `id`).
    pub object_url: String,
    /// `Mention` tags on the Note, capped at [`MAX_MENTIONS_PER_POST`].
    /// Empty for a post that mentions nobody.
    pub mentions: Vec<MentionRef>,
}

/// Collect `Mention` entries from a Note's `tag`. Tolerant of every
/// shape servers actually serve: absent, a lone object, or an array
/// mixing Mentions with Hashtags and Emoji. Non-Mention types and
/// entries missing either field are skipped, never fatal — a malformed
/// tag must cost the mention, not the post.
fn mentions_from_tag(note: &Value) -> Vec<MentionRef> {
    let one = |v: &Value| -> Option<MentionRef> {
        if v.get("type").and_then(Value::as_str)? != "Mention" {
            return None;
        }
        Some(MentionRef {
            name: optional_str(v, "name")?,
            href: optional_str(v, "href")?,
        })
    };
    match note.get("tag") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(one)
            .take(MAX_MENTIONS_PER_POST)
            .collect(),
        Some(v @ Value::Object(_)) => one(v).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn post_from_note(note: &Value, fallback_author: Option<&str>) -> Option<RemotePost> {
    let author_url = note
        .get("attributedTo")
        .and_then(Value::as_str)
        .or(fallback_author)?
        .to_owned();
    let content_html = note
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if content_html.is_empty() {
        return None;
    }
    let published = note
        .get("published")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let object_url = note
        .get("url")
        .and_then(Value::as_str)
        .or_else(|| note.get("id").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned();
    Some(RemotePost {
        author_url,
        content_html,
        published,
        object_url,
        mentions: mentions_from_tag(note),
    })
}

/// Pure parse: collect the `Create(Note)` items (and tolerated bare
/// `Note` items) from an outbox page's `orderedItems`, newest-first as
/// served, capped at `cap`. Boosts (`Announce`) and non-Note objects
/// are skipped — the v1 feed renders authored text posts only.
#[must_use]
pub fn posts_from_outbox_page(page: &Value, cap: usize) -> Vec<RemotePost> {
    let Some(items) = page.get("orderedItems").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if out.len() >= cap {
            break;
        }
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        let post = match kind {
            "Create" => {
                let activity_actor = item.get("actor").and_then(Value::as_str);
                match item.get("object") {
                    Some(obj) if obj.get("type").and_then(Value::as_str) == Some("Note") => {
                        post_from_note(obj, activity_actor)
                    }
                    _ => None,
                }
            }
            "Note" => post_from_note(item, None),
            _ => None,
        };
        if let Some(p) = post {
            out.push(p);
        }
    }
    out
}

/// Fetch the newest posts from an actor's outbox: GET the collection,
/// follow its `first` page when the items aren't inline (the
/// Mastodon-family shape), and reduce to at most `cap` [`RemotePost`]s.
/// Same SSRF hardening as [`fetch_remote_actor`] on both requests.
///
/// # Errors
///
/// Same [`FetchActorError`] surface as the actor fetch; a page with no
/// parsable items is `Ok(vec![])`, not an error (fail-open to an empty
/// feed entry, never a broken feed).
pub async fn fetch_outbox_posts(
    outbox: &url::Url,
    cap: usize,
) -> Result<Vec<RemotePost>, FetchActorError> {
    let client = pinned_no_redirect_client(outbox, ACTOR_FETCH_TIMEOUT).await?;
    let collection = fetch_json_ld_at_url(&client, outbox, ACTOR_FETCH_TIMEOUT).await?;
    if collection.get("orderedItems").is_some() {
        return Ok(posts_from_outbox_page(&collection, cap));
    }
    match collection.get("first") {
        Some(Value::String(first_url)) => {
            let Ok(first) = first_url.parse::<url::Url>() else {
                return Ok(Vec::new());
            };
            let client = pinned_no_redirect_client(&first, ACTOR_FETCH_TIMEOUT).await?;
            let page = fetch_json_ld_at_url(&client, &first, ACTOR_FETCH_TIMEOUT).await?;
            Ok(posts_from_outbox_page(&page, cap))
        }
        Some(embedded @ Value::Object(_)) => Ok(posts_from_outbox_page(embedded, cap)),
        _ => Ok(Vec::new()),
    }
}

// ── thread replies ────────────────────────────────────────────────────
//
// A reply lives in the REPLIER's outbox on THEIR server, so walking the
// accounts we follow can never surface it. An `ActivityPub` Note carries
// a `replies` Collection instead, and Mastodon populates it — so a
// thread is pulled on demand exactly the way the feed is pulled, and
// nothing is stored anywhere on our side.

/// Replies retained for one thread. A hostile — or merely enormous —
/// thread has to cost a bounded amount of memory and screen, and fifty
/// is well past the point where a reader opens the post on its home
/// server instead.
pub const MAX_THREAD_REPLIES: usize = 50;

/// Collection/page GETs spent walking one thread's `replies`.
///
/// Mastodon's replies collection is deliberately two-staged: the inline
/// `first` page carries the author's OWN self-replies (usually empty)
/// and its `next` — `?only_other_accounts=true` — is where everybody
/// else's replies live. One page fetch would therefore show an empty
/// room for almost every real thread; two is the smallest number that
/// shows the conversation, and also the ceiling, because every page is a
/// round trip whose timing a remote server chooses.
pub const MAX_THREAD_REPLY_PAGES: usize = 2;

/// Reply objects dereferenced per thread. Mastodon reduces every
/// non-local reply in the collection to a bare URI string, so most
/// entries cost their own GET; uncapped, one popular post would mean
/// fifty requests from a phone.
pub const MAX_THREAD_REPLY_FETCHES: usize = 20;

/// Wall-clock ceiling for one whole thread pull, across every request it
/// makes. [`ACTOR_FETCH_TIMEOUT`] bounds each request on its own, but a
/// server answering slowly-but-legally to twenty of them would still
/// hold a view open for minutes. Whatever has been collected when the
/// budget runs out is what the caller gets.
pub const THREAD_FETCH_BUDGET: Duration = Duration::from_secs(20);

/// One entry in a replies collection page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyEntry {
    /// The page carried the whole object; nothing left to fetch.
    Inline(RemotePost),
    /// The page carried only the reply's URI — what Mastodon serves for
    /// every reply that is not local to the collection's own server.
    Url(String),
}

/// One parsed replies page: the entries it carried plus the `next` page
/// when it names one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepliesPage {
    /// Entries in served order, capped by the caller's `cap`.
    pub entries: Vec<ReplyEntry>,
    /// `next` page URL as served, when the page names one.
    pub next: Option<String>,
}

/// One thread as a reader shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadReplies {
    /// Replies oldest-first, capped at [`MAX_THREAD_REPLIES`].
    pub replies: Vec<RemotePost>,
    /// The post's document carried a `replies` collection we could read.
    ///
    /// Not decoration: "nobody has replied" and "this server does not
    /// publish replies" are different facts about the world, and a
    /// reader that draws them identically is lying about one of them.
    pub collection_served: bool,
}

/// The host of `url`, lowercased; `None` for anything unparsable or
/// hostless.
fn host_of(url: &str) -> Option<String> {
    url.parse::<url::Url>()
        .ok()?
        .host_str()
        .map(str::to_lowercase)
}

/// Whether an object served by `origin_host` may claim `author_url`.
///
/// A replies collection is a list of URLs its own server chose, and an
/// inlined object is bytes that server wrote. Without this rule any host
/// could serve a reply attributed to somebody else's actor and it would
/// render under that person's name. `ActivityPub`'s authoritative-origin
/// rule is the answer: a document is evidence only about actors on the
/// host that served it.
fn author_matches_origin(author_url: &str, origin_host: &str) -> bool {
    host_of(author_url).is_some_and(|h| h == origin_host)
}

/// A `Note`, or a `Create` wrapping one, reduced to a [`RemotePost`].
/// Both shapes turn up inside replies collections.
fn post_from_object(value: &Value) -> Option<RemotePost> {
    match value.get("type").and_then(Value::as_str).unwrap_or("") {
        "Create" => {
            let activity_actor = value.get("actor").and_then(Value::as_str);
            let obj = value.get("object")?;
            if obj.get("type").and_then(Value::as_str) == Some("Note") {
                post_from_note(obj, activity_actor)
            } else {
                None
            }
        }
        "Note" => post_from_note(value, None),
        _ => None,
    }
}

/// `next` as a URL, whether the page serves it as a string or as a
/// `CollectionPage` object naming its own `id`.
fn next_page_url(page: &Value) -> Option<String> {
    match page.get("next")? {
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_owned())
            }
        }
        v @ Value::Object(_) => optional_str(v, "id"),
        _ => None,
    }
}

/// Pure parse of one replies page, tolerating every shape servers
/// actually serve: `items` or `orderedItems`; entries that are bare URI
/// strings, bare `Note` objects, `Create` activities wrapping one, or
/// stubs carrying only an `id`.
///
/// `origin_host` is the host that served the page. An inline object
/// attributed to an actor on a DIFFERENT host is dropped: an inlined
/// object is bytes the origin wrote, and without the
/// authoritative-origin rule any host could serve a reply attributed to
/// somebody else's actor and it would render under that person's name.
/// Malformed entries are skipped, never fatal: one junk item costs that
/// reply, not the thread.
#[must_use]
pub fn replies_page_from_value(page: &Value, origin_host: &str, cap: usize) -> RepliesPage {
    let items = page
        .get("items")
        .or_else(|| page.get("orderedItems"))
        .and_then(Value::as_array);
    let mut entries = Vec::new();
    for item in items.into_iter().flatten() {
        if entries.len() >= cap {
            break;
        }
        match item {
            Value::String(uri) => {
                let trimmed = uri.trim();
                if !trimmed.is_empty() {
                    entries.push(ReplyEntry::Url(trimmed.to_owned()));
                }
            }
            Value::Object(_) => {
                if let Some(post) = post_from_object(item) {
                    if author_matches_origin(&post.author_url, origin_host) {
                        entries.push(ReplyEntry::Inline(post));
                    }
                } else if let Some(id) = optional_str(item, "id") {
                    // A stub carrying an id and no content: the object
                    // itself is one dereference away.
                    entries.push(ReplyEntry::Url(id));
                }
            }
            _ => {}
        }
    }
    RepliesPage {
        entries,
        next: next_page_url(page),
    }
}

/// Drop entries naming a reply already collected, keeping first-seen
/// order. A `next` page can repeat what the page before it carried, and
/// a repeat costs a wasted dereference and a duplicated row.
fn dedup_entries(entries: Vec<ReplyEntry>) -> Vec<ReplyEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = match &entry {
            ReplyEntry::Inline(post) => post.object_url.clone(),
            ReplyEntry::Url(uri) => uri.clone(),
        };
        // A reply with no identity at all can't be de-duped; keep it
        // rather than collapsing every such reply into one row.
        if key.is_empty() || seen.insert(key) {
            out.push(entry);
        }
    }
    out
}

/// Order a thread the way it is read: down the page, oldest first.
///
/// UTC ISO-8601 sorts lexicographically. A reply with no stamp goes LAST
/// rather than first — an empty string sorts before every date, and
/// calling an undated reply the oldest one is a claim we cannot make.
fn sort_oldest_first(replies: &mut [RemotePost]) {
    replies.sort_by(|a, b| {
        (a.published.is_empty(), &a.published).cmp(&(b.published.is_empty(), &b.published))
    });
}

/// Fetch one collection page, refusing to leave the origin host and to
/// exceed either budget. `None` for every refusal and every failure —
/// the walk simply stops with what it already has.
async fn fetch_reply_page(
    url_str: &str,
    origin_host: &str,
    deadline: Instant,
    pages_fetched: &mut usize,
) -> Option<Value> {
    if *pages_fetched >= MAX_THREAD_REPLY_PAGES || Instant::now() >= deadline {
        return None;
    }
    let url: url::Url = url_str.parse().ok()?;
    // A collection page for this post's thread lives on the server that
    // served the post. A `first`/`next` pointing elsewhere is the remote
    // steering our reader onto a host of its choosing, so it is refused
    // rather than followed.
    if url.host_str().map(str::to_lowercase).as_deref() != Some(origin_host) {
        return None;
    }
    *pages_fetched += 1;
    let client = pinned_no_redirect_client(&url, ACTOR_FETCH_TIMEOUT)
        .await
        .ok()?;
    fetch_json_ld_at_url(&client, &url, ACTOR_FETCH_TIMEOUT)
        .await
        .ok()
}

/// Dereference one reply URI and reduce it. `None` for anything that
/// fails — an unreachable, oversized, unparsable or misattributed reply
/// costs itself and nothing else.
async fn fetch_reply_object(uri: &str) -> Option<RemotePost> {
    let url: url::Url = uri.parse().ok()?;
    let host = url.host_str()?.to_lowercase();
    let client = pinned_no_redirect_client(&url, ACTOR_FETCH_TIMEOUT)
        .await
        .ok()?;
    let value = fetch_json_ld_at_url(&client, &url, ACTOR_FETCH_TIMEOUT)
        .await
        .ok()?;
    let post = post_from_object(&value)?;
    author_matches_origin(&post.author_url, &host).then_some(post)
}

/// Pull the replies to the post at `object_url`, on demand and without
/// storing anything anywhere.
///
/// GET the object, read its `replies` value, and walk it: a bare URL is
/// fetched, an inline `Collection` is followed through `first`, a
/// `CollectionPage`'s `items`/`orderedItems` are read, and `next` is
/// followed while both budgets hold ([`MAX_THREAD_REPLY_PAGES`],
/// [`THREAD_FETCH_BUDGET`]). Entries that are bare URIs are dereferenced
/// up to [`MAX_THREAD_REPLY_FETCHES`] times. Every request rides the
/// same pinned, redirect-free, size-capped, SSRF-guarded client as
/// [`fetch_outbox_posts`], with the same per-request timeout.
///
/// Replies come back oldest-first and capped at [`MAX_THREAD_REPLIES`].
/// [`ThreadReplies::collection_served`] separates "no replies yet" from
/// "this server published no replies collection".
///
/// # Errors
///
/// [`FetchActorError`] only when the POST ITSELF could not be fetched —
/// everything after that degrades to fewer replies rather than an error,
/// because a half-read thread is still a thread.
pub async fn fetch_thread_replies(object_url: &url::Url) -> Result<ThreadReplies, FetchActorError> {
    let deadline = Instant::now() + THREAD_FETCH_BUDGET;
    let client = pinned_no_redirect_client(object_url, ACTOR_FETCH_TIMEOUT).await?;
    let object = fetch_json_ld_at_url(&client, object_url, ACTOR_FETCH_TIMEOUT).await?;
    let Some(origin_host) = object_url.host_str().map(str::to_lowercase) else {
        return Ok(ThreadReplies::default());
    };

    let mut pages_fetched = 0usize;
    let unread = ThreadReplies::default();
    let Some(replies) = object.get("replies") else {
        return Ok(unread);
    };
    let mut page = match replies {
        Value::Object(_) => replies.clone(),
        Value::String(url_str) => {
            match fetch_reply_page(url_str, &origin_host, deadline, &mut pages_fetched).await {
                Some(v) => v,
                // Named but unreadable: we cannot claim the collection
                // was served, and the reader says so.
                None => return Ok(unread),
            }
        }
        _ => return Ok(unread),
    };

    let empty = ThreadReplies {
        replies: Vec::new(),
        collection_served: true,
    };
    // A Collection wrapping its pages: step into `first` before reading.
    if page.get("items").is_none() && page.get("orderedItems").is_none() {
        match page.get("first") {
            Some(Value::String(first_url)) => {
                match fetch_reply_page(first_url, &origin_host, deadline, &mut pages_fetched).await
                {
                    Some(v) => page = v,
                    None => return Ok(empty),
                }
            }
            Some(embedded @ Value::Object(_)) => page = embedded.clone(),
            _ => return Ok(empty),
        }
    }

    let mut entries: Vec<ReplyEntry> = Vec::new();
    loop {
        let room = MAX_THREAD_REPLIES.saturating_sub(entries.len());
        let parsed = replies_page_from_value(&page, &origin_host, room);
        entries.extend(parsed.entries);
        entries = dedup_entries(entries);
        if entries.len() >= MAX_THREAD_REPLIES || Instant::now() >= deadline {
            break;
        }
        let Some(next) = parsed.next else { break };
        let Some(v) = fetch_reply_page(&next, &origin_host, deadline, &mut pages_fetched).await
        else {
            break;
        };
        page = v;
    }

    let mut replies: Vec<RemotePost> = Vec::new();
    let mut fetches = 0usize;
    for entry in entries {
        if replies.len() >= MAX_THREAD_REPLIES {
            break;
        }
        match entry {
            ReplyEntry::Inline(post) => replies.push(post),
            ReplyEntry::Url(uri) => {
                // Out of dereference budget: skip this one, but keep
                // walking — the inline entries behind it are free.
                if fetches >= MAX_THREAD_REPLY_FETCHES || Instant::now() >= deadline {
                    continue;
                }
                fetches += 1;
                if let Some(post) = fetch_reply_object(&uri).await {
                    replies.push(post);
                }
            }
        }
    }
    sort_oldest_first(&mut replies);
    Ok(ThreadReplies {
        replies,
        collection_served: true,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/gargron_actor.json")).unwrap()
    }

    #[test]
    fn vanilla_actor_without_attestation_decodes_with_none() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.attestation_v2.is_none());
        assert!(actor.rsa_public_key_pem.is_some());
        assert_eq!(actor.preferred_username, "gargron");
    }

    // The inbox is what we POST Follow/Create/DM activities to. It must
    // decode for a plain Mastodon actor that carries no PQ attestation —
    // this is the type delivery uses so a non-fetchit target is reachable.
    #[test]
    fn remote_actor_exposes_inbox_without_attestation() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(
            actor.inbox.as_str(),
            "https://mastodon.example/users/gargron/inbox"
        );
    }

    // An actor doc missing the mandatory `inbox` is malformed and useless
    // for delivery — decode must fail rather than yield an unreachable actor.
    #[test]
    fn remote_actor_missing_inbox_is_rejected() {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove("inbox");
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn actor_without_public_key_decodes_with_none_pem() {
        let mut v = fixture();
        let obj = v.as_object_mut().unwrap();
        obj.remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        obj.remove("publicKey");
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.rsa_public_key_pem.is_none());
    }

    #[test]
    fn non_actor_class_is_rejected() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .insert("type".into(), serde_json::json!("Note"));
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn forged_public_key_owner_is_rejected() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        v["publicKey"]["owner"] = serde_json::json!("https://evil.example/actors/mallory");
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn malformed_v2_attestation_is_a_hard_error() {
        let mut v = fixture();
        v.as_object_mut().unwrap().insert(
            PQ_ATTESTATION_V2_PROPERTY_URI.into(),
            serde_json::json!("garbage"),
        );
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn v2_attestation_is_decoded_and_verifies() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![7u8; 16];
        let pem = crate::actor::spki_der_to_pem(&spki_der);
        let (att2, derived) = crate::attestation::test_attested_v2(
            "josh",
            &actor_url,
            &spki_der,
            &"a".repeat(64),
            "https://relay.example/",
            3,
        );
        let v = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "josh",
            "inbox": format!("{}/inbox", actor_url.as_str()),
            "publicKey": { "owner": actor_url.as_str(), "publicKeyPem": pem },
            PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(actor.attestation_v2, Some(att2));
        assert_eq!(actor.verify_attestation_v2().unwrap(), derived);
    }

    #[test]
    fn verify_without_attestation_or_pem_fails_closed() {
        let v = serde_json::json!({
            "id": "https://x.example/a",
            "type": "Person",
            "preferredUsername": "a",
            "inbox": "https://x.example/a/inbox",
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.verify_attestation_v2().is_err());

        // Attestation present but no RSA key: still fails closed.
        let actor_url: url::Url = "https://etchit.io/actors/a".parse().unwrap();
        let (att2, _) = crate::attestation::test_attested_v2(
            "a",
            &actor_url,
            &[1],
            &"a".repeat(64),
            "https://relay.example/",
            1,
        );
        let v2 = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "a",
            "inbox": format!("{}/inbox", actor_url.as_str()),
            PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor2 = RemoteActor::from_json_ld(&v2).unwrap();
        assert!(actor2.verify_attestation_v2().is_err());
    }

    #[test]
    fn tampered_v2_attestation_fails_verification() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![7u8; 16];
        let pem = crate::actor::spki_der_to_pem(&spki_der);
        let (mut att2, _) = crate::attestation::test_attested_v2(
            "josh",
            &actor_url,
            &spki_der,
            &"a".repeat(64),
            "https://relay.example/",
            3,
        );
        att2.relay_hint = "https://evil.example/".into();
        let v = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "josh",
            "inbox": format!("{}/inbox", actor_url.as_str()),
            "publicKey": { "owner": actor_url.as_str(), "publicKeyPem": pem },
            PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.verify_attestation_v2().is_err());
    }

    #[test]
    fn remote_actor_exposes_outbox_when_served() {
        let mut v = fixture();
        v["outbox"] = serde_json::json!("https://mastodon.example/users/g/outbox");
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(
            actor.outbox.unwrap().as_str(),
            "https://mastodon.example/users/g/outbox"
        );
        // Absent outbox stays None — exotic actors still decode.
        let mut bare = fixture();
        bare.as_object_mut().unwrap().remove("outbox");
        assert!(RemoteActor::from_json_ld(&bare).unwrap().outbox.is_none());
    }

    #[test]
    fn remote_actor_carries_the_icon_url_when_served() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        v["icon"] = serde_json::json!({
            "type": "Image", "mediaType": "image/png",
            "url": "https://files.mastodon.example/avatars/1.png"
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(
            actor.icon_url.as_deref(),
            Some("https://files.mastodon.example/avatars/1.png")
        );

        // An actor with no icon decodes exactly as before — the avatar
        // is additive, never a decode requirement.
        let mut bare = fixture();
        bare.as_object_mut().unwrap().remove("icon");
        assert!(RemoteActor::from_json_ld(&bare).unwrap().icon_url.is_none());
    }

    #[test]
    fn remote_actor_carries_display_name_and_bio_when_served() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        v["name"] = serde_json::json!("Eugen Rochko");
        v["summary"] = serde_json::json!("<p>Founder of <b>Mastodon</b>.</p>");
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(actor.name.as_deref(), Some("Eugen Rochko"));
        // The bio is carried RAW; reduction to text is the caller's job.
        assert_eq!(
            actor.summary.as_deref(),
            Some("<p>Founder of <b>Mastodon</b>.</p>")
        );
    }

    #[test]
    fn absent_or_blank_name_and_summary_read_as_none() {
        let mut v = fixture();
        let obj = v.as_object_mut().unwrap();
        obj.remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        obj.remove("name");
        obj.remove("summary");
        let bare = RemoteActor::from_json_ld(&v).unwrap();
        assert!(bare.name.is_none());
        assert!(bare.summary.is_none());

        // A server that serves an empty string means "no name": the
        // fallback to the handle must fire, not render a blank line.
        v["name"] = serde_json::json!("   ");
        v["summary"] = serde_json::json!("");
        let blank = RemoteActor::from_json_ld(&v).unwrap();
        assert!(blank.name.is_none());
        assert!(blank.summary.is_none());
    }

    #[test]
    fn mentions_are_collected_from_the_tag_array() {
        let note = serde_json::json!({
            "type": "Note",
            "attributedTo": "https://m.example/users/g",
            "content": "<p>hey @alice and @bob</p>",
            "tag": [
                {"type": "Mention", "name": "@alice@mastodon.example",
                 "href": "https://mastodon.example/users/alice"},
                {"type": "Hashtag", "name": "#rust", "href": "https://m.example/tags/rust"},
                {"type": "Mention", "name": "@bob@fosstodon.org",
                 "href": "https://fosstodon.org/users/bob"},
            ],
        });
        let post = post_from_note(&note, None).unwrap();
        assert_eq!(
            post.mentions,
            vec![
                MentionRef {
                    name: "@alice@mastodon.example".into(),
                    href: "https://mastodon.example/users/alice".into(),
                },
                MentionRef {
                    name: "@bob@fosstodon.org".into(),
                    href: "https://fosstodon.org/users/bob".into(),
                },
            ],
            "hashtags and emoji share the tag array; only Mentions ride",
        );
    }

    #[test]
    fn tolerates_a_lone_tag_object_and_malformed_entries() {
        let single = serde_json::json!({
            "type": "Note", "attributedTo": "https://m.example/u/g", "content": "hi",
            "tag": {"type": "Mention", "name": "@a@h", "href": "https://h/users/a"},
        });
        assert_eq!(post_from_note(&single, None).unwrap().mentions.len(), 1);

        // A Mention missing href (or name) is skipped; the POST survives.
        let broken = serde_json::json!({
            "type": "Note", "attributedTo": "https://m.example/u/g", "content": "hi",
            "tag": [
                {"type": "Mention", "name": "@a@h"},
                {"type": "Mention", "href": "https://h/users/b"},
                {"type": "Mention", "name": "", "href": "https://h/users/c"},
                "not an object",
            ],
        });
        let post = post_from_note(&broken, None).unwrap();
        assert!(post.mentions.is_empty());
        assert_eq!(post.content_html, "hi", "a bad tag costs the mention only");

        // No tag at all is the common case.
        let none = serde_json::json!({
            "type": "Note", "attributedTo": "https://m.example/u/g", "content": "hi",
        });
        assert!(post_from_note(&none, None).unwrap().mentions.is_empty());
    }

    #[test]
    fn mentions_are_capped_against_a_hostile_tag_array() {
        let tags: Vec<Value> = (0..(MAX_MENTIONS_PER_POST + 40))
            .map(|i| {
                serde_json::json!({
                    "type": "Mention",
                    "name": format!("@u{i}@h"),
                    "href": format!("https://h/users/{i}"),
                })
            })
            .collect();
        let note = serde_json::json!({
            "type": "Note", "attributedTo": "https://m.example/u/g",
            "content": "spam", "tag": tags,
        });
        assert_eq!(
            post_from_note(&note, None).unwrap().mentions.len(),
            MAX_MENTIONS_PER_POST,
        );
    }

    fn outbox_page() -> Value {
        serde_json::json!({
            "type": "OrderedCollectionPage",
            "orderedItems": [
                {
                    "type": "Create",
                    "actor": "https://m.example/users/g",
                    "object": {
                        "type": "Note",
                        "attributedTo": "https://m.example/users/g",
                        "content": "<p>hello <b>world</b></p>",
                        "published": "2026-07-13T06:00:00Z",
                        "url": "https://m.example/@g/1"
                    }
                },
                { "type": "Announce", "object": "https://elsewhere.example/x" },
                {
                    "type": "Create",
                    "actor": "https://m.example/users/g",
                    "object": { "type": "Image", "url": "https://m.example/i/2" }
                },
                {
                    "type": "Note",
                    "attributedTo": "https://m.example/users/g",
                    "content": "bare note",
                    "id": "https://m.example/notes/3"
                }
            ]
        })
    }

    #[test]
    fn outbox_page_reduces_to_authored_notes_only() {
        let posts = posts_from_outbox_page(&outbox_page(), 10);
        assert_eq!(posts.len(), 2, "boosts + non-Note objects skipped");
        assert_eq!(posts[0].author_url, "https://m.example/users/g");
        assert_eq!(posts[0].content_html, "<p>hello <b>world</b></p>");
        assert_eq!(posts[0].published, "2026-07-13T06:00:00Z");
        assert_eq!(posts[0].object_url, "https://m.example/@g/1");
        // Bare Note falls back to its id for the object url.
        assert_eq!(posts[1].object_url, "https://m.example/notes/3");
    }

    #[test]
    fn outbox_page_honors_cap_and_tolerates_junk() {
        assert_eq!(posts_from_outbox_page(&outbox_page(), 1).len(), 1);
        assert!(posts_from_outbox_page(&serde_json::json!({}), 10).is_empty());
        assert!(
            posts_from_outbox_page(&serde_json::json!({"orderedItems": "nope"}), 10).is_empty()
        );
        // A Note with no content renders nothing worth feeding.
        let empty = serde_json::json!({"orderedItems":[
            {"type":"Note","attributedTo":"https://m.example/u/g","content":""}
        ]});
        assert!(posts_from_outbox_page(&empty, 10).is_empty());
    }

    // ── thread replies ────────────────────────────────────────────────

    const ORIGIN: &str = "m.example";

    fn inline_note(n: u32) -> Value {
        serde_json::json!({
            "type": "Note",
            "attributedTo": "https://m.example/users/alice",
            "content": format!("<p>reply {n}</p>"),
            "published": format!("2026-07-13T06:0{n}:00Z"),
            "id": format!("https://m.example/notes/{n}"),
        })
    }

    fn urls(page: &RepliesPage) -> Vec<&str> {
        page.entries
            .iter()
            .filter_map(|e| match e {
                ReplyEntry::Url(u) => Some(u.as_str()),
                ReplyEntry::Inline(_) => None,
            })
            .collect()
    }

    /// The whole shape matrix a replies page can arrive in, one table.
    #[test]
    fn every_page_shape_reduces() {
        struct Case {
            name: &'static str,
            page: Value,
            entries: usize,
            next: Option<&'static str>,
        }
        let cases = vec![
            Case {
                name: "no items at all",
                page: serde_json::json!({ "type": "CollectionPage" }),
                entries: 0,
                next: None,
            },
            Case {
                name: "items as bare URIs (the Mastodon remote shape)",
                page: serde_json::json!({
                    "type": "CollectionPage",
                    "items": ["https://other.example/notes/1", "https://x.example/notes/2"],
                }),
                entries: 2,
                next: None,
            },
            Case {
                name: "orderedItems instead of items",
                page: serde_json::json!({
                    "type": "OrderedCollectionPage",
                    "orderedItems": [inline_note(1)],
                }),
                entries: 1,
                next: None,
            },
            Case {
                name: "Create activities wrapping Notes",
                page: serde_json::json!({
                    "type": "CollectionPage",
                    "items": [{
                        "type": "Create",
                        "actor": "https://m.example/users/alice",
                        "object": {
                            "type": "Note",
                            "content": "<p>wrapped</p>",
                            "id": "https://m.example/notes/9",
                        },
                    }],
                }),
                entries: 1,
                next: None,
            },
            Case {
                name: "next as a plain string",
                page: serde_json::json!({
                    "type": "CollectionPage",
                    "items": [],
                    "next": "https://m.example/notes/1/replies?page=2",
                }),
                entries: 0,
                next: Some("https://m.example/notes/1/replies?page=2"),
            },
            Case {
                name: "next as an object naming its own id",
                page: serde_json::json!({
                    "type": "CollectionPage",
                    "items": [],
                    "next": { "type": "CollectionPage", "id": "https://m.example/r?page=2" },
                }),
                entries: 0,
                next: Some("https://m.example/r?page=2"),
            },
        ];
        for c in cases {
            let parsed = replies_page_from_value(&c.page, ORIGIN, MAX_THREAD_REPLIES);
            assert_eq!(parsed.entries.len(), c.entries, "{}", c.name);
            assert_eq!(parsed.next.as_deref(), c.next, "{}", c.name);
        }
    }

    #[test]
    fn malformed_entries_are_skipped_not_fatal() {
        let page = serde_json::json!({
            "items": [
                42,
                null,
                "   ",
                { "type": "Like", "actor": "https://m.example/users/alice" },
                { "type": "Note", "attributedTo": "https://m.example/users/alice",
                  "content": "<p>survives</p>", "id": "https://m.example/notes/1" },
            ],
        });
        let parsed = replies_page_from_value(&page, ORIGIN, MAX_THREAD_REPLIES);
        // The junk entries are dropped; the Like carries an actor but no
        // id, so it contributes nothing either.
        assert_eq!(parsed.entries.len(), 1);
        assert!(matches!(parsed.entries[0], ReplyEntry::Inline(_)));
    }

    #[test]
    fn a_stub_object_with_only_an_id_becomes_a_dereference() {
        let page = serde_json::json!({
            "items": [{ "type": "Note", "id": "https://other.example/notes/7" }],
        });
        let parsed = replies_page_from_value(&page, ORIGIN, MAX_THREAD_REPLIES);
        assert_eq!(urls(&parsed), vec!["https://other.example/notes/7"]);
    }

    /// The authoritative-origin rule. A server may inline replies it
    /// authored; it may NOT inline a reply attributed to somebody on
    /// another host, or every instance could put words in any account's
    /// mouth simply by listing them in its own thread.
    #[test]
    fn an_inlined_reply_attributed_off_host_is_dropped() {
        let forged = serde_json::json!({
            "type": "Note",
            "attributedTo": "https://mastodon.social/users/gargron",
            "content": "<p>I endorse this</p>",
            "id": "https://evil.example/notes/1",
        });
        let page = serde_json::json!({ "items": [forged, inline_note(1)] });
        let parsed = replies_page_from_value(&page, "evil.example", MAX_THREAD_REPLIES);
        // Only the entry the origin may speak for survives — and here
        // that is neither, because inline_note claims m.example.
        assert!(parsed.entries.is_empty());

        // Served by the host it names: kept.
        let ok = replies_page_from_value(
            &serde_json::json!({ "items": [inline_note(1)] }),
            ORIGIN,
            MAX_THREAD_REPLIES,
        );
        assert_eq!(ok.entries.len(), 1);
    }

    #[test]
    fn an_oversized_page_is_truncated_at_the_cap() {
        let items: Vec<Value> = (0..(MAX_THREAD_REPLIES + 25))
            .map(|i| serde_json::json!(format!("https://m.example/notes/{i}")))
            .collect();
        let page = serde_json::json!({ "items": items });
        let parsed = replies_page_from_value(&page, ORIGIN, MAX_THREAD_REPLIES);
        assert_eq!(parsed.entries.len(), MAX_THREAD_REPLIES);
        // And the caller's own smaller room is honored, which is how the
        // page walk stops accumulating once it is full.
        assert_eq!(replies_page_from_value(&page, ORIGIN, 3).entries.len(), 3);
    }

    #[test]
    fn a_repeat_across_pages_is_collected_once() {
        let entries = vec![
            ReplyEntry::Url("https://m.example/notes/1".into()),
            ReplyEntry::Inline(post_from_note(&inline_note(2), None).unwrap()),
            // Both repeats: `next` pages overlap in the wild.
            ReplyEntry::Url("https://m.example/notes/1".into()),
            ReplyEntry::Inline(post_from_note(&inline_note(2), None).unwrap()),
            ReplyEntry::Url("https://m.example/notes/3".into()),
        ];
        assert_eq!(dedup_entries(entries).len(), 3);
    }

    #[test]
    fn identity_less_entries_are_not_collapsed_into_one() {
        // Two different replies that each carry no url and no id would
        // both key on "" — de-duping them would silently eat one.
        let bare = |body: &str| RemotePost {
            author_url: "https://m.example/users/alice".to_owned(),
            content_html: body.to_owned(),
            published: String::new(),
            object_url: String::new(),
            mentions: Vec::new(),
        };
        let entries = vec![
            ReplyEntry::Inline(bare("<p>one</p>")),
            ReplyEntry::Inline(bare("<p>two</p>")),
        ];
        assert_eq!(dedup_entries(entries).len(), 2);
    }

    #[test]
    fn replies_read_oldest_first_with_undated_ones_last() {
        let at = |stamp: &str| RemotePost {
            author_url: "https://m.example/users/alice".to_owned(),
            content_html: "<p>x</p>".to_owned(),
            published: stamp.to_owned(),
            object_url: format!("https://m.example/notes/{stamp}"),
            mentions: Vec::new(),
        };
        let mut replies = vec![
            at("2026-07-13T06:05:00Z"),
            at(""),
            at("2026-07-13T06:00:00Z"),
            at("2026-07-12T23:59:59Z"),
        ];
        sort_oldest_first(&mut replies);
        let stamps: Vec<&str> = replies.iter().map(|r| r.published.as_str()).collect();
        assert_eq!(
            stamps,
            vec![
                "2026-07-12T23:59:59Z",
                "2026-07-13T06:00:00Z",
                "2026-07-13T06:05:00Z",
                "",
            ],
            "a stampless reply is not evidence that it is the oldest",
        );
    }

    #[test]
    fn a_thread_pull_never_leaves_the_origin_host() {
        // The page walk refuses an off-host `first`/`next` before any
        // socket opens, so the constants below are the whole story: two
        // pages, twenty dereferences, one wall-clock budget.
        assert_eq!(MAX_THREAD_REPLY_PAGES, 2);
        assert_eq!(MAX_THREAD_REPLY_FETCHES, 20);
        assert_eq!(MAX_THREAD_REPLIES, 50);
        assert!(THREAD_FETCH_BUDGET.as_secs() >= ACTOR_FETCH_TIMEOUT.as_secs());
    }

    #[tokio::test]
    async fn an_off_host_next_page_is_refused_without_a_request() {
        let mut pages = 0usize;
        let deadline = Instant::now() + THREAD_FETCH_BUDGET;
        assert!(
            fetch_reply_page("https://evil.example/steal", ORIGIN, deadline, &mut pages)
                .await
                .is_none(),
        );
        assert_eq!(pages, 0, "a refused page must not spend the page budget");
    }

    #[tokio::test]
    async fn the_page_budget_stops_the_walk() {
        let deadline = Instant::now() + THREAD_FETCH_BUDGET;
        let mut pages = MAX_THREAD_REPLY_PAGES;
        assert!(
            fetch_reply_page("https://m.example/r?page=3", ORIGIN, deadline, &mut pages)
                .await
                .is_none(),
        );
        assert_eq!(pages, MAX_THREAD_REPLY_PAGES);
        // An exhausted wall-clock budget stops it just as hard.
        let mut fresh = 0usize;
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("a monotonic clock one second in the past");
        assert!(
            fetch_reply_page("https://m.example/r?page=2", ORIGIN, expired, &mut fresh)
                .await
                .is_none(),
        );
        assert_eq!(fresh, 0);
    }
}
