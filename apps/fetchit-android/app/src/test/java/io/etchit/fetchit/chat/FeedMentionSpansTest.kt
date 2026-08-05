package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Matching a post's Mention tags back onto its plain-text body. */
class FeedMentionSpansTest {

    private fun mention(name: String) = FeedMention(name, "https://h/users/${name.trim('@')}")

    private fun textOf(body: String, span: MentionSpan) =
        body.substring(span.start, span.endExclusive)

    @Test
    fun fullHandleFormIsMatched() {
        val body = "hey @alice@mastodon.example, look at this"
        val spans = mentionRanges(body, listOf(mention("@alice@mastodon.example")))
        assertEquals(1, spans.size)
        assertEquals("@alice@mastodon.example", textOf(body, spans.single()))
    }

    @Test
    fun mastodonsLocalPartOnlyRenderingIsMatched() {
        // Mastodon renders a mention as `<a><span>@</span><span>alice</span></a>`
        // with the domain in a hidden span, so the reduced text carries only
        // "@alice" while the tag still names the full handle. Without the
        // local-part fallback every Mastodon mention would be untappable.
        val body = "hey @alice, look at this"
        val spans = mentionRanges(body, listOf(mention("@alice@mastodon.example")))
        assertEquals(1, spans.size)
        assertEquals("@alice", textOf(body, spans.single()))
        assertEquals("https://h/users/alice@mastodon.example", spans.single().mention.href)
    }

    @Test
    fun matchingIsCaseInsensitive() {
        val body = "cc @Alice@Mastodon.Example"
        val spans = mentionRanges(body, listOf(mention("@alice@mastodon.example")))
        assertEquals(1, spans.size)
        assertEquals("@Alice@Mastodon.Example", textOf(body, spans.single()))
    }

    @Test
    fun aLongerHandleIsNotMatchedByAShorterOne() {
        // "@alice" must not light up inside "@alicia" — the span would sit on
        // the wrong name and open the wrong person's profile.
        val body = "hey @alicia how are you"
        assertTrue(mentionRanges(body, listOf(mention("@alice@h"))).isEmpty())
    }

    @Test
    fun anEmailInProseIsNotClaimedAsItsOwnMention() {
        // The local-part fallback searches for "@alice"; inside an ordinary
        // email the preceding character is part of a longer token, so the
        // boundary check must refuse it.
        val body = "write to me at bob@alice.example please"
        assertTrue(mentionRanges(body, listOf(mention("@alice@h"))).isEmpty())
    }

    @Test
    fun everyOccurrenceOfOneMentionIsSpanned() {
        val body = "@alice and again @alice"
        val spans = mentionRanges(body, listOf(mention("@alice@h")))
        assertEquals(2, spans.size)
        assertEquals(listOf(0, 17), spans.map { it.start })
    }

    @Test
    fun spansNeverOverlapEachOtherOrABlockedRange() {
        val body = "see autonomi://abc and @alice"
        val blocked = listOf(4 until 18)
        val spans = mentionRanges(body, listOf(mention("@alice@h")), blocked)
        assertEquals(1, spans.size)
        spans.forEach { s ->
            blocked.forEach { b ->
                assertTrue(
                    "mention span must not intersect a link span",
                    s.start >= b.last + 1 || s.endExclusive <= b.first,
                )
            }
        }
    }

    @Test
    fun aMentionInsideAnAlreadyClaimedRangeIsSkipped() {
        val body = "@alice"
        // The whole body is claimed by an earlier span; nothing is left.
        assertTrue(mentionRanges(body, listOf(mention("@alice@h")), listOf(0 until 6)).isEmpty())
    }

    @Test
    fun theSpanCountIsBounded() {
        val body = (0 until (MAX_MENTION_SPANS + 20)).joinToString(" ") { "@u$it" }
        val mentions = (0 until (MAX_MENTION_SPANS + 20)).map { mention("@u$it@h") }
        assertEquals(MAX_MENTION_SPANS, mentionRanges(body, mentions).size)
    }

    @Test
    fun emptyInputsAndMalformedTagsYieldNothing() {
        assertTrue(mentionRanges("", listOf(mention("@a@h"))).isEmpty())
        assertTrue(mentionRanges("hi @a", emptyList()).isEmpty())
        assertTrue(mentionRanges("hi @a", listOf(FeedMention("", "https://h/a"))).isEmpty())
        assertTrue(mentionRanges("hi @a", listOf(FeedMention("@a@h", ""))).isEmpty())
    }

    @Test
    fun spansComeBackInReadingOrder() {
        val body = "@bob@h and @alice@h"
        val spans = mentionRanges(body, listOf(mention("@alice@h"), mention("@bob@h")))
        assertEquals(listOf("@bob@h", "@alice@h"), spans.map { textOf(body, it) })
    }
}
