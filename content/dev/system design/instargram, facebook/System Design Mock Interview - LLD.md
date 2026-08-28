---
title: "System Design Mock Interview - LLD: \"Now Design That Feed Service as Classes\""
labels: ["System Design", "LLD", "OOP", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> When you start studying system design, the first two terms you run into are **HLD (High Level Design)** and **LLD (Low Level Design)**.
>
> This post is the **LLD** half — **the trees inside the forest: how to implement the details and the code well**. In the [HLD post](<./System Design Mock Interview - HLD.md>) we drew Instagram's forest; this time we walk into a machine coding interview and design the **feed service inside it as classes**.

# The LLD Mock Interview — "Design the Feed and Likes as Classes"

## 0. Before We Start — HLD vs LLD in 30 Seconds

| | **HLD** | **LLD (this post)** |
|---|---|---|
| Metaphor | Draw the forest | Plant the trees |
| The prompt | "Design Instagram" | "Design Instagram's feed and likes as classes" |
| Deliverable | Architecture diagram | UML/class diagram + working code skeleton |
| Core skills | Requirements gathering, **negotiating trade-offs**, a feel for scale | DSA, **OO principles**, testing, query optimization |
| Who does it at work | Staff/principal engineers, solution architects | SDE 1–2 (junior to mid-level) |
| Interview format | 45 min–1 hour (whiteboard discussion) | 2–4 hours (machine coding) |

The LLD interview also goes by **machine coding / object-oriented design interview**. You get 2–4 hours, and after diagramming you're expected to produce a **code skeleton that actually runs**. Check the clock first — for 3 hours, a solid split is **30 min requirements & design / 2 hours implementation / 30 min tests & refactoring**. Start coding without a design and you'll rip it up halfway through; leave no time for tests and you forfeit an entire scoring category. Let's walk in.

---

## 1. Clarifying Requirements — No Code Yet

**Interviewer** — Here's the problem. **Design and implement Instagram's core features — posts, likes, follows, and feed viewing — as classes.**

**Me** — Sure. Before coding, let me narrow the scope. Is the feed **chronological** by default? Any chance it switches to ranked recommendations later?

**Interviewer** — Chronological by default, but keep the door open for ranked.

**Me** — Then I'll take: three post types — **photo/Reel/carousel**; **likes can be undone**; and likes, comments, and follows **notify the author**. Can I start under a single-process assumption for concurrency?

**Interviewer** — Sounds good, go ahead.

> 💡 **Coaching note** — Step one of LLD is still requirements. The key move is **asking up front about "what's likely to change"** — the answer we just extracted, "ranked feed is a possibility," will drive the design direction for this entire interview.

---

## 2. Collect the Nouns, Divide the Responsibilities

**Me** — Underline the **nouns** in the requirements and you get class candidates — user, post, comment, like, follow, feed, notification. The **verbs** (post, follow, sort, notify) are responsibility candidates. Let me wire up the relationships.

```
User ──follows──▶ User          (managed by FollowService)
User ──1:N──▶ Post (type: PHOTO / REEL / CAROUSEL)
Post ──1:N──▶ Comment, Like
FeedService ─ gathers posts from followings, sorts, returns
FeedRankingPolicy ─ the ordering policy (the first thing that will change!)
NotificationService ─ subscribes to like/comment/follow events
```

The question I kept asking myself was: "**what changes first?**" As we confirmed, it's the **feed ordering policy** — chronological to ranked, eventually with ads injected. That's literally the path real Instagram took. So instead of hard-wiring the sort into FeedService, I'll put it **behind an interface**.

> 💡 **Coaching note** — "Nouns = class candidates, verbs = responsibility candidates" is the classic starting point for entity extraction. Then **find what changes, and the pattern follows**: swapping the ordering policy → **Strategy**; adding post types → **Factory**; one event (a like) fanning out to many reactions (notification, counter, feed) → **Observer**; per-state behavior for posts (draft/published/archived) → **State**. This mapping matters more than memorizing pattern names.

---

## 3. The Code Skeleton — Put Interfaces Where Change Happens

**Me** — Time to code the skeleton. The centerpiece is isolating the ordering policy.

```java
interface FeedRankingPolicy {               // the policy can change
    List<Post> rank(List<Post> candidates); // without touching FeedService (OCP)
}

class ChronologicalPolicy implements FeedRankingPolicy { /* time-ordered */ }
class EngagementPolicy    implements FeedRankingPolicy { /* ranked — later */ }

class FeedService {
    private final FollowService follows;
    private final PostRepository posts;
    private final FeedRankingPolicy policy;  // depends on the interface, not an impl (DIP)

    public List<Post> getFeed(User viewer, int size) {
        List<Post> candidates = posts.recentByAuthors(follows.followingOf(viewer));
        return policy.rank(candidates).subList(0, size);
    }
}
```

A like triggers **independent** reactions — notification, counter, feed cache — so I'll model it with Observer. LikeService publishes events without knowing who's listening.

```java
interface PostEventListener { void onEvent(PostEvent e); }
// NotificationService, LikeCounter, FeedCacheUpdater each subscribe

class LikeService {
    private final List<PostEventListener> listeners;
    public void like(User u, Post p) {
        /* persist (duplicate likes from the same user are ignored — idempotent) */
        listeners.forEach(l -> l.onEvent(new PostEvent(LIKED, u, p)));
    }
}
```

Post creation varies by type (photo/Reel/carousel) in validation and processing, so it goes through a **Factory**. When a new type shows up, there's exactly one place to touch.

**Interviewer** — `EngagementPolicy` is still empty. There's no recommendation logic — is that okay?

**Me** — Yes — today's scope is chronological, but the point is showing **a structure where the policy is swappable**. Remember in the [HLD](<./System Design Mock Interview - HLD.md>) we decided "separating feed assembly from ordering makes it easy to evolve into a recommendation pipeline"? In code, that decision shows up as this one interface.

> 💡 **Coaching note** — SOLID is not something you recite; it's something you **show in the code**. Two principles are baked into that skeleton: **OCP (Open-Closed)** — adding a policy touches no existing code — and **DIP (Dependency Inversion)** — FeedService leans on an interface, not an implementation. The interviewer's "it's empty, is that okay?" isn't a trap; it's **an invitation to explain your intent**.

---

## 4. The Performance Grilling — Data Structures and Queries

**Interviewer** — Let's look at `getFeed`. If I follow 500 people, how expensive is this method?

**Me** — Two places to check.

**First, query count.** If `recentByAuthors` fires one query per following, that's the **N+1 problem** — 500 queries out the door. I'll design the repository so it's "1 query for the following list + 1 `IN` query by author" — two queries total. Like counts also shouldn't be a `COUNT(*)` on every read; keep a counter column (or cache) instead — that's exactly the job of the LikeCounter we subscribed via Observer.

**Second, merge cost.** The 500 per-author lists are **each already sorted by time**. Dumping everything into one pile and re-sorting is O(total posts × log). Instead, put only the head of each list into a **min-heap (priority queue)** and, every time you pop one, feed in the next post from that same list — a **k-way merge**. The top 20 feed items cost O(20 × log 500). You never look at the whole thing.

**Interviewer** — Show me in code what goes into the heap.

**Me** —

```java
// hold (post, source-list index), compared by recency
PriorityQueue<PeekEntry> heap =
    new PriorityQueue<>(comparing(e -> e.post.createdAt(), reverseOrder()));

lists.forEach(list -> heap.offer(list.peekHead()));   // only each list's head
while (result.size() < 20 && !heap.isEmpty()) {
    PeekEntry top = heap.poll();                      // the most recent post
    result.add(top.post);
    top.source.next().ifPresent(heap::offer);         // refill from that list
}
```

> 💡 **Coaching note** — The DSA portion of LLD isn't algorithm puzzles; it evaluates **choices that emerge naturally from the design**. "Merging multiple sorted lists = k-way merge + heap" is the standard answer for feed/timeline problems. On the query side, the standard point deductions are **N+1** and **COUNT(*) on every read**.

---

## 5. The Concurrency Grilling — Shelved Assumptions Come Back

**Interviewer** — You started under a single-process assumption. Let's remove it. **Two requests like the same post at the same time** — what happens?

**Me** — Problems at two layers.

**First, duplicate likes.** If the same user's request arrives twice concurrently, both can pass the "check if already liked → insert if not" check. Application-level checks can't stop this alone, so the last line of defense goes in the database: a **unique constraint on `(user_id, post_id)`**. Treat a constraint violation as "already liked" and swallow it quietly — and you get idempotency for free.

**Second, lost counter updates.** If `count = count + 1` is done as an application-side read-modify-write, two requests can read the same value and **one increment vanishes**. Counters must use the store's atomic operations — an atomic **`UPDATE posts SET like_count = like_count + 1`** in the DB, or **Redis `INCR`**. Cached counters can still drift, so a periodic re-aggregation batch corrects them.

**Interviewer** — Does follow have the same problem?

**Me** — Yes, same pattern. A unique constraint on `follows(follower_id, followee_id)` prevents duplicate follows, and "following yourself" is blocked by application-level validation.

> 💡 **Coaching note** — An assumption you shelved early ("single process for now") **always comes back**. Because you shelved it *explicitly*, it's not a deduction — it's structure points — and having the answer ready when it returns is bonus points. The skeleton of the answer fits in two lines: **idempotency via unique constraints; counters via atomic operations.**

---

## 6. Tests — The Last 30 Minutes

**Interviewer** — Thirty minutes left. Let's see some tests.

**Me** — I designed `getFeed` to have pure inputs and outputs from the start, so this is easy to attach. Three scenarios:

1. **Follow → new post → appears in feed**: A follows B, B posts, A's feed shows it
2. **Unfollow → removed from feed**: after unfollowing, B's posts no longer appear
3. **Swap policy → order changes**: same data, swapping `ChronologicalPolicy` for a fake policy changes only the order

```java
@Test
void feed_shows_followee_posts_in_time_order() {
    follows.follow(alice, bob);
    posts.save(post(bob, "10:00"));
    posts.save(post(bob, "10:05"));

    List<Post> feed = feedService.getFeed(alice, 20);

    assertThat(feed).extracting(Post::createdAt)
                    .containsExactly(at("10:05"), at("10:00"));
}
```

Swapping in a fake `FeedRankingPolicy` lets me verify FeedService's assembly logic in isolation, no recommendation logic required. Time dependency is severed by injecting `createdAt`.

> 💡 **Coaching note** — Tests aren't "nice to have if there's time" — they're a scoring category. Specifically, the question is **whether you designed a structure that can be tested** — notice how the interface separation from section 3 pays off here as fake injection.

---

## 7. Interview Retro — What Was Actually Being Graded

Rewinding those hours, the flow had seven steps.

1. **Clarify requirements** — extracted the "what changes" answer (ranked feed) up front; stated and shelved the concurrency assumption
2. **Extract entities** — classes from the nouns, responsibilities from the verbs
3. **Design relationships & responsibilities** — diagrammed who knows what
4. **Flexibility where change happens** — Strategy (ordering), Observer (like events), Factory (post types)
5. **Performance** — killed N+1, counter cache, k-way merge + heap
6. **Concurrency** — idempotency via unique constraints, counters via atomic operations
7. **Tests** — scenario verification enabled by fake injection

And one thing that was never an explicit step but was **being graded from minute one** — the code itself. In machine coding interviews, work habits — intention-revealing names, short single-purpose methods, small feature-sized commits — count as much as the design. "Readable code + passing tests" beats four hours of dazzling architecture, every time.

And none of this is interview-only technique. When the HLD the seniors drew gets carved into services and assigned, **modeling the data, tuning the queries, implementing the code, and testing it** — these steps are just the daily life of an SDE 1–2. The LLD interview merely checks whether you can do that daily work "under a time limit, with principles intact."

**To make it muscle memory** — set a 2–3 hour timer and do the classics yourself: Instagram feed (this post; Strategy + Observer), parking lot (the standard warm-up; Factory + Strategy), elevator (State), Splitwise (settlement strategies), movie ticketing (seat locking; concurrency).

---

### 📝 TL;DR

> **"An LLD interview is where you collect classes from the nouns, put an interface at 'the first thing that will change,' and close with a heap and tests — show your everyday work, with the principles visible."**

---

## Previous Post

The whole forest this feed service stands in — the upload pipeline, feed fan-out, the celebrity problem — is covered in [System Design Mock Interview - HLD](<./System Design Mock Interview - HLD.md>).
