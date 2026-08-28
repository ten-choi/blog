---
title: "System Design Mock Interview - HLD: \"Design Instagram\""
labels: ["System Design", "HLD", "Architecture", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> When you start studying system design, the first two terms you run into are **HLD (High Level Design)** and **LLD (Low Level Design)**.
>
> This post is the **HLD** half — **drawing the forest: the overall structure and architecture of a system**. We'll pretend we just walked into a 45-minute whiteboard interview and design Instagram end to end, answering the interviewer's questions as they come. Planting the trees inside that same Instagram forest happens over in the [LLD post](<./System Design Mock Interview - LLD.md>).

# The HLD Mock Interview — "Design Instagram"

## 0. Before We Start — HLD vs LLD in 30 Seconds

| | **HLD (this post)** | **LLD** |
|---|---|---|
| Metaphor | Draw the forest | Plant the trees |
| The prompt | "Design Instagram" | "Design Instagram's feed and likes as classes" |
| Deliverable | Architecture diagram | UML/class diagram + working code skeleton |
| Core skills | Requirements gathering, **negotiating trade-offs**, a feel for scale | DSA, **OO principles**, testing, query optimization |
| Who does it at work | Staff/principal engineers, solution architects | SDE 1–2 (junior to mid-level) |
| Interview format | 45 min–1 hour (whiteboard discussion) | 2–4 hours (machine coding) |

Alright, let's walk into the room. But first, check the clock — for a 45-minute interview, a solid split is **5 min requirements / 5 min back-of-envelope math / 5 min API & data model / 15 min architecture / 10 min deep dive (trade-offs) / 5 min wrap-up**. Burn 10 minutes on requirements and everything downstream gets squeezed.

---

## 1. Requirements First — No Boxes Yet

**Interviewer** — Here's today's problem. **Design Instagram.**

**Me** — Sure. Before I draw anything, I'd like to narrow the scope. Can I ask a few questions? Should I take the core features to be **photo/Reels upload, follow, and feed viewing**? Are DMs or Stories in scope?

**Interviewer** — Those three are enough.

**Me** — Let me check the non-functional side too. What **daily active user count** should I assume? And when someone posts, **how quickly** does it need to show up in their followers' feeds?

**Interviewer** — 500 million DAU, and feed delivery within a few seconds is fine.

> 💡 **Coaching note** — The candidate who immediately starts drawing boxes and the candidate who asks about scope, scale, and latency first — you can tell them apart in the first five minutes. Step one of any HLD interview is always **collecting functional requirements (the what) and non-functional requirements (the how much — availability, scalability, consistency, cost, performance)**.

---

## 2. Back-of-Envelope Math — Turning Requirements into Numbers

**Me** — Let me rough out the scale. If 500M DAU each post once and view 50 posts per day on average, then **reads outnumber writes 50 to 1**. Converting to per-second, feed reads land in the hundreds of thousands of QPS. And if an average photo is 2MB, new media alone runs into petabytes per day.

Two design directions fall out of this. First, **this system lives or dies on read optimization**. Second, **media files are way too big for the database** — we have to separate files from metadata.

> 💡 **Coaching note** — Back-of-envelope estimation doesn't need to be precise. **Order-of-magnitude intuition** is enough; what matters is using those numbers **to justify your next decision**. That single line — "reads are 50x writes" — will justify every cache, CDN, and fan-out decision in the back half of this interview.

---

## 3. API and Data Model — Contracts Before Boxes

**Me** — Before drawing, let me write down the system's **contract**. Three core APIs:

```
POST /posts                 (media_ids, caption)          → post_id
POST /users/{id}/follow                                   → 200
GET  /feed?cursor=...&size=20                             → posts[], next_cursor
```

The feed uses **cursor-based pagination, not offsets** — new posts are constantly being inserted in real time, so "page 3" isn't a stable concept. A cursor (the timestamp/ID of the last post you saw) is the natural fit.

The minimal data model is three tables:

```
users   (id, name, ...)
posts   (id, author_id, media_url, caption, created_at)   -- index on (author_id, created_at)
follows (follower_id, followee_id, created_at)             -- two indexes, one per lookup direction
```

**Interviewer** — Why does `follows` need two indexes?

**Me** — Because we query it in both directions. Building a feed, we look up "the people **I** follow" (keyed on follower_id). Sending notifications, we look up "the **followers** of this person" (keyed on followee_id). Both are hot paths, so both directions need an index.

> 💡 **Coaching note** — Candidates who write down the **API and data model before the boxes** come across as grounded, because the entire architecture discussion that follows sits on top of this contract. For any feed-style problem, "cursor-based pagination" should come out almost as a reflex.

---

## 4. The Write Path — The Upload Pipeline

**Me** — I'll draw the write path first. When a photo comes in, we actually need to: store the original, resize for feed and thumbnails, fan out to follower feeds, and send notifications. Do all of that synchronously and the upload button hangs for seconds. So the rule is: **only what the response strictly needs happens synchronously; everything else goes behind a queue**.

- **Media files go to object storage (S3)**; **metadata (author, caption, S3 URL) goes to the database**. It's the classic split: big and immutable on one side, small and frequently queried on the other.
- Once the write lands, we **publish a "new post" event to Kafka** and return the response. Resizing, feed fan-out, and notifications are handled asynchronously by services subscribing to that event.

**Interviewer** — What about Reels? Video is much bigger than photos.

**Me** — If you send a large video in a single request and the connection drops halfway, you start over from zero. So the client **uploads in chunks**. S3's **multipart upload** covers this in three steps: ① get an Upload ID (Initiation) → ② send chunks in parallel, receiving an E-Tag per part (Upload Parts) → ③ send the E-Tag list as the completion signal, and S3 stitches the parts together (Completion). After upload, a media processing service transcodes into multiple resolutions (1080p/720p/480p) so playback matches the viewer's device and bandwidth.

> 💡 **Coaching note** — The parts used here are the basic vocabulary of HLD: **object storage** (big, immutable files), **message queues** (peeling heavy or failure-prone work off the request/response path), and the evergreen **sync vs async** trade-off. "Only do synchronously what the response needs" is a principle that travels everywhere.

---

## 5. The Read Path — The Feed, the Main Event

**Me** — Now for the main event: the feed. There are two big ways to assemble the latest posts from everyone you follow.

| | **Fan-out on Read (Pull)** | **Fan-out on Write (Push)** |
|---|---|---|
| How | On every feed request, **gather and sort** the latest posts from everyone you follow, on the spot | When a post is created, **pre-insert it into every follower's feed cache** |
| Reads | Slow (query N people + merge, every time) | **Fast (straight from cache)** |
| Writes | Cheap | Costs one write per follower |

Since we calculated reads are 50x writes, **the default is Push** — when a post lands, pre-insert it into followers' feed caches (Redis), and serve reads straight from cache.

**Interviewer** — What happens when a celebrity with 50 million followers posts?

**Me** — That's exactly Push's weak spot. One post triggers 50 million cache writes. So I'd go **hybrid** — regular users' posts get pushed ahead of time, but **posts from accounts above a follower threshold are pulled** and merged at read time. From the user's perspective, "my feed = my cache + the latest posts from the handful of celebrities I follow."

**Interviewer** — That feed cache — what happens if the entire Redis cluster goes down?

**Me** — The feed can't just die, so we keep a **fallback path**. On a cache miss, we answer via the Pull approach from earlier — merge the followings' latest posts on the spot. Slow, but it works. Meanwhile, we **rebuild the cache gradually (warm-up)** so traffic doesn't stampede. To keep everyone from piling onto Pull at once, we can prioritize restoring popular accounts first, or temporarily shorten the feed — **graceful degradation** is a legitimate option here.

**Interviewer** — Is it acceptable for like counts to differ by a few seconds between users?

**Me** — Yes. Like counts only need **eventual consistency**, so caching plus async aggregation is fine. But state changes with security implications — blocking an account, going private — need **strong consistency**. Different items in the same system have different consistency requirements.

> 💡 **Coaching note** — This section is the heart of the HLD interview. **There is no single perfect answer** in system design — the interviewer isn't asking "is A correct?" They're **poking at where A breaks (celebrities, cache outages) and watching how you adjust to the constraints**. Know the classic matchups — Push vs Pull, consistency vs availability (CAP), precompute vs compute-on-read — and for every component, have one **"what if this dies?" fallback answer** ready.

---

## 6. The Full Picture

**Me** — Putting every decision so far on one page:

```
Client
   │ ① Upload (Reels split into chunks → multipart upload)
   ▼
Upload Service ──② original → S3 ──③ metadata → DB (sharded)
   └─④ publish "new post" event to Kafka
        │
        ├─▶ Media Processing Service ─ resize/thumbnails; Reels transcoded per resolution → S3 → CDN
        ├─▶ Feed Service ─ push into follower feed caches (Redis); celebrities handled via pull
        └─▶ Notification Service ─ notify followers of the new post

Feed read:  Client → Feed Service → Redis feed cache (+ merge celebrity posts)
Media read: Client → CDN (never touches S3)
```

A **load balancer** sits at the traffic entrance and every service scales horizontally. For the metadata DB, read load spreads via **replication**, and once the data no longer fits on one machine, we **shard**. All image and video serving goes through the **CDN** so traffic never reaches origin storage.

> 💡 **Coaching note** — Memorize each whiteboard component paired with **the condition that makes you reach for it**, and the diagram draws itself: load balancer (one server can't take the traffic), cache (same data read repeatedly), CDN (static media closer to users), replication (spreading reads), sharding (splitting writes/storage), message queue (decoupling work from request/response), S3 (big, immutable files).

---

## 7. "Where Would You Improve First?" — Version 2

**Interviewer** — We have some time left. What do you see as the **limitations** of this design?

**Me** — I'd point at three spots.

1. **Uploads routing through the backend** — issue S3 **presigned URLs** so clients upload directly to S3, which slashes traffic on the upload service. Since Reels are already chunked, it's a natural place to add **resumable uploads** with per-chunk retry, and I'd make the pipeline **idempotent** so a chunk arriving twice is harmless.
2. **The follow graph outgrowing one database** — that day is coming. **Shard by user ID**, but choose the shard key based on which lookup dominates: "who I follow" vs "who follows me."
3. **The ceiling of a chronological feed** — evolving to ranked recommendations means a ranking pipeline behind the feed service. If we **separate feed 'assembly' from 'ordering'** now, swapping the ordering policy later is a plug-in change.

> 💡 **Coaching note** — **Predicting your own design's limits and failure modes and proposing a "version 2" unprompted (foresight)** is a major plus signal. And that last answer — "separate assembly from ordering" — is exactly what gets implemented as the Strategy pattern in the [LLD post](<./System Design Mock Interview - LLD.md>). It's where a forest-level decision becomes tree-level code.

---

## 8. Interview Retro — What Was Actually Being Graded

Rewinding those 45 minutes, the flow had six steps.

1. **Requirements gathering** — narrowed to three features, asked about scale and latency
2. **Back-of-envelope math** — derived "reads are 50x writes" and used it as the design's foundation
3. **API & data model** — wrote the contract (cursor pagination) and tables/indexes before any boxes
4. **Architecture** — picked components and drew the write and read paths
5. **Trade-off negotiation** — hybrid for the celebrity problem, fallback + warm-up for cache failure, per-item consistency for the consistency question
6. **Foresight** — named the limits and pitched version 2 before being asked

The same thing happens on the job. The differences: the whiteboard becomes a design doc, and the person drawing it is a **staff engineer or solution architect**. The finished HLD gets carved into small services and assigned to SDE 1–3s — and the story of the developer who lands "feed service" is the LLD. That's also why juniors study HLD: **you plant better trees when you know where your component sits in the forest**.

---

### 📝 TL;DR

> **"An HLD interview isn't about guessing the right answer — it's about showing the negotiation: turn requirements into numbers, justify decisions with those numbers, and name where your design breaks before anyone asks."**

---

## Next Up

The interviewer follows up — "So, that feed service. Care to design it as classes?" Continued in [System Design Mock Interview - LLD](<./System Design Mock Interview - LLD.md>).
