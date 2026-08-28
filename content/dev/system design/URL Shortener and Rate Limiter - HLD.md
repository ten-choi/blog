---
title: "System Design Mock Interview - HLD: \"Design a URL Shortener — and a Rate Limiter, Too\""
labels: ["System Design", "HLD", "Distributed ID", "Rate Limiter", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> Most system design interview problems hand you an entire service — a photo feed, a ticketing site, a delivery app — and ask you to design it end to end. Today's problem is different. **It looks small.** A URL shortener? Feels like one table would do it.
>
> But component-style problems don't get asked because they're small — they get asked because they **look** small. The scope is narrow, so the interviewer drills all the way into the guts of the part — and small problems sometimes come **two to a 45-minute session**. Today is one of those days.

# The HLD Mock Interview — "Design a URL Shortener, and a Rate Limiter Too"

## 0. Before We Start — How This Differs from Service-Style Problems

| | **Service-style problems** | **Component-style problems (this post)** |
|---|---|---|
| Example prompts | Instagram, ticket booking, food delivery, chat | URL shortener, rate limiter, ID generator, notification queue |
| Scope | Wide and shallow — combining components and paths | **Narrow and deep — the internals of one part** |
| What's graded | Trade-off negotiation, a feel for scale | **Precision of order-of-magnitude math, algorithm comparison, edge cases** |
| Common mistake | Listing boxes with no deep dive | Saying "this is easy," skimming, then collapsing at the depth questions |

Two problems means splitting the clock — **25 minutes for the URL shortener / 15 for the rate limiter / 5 to wrap up**. The smaller the problem, the faster requirements should go: one or two minutes, then straight to the main event.

---

## 1. Requirements First — Small Problems Get Narrowed Fast

**Interviewer** — Here's today's problem. **Design a URL shortener.** Something like bit.ly.

**Me** — Let me confirm scope. The core is two things, right? **Creation** — take a long URL and mint a short key — and **redirect** — send a request for a short key on to the original. Should I include **custom aliases**, where users pick their own key, and **expiration**?

**Interviewer** — Include aliases; just mention expiration as an option.

**Me** — Non-functional side too. The redirect is the path users hit on every click, so it has to finish **within tens of milliseconds**, and redirects will vastly outnumber creations, so I'll assume **reads to writes at about 100:1**. And the key should be **as short as possible** — that's this service's entire reason to exist.

> 💡 **Coaching note** — In service-style problems, the requirements step is about trimming features; component-style problems only have a couple of features to begin with. Instead, the points here come from **volunteering quality requirements like "shorter keys are better" yourself** — that becomes the justification for the key-length math and encoding choice later.

---

## 2. Back-of-Envelope Math — Seven Characters Lasts a Lifetime

**Me** — Let me run the numbers. If creation is **1,000 per second**, redirects at 100x are **100,000 per second**. One conclusion falls out immediately — this system lives or dies on the read path, and **redirects have to be absorbed by a cache**.

The key length gets decided here too. If keys use the **62-character alphabet (Base62)** — upper, lower, digits:

```
62^6 ≈ 5.7 × 10^10  (about 57 billion)
62^7 ≈ 3.5 × 10^12  (about 3.5 trillion)
```

At 1,000 per second, that's roughly 31.5 billion per year. Six characters runs dry in under two years, but **seven lasts over a century** — effectively forever. So the key is locked in at **7 characters of Base62**. Storage-wise, even at 500 bytes per URL that's about 43GB a day, ~16TB a year — the metadata itself isn't heavy.

> 💡 **Coaching note** — Service-style estimation extracts a **direction** ("reads are 50x writes"); component-style estimation turns **the concrete number 62^7 into the concrete decision of key length**. Digit-level intuition is literally on the rubric — answering "why 7 characters?" without the math costs you points.

---

## 3. Key Generation — The Heart of This Problem

**Me** — Now the main event. There are three families of strategies for making short keys **unique**.

| | **(a) Truncated hash** | **(b) Global counter** | **(c) Distributed ID (Snowflake-style)** |
|---|---|---|---|
| How | First 7 Base62 chars of the MD5(URL) digest | Increment counter → Base62 | Timestamp + machine ID + sequence → Base62 |
| Uniqueness | **Needs collision handling** | Guaranteed | Guaranteed (no coordination) |
| Weak spot | Rehash loop on collision | **Single point of failure, sequential keys** | Longer keys (below) |

With (a), pack enough keys into a 62^7 space and the birthday problem makes collisions inevitable, embedding a collision-check-and-rehash loop in the write path. With (b), uniqueness is free but the counter has to live in one place. So the real candidates are a distributed version of (b), and (c).

**Interviewer** — Let's go with (b). **What if that counter DB dies?** Creation halts completely.

**Me** — Which is why I wouldn't use the counter as-is — I'd switch to **range allocation**. Each app server checks out **a whole block of numbers** from a central issuer (say, a million at a time) and burns through it in memory. The central issuer is only involved when handing out blocks, so its load drops by orders of magnitude, and if it goes down briefly, servers coast on the blocks they already hold. If a server dies mid-block, those numbers are discarded — in a 62^7 space, that much waste is a non-issue.

**Interviewer** — But anything counter-based means sequential keys. **Couldn't someone walk other people's links just by adding 1?**

**Me** — Correct — sequential keys are exposed to enumeration attacks. There are two answers. One: keep range allocation but insert **a bijective shuffle layer when converting numbers to keys**, scrambling the order. The other is a **Snowflake-style distributed ID** — split 64 bits into **41 bits of timestamp + 10 bits of machine ID + 12 bits of sequence**, and every server can mint millions of unique IDs per second **with zero coordination**, and sequential enumeration gets hard too. The catch: 64 bits encoded in Base62 runs to **11 characters**, so you give up "7." **If key length is the top priority, range allocation plus shuffle; if coordination-free simplicity wins, Snowflake** — and since short keys are this service's reason to exist, I'll take the former. Custom aliases live outside this scheme anyway — a unique constraint on an alias table handles first-come-first-served.

> 💡 **Coaching note** — The core of a component-style problem is always the three-step: **list the candidates → name each one's weak spot → choose conditionally**. Not "I'd use Snowflake" as one line, but **stating Snowflake's cost (11-character keys) and ruling on it against the requirement (short keys)** — that's how you show depth on a parts problem.

---

## 4. The Redirect Path — Even a Status Code Carries a Trade-off

**Me** — The read path. A short key comes in, we look up the original URL, and return a redirect — and the fork in the road starts at **301 vs 302**.

- **301 (Moved Permanently)** — the browser caches the result, so **from the next click on, the request never even reaches the server**. Minimal server load, but **click analytics are lost**.
- **302 (Found / temporary)** — every click passes through the server, so click counts and referrer **analytics are possible**. You absorb the load in exchange.

Since click analytics are most of the revenue in the short-URL business, the practical default is **302**. It's not the technology deciding — **"what you want decides the status code."**

Server-side, the 100K read QPS gets absorbed by cache. URL access follows a classic power law — **the top 20% of hot keys take most of the traffic** — and a mapping never changes once created, making this **the most cache-friendly data there is: no invalidation to worry about**. Redis with LRU gets you past a 90% hit rate without much effort.

**Interviewer** — Cache misses will fall through to the DB, and once data outgrows one machine you'll shard. **hash(key) mod N — good enough?**

**Me** — No. With mod N, **the moment N changes**, almost every key's owning server changes — add a single server and cache and DB routing get reshuffled wholesale. So we use **consistent hashing**. Put servers and keys on the same hash ring, have each key owned by the nearest server clockwise, and adding or removing a server moves **only about K/N keys on average**. The load-skew problem with few servers is solved by scattering each server across the ring as **hundreds of virtual nodes**.

> 💡 **Coaching note** — Consistent hashing is the part that usually hides behind the one-liner "we shard" in a service-style design. Component-style interviews open exactly that line and check whether you can walk from **"why mod N fails" all the way to virtual nodes**. Same with 301/302 — the point isn't memorizing status codes, it's answering with **the cache-vs-analytics trade-off**.

---

## 5. The Second Problem — "What If a Bot Hits It 100K Times a Second?"

**Interviewer** — Good, that's enough on the shortener. But that **creation API — what happens when a bot hits it 100,000 times a second?** It starts filling your 62^7 space with garbage.

**Me** — As designed, nothing stops it. We need a **rate limiter** in front — let me design that next. Requirements: **N requests per minute per user (or API key)**, some tolerance for a legitimate user's **momentary burst**, and a clear rejection response for excess requests. I'll also take as a premise that **wrongly blocking a legitimate request is worse** than the limit engaging a few milliseconds late.

> 💡 **Coaching note** — This is the classic component-style progression — the hole in the first problem becomes the second problem. In real interviews too, URL shortener / rate limiter / notification system are the staple pairings squeezed two-to-45-minutes, so **pacing the first problem to end at 20–25 minutes** is itself a skill to practice.

---

## 6. Algorithm Comparison — The Main Event This Time

**Me** — The heart of a rate limiter is the algorithm choice. Let me compare the candidates.

| | How | Bursts | Weak spot |
|---|---|---|---|
| **Fixed window** | Counter resets every fixed interval | Uncontrolled | **Boundary problem** (below) |
| **Sliding window log** | Record every request timestamp | Exactly controlled | A log entry per request — **memory-expensive** |
| **Sliding window counter** | Weighted average of previous and current window counters | Approximately controlled | An approximation (fine in practice) |
| **Token bucket** | Bucket refills R tokens/sec, requests consume them | **Allowed up to capacity C** | Parameter tuning |
| **Leaky bucket** | Queue requests, **drain at a constant rate** | Absorbed but delayed | Overflow beyond drain rate waits/drops |

Start with the fixed window's boundary problem. With a 100-per-minute limit, **100 requests at 0:59 and another 100 at 1:01** are both allowed — 200 requests in two seconds, momentarily double the limit. So fixed windows are strictly for "rough enforcement is fine" territory.

My pick is the **token bucket**. Capacity C is the burst allowance, refill rate R is the average rate limit — **two parameters mapping exactly onto the two requirements** — and the state is just (token count, last refill time), so it's cheap. It's the practical default. As an aside, you've almost certainly met a leaky bucket in the wild — a ticketing site's virtual waiting room that admits **"only N people per second"** is precisely one. Want to **reject** the overflow, token bucket; want to **queue it and drain it**, leaky bucket — same family, different temperament.

> 💡 **Coaching note** — Listing four algorithm names is something a search engine can do. The points split on **producing the fixed window's boundary numbers on the spot (0:59 / 1:01)** and **mapping the token bucket's parameters (C, R) onto the requirements (burst, average)**. True to component-style form, this is the problem's deep dive.

---

## 7. Distributed Setup — When the Counters Scatter

**Interviewer** — You won't have one server. **Spread across ten**, each server's buckets scatter too.

**Me** — Right — count separately per server and a user effectively gets N×10 per minute. So we **centralize bucket state in Redis**. The catch is that "read tokens → compute → write" as separate commands leaves a gap for races — so we **bundle it into a Lua script and run it atomically** (a plain counter scheme gets atomicity from a single INCR). Redis executes scripts on a single thread, so the verdict is exact.

**Interviewer** — So now **what if that Redis is the bottleneck, or dies?** Every request routes through it.

**Me** — Two-part answer. If it's a bottleneck — rate limits tolerate approximation anyway, so **each server rules on a local bucket first and syncs with Redis periodically**, taking the Redis round-trip out of the request path. If it dies — you have to choose **fail-open or fail-closed**. If the rate limiter dying **blocks the entire public API, the limiter has become the outage** — so public APIs fail **open (let traffic through)**; conversely, where the purpose is security, like login-attempt limiting, **closed (block)** is correct. That's decided not by the technology but by what the API is for.

Finally, placement and the response contract. This logic doesn't get embedded in each service — it lives in the **API gateway**. Not just the shortener's create and redirect, but every API gets protection for free, and policy stays in one place. Rejections return **429 Too Many Requests** with a **`Retry-After` header** telling clients when to try again — so a well-built client can back off on its own.

> 💡 **Coaching note** — "What if that Redis dies?" belongs to the same genre as the classic "what if the cache cluster goes down?" question, but the axis of the answer differs — for something like a feed cache, the answer is a **fallback path** (recompute the slow way); for the limiter, it's the **policy choice of fail-open vs fail-closed**. What the component protects flips the correct direction under failure.

---

## 8. Interview Retro — What Was Actually Being Graded

1. **Requirements** — few features, so I volunteered quality requirements: "shorter keys are better," "allow bursts"
2. **Back-of-envelope math** — 62^7 ≈ 3.5 trillion drove the "7 characters" decision; 100:1 drove the read cache
3. **Key generation deep dive** — compared hash/counter/Snowflake by weak spot, ruled for range allocation + shuffle against the requirements
4. **Redirect path** — 301/302 as a trade-off, and consistent hashing for sharding explained from first principles
5. **Algorithm comparison** — the fixed window's boundary numbers, the token bucket's parameter-to-requirement mapping
6. **Distribution and failure** — Redis Lua atomicity, local approximation, fail-open vs closed, 429 + Retry-After

And one meta-insight. Each of these two problems is something that **appears as a single line** inside any full-service architecture — "admit N people per second" (leaky bucket), "hot data goes to cache" (the LRU in the upcoming [LLD post](<./URL Shortener and Rate Limiter - LLD.md>)), "we shard" (consistent hashing). **A component-style problem is one that opens up the internals of a part that flashed by as one line in a service architecture.** If service-style problems teach you to draw the forest, this type teaches you to dissect a single tree.

---

### 📝 TL;DR

> **"Component-style HLD digs deepest into the problems that look smallest — compute 62^7 to set the key length, compare candidate algorithms by their weak spots, and answer even the failure direction (open/closed) as policy."**

---

## Next Up

The interviewer follows up — "That token bucket and LRU cache — care to implement them yourself?" Continued in the [URL Shortener and Rate Limiter LLD post](<./URL Shortener and Rate Limiter - LLD.md>).
