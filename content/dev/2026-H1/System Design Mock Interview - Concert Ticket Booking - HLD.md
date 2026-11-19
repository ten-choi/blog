---
title: "System Design Mock Interview - HLD: \"Design a Concert Ticket Booking System\""
labels: ["System Design","HLD","Concurrency","Queueing","Tech Interviews"]
published: true
date: 2026-03-27T21:18:00+09:00
readerComments: "ALLOW"
bloggerPostId: "7294742125074855332"
source: "archive"
archivePath: "_archive/dev/system design/Ticket Booking - HLD.md"
---

> If a feed service like Instagram is the world of **"read explosion + eventual consistency"**, this problem is the exact opposite.
>
> Ticketing is the world of **"write contention + strong consistency"** — the moment sales open, hundreds of thousands of people charge at the same 50,000 seats simultaneously, and selling the same seat twice is absolutely unforgivable. 45-minute whiteboard interview — let's go.

# The HLD Mock Interview — "Design a Concert Ticket Booking System"

## 0. Before We Start — How Is This Different from a Feed Service?

| | **A read-heavy feed (Instagram-style)** | **Ticket booking (this post)** |
|---|---|---|
| Shape of the load | Reads 50x writes, steady | Quiet most of the time, **a thousandfold spike at open** |
| Contested resource | None (my feed is mine) | **50,000 seats fought over by hundreds of thousands** |
| Consistency | Like counts can lag | **Double-selling = an incident. Strong consistency required** |
| The main event | Feed fan-out (Push vs Pull) | **Queueing + seat locking** |

For a 45-minute interview, a solid time split is 5 min requirements / 5 min back-of-envelope math / 5 min API & data model / 15 min architecture / 10 min deep dive / 5 min wrap-up.

---

## 1. Requirements First — No Boxes Yet

**Interviewer** — Today's problem: **design a ticket booking system for a popular concert.**

**Me** — Okay. Before I draw anything, I'd like to make sure I know what we're building. What should a user be able to do? I'm picturing browsing shows, looking at the seat map, picking seats, and paying. Do you also want me to cover things like cancellations, transferring a ticket to someone else, or refunds?

**Interviewer** — Let's keep it to browsing, picking seats, and paying. Leave cancellations, transfers, and refunds out for today.

**Me** — Got it. Then I suspect most of the difficulty is on the non-functional side. Roughly how many people are we expecting right when sales open?

**Interviewer** — Say 50,000 seats, and about a million people trying to get in at open.

**Me** — A million people for 50,000 seats. And I assume we can never sell the same seat to two people?

**Interviewer** — Right, double-selling is not acceptable. One more thing: it should feel fair. First come, first served.

**Me** — Okay, let me write that down so we can come back to it.

```
Functional      browse shows & seat map / hold seats / pay
Out of scope    cancellation, transfer, refund
Non-functional  50K seats, ~1M users at open
                no double-selling (strong consistency on seats)
                fairness (first come, first served)
```

> 💡 **Coaching note** — Notice who drew the line. The candidate **listed candidates and asked**; the interviewer **decided** what was out of scope. Announcing "I'll leave X out" on your own reads as dodging work — asking lets the interviewer steer, and you still get a narrow scope. Also notice where the questions went: in most product-design problems (feeds, messengers) the functional requirements drive the conversation, but in ticketing **the non-functional requirements (the spike, strong consistency, fairness) ARE the problem**. Asking about them first tells the interviewer you've seen that.

---

## 2. Back-of-Envelope Math — These Numbers Decide the Architecture

**Me** — Can I take a couple of minutes for some quick numbers? I think they'll drive most of the design.

**Interviewer** — Go ahead.

**Me** — 50,000 seats, a million people. So **at most 5% of people get a seat**. If most of them hit the button in the first few seconds, we're looking at hundreds of thousands of requests per second at peak — and 95% of that traffic is going to fail no matter what we do.

**Interviewer** — So what does that tell you?

**Me** — Three things, I think. First, **we shouldn't let that spike reach the database**. If 95% of requests are going to fail anyway, sending all of them to the DB just to say no would hurt the 5% who could actually succeed. So I want some kind of line at the entrance. Second, **the seat state has to live in one place that can be updated atomically** — that's where the no-double-selling rule gets enforced. And third, looking at the seat map and grabbing a seat are very different kinds of traffic, so **I'd give browsing and booking separate paths**.

**Interviewer** — Okay. Let's see how that turns into an API.

> 💡 **Coaching note** — In a read-heavy system, one line like "reads are 50x writes" justifies every cache and fan-out decision; in ticketing, the "5% success rate" line justifies **the queue**. The purpose of back-of-envelope math is always to extract the one line that **justifies your next decision** — and when the interviewer asks "so what does that tell you?", that line is the answer.

---

## 3. API and Data Model — Contracts Before Boxes

**Me** — Since we're putting a line at the entrance, the queue shows up in the API too. Let me sketch it.

```
POST /queue/enter        (event_id)                        → queue_token, position
GET  /queue/status       (queue_token)                     → position in line / admitted
GET  /events/{id}/seats                                    → seat map (grade, status)
POST /holds              (queue_token, seat_ids[])         → hold_id, expiry time
POST /bookings           (hold_id, payment_info, idempotency key) → booking_id
```

**Interviewer** — Why separate holds from bookings? Why not book directly?

**Me** — Because picking seats and paying takes a few minutes. If the seat isn't reserved during that time, someone can lose it while they're typing in their card details — that's about the worst experience we could give them. So it's **hold, then pay, then confirm**. But the hold has to expire, or people who close the tab would sit on seats forever. I'd start with something like **7 minutes** — does that sound reasonable?

**Interviewer** — 7 minutes is fine.

**Me** — Then the data model would look roughly like this.

```
events   (id, name, open_at, ...)
seats    (id, event_id, grade, status: AVAILABLE/HELD/SOLD, hold_id, version)
holds    (id, user_id, seat_ids, expires_at, status)
bookings (id, hold_id, user_id, amount, status, idempotency_key)
```

**Interviewer** — Seat map reads are going to explode at open too. Are you hitting the seats table every time?

**Me** — No, I'd serve the seat map from a **cache**. If it's a few seconds behind, that's okay, because the real check happens in the database when someone tries to hold a seat. So what you **see** is approximate, but what you **get** is exact.

> 💡 **Coaching note** — Needing strong consistency does NOT mean applying strong consistency to **every path** — do that and the system collapses. Being able to **articulate the split** between where truth is mandatory (hold/confirm) and where staleness is fine (seat map display) is one of the grading points of this problem. And notice the small "does that sound reasonable?" on the TTL — a number you picked becomes a number you both agreed on.

---

## 4. Traffic Defense — The Virtual Waiting Room

**Me** — If it's okay with you, I'd like to start with the entrance, since that's where the million people hit us first.

**Interviewer** — Sure.

**Me** — Instead of letting everyone into the booking service at once, I'd put them in a **virtual waiting room**. When you arrive, you get a queue token and a position number — that can just be a Redis counter, or a Kafka offset — and the client polls its position. This part holds almost no state, so it scales out easily.

Behind it, we let people in only as fast as the booking service can actually handle — say **N per second**, like a leaky bucket. And the hold API only accepts admitted tokens, so nobody can skip the line by calling it directly.

**Interviewer** — Couldn't you skip the queue and just add a ton of servers? Autoscale it?

**Me** — We could add app servers, but they'd all still be fighting over the same 50,000 rows in **one database**. A hundred times the servers just means a hundred times the contention on that one spot. And since 95% of requests fail anyway, the extra servers would mostly be returning failures faster. When the thing everyone wants is fixed in size, I think the answer is **controlling how many people get in**, not adding servers. The queue position also gives us the first-come-first-served fairness you asked for.

**Interviewer** — Fair enough.

> 💡 **Coaching note** — "Why not just scale out?" is the classic trap question for this problem. You need to be able to say: **when the bottleneck is the shared resource (inventory) itself, horizontal scaling is not the answer**. Every architecture technique has a weak spot, and "fixed inventory" is scale-out's weak spot in ticketing.

---

## 5. Seat Holds — The One Line That Prevents Double-Selling

**Interviewer** — Now say two admitted users click the same seat at the same moment. How do you make sure only one of them gets it?

**Me** — I'd let the database decide, with a **conditional update**.

```sql
UPDATE seats
SET    status = 'HELD', hold_id = :hold_id
WHERE  id IN (:seat_ids)
  AND  status = 'AVAILABLE';   -- this condition IS the lock
```

The `status = 'AVAILABLE'` part is basically the lock. Whoever reaches the row first flips it to HELD, and the second one doesn't match the condition anymore. If the number of updated rows doesn't match the number of seats requested — meaning someone got one of them first — I'd **roll back the whole thing** and return an error. Getting two of your three seats is worse than getting none.

**Interviewer** — Why not a distributed lock? Something like Redis?

**Me** — I could, but the database already holds the truth about the seats, and its row locks already give us the guarantee we need. A separate lock in Redis is one more thing that can disagree with the database. I'd only reach for it if the database turned out to be the bottleneck.

**Interviewer** — What about people who hold seats and then walk away without paying?

**Me** — Once a hold's `expires_at` passes, a background job sets those seats back to `AVAILABLE`. When the payment-complete webhook comes in, that's when we mark them `SOLD`. Payment goes through an external payment gateway (PG), which can be slow or fail, so I'd keep that **asynchronous** — and the `idempotency_key` makes sure a duplicate webhook can't confirm the booking twice.

> 💡 **Coaching note** — You score higher showing that **the one line `WHERE status = 'AVAILABLE'` is the lock** than by throwing around fancy words like "distributed locks" or "Redis Redlock." Tools come second. The class-level implementation of this conditional update is covered in code in the [LLD post](<./Ticket Booking - LLD.md>).

---

## 6. The Full Picture

**Me** — Let me put it all on one page so we can walk through it end to end.

```
Client
   │ ① Entry request → queue token + position issued
   ▼
Virtual Waiting Room (Redis positions / admit N per second) ←─ position polling
   │ ② Admission granted (token)
   ▼
Load Balancer → Booking Service
   ├─ Seat map reads → seat map cache (a few seconds stale is OK)
   ├─ ③ Hold: conditional UPDATE in DB (truth decided here, TTL 7 min)
   └─ ④ Payment request → external PG ─(webhook)→ confirm (SOLD) / fail (release)
                                   │
                                   └─▶ Kafka → notifications, settlement, stats (async)

Expiry processor ─ reverts holds past expires_at back to AVAILABLE
```

**Interviewer** — What if the server dies right after payment goes through? The PG says it's paid, but the seat is still stuck at HELD.

**Me** — The PG **retries** the webhook, and thanks to the idempotency key, receiving it more than once is safe. If something is still out of sync after that, I'd have a **reconciliation job that compares the PG's transaction records against our bookings** and fixes the difference. With money, I think it's more realistic to guarantee that things **end up consistent** than to try to be perfect in real time.

---

## 7. "Where Would You Improve First?" — Version 2

**Interviewer** — We have a few minutes left. Where does this design fall short?

**Me** — Hmm, three places come to mind.

The first is **bots**. A fair queue doesn't help if half the line is scripts. I'd add CAPTCHAs and device fingerprinting at the entrance, purchase limits per account, and watch for odd patterns in the waiting room.

The second is **hot zones**. Even with 50,000 seats, everyone wants the front rows, so the contention piles up in a few zones. **Partitioning the seat table by zone** would keep that contention contained. And for "any two seats in this section" requests, we could count down a per-zone counter first and assign the exact seats later.

The third is **the seat map going stale**. If people keep clicking seats that are already gone because the cache is behind, I'd move toward **pushing seat-status changes over WebSocket or SSE**.

**Interviewer** — Good. Let's stop there.

> 💡 **Coaching note** — Version 2 candidates always come from **"where my design's assumptions break."** The queue's assumption (humans stand in line) is broken by bots; the row lock's assumption (contention is evenly spread) is broken by hotspots.

---

## 8. Interview Retro — What Was Actually Being Graded

1. **Requirements gathering** — asked instead of assumed: let the interviewer set the scope, and identified up front that the non-functional side (spike, no double-selling, fairness) is the body of the problem
2. **Back-of-envelope math** — derived the need for a queue from the "5% success rate"
3. **API & data model** — baked the hold→pay→confirm two-phase flow and TTL into the contract
4. **Architecture** — separated the browsing path (cache) from the booking path (DB truth), plus the virtual waiting room
5. **Trade-off negotiation** — answered "why not scale out?" with the shared-resource bottleneck, and the failure question with idempotency keys + reconciliation jobs
6. **Foresight** — named the next bottlenecks first: bots, hotspots, seat map freshness

Zoom out and you can see the two archetypes of HLD interviews — **read-explosion problems (feeds, timelines) are "precompute and distribute" problems** (caches, fan-out, CDN), and **write-contention problems (tickets, inventory) are "form a line and lock precisely" problems** (queues, atomic locking, idempotency). When you meet a new problem, ask first: *which kind is this?*

---

### 📝 TL;DR

> **"Ticketing design is two sentences — at the entrance, form a line with a queue; at the seat, lock precisely with the one line `WHERE status='AVAILABLE'`."**

---

## Next Up

The interviewer follows up — "That seat hold. Care to design it as classes?" Continued in the [Ticket Booking LLD post](<./Ticket Booking - LLD.md>).
