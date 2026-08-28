---
title: "System Design Mock Interview - HLD: \"Design a Concert Ticket Booking System\""
labels: ["System Design", "HLD", "Concurrency", "Queueing", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
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

**Interviewer** — Here's today's problem. **Design a ticket booking system for a popular concert.**

**Me** — Let me narrow the scope first. Should I take the core features to be **browsing shows and seats, seat selection and booking, and payment**? Leaving cancellations, transfers, and refunds out of scope.

**Interviewer** — Good. Let's go with those three.

**Me** — The non-functional side feels like the real body of this problem. What **concurrent user count at the moment tickets open** should I assume? And I can take it that **selling the same seat to two people** is absolutely not allowed, right?

**Interviewer** — Let's say 50,000 seats and 1 million people piling in at open. Double-selling is obviously out. One more thing — please also care about **fairness: first come, first served**.

> 💡 **Coaching note** — In most product-design problems (feeds, messengers), functional requirements drive the conversation, but in ticketing **the non-functional requirements (the spike, strong consistency, fairness) ARE the problem**. The moment you say this out loud, the interviewer sees you as someone who understands the problem.

---

## 2. Back-of-Envelope Math — These Numbers Decide the Architecture

**Me** — Let me run the numbers. With 50,000 seats and 1 million people waiting, **only 5% of requests can succeed**. If the requests concentrate in the first few seconds after open, we're looking at hundreds of thousands of QPS at peak — and most of that traffic is **requests that are going to fail anyway**.

Three conclusions fall out of this.

1. **We must not take the spike head-on** — letting traffic that's 95% doomed to fail through to the database isn't just wasteful, it's self-harm. We need to **form a line at the entrance**.
2. **Seat state needs strong consistency** — the "truth" about 50,000 seats must be managed atomically in one place.
3. **Separate browsing from booking** — read traffic looking at the seat map and write traffic grabbing seats have completely different requirements, so they get separate paths.

> 💡 **Coaching note** — In a read-heavy system, one line like "reads are 50x writes" justifies every cache and fan-out decision; in ticketing, the "5% success rate" line justifies **the queue**. The purpose of back-of-envelope math is always to extract the one line that **justifies your next decision**.

---

## 3. API and Data Model — Contracts Before Boxes

**Me** — Let me write down the contract first. Since there's a queue, it shows up in the API too.

```
POST /queue/enter        (event_id)                        → queue_token, position
GET  /queue/status       (queue_token)                     → position in line / admitted
GET  /events/{id}/seats                                    → seat map (grade, status)
POST /holds              (queue_token, seat_ids[])         → hold_id, expiry time
POST /bookings           (hold_id, payment_info, idempotency key) → booking_id
```

I've split booking into two phases: **hold (reserve) → pay → confirm**. Picking seats and paying takes a few minutes, and if we don't lock the seats during that window, you get the worst possible UX — losing your seat while on the payment screen. In exchange, holds carry a **TTL (say, 7 minutes)** so abandoners can't sit on seats forever.

Here's the data model:

```
events   (id, name, open_at, ...)
seats    (id, event_id, grade, status: AVAILABLE/HELD/SOLD, hold_id, version)
holds    (id, user_id, seat_ids, expires_at, status)
bookings (id, hold_id, user_id, amount, status, idempotency_key)
```

**Interviewer** — Seat map reads (GET /seats) will also explode at open. Are you hitting the seats table every time?

**Me** — No — browsing is served from a **cached seat map**. It's fine if it's a few seconds stale, because the final truth is decided by the database at hold time anyway. "What you **see** is approximate; what you **grab** is exact" — that's this system's consistency principle.

> 💡 **Coaching note** — Needing strong consistency does NOT mean applying strong consistency to **every path** — do that and the system collapses. Being able to **articulate the split** between where truth is mandatory (hold/confirm) and where staleness is fine (seat map display) is one of the grading points of this problem.

---

## 4. Traffic Defense — The Virtual Waiting Room

**Me** — Now the first main body of the architecture: the entrance. Instead of letting the 1 million people at open into the service, we put them in a **Virtual Waiting Room**.

- Entry requests get a **queue token and a position number** (a Redis counter or Kafka offset), and the client just polls its position. This path is nearly stateless, so it scales horizontally as far as we like.
- We admit people only as fast as the booking service behind it can handle — say, **N per second**. We're throttling the faucet (leaky bucket).
- Only admitted users get access to the hold API, and **token validation** blocks direct calls that try to skip the line.

**Interviewer** — Couldn't you skip the queue and just add a ton of servers (autoscaling)?

**Me** — We can add app servers, but **there's only one database holding the truth about those 50,000 seats**. Scale the servers 100x and you've just funneled 100x the contention into that single point. Besides, 95% of the requests will fail anyway, so the extra capacity would only be used to "return failures faster." When the contested resource is fixed, the answer isn't scale-out — it's **admission control**. And the queue position also answers the fairness requirement.

> 💡 **Coaching note** — "Why not just scale out?" is the classic trap question for this problem. You need to be able to say: **when the bottleneck is the shared resource (inventory) itself, horizontal scaling is not the answer**. Every architecture technique has a weak spot, and "fixed inventory" is scale-out's weak spot in ticketing.

---

## 5. Seat Holds — The One Line That Prevents Double-Selling

**Me** — The second main body: seat locking. When two admitted users try to hold **the same seat at the same time**, there must be exactly one winner. The key is a **conditional atomic update** in the database.

```sql
UPDATE seats
SET    status = 'HELD', hold_id = :hold_id
WHERE  id IN (:seat_ids)
  AND  status = 'AVAILABLE';   -- this condition IS the lock
```

If the affected row count differs from the requested seat count — meaning someone got there first — we **roll back everything** and return a failure (partial success is worse UX). It's all inside one transaction, so it's atomic, and per-seat contention is sorted out by the database's row locks.

**Interviewer** — What about people who hold seats and then walk away without paying?

**Me** — Once a hold's `expires_at` passes, an expiry processor flips the seats back to `AVAILABLE`. When the payment-complete webhook arrives, that's when we confirm the seats as `SOLD`. Payment goes through an external payment gateway (PG), which is slow and can fail, so it stays **asynchronous**, and the `idempotency_key` ensures a duplicate webhook can't double-confirm.

> 💡 **Coaching note** — You score higher showing that **the one line `WHERE status = 'AVAILABLE'` is the lock** than by throwing around fancy words like "distributed locks" or "Redis Redlock." Tools come second. The class-level implementation of this conditional update is covered in code in the [LLD post](<./Ticket Booking - LLD.md>).

---

## 6. The Full Picture

**Me** — Putting every decision so far on one page:

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

**Interviewer** — What if the server dies right after payment confirmation? The PG says it's paid, but the seat is still stuck at HELD.

**Me** — The PG **retries** the webhook, and on our side the idempotency key makes receiving it any number of times safe. Any inconsistency that still remains gets caught by a **reconciliation batch that compares PG transaction records against bookings**. For money flows, "**guaranteed convergence after the fact**" is more realistic than "perfect in real time."

---

## 7. "Where Would You Improve First?" — Version 2

**Interviewer** — We have some time left. What are this design's limitations?

**Me** — I'd point at three spots.

1. **Bots and macros** — queue-position fairness is helpless against bots. I'd add CAPTCHAs and device fingerprinting at entry, per-account purchase limits, and anomaly-pattern detection at the waiting room layer.
2. **Seat contention hotspots** — even among 50,000 seats, contention concentrates on specific front-row zones. **Partitioning the seat table by zone** isolates row-lock contention within each zone. For "any N seats" requests, another option is to allocate against per-zone counters first and defer the exact seat assignment.
3. **Seat map freshness** — if users keep clicking "seats they can't actually grab" because the cache is stale, I'd evolve toward a real-time seat map that **pushes seat-state-change events over WebSocket/SSE**.

> 💡 **Coaching note** — Version 2 candidates always come from **"where my design's assumptions break."** The queue's assumption (humans stand in line) is broken by bots; the row lock's assumption (contention is evenly spread) is broken by hotspots.

---

## 8. Interview Retro — What Was Actually Being Graded

1. **Requirements gathering** — identified up front that the non-functional side (spike, no double-selling, fairness) is the body of the problem
2. **Back-of-envelope math** — derived the need for a queue from the "5% success rate"
3. **API & data model** — baked the hold→pay→confirm two-phase flow and TTL into the contract
4. **Architecture** — separated the browsing path (cache) from the booking path (DB truth), plus the virtual waiting room
5. **Trade-off negotiation** — answered "why not scale out?" with the shared-resource bottleneck, and the failure question with idempotency keys + reconciliation batches
6. **Foresight** — named the next bottlenecks first: bots, hotspots, seat map freshness

Zoom out and you can see the two archetypes of HLD interviews — **read-explosion problems (feeds, timelines) are "precompute and distribute" problems** (caches, fan-out, CDN), and **write-contention problems (tickets, inventory) are "form a line and lock precisely" problems** (queues, atomic locking, idempotency). When you meet a new problem, ask first: *which kind is this?*

---

### 📝 TL;DR

> **"Ticketing design is two sentences — at the entrance, form a line with a queue; at the seat, lock precisely with the one line `WHERE status='AVAILABLE'`."**

---

## Next Up

The interviewer follows up — "That seat hold. Care to design it as classes?" Continued in the [Ticket Booking LLD post](<./Ticket Booking - LLD.md>).
