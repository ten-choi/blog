---
title: "System Design Mock Interview - HLD: \"Design a Food Delivery App (Uber Eats)\""
labels: ["System Design", "HLD", "Real-Time", "Location-Based", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> Some systems are **"read-heavy"** — a feed where reads dwarf writes. Some are **"write-contention"** — a ticket on-sale where a million people fight over the same rows. A delivery app is a third archetype.
>
> A delivery app is a **"real-time state stream"** — a rider's location lives or dies on freshness, becomes worthless the moment it's stale, and in exchange, losing some of it is fine. The **very nature of the data** is different from the other two archetypes. It's a 45-minute whiteboard interview — let's begin.

# The HLD Mock Interview — "Design a Food Delivery App (Uber Eats)"

## 0. Before We Start — The Third Archetype

| | **Read-heavy (a feed)** | **Write-contention (ticketing)** | **Delivery App (this post)** |
|---|---|---|---|
| Shape of the load | Reads are 50x writes | Spike at on-sale moment | **Mostly writes — an endless stream of location updates** |
| Nature of the data | Durable (posts stay) | Durable + consistent (it's money) | **Ephemeral — replaced by the next value in 5 seconds** |
| Consistency | Eventual is enough | Strong consistency required | **Freshness IS consistency — stale = worthless, loss is acceptable** |
| The battleground | Feed fan-out | Queue + seat locking | **Geo search + dispatch matching** |

For a 45-minute interview, a solid time split is 5 min requirements / 5 min back-of-envelope math / 5 min API & data model / 15 min architecture / 10 min deep dive / 5 min wrap-up.

---

## 1. Requirements First — No Boxes Yet

**Interviewer** — Here's today's problem. **Design a delivery app like Uber Eats.**

**Me** — Let me narrow the scope first. Should I take the core features to be **ordering, dispatch (rider matching), and real-time location tracking**? Leaving out restaurant search, reviews, and payment details.

**Interviewer** — Good. Let's go with those three.

**Me** — Let me check the non-functional side. Most of this system's writes will be **location updates the rider app sends periodically** — what active rider count should I assume? And **how fast** does dispatch need to happen, and **how stale** can the rider position on the customer's screen get?

**Interviewer** — Assume 100,000 active riders, sending location every 5 seconds. Dispatch within a few seconds; a position that's a few seconds stale is fine, but **a few minutes stale is meaningless**. Also factor in that lunch and dinner peaks are pronounced.

> 💡 **Coaching note** — Extracting the answer "a few seconds stale is fine, a few minutes stale is meaningless" is the first point scored in this interview. A feed's like count is data that can arrive late as long as it **eventually becomes correct**; location is data that's **useless even when correct** if it arrives late. The habit of asking about **the lifespan of the data** at the requirements stage is where archetype identification starts.

---

## 2. Back-of-Envelope Math — This Data Has a 5-Second Lifespan

**Me** — Let me run the numbers. 100,000 active riders sending location every 5 seconds is **20,000 location writes per second**. Billions per day. But this data has an unusual property — **each record is replaced by the next value 5 seconds later**. We're not accumulating history; only the latest value means anything.

Three conclusions fall out of this.

1. **Location goes in memory, not a disk DB** — persisting data with a 5-second lifespan to disk is waste. Expire stale entries and offline riders disappear on their own.
2. **The structure must support geo search** — dispatch's first question is "who's near this restaurant?" The location store needs not just coordinate updates but **radius search** (the geohash family).
3. **Orders/payments and location split at the storage layer** — orders live in the durable/consistent world (it's money); location lives in the ephemeral/freshness world. Put data with different natures in one store and you satisfy neither.

> 💡 **Coaching note** — The purpose of back-of-envelope math is always to extract the one line that **justifies your next decision** — here, "**20,000 per second, each replaced in 5 seconds**" justifies in-memory + staleness expiry. What you extract isn't just scale — it's **the data's lifespan and replacement cycle**.

---

## 3. API and Data Model — Contracts Before Boxes

**Me** — Let me write the contract first.

```
POST /orders                  (store_id, items[])            → order_id
PUT  /riders/{id}/location    (lat, lng)  ← every 5 seconds  → 204
GET  /orders/{id}/tracking    (WebSocket/SSE upgrade)        → status/location push
```

Tracking will be **WebSocket/SSE push, not polling** — the customer is staring at the screen after ordering, and making them poll every 5 seconds makes tracking traffic as big as the location writes. The data model splits in two by nature.

```
orders (id, user_id, store_id, rider_id, status, ...)   -- RDB, state machine
riders (id, name, vehicle, rating, acceptance_rate)     -- RDB, profiles
location → Redis GEO: GEOADD riders:geo lng lat rider_id  -- in-memory, + last-update timestamp
           search via  GEOSEARCH riders:geo FROMLONLAT ... BYRADIUS 3 km
```

**Interviewer** — Why not just UPDATE the location into the riders table? It's two columns.

**Me** — That's 20,000 UPDATEs per second hammering the disk and the WAL (write-ahead log). An RDB pays that cost to **persist** the write, but this value gets discarded 5 seconds later, so the entire cost is waste. On top of that, geo queries like "riders within 3km" are expensive in an RDB. Put it in Redis GEO and updates are memory operations and radius search comes built in. One caveat — Redis TTLs are per key, and GEO members all share one key, so an individual rider can't just expire. Instead we stamp each rider's **last-update time** and have the dispatch query **filter out anyone stale** (no update in, say, 15 seconds), with a periodic sweep ZREMing them from the GEO set — so **a rider who closes the app ages out of the candidate pool on their own**.

> 💡 **Coaching note** — "Why not just write it to the DB?" is this problem's go-to interrogation. The skeleton of the answer: **match the data's lifespan to the store's guarantees** — pay for durability guarantees (disk, WAL) only on data that needs durability. Apply the most expensive guarantee to every path and the system collapses — pay only where the data demands it.

---

## 4. Dispatch ① — How Do You Find Nearby Riders?

**Me** — Now the main body of this interview: dispatch. The first question is search — **how do you quickly find riders near the restaurant?**

The principle is **geohash**. Cut the map into a grid and give each cell a string address; the key property is that **a shared prefix means nearby**. `wydm6` and `wydm7` are neighbors. So "search nearby" turns from a coordinate computation into **string prefix matching**. One trap, though — a rider just across a cell **boundary** has a different prefix. So in practice you search not just the center cell but **the 8 neighboring cells together**. Redis GEO does this internally, so one line of `GEOSEARCH ... BYRADIUS 3 km` gives us the candidate list within 3km.

**Interviewer** — Once you have candidates, do you just hand the order to the closest rider?

**Me** — Closest-only is wrong. A rider 800m away with a 90% acceptance rate beats one 300m away at 20%, and if they're driving in the opposite direction, straight-line distance is meaningless. So we combine **distance, acceptance rate, heading, and ETA-to-pickup into a weighted score**, sort the candidates, and **offer sequentially from the top** — no acceptance within 30 seconds moves on to the next candidate. This scoring policy will be tuned per city and time of day, so it's the first thing that will change.

> 💡 **Coaching note** — The standard answer to location-based problems is "**turn space into a string grid (geohash)**," and the standard trap is "**the boundary problem → 8 neighbor cells**." Mention the pair and you look like someone who knows the principle; name only the tool (Redis GEO) and you look like someone who memorized it. Separating search (where are they?) from policy (who gets it?) is also a scoring point.

---

## 5. Dispatch ② — Concurrency Hides Here Too

**Interviewer** — Two races. **Offers from two orders reach rider A at the same time**? And **two riders accept the same order at the same time**?

**Me** — Being a real-time stream problem doesn't mean there's no contention. As long as riders and orders are **resources**, the classic inventory-contention problem appears here too. The verdict comes down to one line of **conditional atomic update**.

```sql
-- Rider's acceptance: only valid while the order is still MATCHING
UPDATE orders
SET    rider_id = :rider_id, status = 'ACCEPTED'
WHERE  id = :order_id
  AND  status = 'MATCHING';   -- this condition IS the lock
```

If the affected row count is 0, another rider accepted first or the order was cancelled, so we return "already assigned." Same on the rider side — update with `WHERE status = 'IDLE'`, so even if two orders grab simultaneously, there's exactly one winner. This is where the storage split earns its keep — **location lives in Redis (ephemeral, freshness), but the assignment verdict happens in an RDB transaction (durable, consistent)**.

> 💡 **Coaching note** — An archetype tells you the problem's **center of gravity**; it doesn't mean other archetypes' problems won't appear. Inside the real-time-stream delivery app hides the contested resource pair "order/rider," and at that point the ticketing-style `WHERE status='AVAILABLE'` conditional update is exactly the right tool. **Resource contention points hide everywhere** — archetype classification is the tool that gives you the eyes to find them.

---

## 6. The Full Picture

**Me** — Putting every decision so far on one page:

```
Customer app                     Rider app
   │ ① order                        │ location (every 5s)
   ▼                                ▼
Order Service ── RDB (orders,    Location Ingestion Service
   │             state machine)      └─▶ Redis GEO (GEOADD + freshness filter)
   │ ② "dispatch request" event             ▲
   ▼                                        │ GEOSEARCH radius 3km
Dispatch Service ── candidate search ───────┘
   │  sort by weighted score → sequential offers to top candidates (30s timeout)
   │  acceptance = conditional UPDATE on orders (exactly 1 winner)
   ▼
Kafka (order status events) ─▶ Notification Service (customer/store push)
                            └▶ Tracking Service ── WebSocket/SSE
                                  └─ subscribes to location stream → pushes rider position to customer screen
```

Orders and payments live in the RDB's transactional world, location in Redis's ephemeral world, and state changes flow as Kafka events that notifications and tracking each subscribe to.

**Interviewer** — What if **that location Redis dies entirely**?

**Me** — This is where the nature of the data pays off. Losing a social network's posts or a booking system's records is an unrecoverable disaster, but **location is rebuildable data whose source is still alive** — the rider apps resend it every 5 seconds. Spin up a new Redis and active riders' positions refill within tens of seconds. In the meantime, dispatch is delayed by tens of seconds — the system **degrades gracefully**; no data is lost. That's why the location Redis doesn't need expensive persistence or elaborate replication.

> 💡 **Coaching note** — The answer to "what if this component dies?" comes from the nature of the data. **Data whose loss is a disaster** (posts, bookings) gets protected with replication and backups; **data whose loss self-heals** (a location stream) only needs a rebuild path. Pay for failure handling in proportion to the data's lifespan, too.

---

## 7. "Where Would You Improve First?" — Version 2

**Interviewer** — We have time left. What are this design's limitations?

**Me** — I'd point at three spots.

1. **Supply-demand imbalance at peak** — dispatch failures cluster at 12pm. Forecast per-area order volume and **pre-position riders toward demand zones before the peak** (incentive notifications), and dispatch evolves from "clean up after it bursts" to "prepare before it bursts."
2. **Batched deliveries** — bundling multiple route-overlapping orders onto one rider boosts throughput dramatically, but matching turns from 1:1 assignment into a **route optimization problem**. Because we separated the scoring policy in section 4, only the matching layer needs swapping.
3. **Sharding** — once traffic outgrows one cluster we have to split, and delivery is **inherently region-local** — an order in Seoul never meets a rider in Busan. So **sharding by city (region)** is the obvious answer, with almost no cross-shard issues. A sharp contrast with sharding a social graph, where no such natural boundary exists.

> 💡 **Coaching note** — Picking a shard key is usually one of HLD's hard debates, but the delivery problem is regionally closed by nature, so **the shard key falls out of the domain on its own**. Pointing out "where are this domain's natural boundaries?" elevates the quality of a version-2 answer.

---

## 8. Interview Retro — What Was Actually Being Graded

1. **Requirements gathering** — narrowed to three features and extracted the freshness requirement: "seconds are fine, minutes are not"
2. **Back-of-envelope math** — derived in-memory + staleness expiry and the storage split from "20,000 per second, each replaced in 5 seconds"
3. **API & data model** — tracking as push (WebSocket), location in Redis GEO, orders as an RDB state machine
4. **Architecture** — answered dispatch in two layers: geohash (boundary problem included) and weighted-score matching
5. **Trade-off negotiation** — answered "why not just write to the DB?" with data lifespan, simultaneous acceptance with conditional updates, Redis failure with "rebuildable data"
6. **Foresight** — named the next steps unprompted: demand-forecast pre-positioning, batched deliveries, regional sharding

Zoom out and three big archetypes cover a surprising share of interview problems. **Read-heavy** (a feed) is the precompute-and-distribute problem — cache, fan-out, eventual consistency. **Write-contention** (ticketing) is the line-them-up-and-lock-precisely problem — queue, atomic locking, strong consistency. **Real-time state stream** (delivery) is the catch-the-flowing-latest-value problem — in-memory freshness windows, geo search, push streams. When you meet a new problem, ask first: *is this data read-heavy, write-contention, or a real-time stream?*

---

### 📝 TL;DR

> **"Designing a delivery app is an exercise in reading data lifespans — let 5-second locations flow through an in-memory geohash store with freshness filtering, and lock only the orders and assignments that need durability behind transactions."**

---

## Next Up

The interviewer follows up — "So, that dispatch service. Care to design it as classes?" Continued in the [Food Delivery App LLD post](<./Food Delivery App - LLD.md>).
