---
title: "System Design Mock Interview - LLD: \"Design That Dispatch Service as Classes\""
labels: ["System Design", "LLD", "Real-Time", "Object-Oriented", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> In the [Food Delivery App HLD post](<./Food Delivery App - HLD.md>) we drew the forest — location flows through an in-memory geohash, dispatch sorts candidates by score and offers sequentially, and acceptance is decided by a conditional update.
>
> This time we walk into the machine coding interview and implement that **dispatch service as classes**. Strategy patterns, state machines, atomic updates, heaps — **this is a capstone problem where the classic LLD toolkit reappears in one design**.

# The LLD Mock Interview — "Design the Dispatch Service as Classes"

## 0. Before We Start — Where Dispatch Sits Among LLD Problems

| | **A feed LLD** | **A seat-booking LLD** | **Delivery dispatch (this post)** |
|---|---|---|---|
| Domain archetype | Read-assembly | Resource contention | **Real-time matching — a synthesis of the two** |
| First thing to change | Feed ordering policy | Pricing policy | **Matching score policy** (Strategy) |
| State management | Simple | The state machine IS the problem | **State machine** (an order's lifecycle) |
| DSA highlight | k-way merge + heap | Lock ordering, conditional updates | **Geohash buckets + nearest-k min-heap** |

The time split is the same — for 3 hours: 30 min requirements & design / 2 hours implementation / 30 min tests & refactoring. Let's walk in.

---

## 1. Clarifying Requirements — No Code Yet

**Interviewer** — Here's the problem. **Design and implement, as classes, a dispatch service that finds nearby riders when an order comes in, offers it to them, and assigns it on acceptance.**

**Me** — Let me confirm the scope. Dispatch targets are **riders within a 3km radius**, and an offer moves to the **next candidate after a 30-second timeout** — correct?

**Interviewer** — Correct.

**Me** — For matching score I'll start with **nearest-first**, but assume it **can change** to a weighted score of acceptance rate and ETA. Order status flows `CREATED → MATCHING → ACCEPTED → PICKED_UP → DELIVERED`, with `CANCELLED` reachable from any stage. And since **two orders competing for the same rider** is everyday life in this problem, I'll carry concurrency from the start.

**Interviewer** — Good. Let's go with that.

> 💡 **Coaching note** — The requirements-stage judgment call is what to simplify. In a read-assembly problem like a feed, **setting concurrency aside** is the good move; in a contention problem like this one, setting it aside **costs points** — matching is inherently a many-grab-one problem. The criterion for "what can I simplify?" is always **whether it's the heart of the problem**.

---

## 2. Collect the Nouns, Find What Will Change

**Me** — Nouns first — order, rider, location, candidate, offer, matching score. Wiring up the relationships:

```
Order (state machine: CREATED/MATCHING/ACCEPTED/PICKED_UP/DELIVERED/CANCELLED)
Rider (id, acceptance rate, current status)
RiderLocationStore ─ geohash buckets, radius search (the DSA heart)
MatchingStrategy   ─ candidate ordering policy (first thing to change!)
DispatchService    ─ assembles search → sort → sequential offers → assignment
OrderEventListener ─ subscribes to state changes (customer notifications, tracking screen updates)
```

I see two familiar patterns. **Matching score becomes a Strategy** — a policy that will be tuned and swapped is the classic Strategy signal. **The order becomes a state machine** — it's a thing that flows through time with a lifecycle. The genuinely new piece is `RiderLocationStore` — we need a **spatial data structure** with two operations: location update and radius search.

> 💡 **Coaching note** — With a little practice, noun collection becomes pattern matching: **see a policy that will change → Strategy; see something flowing through time → state machine; see many things reacting to one event → Observer**. The truly new part of a new problem is usually just one spot — here, spatial search. Handle the familiar quickly and **spend your time on the one new thing**: that's the knack of time allocation.

---

## 3. The Code Skeleton — Transition Table, Strategy, and Assembly

**Me** — First I pin the order status down as a transition table, so illegal transitions get rejected by structure rather than by scattered if-statements.

```java
enum OrderStatus {
    CREATED, MATCHING, ACCEPTED, PICKED_UP, DELIVERED, CANCELLED;

    private static final Map<OrderStatus, Set<OrderStatus>> ALLOWED = Map.of(
        CREATED,   Set.of(MATCHING, CANCELLED),
        MATCHING,  Set.of(ACCEPTED, CANCELLED),
        ACCEPTED,  Set.of(PICKED_UP, CANCELLED),
        PICKED_UP, Set.of(DELIVERED),      // no cancelling after pickup (matches the refund policy)
        DELIVERED, Set.of(),               // terminal
        CANCELLED, Set.of()
    );

    public boolean canTransitionTo(OrderStatus next) {
        return ALLOWED.get(this).contains(next);
    }
}
```

The matching policy gets pulled out as a Strategy.

```java
interface MatchingStrategy {                       // the scoring policy can change
    List<Rider> rank(Order order, List<RiderDistance> candidates);  // without touching the dispatch flow
}
class NearestFirstStrategy  implements MatchingStrategy { /* by distance — today */ }
class WeightedScoreStrategy implements MatchingStrategy { /* distance + acceptance + ETA — later */ }

class DispatchService {
    private final RiderLocationStore locations;
    private final MatchingStrategy strategy;       // depends on the interface (DIP)
    private final OfferChannel offers;

    public void dispatch(Order order) {
        order.transitionTo(OrderStatus.MATCHING);
        var candidates = locations.findNearby(order.pickupPoint(), Km.of(3));
        for (Rider rider : strategy.rank(order, candidates)) {
            if (offers.propose(rider, order, Duration.ofSeconds(30)))  // wait for acceptance
                return;                             // accepted — assignment done
        }                                           // timeout/decline → next candidate
        // candidates exhausted → widen the radius or push to a retry queue
    }
}
```

**Interviewer** — `WeightedScoreStrategy` is empty. If you're not implementing it today, why set up the interface at all?

**Me** — Because we confirmed in the [HLD](<./Food Delivery App - HLD.md>) that "the scoring policy gets tuned per city and time of day." The point of today's design is showing that when the policy changes, `DispatchService`'s search-and-offer flow doesn't change by a single line — and evolutions like batched delivery happen behind this same interface.

> 💡 **Coaching note** — **Patterns aren't picked for novelty; they're the same answer to the same question: "what will change?"** The interviewer's "why is it empty?" isn't a deduction signal — it's **an opening to explain the decision's grounding (the HLD requirement)**.

---

## 4. Spatial Search — This Interview's DSA Heart

**Interviewer** — Let's look at `findNearby`. What if you implement it **in-memory, without Redis**?

**Me** — I'd build it with geohash buckets. Encode the coordinates into a geohash string at precision ~5, and that string is the bucket key.

```java
class RiderLocationStore {
    private final Map<String, Set<RiderId>> buckets = new ConcurrentHashMap<>();
    private final Map<RiderId, RiderPosition> positions = new ConcurrentHashMap<>();

    public void update(RiderId id, GeoPoint p) {
        String newCell = Geohash.encode(p, PRECISION);
        String oldCell = /* previous cell */;
        if (!newCell.equals(oldCell)) {            // move buckets only when the cell changes
            buckets.get(oldCell).remove(id);
            buckets.computeIfAbsent(newCell, k -> newSet()).add(id);
        }
        positions.put(id, new RiderPosition(p, clock.now()));  // replace with the latest value
    }

    public List<RiderDistance> findNearby(GeoPoint center, Km radius) {
        String cell = Geohash.encode(center, PRECISION);
        var candidates = new ArrayList<RiderId>();
        for (String c : Geohash.neighborsAndSelf(cell))   // center + 8 neighbor cells
            candidates.addAll(buckets.getOrDefault(c, Set.of()));

        // min-heap by distance — extract only the nearest k
        PriorityQueue<RiderDistance> heap =
            new PriorityQueue<>(comparing(RiderDistance::meters));
        candidates.stream()
                  .map(id -> distanceTo(center, id))
                  .filter(d -> d.meters() <= radius.toMeters() && isFresh(d.rider()))
                  .forEach(heap::offer);
        return pollTop(heap, K);                          // top k
    }
}
```

`isFresh` filters out riders whose last update is older than some threshold (say, 15 seconds) — the same freshness-filter idea the HLD applied on the Redis side to age offline riders out of the candidate pool.

**Interviewer** — What if the restaurant sits **right on a cell boundary**? Doesn't the rider across the street drop out of the candidates?

**Me** — That's geohash's classic trap. Across the boundary the prefix differs, so looking at only the center cell misses them. Hence `neighborsAndSelf` — **always search the 8 neighboring cells together**. Cell size is why I picked precision 5: those cells are about 4.9km on a side, so the 3×3 block comfortably covers a 3km radius. At precision 6 a cell is only about 1.2km × 0.6km — nine of them span roughly 3.7km × 1.8km, nowhere near enough. For a larger radius, drop the precision one more level (bigger cells) and do the same thing.

> 💡 **Coaching note** — The min-heap here is **a data structure that emerges naturally from the design** — the requirement "just the nearest k, no need to sort all candidates" calls for a heap. And the boundary problem is a spot that **would have scored better said before the interviewer poked at it**. In any spatial-index problem, boundary handling always comes up.

---

## 5. Concurrency — The Contention Is Three Layers Deep

**Interviewer** — Now, the races. **Two orders grab the same rider at once**? **The customer cancels the instant the rider accepts**?

**Me** — This domain's contention comes in three layers, but all three fall to the same weapon — **conditional atomic updates working together with the transition table**.

**First, the rider grab.** The problem of accepting two orders' offers simultaneously is decided by a conditional update on the store for rider assignment.

```java
// UPDATE riders SET current_order=:orderId, status='ASSIGNED'
// WHERE id=:riderId AND status='IDLE'      → 0 rows affected = already assigned to another order
```

**Second, accept vs cancel.** When the rider's acceptance (`MATCHING → ACCEPTED`) collides with the customer's cancellation (`MATCHING → CANCELLED`), both are conditional updates on the order status (`WHERE status='MATCHING'`), so **the store leaves exactly one winner by arrival order**. The loser gets rejected by the transition table too — `CANCELLED → ACCEPTED` isn't in `ALLOWED`, so it's double-blocked at the code level.

**Third, timeout vs accept.** The instant the 30-second timeout handler passes the offer to the next candidate, the original rider's acceptance can arrive. It's the classic TTL-sweeper pattern — the timeout is also decided by a conditional update with `WHERE offer_status='PENDING' AND expires_at < :now`, so if acceptance lands first the timeout loses, and if the timeout lands first the acceptance is rejected as an "expired offer." And since testing 30 seconds requires holding time in your hand, we **inject a `Clock`**.

> 💡 **Coaching note** — It looks like three layers but the answer is one line: **decide with a single atomic store operation, seal the result with the transition table**. Unique constraints against duplicate likes, seat locks, TTL sweepers, rider grabs — wherever a contention point hides, this same weapon works unchanged.

---

## 6. Tests — The Last 30 Minutes

**Interviewer** — Let's wrap up with tests.

**Me** — Four, in order of this problem's pressure points.

```java
@Test
void when_two_orders_grab_the_same_rider_only_one_wins() throws Exception {
    var pool = Executors.newFixedThreadPool(2);
    var results = pool.invokeAll(List.of(
        () -> tryAssign(order1, riderA),
        () -> tryAssign(order2, riderA)
    ));
    assertThat(successCount(results)).isEqualTo(1);   // exactly 1 winner
}
```

1. **Concurrent assignment race** — two orders grab the same rider, exactly one succeeds (code above)
2. **Next candidate after timeout** — advance a fake `Clock` by 31 seconds and the offer moves to the second candidate (no `sleep`)
3. **Strategy swap** — swap `NearestFirstStrategy` and a fake strategy over the same candidate list and only the offer order changes — `DispatchService`'s assembly logic is verified independently
4. **Illegal transition blocked** — `transitionTo(ACCEPTED)` on a `CANCELLED` order throws

`RiderLocationStore` is an in-memory implementation, so it's usable in tests as-is, and the boundary case — whether the rider just across a cell boundary makes the candidate list — gets pinned down with two coordinates.

> 💡 **Coaching note** — The four tests are this interview's scorecard: concurrency (section 5), time (Clock injection), flexibility (strategy fake), state safety (transition table). The point of the last 30 minutes is showing a structure where **every design-stage decision gets repaid as testability**.

---

## 7. Interview Retro — What Was Actually Being Graded

1. **Requirements clarification** — pinned down radius, timeout, and state flow; carried concurrency from the start because it's the heart of the problem
2. **Entity extraction** — handled the familiar patterns (Strategy, state machine) quickly and budgeted time for the one new thing (spatial search)
3. **Flexibility where change lives** — matching score as a Strategy, order lifecycle as a transition table
4. **DSA** — geohash buckets + 8 neighbor cells (boundary problem) + nearest-k min-heap
5. **Concurrency** — rider grab, accept vs cancel, timeout vs accept — all via conditional atomic updates + the transition table
6. **Tests** — nailed the four pressure points: race, timeout, strategy swap, illegal transition

Zoom out and dispatch's anatomy becomes visible — **read-assembly** (gather and sort candidates: Strategy plus a heap), **resource contention** (state machine plus atomic updates), and one genuinely spatial ingredient (geohash search). Real-time matching is a synthesis problem — and matching problems are more common than you'd think.

**To make it stick** — matching-type practice problems: dispatch (this post), Uber ride matching (nearly isomorphic), call-center agent assignment (skill matching instead of space), dating apps (mutual acceptance), a stock exchange matching engine (price-time priority queue) — all the same skeleton: "**collect candidates, sort by policy, assign atomically**."

---

### 📝 TL;DR

> **"Real-time matching LLD is a capstone problem — collect candidates with geohash buckets and a heap, sort them with a Strategy, and let conditional atomic updates plus a transition table leave exactly one winner."**

---

## Previous Post

The forest this dispatch service stands in — the 20,000-per-second location stream, Redis GEO, and the "rebuildable data" perspective — is covered in the [Food Delivery App HLD post](<./Food Delivery App - HLD.md>).
