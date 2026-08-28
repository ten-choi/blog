---
title: "System Design Mock Interview - LLD: \"Design That Seat Hold as Classes\""
labels: ["System Design", "LLD", "Concurrency", "Object-Oriented", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> In the [Ticket Booking HLD post](<./Ticket Booking - HLD.md>) we drew the forest — form a line with a queue, lock seats with a conditional update.
>
> This time we walk into the machine coding interview and implement that **seat hold and booking flow as classes**. In many LLD problems you can open with "let's set concurrency aside for now" — here we can't, because **concurrency IS the problem**.

# The LLD Mock Interview — "Design the Seat Hold and Booking Flow as Classes"

## 0. Before We Start — How Is This Different from a Read-Assembly LLD?

| | **A read-assembly LLD (e.g. a feed)** | **Ticket Booking LLD (this post)** |
|---|---|---|
| First thing to change | Feed ranking policy → Strategy pattern | Pricing policy → Strategy pattern |
| State management | Simple (a post is done once it's up) | **The state machine is the main event** (hold→confirm→expire/cancel) |
| Concurrency | Can be shelved behind a single-process assumption at first | **Central to the design from the start** |
| DSA point | k-way merge + heap | Lock ordering (deadlocks), conditional atomic updates |

For a 3-hour session, a solid time split is 30 min requirements & design / 2 hours implementation / 30 min tests & refactoring. Let's walk in.

---

## 1. Clarifying Requirements — This Time, Concurrency Can't Be Set Aside

**Interviewer** — Here's the problem. **Design and implement the booking domain as classes: seat selection → hold → payment → confirmation.**

**Me** — Let me confirm the scope. **Hold TTL is 7 minutes**, and when grabbing multiple seats at once it's **all-or-nothing** — is that right?

**Interviewer** — Correct.

**Me** — For pricing, I'll assume there's a **base price per grade**, and that early-bird discounts or promotions **may be added later**. Payment is an external payment gateway (PG), so I'll put it behind an interface and stub it. And since this problem is meaningless without concurrency — **I'll embrace concurrent requests for the same seat from the start**.

**Interviewer** — Good. Let's go with that.

> 💡 **Coaching note** — In a read-assembly problem like a feed, "I'll set concurrency aside with a single-process assumption" is a good move. Make the same move here and you're **setting aside the body of the problem** — that's a deduction. What can be simplified and what can't — that judgment itself is a grading item at the requirements stage.

---

## 2. Collect the Nouns, Find What Will Change — and Find the 'State'

**Me** — Let me collect the nouns — event, seat, hold, booking, payment, pricing policy. Connecting the relationships:

```
Event ──1:N──▶ Seat (grade, status: AVAILABLE/HELD/SOLD, version)
SeatHold (user, seat_ids, expires_at, status: ACTIVE/CONFIRMED/EXPIRED/RELEASED)
Booking (hold, amount, status, idempotency_key)
PricingPolicy ─ per-grade pricing + promotions (first thing to change!)
PaymentGateway ─ external PG (interface + stub)
```

Two things stand out in this domain. First, **the "first thing to change" is the pricing policy** — starting from grade-based pricing, then early-bird discounts, coupons, all the way to dynamic pricing. That gets extracted via the Strategy pattern. Second, there's an axis many domains don't have — **state**. Holds and bookings are objects whose state flows over time, so we need to **explicitly restrict the allowed transitions**. I want to block the bug where `EXPIRED` comes back to life as `CONFIRMED` — as close to compile time as possible.

> 💡 **Coaching note** — On top of "nouns = classes, verbs = responsibilities," in this problem you must find **"the things that change as time passes."** Those are your state machine candidates. In booking/order/delivery-style domains, the state machine is almost always the main event.

---

## 3. The Code Skeleton — State Machine and Strategy

**Me** — Let me set up the skeleton. First, pin the state transitions down in one place.

```java
enum HoldStatus {
    ACTIVE, CONFIRMED, EXPIRED, RELEASED;

    private static final Map<HoldStatus, Set<HoldStatus>> ALLOWED = Map.of(
        ACTIVE,    Set.of(CONFIRMED, EXPIRED, RELEASED),
        CONFIRMED, Set.of(),          // confirmed is a terminal state
        EXPIRED,   Set.of(),
        RELEASED,  Set.of()
    );

    public boolean canTransitionTo(HoldStatus next) {
        return ALLOWED.get(this).contains(next);
    }
}

class SeatHold {
    private HoldStatus status = HoldStatus.ACTIVE;
    private final Instant expiresAt;

    public void transitionTo(HoldStatus next) {
        if (!status.canTransitionTo(next))
            throw new IllegalStateException(status + " → " + next);
        this.status = next;
    }
}
```

Pricing gets extracted as a strategy.

```java
interface PricingPolicy {                       // adding promotions must not
    Money price(List<Seat> seats, User buyer);  // change the booking flow (OCP)
}
class GradeBasePricing implements PricingPolicy { /* base price per grade */ }
class EarlyBirdPricing  implements PricingPolicy { /* early-bird discount — later */ }
```

**Interviewer** — Any reason you pinned the transitions in an enum table? If-statements would work too.

**Me** — With if-statements, transition rules tend to scatter across the codebase. Gathering them into a table turns the allowed transitions into **a spec you can see at a glance**, and when a new state is added, it's easy to catch a missed transition in review. "You can never go from EXPIRED to CONFIRMED" exists as code, not as documentation.

> 💡 **Coaching note** — The Strategy pattern shows up in nearly every LLD problem, and that's no accident. **Patterns aren't relearned per problem — they're the same answer to the same question: "where will this change?"** The other half here is the state machine side — a transition table is the lightest implementation of the State pattern, and if per-state behavior gets complex, you promote it to per-state classes.

---

## 4. Concurrency — The Main Event of This Interview

**Interviewer** — Alright, the core. **Two threads try to hold the same seat at the same time.** Make sure there's exactly one winner.

**Me** — If the application does "read → looks free → save," both threads pass the "looks free" check. The gap between check and update is the problem. So we push **the verdict down into a single atomic operation in the store**.

```java
class SeatRepository {
    /** @return the number of rows actually flipped to HELD */
    int holdSeats(List<Long> seatIds, long holdId) {
        // UPDATE seats SET status='HELD', hold_id=:holdId
        // WHERE id IN (:seatIds) AND status='AVAILABLE'
    }
}

class HoldService {
    @Transactional
    public SeatHold hold(User user, List<Long> seatIds) {
        List<Long> sorted = seatIds.stream().sorted().toList();  // global lock order (see point 3)
        long holdId = holds.nextId();
        int updated = seats.holdSeats(sorted, holdId);
        if (updated != sorted.size())
            throw new SeatsAlreadyTakenException();  // transaction rollback → all-or-nothing
        return holds.save(SeatHold.activeFor(user, sorted, clock.now().plus(TTL)));
    }
}
```

Three points.

1. **`WHERE status='AVAILABLE'` is the lock** — even when two transactions race, the database's row locks decide the order, and the loser updates 0 rows because the condition no longer matches.
2. **Affected rows ≠ requested seats → exception → transaction rollback** — all-or-nothing is implemented via the transaction boundary.
3. **Seat IDs are sorted before updating** — if A grabs (3, 7) and B grabs (7, 3) and the rows are locked in **separate statements** (per-row `SELECT FOR UPDATE`, one UPDATE per seat), they can end up waiting on each other: a **deadlock**. Fixing a global lock order is the classic prevention. To be precise, within the single `IN` UPDATE above the database picks its own locking order regardless of list order — here the statement's atomicity is doing the work, and the sort is cheap insurance for the day this grows into multi-statement locking.

**Interviewer** — How does this compare with `SELECT FOR UPDATE` or optimistic locking (a version column)?

**Me** — All three can work, but they fit different situations. **Optimistic locking** is great when conflicts are rare — but a ticket-open is conflict-by-default, so you get a retry storm. **`SELECT FOR UPDATE` (pessimistic)** is for when you need complex validation logic after reading. Here the verdict is a single question — "is it AVAILABLE?" — so **one conditional UPDATE** is the simplest and has the fewest round trips. Use the simple thing first; escalate when the requirements get complex.

> 💡 **Coaching note** — The skeleton of a concurrency answer is the same whether it's ticketing or likes: **eliminate the check-then-update gap and make the verdict a single atomic operation**. A likes counter's "unique constraint + atomic INCR" and this post's "conditional UPDATE" are the same principle in different clothes. The extra talking points unique to this problem: **lock ordering (deadlocks)** and **the optimistic-vs-pessimistic decision criterion** (conflict frequency).

---

## 5. TTL Expiry — Code That Deals with Time

**Interviewer** — Who releases a hold once its 7 minutes are up?

**Me** — Two layers.

- **Lazy evaluation** — when someone tries to hold that seat again, if the existing hold has expired, we release it on the spot and proceed. Even if the scheduler runs late, seats don't sit idle.
- **The sweeper** — periodically cleans up ACTIVE holds where `expires_at < now`. There's a race here too — the sweeper can collide with the exact moment a user finishes paying. So expiry is also decided atomically via a **conditional update** (`WHERE status='ACTIVE' AND expires_at < :now`). If confirmation lands first, the sweeper loses; if expiry lands first, the payment confirmation fails and flows into the refund path.

And since time baked into logic makes testing impossible, I won't call `Instant.now()` directly — I'll **inject a `Clock`**.

> 💡 **Coaching note** — For time-dependent logic — TTLs, deadlines, retries — design maturity shows in whether **"clock injection" is already in place**. And since even expiry is just another state transition, the transition table from section 3 and the conditional update from section 4 get reused here as-is.

---

## 6. Tests — The Last 30 Minutes

**Interviewer** — Let's wrap up with tests. What will you verify?

**Me** — Four tests, ordered by this problem's pressure points.

```java
@Test
void concurrent_holds_on_same_seat_have_exactly_one_winner() throws Exception {
    var pool = Executors.newFixedThreadPool(2);
    var results = pool.invokeAll(List.of(
        () -> tryHold(alice, seat42),
        () -> tryHold(bob,   seat42)
    ));
    assertThat(successCount(results)).isEqualTo(1);   // exactly 1 winner
}
```

1. **Concurrent hold race** — two threads grab the same seat, exactly one succeeds (code above)
2. **All-or-nothing** — requesting (3, 7) when 7 is already taken must not grab 3 either
3. **Re-hold after TTL expiry** — advance a fake `Clock` by 8 minutes and a different user can grab the same seat
4. **Illegal transition blocked** — `transitionTo(CONFIRMED)` on an EXPIRED hold throws

The PG is a stub behind an interface, so we can fabricate both payment-success and payment-failure scenarios at will, and thanks to `Clock` injection, test 3 runs without a single `sleep`.

> 💡 **Coaching note** — With concurrency tests, the score isn't for "perfect reproduction" — it's for **having expressed the race scenario in code** at all. And the habit of **nailing down a state machine's forbidden transitions in tests**, like #4, is the cheapest regression insurance you can buy in real work.

---

## 7. Interview Retro — What Was Actually Being Graded

1. **Requirements clarification** — extracted the TTL and all-or-nothing, and judged that concurrency could NOT be set aside in this problem
2. **Entity extraction** — found classes in the nouns, and the state machine in "the things that change over time"
3. **Flexibility where change comes** — pricing policy as a Strategy, state transitions as a table
4. **Concurrency** — conditional atomic update + transaction rollback (all-or-nothing) + fixed lock ordering (deadlocks), down to the optimistic-vs-pessimistic decision criterion
5. **Handling time** — lazy + sweeper redundancy, expiry as a conditional update too, Clock injection
6. **Tests** — nailed down the four pressure points: race, rollback, expiry, illegal transition

Zoom out and the two archetypes of LLD emerge — in **read-assembly domains** (feeds), strategies and merge data structures are the main event; in **resource-contention domains** (seats, inventory, accounts), the state machine and atomic updates are the main event. When you meet a new problem, ask first: *is there a resource here that multiple actors fight over?*

**To make it stick** — resource-contention practice problems: ticket booking (this post), movie booking (nearly isomorphic), inventory decrement (e-commerce flash sales), bank transfers (preventing double withdrawal), meeting room booking (overlapping time intervals).

---

### 📝 TL;DR

> **"Resource-contention LLD boils down to three things — cage the states in a transition table, leave exactly one winner via conditional atomic updates, and inject the clock so time becomes testable."**

---

## Previous Post

The forest this seat lock stands in — the virtual waiting room, the 5%-success-rate math, idempotent webhooks — was covered in the [Ticket Booking HLD post](<./Ticket Booking - HLD.md>).
