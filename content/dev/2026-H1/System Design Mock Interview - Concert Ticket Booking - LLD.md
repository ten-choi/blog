---
title: "System Design Mock Interview - LLD: \"Design That Seat Hold as Classes\""
labels: ["System Design","LLD","Concurrency","Object-Oriented","Tech Interviews"]
published: true
date: 2026-04-08T11:26:00+09:00
readerComments: "ALLOW"
bloggerPostId: "1126863387339354116"
source: "archive"
archivePath: "_archive/dev/system design/Ticket Booking - LLD.md"
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

**Interviewer** — Here's the problem. **Implement the booking domain as classes: seat selection → hold → payment → confirmation.**

**Me** — Okay, a few questions first. How long should a hold last before it expires?

**Interviewer** — 7 minutes, same as in the design round.

**Me** — And if someone selects several seats at once and one of them is already taken — should they get the rest, or should the whole request fail?

**Interviewer** — What do you think?

**Me** — I'd fail the whole thing. If you're buying three seats for you and your friends, two scattered seats isn't really what you wanted. So **all-or-nothing**.

**Interviewer** — Agreed.

**Me** — For pricing, is it just a fixed price per seat grade?

**Interviewer** — For now. But marketing will probably want early-bird discounts and promotions at some point.

**Me** — Then I'll make pricing easy to swap. And payment — should I integrate with a real payment gateway, or can I put it behind an interface and stub it?

**Interviewer** — Stub it.

**Me** — One more. In some problems I'd ask to assume a single process and leave concurrency for later. Here I don't think I can — two people grabbing the same seat is the whole problem. So I'd like to **handle concurrent requests from the start**, if that's okay.

**Interviewer** — Yes, please do.

> 💡 **Coaching note** — Every assumption here came out as a question, and the interviewer confirmed it — or turned it back ("What do you think?"), which is an invitation to show judgment, not a trap. And in a read-assembly problem like a feed, "I'll set concurrency aside with a single-process assumption" is a good move. Make the same move here and you're **setting aside the body of the problem** — that's a deduction. What can be simplified and what can't — that judgment itself is a grading item at the requirements stage.

---

## 2. Collect the Nouns, Find What Will Change — and Find the 'State'

**Me** — Let me start by listing the nouns: event, seat, hold, booking, payment, pricing. Roughly, they connect like this.

```
Event ──1:N──▶ Seat (grade, status: AVAILABLE/HELD/SOLD, version)
SeatHold (user, seat_ids, expires_at, status: ACTIVE/CONFIRMED/EXPIRED/RELEASED)
Booking (hold, amount, status, idempotency_key)
PricingPolicy ─ per-grade pricing + promotions (first thing to change!)
PaymentGateway ─ external PG (interface + stub)
```

Two things jump out at me. One is what you just mentioned — **pricing is the first thing that'll change**. Grade-based today, then early-bird, coupons, maybe dynamic pricing someday. So I'd pull that out as a strategy.

The other is **state**. A hold starts active, then gets confirmed, or expires, or gets released. That changes over time, so I want the allowed transitions written down explicitly. The bug I'm most worried about is an expired hold getting confirmed anyway.

**Interviewer** — How would that even happen?

**Me** — The payment webhook arrives a few seconds after the hold expired, and the code just sets the status to CONFIRMED without checking where it came from. If the transitions are restricted in one place, that becomes an error instead of a silent double-sell.

> 💡 **Coaching note** — On top of "nouns = classes, verbs = responsibilities," in this problem you must find **"the things that change as time passes."** Those are your state machine candidates. In booking/order/delivery-style domains, the state machine is almost always the main event.

---

## 3. The Code Skeleton — State Machine and Strategy

**Me** — Let me put the skeleton up. I'll start with the state transitions, all in one place.

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

And pricing as a strategy, since that's the part you said will change.

```java
interface PricingPolicy {                       // adding promotions must not
    Money price(List<Seat> seats, User buyer);  // change the booking flow (OCP)
}
class GradeBasePricing implements PricingPolicy { /* base price per grade */ }
class EarlyBirdPricing  implements PricingPolicy { /* early-bird discount — later */ }
```

**Interviewer** — Why put the transitions in a table inside the enum? If-statements would work too.

**Me** — They would, but with if-statements the rules tend to end up scattered across services. In a table, you can see every allowed transition at a glance, and if someone adds a new state later, a missing transition is easy to spot in review. "You can never go from EXPIRED to CONFIRMED" lives in the code, not in a wiki page.

> 💡 **Coaching note** — The Strategy pattern shows up in nearly every LLD problem, and that's no accident. **Patterns aren't relearned per problem — they're the same answer to the same question: "where will this change?"** The other half here is the state machine side — a transition table is the lightest implementation of the State pattern, and if per-state behavior gets complex, you promote it to per-state classes.

---

## 4. Concurrency — The Main Event of This Interview

**Interviewer** — Alright, the core. **Two threads try to hold the same seat at the same time.** Make sure exactly one wins.

**Me** — If the code reads the seat, sees that it's free, and then saves, both threads can see "free" before either one saves. The gap between the check and the update is the problem. So I'd **push the decision down into a single atomic operation** in the database.

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
        List<Long> sorted = seatIds.stream().sorted().toList();  // global lock order
        long holdId = holds.nextId();
        int updated = seats.holdSeats(sorted, holdId);
        if (updated != sorted.size())
            throw new SeatsAlreadyTakenException();  // transaction rollback → all-or-nothing
        return holds.save(SeatHold.activeFor(user, sorted, clock.now().plus(TTL)));
    }
}
```

The `status='AVAILABLE'` condition is what does the locking. When two transactions race, the database's row lock decides who goes first, and the second one updates zero rows because the seat isn't available anymore. If fewer rows were updated than seats requested, I throw, the transaction rolls back, and that gives us all-or-nothing.

**Interviewer** — Why are you sorting the seat IDs?

**Me** — It's insurance against deadlocks. If A locks seats 3 then 7, and B locks 7 then 3, in separate statements, they can end up waiting on each other forever. Always locking in the same order prevents that. To be honest, in this single `IN` update the database picks its own order anyway, so it's not strictly needed today — but if this ever turns into one statement per seat, the sort is already there.

**Interviewer** — How does this compare with `SELECT FOR UPDATE`, or optimistic locking with a version column?

**Me** — All three can work; it depends on the situation. **Optimistic locking** is great when conflicts are rare — but at ticket open, conflicts are the normal case, so we'd get a storm of retries. **`SELECT FOR UPDATE`** makes sense when you need to read the row and run more complex checks before deciding. Here the only question is "is it available?", so **one conditional UPDATE** is the simplest and needs the fewest round trips. I'd start with that and only move to something heavier if the rules get more complicated.

> 💡 **Coaching note** — The skeleton of a concurrency answer is the same whether it's ticketing or likes: **eliminate the check-then-update gap and make the verdict a single atomic operation**. A likes counter's "unique constraint + atomic INCR" and this post's "conditional UPDATE" are the same principle in different clothes. The extra talking points unique to this problem: **lock ordering (deadlocks)** and **the optimistic-vs-pessimistic decision criterion** (conflict frequency). And note the honesty about the sort — saying "this isn't strictly needed yet, here's why it's there" scores better than pretending it's essential.

---

## 5. TTL Expiry — Code That Deals with Time

**Interviewer** — Who releases a hold once its 7 minutes are up?

**Me** — I'd do it in two ways. First, **lazily**: when someone tries to hold a seat and the existing hold on it has already expired, we release it right there and continue. That way seats don't sit idle even if a background job is running late.

Second, a **sweeper** that periodically cleans up active holds whose `expires_at` has passed. But there's a race here too — the sweeper might run at the exact moment the user finishes paying.

**Interviewer** — So what happens then?

**Me** — Expiry is just another state change, so I'd do it the same way: a **conditional update**, `WHERE status='ACTIVE' AND expires_at < :now`. If the payment confirmation lands first, the sweeper's update matches nothing. If expiry lands first, the confirmation fails and we refund the payment.

Oh, and I won't call `Instant.now()` directly anywhere. I'll **inject a `Clock`**, otherwise there's no way to test any of this without actually waiting 7 minutes.

> 💡 **Coaching note** — For time-dependent logic — TTLs, deadlines, retries — design maturity shows in whether **"clock injection" is already in place**. And since even expiry is just another state transition, the transition table from section 3 and the conditional update from section 4 get reused here as-is.

---

## 6. Tests — The Last 30 Minutes

**Interviewer** — Let's wrap up with tests. What would you verify?

**Me** — I'd go after the riskiest parts first. The race is number one.

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

So the full list would be:

1. **Concurrent hold race** — two threads grab the same seat, exactly one succeeds (above)
2. **All-or-nothing** — if I ask for seats 3 and 7 and 7 is already taken, I shouldn't end up holding 3 either
3. **Re-hold after expiry** — move a fake `Clock` forward 8 minutes, and a different user can grab the same seat
4. **Illegal transition** — calling `transitionTo(CONFIRMED)` on an expired hold throws

The payment gateway is a stub, so I can make it succeed or fail whenever I want. And because the clock is injected, test 3 runs without a single `sleep`.

**Interviewer** — Good. That's time.

> 💡 **Coaching note** — With concurrency tests, the score isn't for "perfect reproduction" — it's for **having expressed the race scenario in code** at all. And the habit of **nailing down a state machine's forbidden transitions in tests**, like #4, is the cheapest regression insurance you can buy in real work.

---

## 7. Interview Retro — What Was Actually Being Graded

1. **Requirements clarification** — turned every assumption (TTL, all-or-nothing, stubbed PG) into a question, and judged that concurrency could NOT be set aside in this problem
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
