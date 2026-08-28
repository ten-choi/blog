---
title: "System Design Mock Interview - LLD: \"Design That Message Delivery as Classes\""
labels: ["System Design", "LLD", "Messaging", "Object-Oriented", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> In the [LINE Chat HLD post](<./LINE Chat - HLD.md>) we drew the forest — gateways hold the connections, messages are stored first (store-and-forward), and delivery is guaranteed with ACKs and retransmission.
>
> This time we walk into the machine coding interview and implement that **message delivery layer as classes**. Its identity in one sentence: **redo, at the application level, what TCP does for you at the transport layer** — ACKs, retransmission, order reassembly, dedup.

# The LLD Mock Interview — "Design the Message Delivery Layer as Classes"

## 0. Before We Start — What Kind of LLD Is This?

| | **A typical domain-modeling LLD** (a feed, a booking flow) | **Messenger LLD (this post)** |
|---|---|---|
| Domain archetype | Model the business rules as classes | **Reliability protocol — TCP's job at the app level** |
| First thing to change | A business policy (ranking, pricing) | **Retry policy** (a Strategy) |
| State management | A few status fields | **A single message is a state machine** (PENDING→…→READ) |
| DSA point | Whatever the queries demand | **Sequence-gap reassembly — a min-heap ReorderBuffer** |

Check the clock first — for 3 hours, a solid split is 30 min requirements & design / 2 hours implementation / 30 min tests & refactoring. Let's walk in.

---

## 1. Clarifying Requirements — The Network Drops Whenever It Wants

**Interviewer** — Here's the problem. **Design and implement, as classes, a delivery layer where a sent message is always delivered, order is preserved within a conversation, and there are no duplicates.** Read receipts included.

**Me** — Let me confirm the scope. **Delivery guarantee via receiver ACK + retransmission of un-ACKed messages**, and **ordering per conversation** (no global order needed) — correct?

**Interviewer** — Correct.

**Me** — I'll lay down two assumptions. First, **the retry policy — how many times, at what intervals — will change**, so I'll separate it out. It's a spot that always gets tuned in production. Second, this problem's premise is "**the network drops whenever it wants**." Mid-transfer disconnects, lost ACKs, reordering, the same message arriving twice — I'll treat these not as exceptions but as **normal input**.

**Interviewer** — Good. Go with that.

> 💡 **Coaching note** — The requirements-stage judgment call in this problem is "**can we remove failure?**" The answer is no — failure (loss, duplication, reordering) IS the body of the problem. Saying "I'll build the happy path first and handle failures later" costs you points on this one.

---

## 2. Collect the Nouns, Find What Changes and What Has 'State'

**Me** — Nouns first — message, conversation, outbox, ACK, retry policy, duplicate, ordering. Wiring up the relationships:

```
Message      (state machine: PENDING → SENT → DELIVERED → READ, FAILED on failure)
Conversation (channel_id, issues sequences — the root of ordering)
OutboxQueue  (holds sent-but-not-yet-ACKed messages → retransmit on timeout)
RetryPolicy  (retry count & intervals — the first thing to change!)
DedupWindow  (receiver-side dedup — remembers recent message IDs)
ReorderBuffer(receiver-side order reassembly — the DSA body)
MessageListener (subscribes to receive events — UI refresh, notifications, read handling)
```

Three familiar patterns show up. **The retry policy becomes a Strategy** — a policy that will be tuned belongs behind an interface. **The message becomes a state machine** — a single message flows through `PENDING → SENT → DELIVERED → READ`. **Receiving becomes an Observer** — when one message arrives, the chat screen, the notification badge, and the read handler each react. What's genuinely new is **the sender's Outbox and the receiver's ReorderBuffer** — the two ends of a reliability protocol. And since time intervenes everywhere (retry timeouts, backoff), we lay down **Clock injection** from the start.

> 💡 **Coaching note** — Once you've done a few LLD problems, noun collection is nearly automatic: a policy that will change → Strategy; something that flows through time → state machine; many reactions to one event → Observer. What's really new in this problem is the setup that **"the sender and receiver cannot trust each other"** — which is why a defensive part appears on each side (Outbox / ReorderBuffer).

---

## 3. The Code Skeleton — State Machine, Strategy, Outbox

**Me** — First, pin the message states down with a transition table.

```java
enum MessageStatus {
    PENDING, SENT, DELIVERED, READ, FAILED;

    private static final Map<MessageStatus, Set<MessageStatus>> ALLOWED = Map.of(
        PENDING,   Set.of(SENT, FAILED),
        SENT,      Set.of(DELIVERED, FAILED),   // ACK received → DELIVERED
        DELIVERED, Set.of(READ),
        READ,      Set.of(),                    // terminal — no going back
        FAILED,    Set.of(PENDING)              // only the user's "resend" tap allowed
    );

    public boolean canTransitionTo(MessageStatus next) {
        return ALLOWED.get(this).contains(next);
    }
}
```

The retry policy is extracted as a Strategy, and the **Outbox** is the sender-side heart of this problem — it holds messages that were sent but not yet ACKed, releases them when the ACK arrives, and resends them on timeout.

```java
interface RetryPolicy {
    Duration nextDelay(int attempt);            // policy changes must not touch the Outbox
    boolean shouldGiveUp(int attempt);
}
class ExponentialBackoffPolicy implements RetryPolicy { /* 1s, 2s, 4s... max 5 attempts */ }

class OutboxQueue {
    private final Map<MessageId, PendingEntry> unacked = new ConcurrentHashMap<>();
    private final RetryPolicy policy;
    private final Clock clock;                  // time in our hands (testable)

    public void markSent(Message m) {
        unacked.put(m.id(), new PendingEntry(m, 1, clock.now()));   // attempt = 1, sentAt = now
    }
    public void onAck(MessageId id) {
        var entry = unacked.remove(id);         // ACK arrived — responsibility released
        if (entry != null) entry.message().transitionTo(MessageStatus.DELIVERED);
    }
    public List<Message> dueForRetry() {        // called periodically
        // return entries where sentAt + policy.nextDelay(attempt) < clock.now()
        // if shouldGiveUp, transition to FAILED and remove
    }
}
```

**Interviewer** — What if the ACK gets lost? The other side received it, but the Outbox doesn't know and will retransmit.

**Me** — That's exactly why **it's the receiver, not the sender, that makes retransmission safe**. The sender can shamelessly repeat "when in doubt, send again" — because the receiver's DedupWindow won't process the same message ID twice (section 5). It's the classic reliability formula: "**at-least-once delivery + idempotent receiver = effectively exactly-once**."

> 💡 **Coaching note** — Strategy for the tunable policy, Clock injection for time — these should be **reflexes**, not inventions. What's new to study is the Outbox's shape — an object that **holds the time between "sent" and "delivered" as state**. This shape copies verbatim into payment retries, webhook dispatch, event publishing — any transmission that needs the other side's confirmation.

---

## 4. Order Reassembly — The DSA Body of This Interview

**Interviewer** — Let's go to the receiving side. You've processed up to sequence **5, and 7 arrives first**. What do you do?

**Me** — Putting 7 straight on screen breaks the ordering guarantee. I'd add a **ReorderBuffer** — anything that isn't the expected next sequence (6) gets parked in a buffer, and the instant 6 arrives, 6 and 7 are **released as a contiguous run**. Since we repeatedly need "the smallest sequence among the future messages," the buffer is naturally a **min-heap**.

```java
class ReorderBuffer {
    private long expectedSeq;                             // next sequence to release
    private final PriorityQueue<Message> future =
        new PriorityQueue<>(comparing(Message::seq));     // future messages parked here (min-heap)
    private final Consumer<Message> deliver;              // releases order-confirmed messages upward

    public void onReceive(Message m) {
        if (m.seq() < expectedSeq) return;                // the past — already released upward
        future.offer(m);
        while (!future.isEmpty() && future.peek().seq() == expectedSeq) {
            deliver.accept(future.poll());                // release the contiguous run at once
            expectedSeq++;
        }
        // anything left in future = a gap exists (expectedSeq hasn't arrived yet)
    }
}
```

The key behavior: processed up to 5, 7 arrives → parked in the heap (`expectedSeq=6`); 6 arrives → release 6 → the heap top is 7, so it chains out → `expectedSeq=8`. We don't manage a fully sorted whole — only **"the sorted part of it"** — which makes the heap exactly the right tool. One contract to state out loud: **duplicates never reach this buffer** — the DedupWindow (section 5) sits upstream and drops retransmitted copies, including copies of messages still parked in the heap. If a duplicate of a parked 7 slipped in, it would occupy the heap twice and push `expectedSeq` past reality, deadlocking the buffer — so ReorderBuffer assumes each seq arrives at most once, and the `< expectedSeq` guard is only a last line of defense.

**Interviewer** — **What if 6 never comes?** Everything after 7 sits trapped in the buffer forever.

**Me** — The moment we detect a gap, we start a timer, and if it isn't filled within a window (say, 2 seconds), we **stop waiting for retransmission and ask the server for a gap fill** — "give me channel X from seq 6." The HLD established that the truth always lives in storage, so server sync is the final safety net. A design that trusted only client-to-client retransmission would have been stuck here.

> 💡 **Coaching note** — The heap earns its place here the same way it does in k-way feed merges and nearest-k searches: the requirement is "**don't sort the whole; manage only the sorted part**" — when you hear that sentence, reach for a heap. And every buffer/queue/waiting room comes with the mandatory question, "**if something gets trapped here, who pulls it out?**" — have the answer ready in advance (here: the gap-fill timeout).

---

## 5. Concurrency and Idempotency — Familiar Weapons Return

**Interviewer** — Walk me through the contention points.

**Me** — There are three, and every one falls to the same two weapons: atomic operations and conditional transitions.

**First, atomic sequence issuance.** If two messages hit the same conversation simultaneously and the same seq gets issued twice, the entire ordering guarantee collapses. Issuance is decided by **one atomic per-conversation increment** — whether it's the DB's `UPDATE conversations SET last_seq = last_seq + 1 ... RETURNING last_seq` or a Redis `INCR`, the point is to never assemble "read-add-write" in the application.

**Second, duplicate receipt.** Retransmission means the same message can arrive twice, so the receiver gets a **DedupWindow** — remember the last N processed message IDs and drop any that reappear. No need to remember everything: retransmissions happen only within a short window, so keeping **just the recent N in an LRU** is enough — and the LRU cache is itself such a staple LLD problem that it makes a nice companion exercise.

**Third, ACK vs the retry timer.** What if the retry timer fires the instant the ACK arrives? It's the classic "confirmation vs timeout" race, and races like this are decided by **conditional state transitions**. ACK handling is valid only if the `SENT → DELIVERED` transition succeeds, and a retry runs only while the entry is still in unacked (only when `remove` returns a value). The transition table and the atomic operation reject whichever side arrives late, so the outcome is the same no matter who wins the race.

> 💡 **Coaching note** — The one-line concurrency thread of this problem: **decide with a single atomic operation, and seal the result with a transition table**. Sequence issuance (atomic increment), dedup (idempotency), race resolution (conditional transitions) — the reliability-protocol archetype doesn't demand exotic weapons; it's the problem of placing the same two weapons at both ends of the protocol.

---

## 6. Tests — The Last 30 Minutes

**Interviewer** — Let's wrap up with tests. What will you verify?

**Me** — Four, ordered by this problem's pressure points.

```java
@Test
void buffer_releases_contiguous_run_in_order_when_gap_fills() {
    var delivered = new ArrayList<Message>();
    var buffer = new ReorderBuffer(5, delivered::add);   // expectedSeq = 5

    buffer.onReceive(msg(5));
    buffer.onReceive(msg(7));                         // no 6 — 7 waits
    assertThat(seqsOf(delivered)).containsExactly(5L);

    buffer.onReceive(msg(6));                         // the moment the gap fills
    assertThat(seqsOf(delivered)).containsExactly(5L, 6L, 7L);  // chain release
}
```

1. **Gap reassembly** — 5 and 7 arrive → only 5 released; 6 arrives → 5·6·7 completed in order (the code above)
2. **Duplicates processed once** — feeding the same message ID twice releases/processes it once (DedupWindow)
3. **Retry backoff** — advancing a fake `Clock` by 1s, 2s, 4s retransmits exactly once at each mark, and past the give-up count it transitions to `FAILED` — runs without a single `sleep`
4. **Illegal transitions blocked** — `transitionTo(SENT)` on a `READ` message throws — the test nails shut the bug where read reverts to unread

Thanks to the Observer, release results can be verified as a plain list (`delivered::add` in test 1), and thanks to Clock injection, test 3 runs deterministically. The network sits behind an interface as a fake implementation, so loss, delay, and duplication can be injected at will.

> 💡 **Coaching note** — For a reliability protocol, **"the unhappy paths ARE the spec."** One happy-path test (send → arrives) is enough; everything else should be loss, reordering, duplication, and timeouts. Declaring failure as normal input at the design stage (section 1) is redeemed here, verbatim, as the test list.

---

## 7. Interview Retro — What Was Actually Being Graded

1. **Requirements clarification** — separated the retry policy as "the thing that will change" and declared failure (loss, duplication, reordering) as normal input
2. **Entity extraction** — dispatched the familiar patterns fast (Strategy, state machine, Observer) and spent the time on the new shapes (Outbox / ReorderBuffer)
3. **Flexibility where change lives** — retries as a Strategy, message lifecycle as a transition table
4. **DSA** — expected-sequence counter + min-heap ReorderBuffer, gap timeout → server gap fill
5. **Concurrency & idempotency** — atomic sequence issuance, DedupWindow (LRU), ACK vs retry decided by conditional transitions
6. **Tests** — nailed the four pressure points: gap reassembly, duplicates, backoff, illegal transitions

If you take one thing from this problem, take its archetype: message delivery is a **reliability protocol** — the shape of **all code that talks to a peer it cannot trust** — and its skeleton (store, ACK, retransmit, dedupe, reorder) transfers far beyond messengers.

**To make it stick** — practice problems for the reliability-protocol archetype: a chat delivery layer (this post), a job queue library (no job loss + retries + idempotent workers), an event bus (publish guarantees + subscriber ACKs), a file sync client (chunk retransmission + order reassembly), a TCP imitation (the thing itself) — all the same skeleton: "**store first, confirm with ACKs, retransmit shamelessly, let the receiver block duplicates, let the buffer restore order.**"

---

### 📝 TL;DR

> **"Reliability-protocol LLD assembles from four parts — the Outbox holds the un-ACKed, the RetryPolicy (Strategy) resends, the DedupWindow blocks duplicates, and the ReorderBuffer (heap) restores order. Failure isn't an exception; it's normal input."**

---

## Previous Post

The forest this delivery layer stands in — 50 million concurrent connections, connection gateways and the session registry, store-and-forward — was covered in the [LINE Chat HLD post](<./LINE Chat - HLD.md>).
