---
title: "System Design Mock Interview - HLD: \"Design a Mobile Payment Service like PayPay\""
labels: ["System Design", "HLD", "Payments", "Ledger", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> Ticketing-style problems fight for strong consistency at **"the opening moment"** — a few minutes of contention, then it's over. This problem is a world where that fight never ends.
>
> Payments are the **"absolute-correctness archetype (the money archetype)"** — money must never be lost, must never appear out of thin air, and every change must be auditable after the fact. Seats you can simply count; with money, **the path it traveled is the truth**. 45-minute whiteboard interview — let's go.

# The HLD Mock Interview — "Design a Mobile Payment Service like PayPay"

## 0. Before We Start — How This Differs from an Inventory-Contention Problem

| | **A typical inventory-contention problem (ticketing)** | **PayPay payments (this post)** |
|---|---|---|
| When consistency matters | **The opening moment** — a few minutes of contention | **Always** — 24/7/365, every transaction is the main event |
| The shape of truth | Seats can be **counted** (current state) | Money's truth is **the path it traveled** (history) |
| The outside world | One payment gateway (PG, webhooks) | **Banks and card networks** — slow, failure-prone, beyond our control |
| Where the game is won | Queue + seat locking | **Ledger + idempotency + reconciliation** |

Check the clock first — for a 45-minute interview, a solid split is 5 min requirements / 5 min back-of-envelope math / 5 min API & data model / 15 min architecture / 10 min deep dive / 5 min wrap-up.

---

## 1. Requirements First — No Boxes Yet

**Interviewer** — Here's today's problem. **Design a mobile payment service like PayPay.**

**Me** — Let me narrow the scope first. Can I take the core features to be these four: **balance top-up (bank account / card), QR payments (merchants), P2P transfers, and merchant settlement**? Points, coupons, and pay-later credit are out of scope.

**Interviewer** — Good. Let's go with those four.

**Me** — For this problem, the non-functional side feels like the real body of the question. Let me confirm — first, **losing, creating, or double-spending money is unacceptable, down to the last yen**, right? Second, since this is a financial service, **every transaction must have an audit trail**. Third, I'll assume **external institutions like banks and card networks are slow, failure-prone, and outside our control**.

**Interviewer** — All correct. One more — when PayPay ran its early **"10 Billion Yen Campaign"**-style events, payments spiked instantly. Account for that too.

> 💡 **Coaching note** — For most systems, the non-functional requirements ask "how fast" or "how much scale." For money problems, **"never be wrong" comes before "be fast."** And nailing down "external institutions are beyond our control" at the requirements stage — that's the foreshadowing for the sagas and reconciliation coming later.

---

## 2. Back-of-Envelope Math — But This Time the Conclusion Is Different

**Me** — Let me run the numbers. If 60 million MAU in Japan each make 1–2 payments a day, that's roughly 100 million transactions daily — about a thousand per second on average — and with lunch peaks and campaign spikes layered on, **momentary bursts into the tens of thousands of QPS**.

But looking at these numbers, my takeaway is an unusual one. Tens of thousands of QPS is a scale we can absorb with sharding and horizontal scaling — an engineering problem that's already solved. **The bottleneck in this problem isn't QPS; it's correctness.** Processing tens of thousands per second is easier than getting **not a single one of them wrong**. So every design decision from here on will be made not by "faster," but by "**money is preserved under any combination of failures**."

> 💡 **Coaching note** — The purpose of back-of-envelope math is always "the one line that justifies the next decision" — a feed system's line might be "reads are 50x writes"; a ticketing system's, "only 5% of requests can succeed." The money problem's line is, unusually, **"scale is not the bottleneck"** — running the numbers and then declaring that scale isn't the deciding factor is itself a scoring move. Skip the math and say the same thing, and it's a hunch; do the math first, and it's a judgment.

---

## 3. Core Piece ① — The Ledger: A Balance Is Not a State, It's the Sum of a History

**Me** — The data model is the first real body of this problem.

**Interviewer** — Hold on, can't we keep it simple? **Put a balance column on the users table and UPDATE it on every payment.** Seems fine to me.

**Me** — That looks natural, but for money there are three reasons it doesn't work.

1. **You can't tell why it went wrong.** UPDATE overwrites the previous value. When a bug or an outage puts the balance off by 100 yen, all that's left is "the current balance" — there's no basis for tracing which transaction broke it.
2. **You can't audit it.** A financial audit asks "which transactions produced this balance," and with only state and no history, you can't answer.
3. **You can't recover.** There's no source of truth, so there's no way to restore a corrupted balance to "the correct value" at all.

So the truth lives in an **append-only double-entry ledger** — the same method accounting has used for 500 years.

```
ledger_entries (id, transaction_id, account_id, amount(signed), type, created_at)
  -- INSERT only. UPDATE and DELETE aren't even granted as permissions

Example: A pays merchant M 1,000 yen via QR
  (tx_42, account A, -1000, PAYMENT, ...)   ← debit
  (tx_42, account M, +1000, PAYMENT, ...)   ← credit
```

Every transaction is recorded as a **debit/credit pair**, and the sum of any one transaction is always zero. Even a top-up is a double entry against a "bank receivable account," so **summing the entire system always yields zero** — that money was neither created nor destroyed becomes verifiable at the schema level. The balance column on users isn't deleted; it's **demoted to a snapshot (cache) of the ledger** — we can't re-sum everything on every read, so keep it for fast lookups, but the truth is always the ledger.

> 💡 **Coaching note** — The shift in one sentence: **"A balance is not a state — it's the sum of a history."** A seat inventory only needs the current state (AVAILABLE/SOLD) to be right, but money is wrong even when the current value is right, if you can't explain the path. Don't just say "no" to balance UPDATE — overturn it with **the three reasons (tracing, audit, recovery)**. That's what gets scored.

---

## 4. Core Piece ② — Double Spending and Exactly-Once

**Me** — The second core piece is the flow of a payment request. Networks retry, users double-tap buttons, external authorizations fail. Through all of it, money must move **exactly once**.

- **Idempotency keys** — the client generates a unique key for every payment request. The server stores keys it has processed, and when the same key arrives again, it **returns the stored result instead of processing again**. However many retries come in, the entry is written once.
- **Conditional atomic debit** — combine the balance check and the debit into a single atomic operation. It's the same conditional-update pattern that keeps a ticketing system from selling one seat twice.

```sql
UPDATE balances
SET    balance = balance - :amount
WHERE  account_id = :account_id
  AND  balance >= :amount;   -- this condition is the lock that prevents double spending
```

- **State machine + saga** — transactions involving an external institution, like a card top-up, can't be wrapped in one database transaction. So we model the transaction as a state machine — **PENDING → AUTHORIZED → CAPTURED** (on failure, **FAILED → REVERSED**) — and confirm it stage by stage.

**Interviewer** — What if you've already debited the balance and then the card network declines? Do you roll back?

**Me** — Not a rollback — a **compensating entry**. The ledger is append-only, so nothing can be erased; we **add an entry in the opposite direction** to undo it — if there was a -1000 debit, a new +1000 REVERSED entry gets stacked on top. The resulting balance is the same, but the history remains: "we debited, then reversed on a declined authorization." This is the ledger version of a saga (compensating transactions). The harder case is a timeout — you end up in a state where you **don't know** whether the authorization went through. Then you never guess: you send an **inquiry** to the external institution to synchronize state, and if it still can't be confirmed, the transaction goes to a **hold queue** for a human or the reconciliation batch to adjudicate.

> 💡 **Coaching note** — The title of this chapter is **"how to move money in a world without distributed transactions."** The magic of binding our DB and the bank's DB in one transaction (2PC) isn't usable in practice. Instead: ① kill duplicates with idempotency keys, ② record "how far we got" with a state machine, ③ undo failures with compensating entries. Answer "rollback" and you lose points; answer "an entry in the opposite direction" and you score — in a ledger, **even undoing is a record**.

---

## 5. Settlement and Reconciliation — Guaranteed Convergence, After the Fact

**Me** — Merchant settlement doesn't need to be real-time. A **daily batch** sums each merchant's ledger entries, deducts fees, and **instructs a bank transfer** for the remainder. Since the ledger is the truth, settlement is just "read the ledger and sum" — it creates no separate truth of its own.

And this system has one final net — **reconciliation**. Every day, we match the internal ledger against the transaction records the card networks and banks send us, entry by entry, and route mismatches to a **manual handling queue**. In most systems reconciliation is a footnote; in a money problem, the reconciliation batch is a core piece of the architecture.

**Interviewer** — What if our server dies right after the card network authorizes, before we record the response? The card company says approved, but our ledger still says PENDING.

**Me** — The net has three layers. First, when the client **retries with the idempotency key**, the server picks up the state machine where it left off. Second, transactions stuck in PENDING too long get synchronized by an **inquiry batch** that asks the external institution. Third, whatever mismatch survives all that, the **daily reconciliation** is guaranteed to catch. For money flows, the guarantee isn't "perfect in real time" — it's "**guaranteed to converge after the fact**." In a sense, that guarantee is this system's reason for existing.

> 💡 **Coaching note** — Answering a failure question with a single component isn't enough. The model answer for money problems is a triple net at three different time scales: **idempotent retry (seconds) → status inquiry (minutes) → reconciliation (daily)**. If you can express "by when does it converge" as layers, you read as someone who's done this for real.

---

## 6. The Full Picture

**Me** — Putting every decision so far on one page:

```
Client (QR scan / transfer / top-up)
   │ ① payment request (+ client-generated idempotency key)
   ▼
Load Balancer → Payment Service ── idempotency store (duplicate? return stored result)
   │ ② create transaction (state machine: PENDING → ...)
   ▼
Ledger Service ── append-only double-entry DB (conditional debit; the truth lives here)
   │
   ├─③ External Gateway ─ banks & card networks (retries, circuit breaker, inquiry on timeout)
   │        └─ authorization failed → compensating entry / undecidable → hold queue
   └─④ Kafka (transaction-confirmed events)
         ├─▶ Settlement batch ─ daily per-merchant totals → bank transfer instructions
         ├─▶ Reconciliation batch ─ internal ledger vs card/bank records; mismatch → manual queue
         ├─▶ Notification service ─ payment-complete push
         └─▶ FDS ─ fraud detection
```

The synchronous path is kept to the minimum — "idempotency check → ledger entry" — and settlement, reconciliation, notifications, and fraud detection all live in the asynchronous world behind the event stream.

---

## 7. "Where Would You Improve First?" — Version 2

**Interviewer** — We have some time left. What are the limitations of this design?

**Me** — I'd point at three spots.

1. **Hot accounts during campaign spikes** — when a 10-billion-yen campaign fires, a big merchant's **single account** takes thousands of credit entries per second. The ledger writes themselves are INSERTs, so lock contention is mild, but the balance-snapshot update serializes on one row. I'd **split the account into N sub-accounts (sharded buckets)**, spread the writes, and periodically roll them up into the main account — a merchant doesn't need a real-time balance, only an accurate settlement.
2. **Move the fraud detection system (FDS) to async-parallel on the payment path** — right now detection is after the fact, but things like transfers from a stolen account need to be caught mid-payment. Putting it on the synchronous path adds latency, though, so I'd go two-tier: **fast rule checks synchronous, heavy models async in parallel**, holding only the suspicious transactions.
3. **Ledger partitioning and snapshot checkpoints** — the ledger never deletes, so it grows forever. Partition by account ID, and **pin a checkpoint** — "the sum up to this point" — so balance recomputation only reads entries after the checkpoint.

> 💡 **Coaching note** — Version 2 always comes from "where my design's assumptions break." The ledger's assumption (writes are spread out) is broken by hot accounts; append-only's assumption (just read it all) is broken by a table that grows without bound. A ticketing system's hotspot (front-row seats) and this problem's hot account are **the same disease in different patients**.

---

## 8. Interview Retro — What Was Actually Being Graded

1. **Requirements gathering** — identified up front that the non-functionals ("no loss, no creation, no double spend; audit trail; external institutions beyond our control") were the real problem
2. **Back-of-envelope math** — computed tens of thousands of QPS and still drew the inverted conclusion: "the bottleneck is correctness, not QPS"
3. **The ledger** — overturned balance UPDATE with three reasons (tracing, audit, recovery) and established append-only double entry as the truth
4. **Exactly-once** — blocked double spending and external failures with idempotency keys + conditional debit + state machine + compensating entries
5. **Trade-off negotiation** — answered the failure question with a triple net: idempotent retry, status inquiry, reconciliation
6. **Foresight** — named the next bottlenecks first: hot accounts, FDS placement, ledger partitioning

Put this next to a ticketing-style problem and you can see the two faces of consistency. **Ticketing's strong consistency is a fight over a "moment"** — survive the few minutes after open with a queue and locks and you're done — while **money is an "always" fight**, where every transaction is the main event. And the answer isn't stronger locks; it's **records (the ledger)**. A lock protects this moment; a record restores the truth after any failure. When you meet a new problem, ask: *is what I'm protecting here a moment, or a history?*

---

### 📝 TL;DR

> **"Payment design is three sentences — put the truth in an append-only double-entry ledger, make money move exactly once with idempotency keys and conditional debits, and force whatever mismatch remains to converge through reconciliation."**

---

## Next Up

The interviewer follows up — "That wallet (the ledger). Care to design it as classes?" Continued in the [PayPay Payments LLD post](<./PayPay Payments - LLD.md>).
