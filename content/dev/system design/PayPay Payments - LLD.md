---
title: "System Design Mock Interview - LLD: \"Design That Wallet (the Ledger) as Classes\""
labels: ["System Design", "LLD", "Payments", "Concurrency", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> In the [PayPay Payments HLD post](<./PayPay Payments - HLD.md>) we drew the forest — the truth lives in an append-only ledger, and money moves exactly once via idempotency keys and conditional debits.
>
> This time we walk into the machine coding interview and implement that **wallet and ledger as classes**. Where a resource-contention problem (think seat booking) asks you to "leave exactly one winner," this post is an **invariant problem** — defending one sentence, "the total money in the system is preserved," with code and tests.

# The LLD Mock Interview — "Design the Wallet (Ledger) as Classes"

## 0. Before We Start — How This Differs from a Resource-Contention LLD

| | **A typical resource-contention LLD (e.g., seat booking)** | **PayPay payments LLD (this post)** |
|---|---|---|
| Problem archetype | Resource contention — **leave exactly one winner** | **Invariant type — defend "the sum of money is preserved"** |
| Core entities | Seat, SeatHold (state flows) | **LedgerEntry — being immutable IS the design** |
| Concurrency | Concurrent holds on the same seat | Concurrent withdrawals from the same balance + **concurrent duplicates of the same idempotency key** |
| What the tests verify | Scenarios (contention, expiry, transitions) | **Invariants (after random transactions, the sum still holds)** |

Time budget is the same — with 3 hours: 30 min requirements & design / 2 hours implementation / 30 min tests & refactoring. Let's walk in.

---

## 1. Clarifying Requirements — Extract the Invariants First

**Interviewer** — Here's the problem. **Design and implement a wallet domain — top-up, payment, transfer — as classes, centered on a ledger.**

**Me** — Let me confirm the scope. Every transaction is **double-entry** — debit and credit recorded as a pair, no updates or deletes — correct? And two rules that must never break: **the same request retried multiple times writes exactly once** (idempotency), and **a balance can never go negative**.

**Interviewer** — Correct. There are fees too — P2P transfers are free, but merchant payments carry a fee, and the rate can change.

**Me** — Then the fee policy is "the first thing that will change." I'll split it behind an interface. And concurrency can't be swept aside here — **concurrent withdrawals against the same account are in scope from the start**.

> 💡 **Coaching note** — What you need to extract at the requirements stage of this domain isn't a feature list but an **invariant list**: ① every entry comes in pairs and sums to zero, ② the same idempotency key executes once, ③ no negative balances. Features are whatever you can build without breaking those three sentences. The moment you reflect the requirements back in the language of invariants, the interviewer sees "someone who has handled money."

---

## 2. Collect the Nouns, Then Find What Must NOT Change

**Me** — Let me collect the nouns — account, ledger entry, transaction, transfer, idempotency key, fee policy.

```
Account (id, balance snapshot, version)
LedgerEntry ─ immutable! no modification after creation (Java record)
Transaction (state machine: PENDING → CAPTURED / FAILED → REVERSED)
TransferService ─ assembles the use case
IdempotencyStore ─ stores processed keys and their results
FeePolicy ─ fee policy (the first thing that will change!)
```

Here's the twist in this domain. Design usually means finding "what will change" and making it flexible; this domain's specialty is the opposite direction — **one entity (LedgerEntry) being immutable is itself the design**. No setters, no mutation methods, an object that dies exactly as it was born. It enforces the domain rule "the ledger cannot be edited" at the language level. The state machine uses the classic **transition-table pattern**, and FeePolicy is the **Strategy pattern** — the same "put an interface where the policy will change" move, applied to fees.

> 💡 **Coaching note** — "What changes goes behind an interface; what must not change goes immutable." Flexibility isn't the only design skill — **deliberately imposing rigidity** is design too. One record type is where the HLD decision "this table has no UPDATE" lands in code.

---

## 3. The Code Skeleton — Immutable Entries, a Transition Table, and One Transaction

**Me** — Let me put up the skeleton. First, the thing that never changes.

```java
record LedgerEntry(
    long transactionId,
    long accountId,
    long amount,        // smallest unit (yen), signed — debits negative, credits positive
    EntryType type,     // CHARGE / PAYMENT / TRANSFER / FEE / REVERSAL
    Instant createdAt
) {}                    // record — no setters. Immutable after creation

enum TransactionStatus {
    PENDING, AUTHORIZED, CAPTURED, FAILED, REVERSED;

    private static final Map<TransactionStatus, Set<TransactionStatus>> ALLOWED = Map.of(
        PENDING,    Set.of(AUTHORIZED, CAPTURED, FAILED),
        AUTHORIZED, Set.of(CAPTURED, FAILED),
        CAPTURED,   Set.of(REVERSED),   // after capture, no 'cancel' — only 'reverse'
        FAILED,     Set.of(REVERSED),
        REVERSED,   Set.of()
    );
    public boolean canTransitionTo(TransactionStatus next) {
        return ALLOWED.get(this).contains(next);
    }
}

interface FeePolicy {                          // when the rate changes,
    long feeOf(TransferCommand cmd);           // the transfer flow doesn't (OCP)
}
```

A transfer performs these five steps, **all inside one transaction**.

```java
class TransferService {
    @Transactional
    public TransferResult transfer(TransferCommand cmd) {
        // ① idempotency check — key already processed? return the stored result as-is
        // ② lock accounts — in sorted ID order (deadlock avoidance)
        // ③ conditional debit check — balance >= amount + fee
        // ④ write debit + credit (+ fee) entries — LedgerEntry INSERTs, summing to zero
        // ⑤ finalize transaction state — PENDING → CAPTURED
    }
}
```

**Interviewer** — What if the user cancels a payment? Do you **DELETE** that transaction's entries?

**Me** — The ledger never deletes. We **add reversal entries in the opposite direction** — if the original transaction was (A -1000, M +1000), we stack a new REVERSAL pair (M -1000, A +1000) and transition the transaction to REVERSED. The balances come back, but the history remains: "paid, then cancelled." It's like an accounting book — you don't erase a wrong line with an eraser; you strike it through in red and write again. That's also why, in the transition table, the only state after CAPTURED is REVERSED.

> 💡 **Coaching note** — "Cancel = DELETE" is this interview's planted trap. In a ledger, **even undoing is an entry**, which is why REVERSAL is a citizen of EntryType. This one answer threads together the record from chapter 3 (immutability), the transition table (CAPTURED→REVERSED), and the compensating transactions from the HLD post — in a single line.

---

## 4. Concurrency — Let One Atomic Operation Make the Call

**Interviewer** — The key question. **Two withdrawal requests for 80 yen hit an account with a 100-yen balance at the same time.** Both can't succeed, right?

**Me** — If the application does "read balance → looks sufficient → debit," both threads pass the "looks sufficient" check. It's the classic check-then-act gap. So the verdict comes down to **one atomic operation in the store**.

```java
class AccountRepository {
    /** @return number of rows actually debited (0 = insufficient balance, or lost the race) */
    int debit(long accountId, long amount) {
        // UPDATE accounts SET balance = balance - :amount
        // WHERE id = :accountId AND balance >= :amount
    }
}
```

Even when the two requests race, the DB row lock imposes an order, and for the loser the `balance >= 80` condition is already false — zero rows updated, an exception is thrown, and the whole transaction rolls back. Two concurrency holes remain.

- **The same idempotency key arriving twice concurrently** — "look up key → not there → process" has the same gap. Put a **unique constraint** on the idempotency key column so the later INSERT loses by constraint violation — the same trick that keeps a social feed from recording the same user's like twice.
- **The optimistic locking (version) alternative** — give Account a version and update with `WHERE version = :v`. Great for ordinary user wallets where conflicts are rare, but on a hot account mid-campaign where conflict is the norm, it becomes a retry storm. The selection criterion is **conflict frequency**.

> 💡 **Coaching note** — Whatever the domain, **the skeleton of the concurrency answer is almost always the same** — eliminate the check-then-act gap and let one atomic operation make the call. Duplicate likes: unique constraint. Seats: `WHERE status='AVAILABLE'`. Balances: `WHERE balance >= :amount`. The problem changes; the grammar of the answer doesn't. This problem's extra talking point is covering **the race on the idempotency key itself**.

---

## 5. Invariant Tests — The Highlight of This Post

**Interviewer** — Last 30 minutes. What would you verify with tests?

**Me** — In this domain I'd verify **invariants before scenarios**. Number 1 is the heart of the problem.

```java
@Test
void after_1000_random_transactions_the_sum_of_money_is_preserved() {
    var rnd = new Random(42);                    // fixed seed — reproducible on failure
    for (int i = 0; i < 1000; i++) {
        randomOperation(rnd);                    // random pick: top-up, payment, transfer, fee, cancel
    }                                            // (some may fail on insufficient balance — that's fine)
    assertThat(ledger.sumOfAllEntries()).isZero();   // double entry: the total is always zero
}
```

Even a top-up is a pair against the "bank receivable account," so the outside world is itself an account inside the ledger — which is why **after any combination of transactions the total must be zero**, and this single line nets bugs in the debit logic, the fee calculation, and the compensating entries all at once. The remaining pressure points are four.

1. **One winner on concurrent withdrawal** — two threads withdrawing 80 from a balance of 100: exactly one succeeds, final balance is 20
2. **Idempotent retry** — calling transfer 3 times with the same idempotency key writes **exactly one pair** of ledger entries, and all 3 calls return the same result
3. **Illegal transitions blocked** — `transitionTo(PENDING)` on a CAPTURED transaction throws
4. **Balances restored after compensation** — pay then cancel: both account balances return to the original, and 4 entries remain (original 2 + reversal 2)

> 💡 **Coaching note** — Tests in other domains verify **scenarios** ("hold a seat and it becomes HELD"); tests in the money domain verify **invariants** ("whatever you do, the sum is preserved"). This is why the property-based style — hurl random operations, then check one property — pairs especially well with money: transaction combinations you never imagined find the bugs for you. Fix the seed for reproducibility and it's complete.

---

## 6. Interview Retro — What Was Actually Being Graded

1. **Requirements clarification** — reflected the problem back in the language of invariants (paired entries, idempotency, no negatives), not features
2. **Entity extraction** — identified that LedgerEntry's **immutability is itself the design**, and enforced it at the language level with a record
3. **Pattern selection** — state transitions via a transition table, fees via Strategy — proven answers matched to recurring questions, not novelty for its own sake
4. **Ledger discipline** — answered "is cancel a DELETE?" with reversal entries in the opposite direction
5. **Concurrency** — conditional atomic debit + unique constraint on the idempotency key + fixed lock ordering; optimistic vs pessimistic chosen by conflict frequency
6. **Testing** — nailed down the invariant (sum preservation) property-based style, not scenario by scenario

Step back, and LLD problems sort into question types. The read-and-assemble type asks "what do you combine"; the resource-contention type, "who wins"; the real-time matching type, "who fits, right now"; the reliability-protocol type, "did it arrive exactly once." The **invariant type asks "what is the one sentence that must survive no matter what you do."** Find that sentence and the entities (immutable entries) and the tests (sum preservation) follow on their own.

**To make it stick** — practice problems of the invariant type: wallet/ledger (this post), bank account transfers (the two-account sum is preserved across a transfer), points/mileage systems (the sum of accrual, expiry, and spend), bill-splitting settlement (Splitwise — receivables and payables sum to zero), inventory-payment sagas (stock + order state restored after compensation). In every one, "is the sum preserved?" is the heart.

---

### 📝 TL;DR

> **"Invariant-type LLD comes down to three things — entries are immutable objects that only accumulate, undo is not a delete but an entry in the opposite direction, and tests verify not scenarios but the invariant: 'the sum of money is preserved.'"**

---

## Previous Post

The forest this ledger stands in — idempotency keys and state machines, sagas and compensating entries, the triple-net reconciliation — was covered in the [PayPay Payments HLD post](<./PayPay Payments - HLD.md>).
