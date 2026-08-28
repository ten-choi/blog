---
title: "System Design Mock Interview - LLD: \"Implement an LRU Cache and a Token Bucket\""
labels: ["System Design", "LLD", "Data Structures", "Concurrency", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> In the [HLD post](<./URL Shortener and Rate Limiter - HLD.md>) we drew the forest — hot URLs get absorbed by a cache, and the creation API is guarded by a token bucket.
>
> This time we walk into the machine-coding interview and build those two parts — **an LRU cache and a token bucket — by hand, no libraries**. Where service-style LLD was about translating a domain into classes, component-style LLD is a problem of **data structures and invariants**.

# The LLD Mock Interview — "Implement an LRU Cache and a Token Bucket"

## 0. Before We Start — How This Differs from Service-Style LLD

| | **Service-style LLD (e.g., "design a feed as classes")** | **Component-style LLD (this post)** |
|---|---|---|
| The core | Domain modeling — Strategy pattern, state machines | **Data structure composition and invariants** |
| Design axis | An interface at "the first place that will change" | **A structure that protects "what must never break" (O(1), total ≤ C)** |
| What's graded | Separation of responsibility, flexibility to change | **Complexity guarantees, boundary conditions, thread safety** |
| Common mistake | Pattern overuse | Sneaking in a library, missing boundary cases (empty/full) |

The time split is the same — with 3 hours, 30 minutes for requirements and design / 2 hours implementing / 30 minutes for tests and refactoring. Two parts, so an hour of implementation each. Let's go in.

---

## 1. Clarifying Requirements — Get the Invariants as a Contract

**Interviewer** — Here's the problem. **Implement an LRU cache and a token bucket rate limiter.** Basic collections from the standard library (HashMap and the like) are fine, but **finished products like LinkedHashMap or Guava are off-limits**.

**Me** — Let me pin the contract down in numbers. The LRU cache — **both get and put in O(1)**, and on exceeding capacity, **evict the least recently used entry**. Correct?

**Interviewer** — Correct. If O(1) breaks, you've failed the problem.

**Me** — The token bucket — **capacity C, refill R per second**, bursts allowed up to C, and it must be **safe under multiple threads**. I'll take it as that. For the record, I know LinkedHashMap's `accessOrder=true` constructor plus an overridden `removeEldestEntry` finishes LRU in a few lines — but since the intent here is to build those internals myself, I'll do it by hand.

> 💡 **Coaching note** — Component-style LLD requirements aren't a feature list; they're **invariants** — "every operation O(1)," "even under concurrent draws, total ≤ C." Getting these stated as a contract gives every later design decision a yardstick. And **mentioning the banned library first** is a plus, not a minus — the person who can't use it and the person who chooses to build it look different.

---

## 2. The LRU Cache — Why You Graft Two Data Structures Together

**Me** — Let me start with why one structure isn't enough. **HashMap alone** gives O(1) lookup but has **no ordering information** for "who's gone longest unused." **A linked list alone** has perfect ordering but takes **O(n)** to find a given key. Each one's deficiency is the other's strength — so we **graft a HashMap (key → node) onto a doubly linked list (usage order)**. Lookups go through the map; order updates are node re-linking — both O(1). At the two ends of the list I'll plant **sentinel (head/tail) nodes**, eliminating every "is this the first/last node?" null branch outright.

```java
class LruCache<K, V> {
    private static class Node<K, V> {
        K key; V value;
        Node<K, V> prev, next;
    }

    private final int capacity;
    private final Map<K, Node<K, V>> map = new HashMap<>();
    private final Node<K, V> head = new Node<>(), tail = new Node<>();  // sentinels

    LruCache(int capacity) {
        this.capacity = capacity;
        head.next = tail; tail.prev = head;   // even an empty list stays linked head↔tail
    }

    public V get(K key) {
        Node<K, V> n = map.get(key);
        if (n == null) return null;
        moveToHead(n);                        // it was used — move to the 'fresh' end
        return n.value;
    }

    public void put(K key, V value) {
        Node<K, V> n = map.get(key);
        if (n != null) { n.value = value; moveToHead(n); return; }
        if (map.size() == capacity) evictTail();
        n = new Node<>(); n.key = key; n.value = value;
        map.put(key, n); addAfterHead(n);
    }

    private void evictTail() {                // just before tail = least recently used
        Node<K, V> lru = tail.prev;
        unlink(lru); map.remove(lru.key);
    }
    private void moveToHead(Node<K, V> n) { unlink(n); addAfterHead(n); }
    private void unlink(Node<K, V> n) { n.prev.next = n.next; n.next.prev = n.prev; }
    private void addAfterHead(Node<K, V> n) {
        n.prev = head; n.next = head.next;
        head.next.prev = n; head.next = n;
    }
}
```

**Interviewer** — Honestly — **why not just use LinkedHashMap?** Hand-roll this at work and it gets rejected in review.

**Me** — At work I'd reject it too — hand-writing what a battle-tested implementation already does is buying bugs. But I take this problem to be asking not "can you use an LRU" but **whether you know that LinkedHashMap's internals are exactly this hashmap-plus-doubly-linked-list**. Redis's LRU eviction, the OS's page replacement — all variations on this structure, and you have to build it by hand once before their trade-offs become legible.

> 💡 **Coaching note** — "There's a library for that" isn't a trap; it's **a question about perspective**. The right answer honors both sides — "at work I'd use it; here I'm building its internals." And sentinel nodes look minor, but the habit of removing boundary-condition branches through structure is itself on the component-style LLD rubric.

---

## 3. The Token Bucket — Throw Away the Timer, Compute the Time

**Me** — The token bucket. The naive build has **a timer thread topping up R tokens per second**, and that's bad in two ways. With a million per-user buckets you get **a million timers (or scheduled jobs)**, and you keep refilling buckets nobody is even hitting.

Flip the idea — **defer the refill to request time (lazy refill)**. Top up by "seconds since last refill × R" on the spot, and you get the mathematically identical result with no timer. The state is just **(current token count, last refill time) — two fields**.

```java
class TokenBucket {
    private final long capacity;        // C: burst allowance
    private final double refillPerSec;  // R: average rate
    private final Clock clock;          // time is injected — for testing

    private double tokens;              // state ①
    private Instant lastRefill;         // state ②

    TokenBucket(long capacity, double refillPerSec, Clock clock) {
        this.capacity = capacity;
        this.refillPerSec = refillPerSec;
        this.clock = clock;
        this.tokens = capacity;          // start full — allow the first burst
        this.lastRefill = clock.instant();
    }

    public synchronized boolean tryAcquire() {
        refill();
        if (tokens < 1) return false;
        tokens -= 1;
        return true;
    }

    private void refill() {
        Instant now = clock.instant();
        double elapsedSec = Duration.between(lastRefill, now).toNanos() / 1e9;
        tokens = Math.min(capacity, tokens + elapsedSec * refillPerSec);  // never exceed C
        lastRefill = now;
    }
}
```

`Math.min(capacity, ...)` is the burst ceiling and `elapsedSec × R` is the average-rate floor — when the [HLD post](<./URL Shortener and Rate Limiter - HLD.md>) said "two parameters for two requirements," in code it's these two lines. And note I didn't call `Instant.now()` directly — the **`Clock` is injected**.

> 💡 **Coaching note** — Clock injection shows up wherever time drives logic — seat-hold TTLs, matching timeouts, retransmission timers, and now this refill. **The instant time enters your logic, inject the clock** — that reflex gets graded regardless of problem type. Lazy refill itself is a general-purpose technique too — whenever you see "periodic update," first ask "can this become computed-at-request-time?"

---

## 4. Concurrency — synchronized First, Then Reduce Contention

**Interviewer** — You put `synchronized` on `tryAcquire`. Start with why it's needed.

**Me** — Because refill-and-deduct is a **read-modify-write**. Two threads enter together, both read "one token left," both pass — **the invariant total ≤ C breaks**. So I wrapped the entire verdict in a critical section. It's the same principle as a conditional `UPDATE ... WHERE status = 'AVAILABLE'` guarding an inventory row in a database — **close the gap between check and update**. Only the store changed, from a DB to memory.

**Interviewer** — Isn't a global lock a bottleneck? We're at hundreds of thousands of requests a second.

**Me** — The key point is that it isn't global. Buckets are **per-user**, so locks are per-bucket — different users never contend in the first place. **Lock striping falls out of the domain structure for free.** The bucket map is built with `ConcurrentHashMap.computeIfAbsent`, which only has to prevent the one race of "two buckets created for the same user." If contention within a single user must shrink too — encode token count and timestamp **into one long and update lock-free with an AtomicLong CAS loop**. That's what production libraries like Bucket4j do.

**Interviewer** — And if the LRU cache has to go multithreaded?

**Me** — That one's trickier. **Even get mutates the list** (a read is a write), so a read lock isn't enough, and a global lock pays back the O(1) advantage in contention. The practical answer is to sell a little correctness — **ConcurrentHashMap plus approximate LRU**: buffer access records instead of applying them to the list immediately, then apply in batches (Caffeine is in this family), or split the cache into segments to stripe the lock. I'd add this out loud: "**perfect LRU order** and **throughput** are a trade-off, and a cache is a probabilistic game anyway — approximate is enough."

> 💡 **Coaching note** — The order of a concurrency answer is the score — **① why it breaks (via the invariant), ② the simplest protection (synchronized), ③ contention relief (striping, CAS)**. Skip ① and start at ③, you sound memorized; build up from ①, you sound like you understand. And pointing at spots where **structure solves the concurrency for you** — "lock striping comes free from the domain" — is a sure plus.

---

## 5. Tests — Transcribe the Invariants Verbatim

**Interviewer** — Thirty minutes left. Let's see tests.

**Me** — I'll transcribe the requirements' invariants into tests, sentence by sentence.

**LRU cache** — ① Put 4 items into capacity 3 and the **least recently used** is evicted. ② **A get is a use** — a looked-up entry moves back in the eviction order.

```java
@Test
void getCountsAsUse_soEvictionOrderShifts() {
    var cache = new LruCache<String, Integer>(3);
    cache.put("a", 1); cache.put("b", 2); cache.put("c", 3);
    cache.get("a");                       // freshen a
    cache.put("d", 4);                    // triggers eviction

    assertThat(cache.get("b")).isNull();  // the victim is b, not a
    assertThat(cache.get("a")).isEqualTo(1);
}
```

**Token bucket** — ③ Burst: all C pass immediately, **the C+1th is rejected**. ④ Refill: advance a fake `Clock` **one second and exactly R more** pass. ⑤ Concurrency: 20 threads calling `tryAcquire` at once and **total successes ≤ C**.

```java
@Test
void advancingClockOneSecond_refillsExactlyRTokens() {
    var clock = new FakeClock();
    var bucket = new TokenBucket(10, 5.0, clock);   // C=10, R=5
    drain(bucket, 10);                              // exhaust the burst
    assertThat(bucket.tryAcquire()).isFalse();      // the 11th is rejected

    clock.advance(Duration.ofSeconds(1));           // advance time, no sleep
    assertThat(acquireCount(bucket, 10)).isEqualTo(5);  // exactly R, no more
}
```

Because the `Clock` was injected, ④ runs deterministically without `sleep(1000)`, and ⑤ follows the standard shape of a concurrency test — nail the race scenario down in code, then count the successes.

> 💡 **Coaching note** — Component-style tests aren't scenarios; they're **invariant checks** — "total ≤ C," "the victim is the least recently used." ② in particular (does get freshen?) is the most commonly missed weak spot in LRU implementations — that one test verifies half the implementation.

---

## 6. Interview Retro — What Was Actually Being Graded

1. **Requirements clarification** — got O(1) and total ≤ C as contractual invariants, and mentioned LinkedHashMap's existence first
2. **Data structure composition** — derived hashmap + doubly linked list from each structure's deficiency (no order / O(n) search), removed boundary cases with sentinels
3. **Flipping the approach** — named the cost of timer-driven refill and inverted it into lazy refill — two fields of state
4. **Concurrency** — stepwise: why the invariant breaks → synchronized → domain-given lock striping → CAS
5. **Time handling** — Clock injection (the reflex: the instant time enters your logic, inject the clock)
6. **Tests** — transcribed the invariants verbatim, made time tests deterministic with a fake Clock

For this problem type, the practice list is literally a parts catalog from production — **LRU/LFU caches** (this post), **token buckets** (this post), **timing-wheel timers** (managing millions of timeouts — the internals of Kafka and Netty), **Bloom filters** (ruling out "not present" in O(1) and tiny memory), **consistent hash rings** (what the [HLD post](<./URL Shortener and Rate Limiter - HLD.md>) did in words, done in code). They share one trait: all of them are parts that flash by as a single line in a full-service design. Put a 3-hour timer on each and build it — a part you've built reads differently in an architecture diagram.

---

### 📝 TL;DR

> **"Component-style LLD is a problem of invariants — protect O(1) by grafting two data structures together, protect total ≤ C with a gapless atomic verdict, and inject the clock so time becomes testable."**

---

## Previous Post

The forest these two parts stand in — the 62^7 key-space math, the key-generation strategy comparison, fail-open/closed — was covered in the [URL Shortener and Rate Limiter HLD post](<./URL Shortener and Rate Limiter - HLD.md>).
