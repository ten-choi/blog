---
title: "Redis Deep Dive: Why It Is Fast on One Thread, and How to Use It Well"
labels: ["Redis","Cache","Performance","Backend","System Design"]
published: true
date: 2026-11-26T10:00:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "5499707327184977629"
---

## Introduction

Plenty of teams run Redis. Fewer can answer this question when someone asks it in a design review:

> "Redis is single-threaded. Our server has 16 cores. Isn't it wasting 15 of them? How is it fast at all?"

The usual answers are "because it's in memory" and "because a single thread needs no locks." Both are true, but they are only part of the story.

This post has two halves. The first explains **why Redis is fast despite running commands on one thread**: the design choices behind it and what "single-threaded" actually means today. The second is about **using Redis well in practice**: a real-time ranking design, the Big Key and Hot Key problems, transactions, and Redis as a messaging system with Pub/Sub and Streams.

## Part 1: Why Redis is fast

### Isn't one thread slow?

The intuition goes like this: eight cores, one in use, seven sitting idle, so it must be slow. But the assumption that more cores always means more speed does not hold for Redis.

Redis's own benchmark page shows a single instance handling on the order of a hundred thousand simple operations per second without pipelining, and well over a million per second with pipelining, at sub-millisecond latency. Exact numbers depend on hardware, but the scale is the point.

So Redis is not fast *because* it is single-threaded. It was **designed to be fast while being single-threaded**. And when Redis does get slow in production, the cause is almost never the thread count. It is heavy commands or oversized data, which we will get to.

### What multithreading costs

Multiple threads are not free:

- **Locks.** Shared data needs locks, and threads wait on each other.
- **Context switches.** Saving and restoring registers and stacks every time the CPU switches threads. The more requests, the more overhead.
- **CPU cache coherence.** Cores have to keep their caches consistent when they touch the same data.
- **Contention.** Throughput only scales linearly with threads when they share nothing.

Redis avoids all of this by design. No shared state between threads means no locks, and no locks means no waiting.

### Why Redis chose a single thread

Redis's creator, Salvatore Sanfilippo (antirez), has explained the choice in the Redis FAQ and on his blog. It was not that multithreading was impossible. Roughly, the reasons were:

1. **The CPU was not the bottleneck.** Redis is usually limited by memory bandwidth and network I/O. Adding cores does not fix either. For an operation that takes well under a microsecond, the cost of taking a lock could be a large fraction of the work itself.
2. **Simplicity.** Multithreaded code is hard to write and slows down feature development. If you assume from the start that there are no locks, no races, and no deadlocks, the code gets much simpler.
3. **More to lose than to gain.** Even simple operations become tricky. A thread doing `LPOP` on a list has to coordinate with another doing `RPUSH` on the same list. Instead, Redis recommends **scaling out with multiple instances**, each single-threaded.

### Five reasons it is fast anyway

#### 1. Everything is in memory

A traditional relational database is built around disk I/O. It has a buffer pool, but that is an optimization on top of a disk-based design. Redis serves every read and write from RAM.

The gap is enormous: memory access is on the order of 100 nanoseconds, a fast NVMe SSD is tens of microseconds, a SATA SSD is around a hundred microseconds or more, and a hard disk is milliseconds. That is hundreds to tens of thousands of times slower than RAM, and faster SSDs do not close the gap.

Being in memory does mean data can be lost on a crash, so Redis offers persistence through **RDB snapshots** and the **AOF** (append-only file) log.

#### 2. I/O multiplexing with an event loop

Redis can serve tens of thousands of client connections on one thread because it never blocks waiting on any single one.

It registers every client socket with the kernel through **epoll** (on Linux; kqueue on BSD/macOS). The kernel watches all of them. Redis runs an event loop that asks the kernel, "which sockets are ready right now?", and handles only those:

- **Ready to read:** a client has sent a command, and the data is already in the socket buffer.
- **Ready to write:** Redis has a reply to send, and the socket buffer has room for it.

A restaurant analogy helps:

- **Blocking I/O:** a waiter takes an order, carries it to the kitchen, and stands there until the dish is ready. They can't serve anyone else meanwhile, so you need one waiter per table.
- **I/O multiplexing:** one waiter hands every order to the head chef and says, "tell me when any dish is ready." The chef (epoll) watches all orders at once, and the waiter only moves when something is ready to serve.

This is also how the **C10K problem** was solved. Posed by Dan Kegel in 1999, it asked how one server could handle 10,000 concurrent connections. One thread per connection runs out of memory; an event loop with non-blocking I/O does not. Nginx and Node.js are built on the same idea.

#### 3. O(1) key lookups

The global keyspace is a hash table. Redis hashes the key, jumps straight to the right bucket, and finds the value, with no scanning. Collisions are resolved by chaining.

The built-in data types also rest on carefully chosen structures, so most operations run in constant or logarithmic time. Sorted sets, for example, use a **skip list** rather than a balanced tree. A skip list gives similar performance with a much simpler implementation, which fits Redis's preference for simplicity.

#### 4. The RESP protocol is cheap to parse

Redis talks to clients over RESP (REdis Serialization Protocol). Its key idea is **length first**.

Many text protocols separate fields with delimiters like commas or spaces. The parser has to scan byte by byte until it finds the delimiter, and it cannot know the size in advance, so it cannot allocate the right buffer up front.

RESP sends the length before the data:

```text
*3\r\n
$3\r\nSET\r\n
$3\r\nkey\r\n
$5\r\nvalue\r\n
```

`*3` means "an array of three elements," and `$5` means "the next string is exactly 5 bytes." The parser reads the length, allocates exactly that much, and reads that many bytes. Less scanning, simpler loops, and lower per-command overhead, which matters when one thread has to parse a million commands a second.

#### 5. Pipelining

Without pipelining, every command costs a full network round trip: send, wait for the reply, send the next one. With pipelining, the client sends many commands at once and reads all the replies together.

If the round trip is 1 ms, sending 100 commands one by one takes over 100 ms. Pipelined, it is roughly one round trip. That is why throughput jumps from around a hundred thousand to over a million operations per second in the benchmarks.

```js
// node-redis: commands queued in the same tick are sent together
const results = await Promise.all([
  redis.set("a", "1"),
  redis.set("b", "2"),
  redis.get("a"),
]);
```

### What "single-threaded" really means

Redis has not been purely single-threaded for a while:

| Version | Change |
|---|---|
| Early Redis | One thread does everything: socket I/O, parsing, execution, replies |
| Redis 4.0 | Background threads take over slow work such as freeing large values (`UNLINK`, lazy free) and AOF fsync, so they don't block the main thread |
| Redis 6.0 | Optional **I/O threads** (`io-threads`) for reading from and writing to sockets |

I/O threads can raise throughput noticeably when there are many clients or large replies. With few clients or tiny commands, the extra context switching can make things slower. The Redis docs suggest using fewer I/O threads than cores (for example, about 6 on an 8-core machine) and then benchmarking.

What has not changed: **command execution is still single-threaded.** "Redis is single-threaded" really means "the path that executes commands is single-threaded," not "the whole process has one thread."

### What actually makes Redis slow

Since one thread executes every command, anything that takes a long time blocks everyone else:

- **O(N) commands with large N.** `KEYS *` on a big keyspace is the classic example. Use `SCAN` instead.
- **Very large keys.** Reading or deleting a hash or list with millions of elements in one go.
- **Hot keys.** Too many requests hitting a single key.

The rule of thumb: in a single-threaded system, always be careful with O(N) operations.

### Data structures matter as much as speed: a ranking benchmark

Consider fetching ten users from the middle of a leaderboard with one million entries.

- **MySQL:** a table with `user_id`, `user_name`, and an indexed `score` column, queried with `ORDER BY score DESC LIMIT 10 OFFSET n`.
- **Redis:** a sorted set with users as members and their points as scores, queried with `ZRANGE leaderboard n n+9 REV`.

At small offsets the two are close. As the offset grows, MySQL gets steadily slower, because even with an index it has to walk past and discard every row before the offset. Redis stays almost flat, because the skip list can jump to a rank in O(log N). In one test at an offset of 900,000, MySQL took about 690 ms while Redis took about 2 ms, a gap of more than 300x.

Memory vs disk explains some of that gap, but most of it comes from the data structure. That is the real lesson: Redis is valuable not only because it is in memory, but because its data types (sorted sets, lists, hashes) let you model the problem directly.

## Part 2: Using Redis well

### Designing a real-time leaderboard

A typical system design question:

> "Show real-time game rankings for hundreds of thousands of users, and push changes to every client the moment rankings change. How would you design it?"

Break it into four problems.

**1. Hundreds of thousands of concurrent connections.** One server will not do. Put several application servers behind a load balancer so connections and requests are spread out and capacity can grow horizontally.

**2. The ranking data structure.** The requirements are: update a score, get the top N, get my rank, and see who is just above and below me. A **sorted set** covers all of them, and keeps itself sorted on every update.

```text
ZINCRBY leaderboard 50 "user:42"           # add points
ZRANGE  leaderboard 0 9 REV WITHSCORES     # top 10
ZREVRANK leaderboard "user:42"             # my rank (0-based)
ZSCORE  leaderboard "user:42"              # my score
ZRANGE  leaderboard 37 47 REV WITHSCORES   # neighbors, if my rank is 42
```

A sorted set is backed by a skip list, so lookups and updates are O(log N) on average. Even with 100 million entries, that is only about 27 steps.

**3. Propagating changes between servers.** When server 1 updates a score, servers 2 through N need to know. **Redis Pub/Sub** fits well: publish a message when a score changes, and every server subscribes.

**4. Pushing updates to clients.** Once a server hears about a change, it pushes it to connected browsers. **Server-Sent Events (SSE)** is a good match: it runs over plain HTTP and is built for one-way, server-to-client streams.

```text
Clients <--SSE-- App servers (behind a load balancer)
                     |   ^
          ZINCRBY /  |   |  SUBSCRIBE rank-updates
          ZRANGE     v   |
                   Redis: sorted set + Pub/Sub
```

Sorted set for storage and lookup, Pub/Sub for server-to-server events, SSE for server-to-client push. Choosing the right data structure first is what keeps the whole design simple.

### Big Keys and Hot Keys

Two problems cause a large share of Redis incidents, and they are often confused.

| | Big Key | Hot Key |
|---|---|---|
| What it is | One key holds too much data | One key gets too many requests |
| Root cause | Data volume | Traffic concentration |
| Typical example | A collection that keeps growing with no limit (e.g., all order history in one list) | Popular product cache, main banner, top-ranking key |
| What breaks | Reading, deleting, replicating, or migrating it blocks the single thread; memory fragmentation; network load | CPU and network on one node spike; that node can fail |

**Detecting them.** `redis-cli` has built-in scanners:

```bash
redis-cli --bigkeys   # the largest key of each type
redis-cli --hotkeys   # frequently accessed keys (requires an LFU maxmemory-policy)
```

Neither gives you an absolute threshold. You still have to look at the results and decide what is too big or too hot for your system. Slow logs (`SLOWLOG GET`) help too.

**Fixing Big Keys: split the data.**

- **Partition the key.** Instead of `orders:user:42`, use `orders:user:42:2026`, `orders:user:42:2025`, and so on.
- **Delete asynchronously.** `DEL` on a huge key blocks the main thread. `UNLINK` frees memory in the background.
- **Read in chunks.** Use `HSCAN`, `SSCAN`, `ZSCAN`, or range commands instead of fetching everything at once.

**Fixing Hot Keys: spread the requests.**

- **Local cache in front of Redis.** Keep the hot value in the application's memory (Caffeine, Guava) so most requests never reach Redis.
- **Replicate the key.** Store copies such as `banner:main:1` through `banner:main:N` across nodes, and have the application pick one at random.
- **Read replicas.** Spread read traffic across replicas.

**Prevent both at design time.**

- Estimate how big each key and collection will grow, and design keys around that.
- Predict which keys will attract traffic, and plan local caching or replication up front.
- Set TTLs so data doesn't pile up forever, and make sure a popular key expiring doesn't send every request to the database at once (a **cache stampede**).
- Periodically check slow logs and run `--bigkeys` / `--hotkeys`.

When Redis slows down, the first question to ask is: is this a Big Key problem or a Hot Key problem?

### Transactions

A single Redis command is already atomic. Redis even has combined commands for common pairs, like `GETDEL` (get and delete) and `GETEX` (get and update the expiry), so nothing can sneak in between the two steps.

The trouble starts when the business logic needs **several commands**. Say a "like" must both increment a post's like counter and add the user to the set of people who liked it. No single command does both. Run them separately and two things can go wrong: another client can interleave between them, or the first can succeed while the second fails, leaving the counter and the set out of sync.

**MULTI / EXEC** groups commands so they run together, in order, with nothing else running in between:

```text
MULTI
INCR  post:100:likes
SADD  post:100:liked_by "user:42"
EXEC
```

After `MULTI`, commands are queued instead of executed. `EXEC` runs the whole queue at once.

**WATCH** adds optimistic locking. Suppose you check stock and decrement it only if some remains. Another client might decrement it between your check and your update. `WATCH` the key first; if anyone modifies it before your `EXEC`, the transaction is aborted and you retry.

```text
WATCH stock:item:7
GET   stock:item:7          # suppose it returns 3
MULTI
DECR  stock:item:7
EXEC                        # returns nil if stock:item:7 changed after WATCH
```

**Limits to know.** Redis transactions are not RDBMS transactions:

- **No rollback.** If one command fails at runtime, the others still run. It is not all-or-nothing.
- **No conditional logic.** You can't branch on a value read inside the transaction.

**When you need more:** use **Lua scripts** (`EVAL`), which run atomically and can contain conditions and loops, or **Redis Functions** (Redis 7+), which let you register reusable Lua logic on the server, much like stored procedures in an RDBMS.

```lua
-- Decrement stock only if enough remains
local stock = tonumber(redis.call('GET', KEYS[1]) or '0')
if stock >= tonumber(ARGV[1]) then
  return redis.call('DECRBY', KEYS[1], ARGV[1])
end
return -1
```

A simple guide: one command, just use it; several commands that must stay consistent, use a transaction; logic with conditions, use Lua or Functions.

### Redis as a messaging system: Pub/Sub and Streams

Redis started in 2009 as a key-value cache, gained the Stream type in Redis 5.0 (2018), and with Redis 8 (2025) folded former Redis Stack features such as JSON and search into the main distribution. It is fair to call it a real-time data platform now, not just a cache.

A **messaging system** lets services talk through messages via a broker instead of calling each other directly. That keeps them loosely coupled, lets slow work run asynchronously, and makes it easy to add more consumers.

#### Pub/Sub: fast broadcast, nothing stored

Publishers send to a channel; every current subscriber receives the message.

```text
SUBSCRIBE chat:room:1
PUBLISH   chat:room:1 "hello"
```

It is fast and simple, which makes it great for live notifications and real-time event fan-out. The catch: **messages are not stored.** A subscriber that is offline when a message is published never sees it, and you can't replay or reprocess anything.

#### Streams: a persistent, replayable log

Streams store messages like an append-only log, and **consumer groups** let several workers share the processing.

```text
XADD       orders * order_id 1001 user_id 42          # producer appends
XGROUP     CREATE orders billing $ MKSTREAM            # create a consumer group
XREADGROUP GROUP billing worker-1 COUNT 10 STREAMS orders >   # worker reads new messages
XACK       orders billing 1700000000000-0              # worker acknowledges
```

Messages stay until you trim them, so consumers can read them later, unacknowledged messages can be retried, and you can track what has been processed.

#### Comparison

| | Pub/Sub | Streams |
|---|---|---|
| Stores messages | No | Yes |
| Offline consumers | Miss the message | Can read it later |
| Reprocessing | Not possible | Possible |
| Consumer management | None | Consumer groups, acknowledgements, pending lists |
| Good for | Live notifications, broadcast | Reliable jobs, event pipelines |

In practice:

- **Pub/Sub:** chat notifications to connected users, live dashboard updates, telling app servers that something changed.
- **Streams:** work after an order (awarding points, sending texts), log and event pipelines, background jobs like thumbnail generation, reports, or bulk notifications.

Many systems use both: Pub/Sub for immediate fan-out, Streams for work that must not be lost.

#### So is Redis a cache or a message queue?

This comes up often, especially as an interview follow-up to "cache or message queue?" The honest answer is: **both, depending on which features you use.**

- As a **cache**, Redis stores key-value data in memory with TTLs and eviction policies, typically in front of a database.
- As a **message broker**, Pub/Sub gives you fire-and-forget broadcast, and Streams give you a persistent log with consumer groups, acknowledgements, and redelivery, which is everything a basic work queue needs.

That does not make it a drop-in replacement for Kafka. Kafka is built for very high-volume, long-retention event streams, partitioned across many brokers and replayed by many independent consumers. Redis Streams fit well when you already run Redis, the volume is moderate, and you want a simple, reliable queue without adding another system. The concept comes first, and the tool follows from your requirements.

## Wrap-up

- Redis is fast on one thread because of **design**, not luck: everything in memory, epoll-based I/O multiplexing, O(1) hashing and carefully chosen data structures, a protocol that is cheap to parse, and pipelining. No locks means no waiting, and the code stays simple.
- "Single-threaded" means **command execution** is single-threaded. Background threads and optional I/O threads exist.
- Redis gets slow because of **O(N) commands, Big Keys, and Hot Keys**, not because of its thread count.
- Its data types are the real superpower: a sorted set turns a leaderboard from a slow `OFFSET` query into an O(log N) lookup.
- Use transactions for multi-command consistency, Lua or Functions for conditional logic, Pub/Sub for broadcast, and Streams for reliable queues.

If you are only using Redis as a key-value cache, you are leaving a lot on the table.
