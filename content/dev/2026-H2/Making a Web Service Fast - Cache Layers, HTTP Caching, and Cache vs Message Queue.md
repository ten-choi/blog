---
title: "Making a Web Service Fast: Cache Layers, HTTP Caching, and Cache vs Message Queue"
labels: ["Cache","Redis","HTTP","CDN","Message Queue","Performance","Backend"]
published: true
date: 2026-11-25T16:26:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "6381211101803370551"
---

## Introduction

Ask a backend developer how to make a slow page faster and the first answer is usually "put Redis in front of it." That is not wrong. An application-level cache in Redis is one of the most common performance wins there is.

But Redis is only one stop on a long road. Between the user's screen and your database, a request passes through several places that can cache a response, and each of them is good at a different job. A developer who only knows Redis tends to push every kind of data through it, including data that should never have left the browser in the first place.

This post walks through every cache layer a typical web service has, what each layer is good for, how HTTP caching actually works in the browser, and the mistakes that show up most often in practice. Then it zooms out: how to think about read and write performance as a whole, and how to decide between a cache and a message queue when a server starts to struggle.

## The cache layers, from the user inward

| Layer | Where it lives | Shared by | Typical contents |
|---|---|---|---|
| Browser cache | The user's device (memory or disk) | One user | CSS, JS, images, fonts |
| CDN | Edge servers near the user | All users in a region | Images, video, static files, game patches |
| Local (in-process) cache | Memory of one app server instance | One instance | Country codes, common codes, config |
| Shared (distributed) cache | A central cache such as Redis | All instances | Sessions, carts, user state, notices |
| DB buffer / OS page cache | Inside the database and the OS | — | Recently read pages and blocks |

The last row matters, but it is mostly managed by the database and the operating system, not by application code. The first four are the ones you design.

Frontend developers usually know the browser cache well. Backend developers know local and shared caches. CDNs sit somewhere in between. The goal is to be comfortable with all of them, so you can decide where each piece of data belongs.

## One rule: finish the request as close to the user as possible

The farther a request travels, the slower it feels and the more of your infrastructure it consumes. A response served from the browser cache costs zero network round trips and zero server CPU. A response served by a CDN edge never reaches your origin. A response from a local cache skips the network hop to Redis. Every request that ends at an outer layer saves the user time and takes load off your servers.

### Why not just one layer?

Because data differs in four ways, and each layer handles a different combination well:

1. **How often it changes.** A logo changes once a year; a shopping cart changes every few seconds.
2. **Who shares it.** Country codes are identical for every user; a session belongs to exactly one.
3. **How big it is.** A video is megabytes; a user's cart is a few hundred bytes. Size drives transfer and storage costs, and with them the best layer.
4. **How fresh it must be.** A stock price must be live. A notice can be a few minutes old without anyone noticing.

Match the layer to those four properties and caching becomes a design decision instead of a reflex.

## How a request flows through the layers

```text
User request
  -> Browser cache          (hit? done)
  -> CDN edge               (hit? done)
  -> Static files: web server directory or object storage (e.g., S3)
  -> Dynamic data: local cache -> shared cache (Redis) -> database
```

Static resources normally stop at storage. Dynamic data usually takes the second path, from the local cache down to the database. Browsers and CDNs *can* cache API responses too, but it is less common and needs care.

Read the diagram from the bottom up and you get the order in which the caches are filled: data starts in the database, gets copied into Redis, a hot subset is held in each instance's local cache, static assets are pushed to the CDN, and finally the browser keeps its own copy.

## Layer by layer

### Browser cache

The browser stores responses on the user's device and reuses them on later requests. This is the fastest layer because nothing goes over the network. It is the natural home for CSS, JavaScript, images, and fonts.

You control it with HTTP headers such as `Cache-Control`, `ETag`, and `Last-Modified` (covered in detail below).

Two things to keep in mind:

- It is **per browser**. Every user has an independent copy, so you cannot "clear" it from the server.
- Because you cannot clear it, you update it by **changing the URL**: put a content hash in the file name or a version in the query string.

### CDN

A CDN (Amazon CloudFront, Cloudflare, Fastly, and so on) keeps copies of your content on edge servers around the world and serves each user from the nearest one. It is the right place for large files: images, video, downloads, game installers and patch files. It cuts origin load and shortens the network distance at the same time.

- Updating cached content is called **purging** (CloudFront calls it **invalidation**). If you deploy without purging, users keep getting the old file until the TTL runs out.
- Be very careful caching **dynamic** content at a CDN. A personalized response cached at the edge can be served to the wrong user, along with their personal data.
- A side note on CloudFront: teams often route dynamic APIs through it with a TTL of 0. Nothing is cached, but traffic rides AWS's private backbone instead of the public internet, which can lower latency.

### Local (in-process) cache

This is data kept in the memory of the application process itself, whether that is a Spring, Node.js, or Python server. Common libraries are Caffeine and Guava on the JVM.

It suits data that is read constantly and changes rarely: country codes, common code tables, configuration values. There is no network hop at all, so it is faster than any remote cache.

The catch: **every instance has its own copy.** Behind a load balancer with ten servers, there are ten caches that can drift out of sync. That is fine for data that almost never changes and risky for anything that does.

### Shared (distributed) cache

This is a central cache that every instance talks to, and Redis is the usual choice. Because all servers see the same data, it is the right place for sessions, shopping carts, and per-user state that any server might need to read.

- Set a **TTL** on entries and configure an **eviction policy**, or memory will eventually fill up.
- Every read is a network round trip, so it is slower than a local cache. Fast, but not free.

## HTTP caching in the browser, in detail

HTTP caching has a lot of headers, and they are easy to mix up. It helps to split them into two questions:

1. **Freshness:** how long can the browser reuse its copy without asking?
2. **Validation:** once that time is up, how does the browser check whether its copy is still good?

### The basic cycle

1. The browser requests a resource.
2. The server responds with the resource plus caching instructions: whether it may be cached, for how long, and how to revalidate it.
3. The browser stores a copy in memory or on disk (the browser decides which, based on size and usage).
4. Later requests are served from that copy without touching the network.
5. When the copy expires, or when the server said to always check, the browser sends a **conditional request**.
6. If nothing changed, the server answers **304 Not Modified** with no body. If it changed, the server sends **200 OK** with the new content.

A 304 is tiny compared with resending a large image, which is the whole point.

### Freshness: `Cache-Control` vs `Expires`

| Header | Since | Format | Notes |
|---|---|---|---|
| `Cache-Control: max-age=3600` | HTTP/1.1 | Seconds, relative to when the response was received | The modern standard |
| `Expires: Wed, 01 Jan 2027 00:00:00 GMT` | HTTP/1.0 | Absolute date | Legacy; ignored when `max-age` is present |

Use `Cache-Control`. If both are present, `Cache-Control` wins.

### Validation: `ETag` vs `Last-Modified`

| Server sends | Browser revalidates with | Compares |
|---|---|---|
| `ETag: "abc123"` | `If-None-Match: "abc123"` | A version identifier for the content |
| `Last-Modified: <date>` | `If-Modified-Since: <date>` | The last modification time |

If both are present, the `ETag` check takes priority.

### `Cache-Control` directives

| Directive | Meaning |
|---|---|
| `public` | Any cache may store it: browser, proxy, or CDN |
| `private` | Only the end user's browser may store it. Use this for personalized responses |
| `no-store` | Do not store it anywhere. This is the real "don't cache" |
| `no-cache` | You *may* store it, but you must revalidate with the server before every use. Despite the name, it does not mean "don't cache" |
| `must-revalidate` | Once stale, it must not be used without successful revalidation. Shared caches sometimes serve stale content when the origin is unreachable; this forbids it |
| `immutable` | It will never change while fresh, so don't revalidate it even on a reload |

Directives combine, for example `Cache-Control: private, no-cache` or `Cache-Control: public, max-age=31536000, immutable`.

### What well-tuned sites actually do

Open the network tab on a large, performance-focused site and you will usually see the same pattern:

- **Static assets** (JS, CSS, fonts, images) have very long lifetimes, often `max-age=31536000` (one year), and file names with a random-looking hash such as `main.3f9a1c.js`.
- **The HTML entry page** (`index.html`) has `no-cache`, often together with `no-store`, so it is checked every time.

The hash in the file name is called a **fingerprint**, and it is the key to the whole strategy. When the build changes a file, its hash changes, so its URL changes. To the browser that is a brand-new resource, not a cached one that needs revalidating. That means you can cache assets "forever" and still ship updates instantly: the new `index.html` simply points at the new file names.

You can check all of this yourself in Chrome DevTools:

1. Open the **Network** tab, tick **Disable cache**, and reload. Every resource is now fetched from the server.
2. Sort by **Size** and click a large JS file, font, or image. Under **Response Headers**, look for `Cache-Control`, `ETag`, `Last-Modified`, and `Expires`.
3. Convert the `max-age` value: `31536000` seconds is one year, `2592000` is 30 days. Large, fingerprinted assets usually get the longest lifetimes.
4. Untick **Disable cache** and reload normally. The **Size** column now shows `(memory cache)` or `(disk cache)` for most resources: they never went over the network.

It is worth doing this on a few well-optimized sites and comparing their settings with your own.

`index.html` cannot be fingerprinted because its URL has to stay fixed. So it is the one file you must not cache for long. `no-cache` (store, but always revalidate) is usually enough; adding `no-store` is the stricter option.

Here is what that looks like in Express:

```js
const express = require("express");
const path = require("path");
const app = express();

// Fingerprinted assets: cache for a year, never revalidate
app.use(
  "/assets",
  express.static(path.join(__dirname, "dist/assets"), {
    maxAge: "1y",
    immutable: true,
  })
);

// Entry page: always revalidate so new deployments show up immediately
app.get("*", (req, res) => {
  res.set("Cache-Control", "no-cache");
  res.sendFile(path.join(__dirname, "dist/index.html"));
});

app.listen(3000);
```

And in Nginx:

```nginx
location /assets/ {
    add_header Cache-Control "public, max-age=31536000, immutable";
}

location = /index.html {
    add_header Cache-Control "no-cache";
}
```

## Choosing a layer for each kind of data

| Data | Characteristics | Good fit |
|---|---|---|
| Images, CSS, JS, fonts | Rarely change, fairly large | Browser cache (+ CDN) |
| Video, downloads, game patches | Very large | CDN |
| Notices, announcements | Shared by everyone, a few minutes stale is fine | Shared cache |
| Permissions, menus | Change rarely | Local cache, or local + shared |
| Country codes, common codes | Almost never change | Local cache |
| Sessions, carts | Per user, change often, any server may need them | Shared cache |

One service will use several of these at once. That is the point: different data in the same application belongs in different layers.

## Why the inner layers still matter: memory vs disk

It is tempting to think a fast NVMe SSD makes caching less important. To see why it doesn't, it helps to look at the hardware underneath.

### The memory hierarchy

A CPU is extremely fast, and disks are extremely slow. Computers bridge that gap with several layers of storage in between:

```text
CPU registers
  -> L1 / L2 / L3 cache
    -> Main memory (RAM)
      -> SSD
        -> HDD
```

The closer a layer is to the CPU, the faster it is, but the smaller and more expensive it gets. The farther away, the larger and cheaper, but slower. You can't build everything out of L1 cache because it is tiny and costly, and you can't run everything from a hard disk because it is far too slow. So systems keep frequently used data near the CPU and push large, rarely touched data out to disk. The memory hierarchy is simply a way of balancing **speed, capacity, and cost**, and it is the same idea as the cache layers above, just at the hardware level.

### Latency at each level

**Latency** is the time from sending a request until the response arrives. Think of it as the fixed cost of an access itself, regardless of how much data you read. Rough, commonly quoted figures for a single random access:

| Storage | Latency | Relative to RAM | If 1 ns were 1 second |
|---|---|---|---|
| L1 cache | ~1 ns | — | 1 second |
| Main memory (RAM) | ~100 ns | 1x | about 1 minute 40 seconds |
| NVMe SSD | ~20 µs | ~200x slower | about 5.5 hours |
| SATA SSD | ~100 µs | ~1,000x slower | about 28 hours |
| HDD | ~5 ms | ~50,000x slower | about 2 months |

These are representative numbers for comparing scale, and real hardware varies. Note that the units change at each step: nanoseconds, microseconds, milliseconds, each a factor of 1,000 apart. From the CPU's point of view, waiting on RAM is a short coffee break, waiting on an NVMe SSD is an afternoon, and waiting on a hard disk is a two-month vacation.

### Random vs sequential access

The figures above are for **random** access: jumping to a new, scattered location every time. Each jump pays the full latency, so latency dominates.

**Sequential** access reads one continuous block after a single seek, streaming the rest. Here **throughput** (bytes per second) matters more than latency, and modern NVMe drives have very high throughput.

So even on the same NVMe SSD, ten thousand small random reads and one large sequential read perform very differently. This is exactly why database index design matters: a good index turns scattered random reads into a few targeted ones.

### The takeaway

A common misconception in the field goes like this: "We moved to the latest SSDs, so we don't need a buffer cache or Redis anymore." NVMe really is fast, but it is still around 200 times slower than RAM. Hardware keeps improving, yet the gaps between layers remain, because they are measured in different units. Keeping frequently used data in the upper layers, in other words in memory, is still the biggest lever you have.

## Common mistakes

- **Downloading static files on every request.** If CSS, JS, and images have no caching headers, every page view refetches them. Set `Cache-Control` and fingerprint your build output.
- **Sending every lookup through Redis.** For data that never changes, a local cache is faster and costs nothing in network traffic.
- **Caching without a TTL.** Memory grows until something breaks. Always set an expiration and an eviction policy.
- **Forgetting to purge the CDN.** The deploy succeeds, and users still see the old file.
- **Caching personalized responses publicly.** Use `private` or `no-store` for anything user-specific, especially at a CDN.
- **Ignoring cache stampedes.** When a popular entry expires, many requests miss at the same moment and hit the database together. Common defenses: add random jitter to TTLs so entries don't expire together, let only one request rebuild the entry while others wait or get the old value (a lock or "single flight"), and refresh hot entries shortly before they expire.

## Zooming out: read performance vs write performance

Caching is a read optimization. To see where it fits, it helps to look at performance as a whole, split into reads and writes.

This is also a classic interview question: *"Explain how you would improve performance, separately for reads and writes."* The weak answer is a pile of keywords: "use a cache, add indexes, shard, use Redis, use Kafka." The strong answer has the same keywords, **organized by layer**. Grouping them makes the answer easier to give and easier to follow, and it shows that you have actually thought about the system.

A useful set of layers is the network/web edge, the application, and the database (plus, sometimes, the overall architecture).

### Read optimization by layer

| Layer | Technique | What it does |
|---|---|---|
| Network / web | Browser cache | The request never leaves the user's device |
| Network / web | CDN | Static files, media, and sometimes API responses are served from an edge near the user |
| Network / web | HTTP/2 (and HTTP/3) | Better transport efficiency: multiplexing, header compression |
| Application | Local cache | Hot, rarely changing data served from process memory |
| Application | Shared cache (Redis) | Data shared across instances without hitting the database |
| Database | Read replicas | Spread read traffic across copies of the data |
| Database | Indexes | Shorter search paths; often the single biggest win as data grows |
| Database | Partitioning | Split tables by range, date, or region so each read touches less data |
| Database | Precomputed results | Build statistics and summary tables on a schedule instead of on demand |

In practice, many performance problems turn out to be in data access, and index tuning alone often makes a dramatic difference.

### Write optimization by layer

| Layer | Technique | What it does |
|---|---|---|
| Application | Message queue | Accept the request, enqueue it, respond immediately, process it in the background |
| Application | Asynchronous processing | Move slow side work (emails, notifications) off the request path |
| Database | Sharding | Split data across nodes so writes are spread out |
| Database | Partitioning | Smaller tables also spread write load |
| Database | Eventual consistency | Give up immediate consistency to gain write throughput and scalability |
| Database | Batch writes | Group many writes into one round trip |
| Database | Fewer indexes | Every index has to be updated on every write; drop the ones nobody uses |

### Before tuning anything

Three things to check first:

1. **Find the bottleneck.** Performance problems tend to follow an 80/20 pattern: a small part of the system causes most of the slowness. Measure with slow query logs and APM before changing anything. Fixing the one real bottleneck often beats polishing everything else.
2. **Accept that there are trade-offs.** Making one side faster usually costs something on the other side, or costs money. Indexes are the textbook example: reads get faster because the search path is shorter, but every write now has to update and re-sort the index.
3. **Know your read/write ratio.** Most services read far more than they write, which is why read optimizations tend to pay off the most. Figure out which side dominates in your service and plan accordingly.

A compact interview answer might sound like this:

> "I'd split it into web, application, and database. For reads: browser caching and a CDN at the edge, a caching strategy in the application, and good indexing plus read replicas in the database. For writes: a queue and asynchronous processing in the application, and partitioning or sharding in the database. Before any of that, I'd measure to find the real bottleneck, and weigh the trade-offs against our read/write ratio."

Expect follow-ups such as: how do you handle replication lag? What is CQRS? What is the difference between write-through and write-back caching?

## Cache or message queue?

Here is a related scenario: *"Traffic spiked and the server slowed down. Would you add a cache or a message queue?"*

The tempting answer is a product name: "Redis, because it's fast," or "Kafka." But Redis is one implementation of a cache, and Kafka is one implementation of a queue; there are plenty of others. Talk about the concept first, then the tool. More importantly, **the right answer depends on whether the problem is on the read side or the write side**, and you can only know that by finding the bottleneck.

### The two ideas

- **Cache: "don't do the same work twice."** Store frequently requested data or expensive results and reuse them. Think of a buffet: the food is already prepared, so you just take it instead of waiting for it to be cooked. It improves **read** performance.
- **Message queue: "do it later."** Instead of processing a request on the spot, put it in a queue, answer the user right away, and let workers handle it in the background. Think of a waiting list at a busy restaurant: the host keeps taking new guests instead of blocking on one table. It improves **write** throughput and also **decouples** systems from each other.

### Where they sit

```text
Cache:  User -> API -> Cache -> Database

Queue:  User -> API -> Queue -> Workers -> Database / email / external APIs
```

### How each one is used

The most common cache pattern is **cache-aside**: check the cache, and on a miss load from the database and store the result.

```js
async function getProduct(id) {
  const key = `product:${id}`;

  const cached = await redis.get(key);
  if (cached) return JSON.parse(cached); // cache hit

  const product = await db.findProduct(id); // cache miss
  await redis.set(key, JSON.stringify(product), { EX: 300 }); // keep for 5 minutes
  return product;
}
```

A queue looks like this: the API only enqueues, and a separate worker does the slow part.

```js
// API: respond immediately
app.post("/orders", async (req, res) => {
  const orderId = await createPendingOrder(req.body);
  await queue.publish("order.created", { orderId });
  res.status(202).json({ orderId, status: "processing" });
});

// Worker: handle the heavy work in the background
queue.subscribe("order.created", async ({ orderId }) => {
  await chargePayment(orderId);
  await sendConfirmationEmail(orderId);
});
```

### When to choose which

| | Cache | Message queue |
|---|---|---|
| Solves | Too many reads (heavy `SELECT` load) | Slow writes or heavy processing (payments, inserts, updates) |
| Core idea | Reuse | Defer and buffer (asynchronous) |
| Position | In front of the database | Between the API and the workers |
| Typical tools | Redis, Memcached | Kafka, RabbitMQ, SQS |
| Extra benefit | Less database load | Looser coupling between services |
| New problems | Consistency between cache and DB; expiration and update policy | More moving parts; results reach the user later; you must design how completion is reported |

Neither one fixes things just by being installed. A cache brings consistency questions. A queue brings asynchronous complexity: you need a way to tell the user when the work is done (polling, a webhook, a push notification) and a plan for backlogs.

A good answer to the interview scenario:

> "First I'd use monitoring to find where the bottleneck is. If it's read load on the database, I'd add a cache such as Redis to absorb it. If requests are piling up because of a write spike or slow processing, I'd put a queue such as Kafka in between, switch that work to asynchronous processing, and let the workers drain it at a steady rate."

## Wrap-up

Principles to take away:

1. **Caching is not just Redis.** Browser, CDN, local cache, and shared cache form a tiered system, and each tier has its own job.
2. **End the request as close to the user as possible.** Every layer you can stop at makes the service faster and cheaper to run.
3. **Pick the layer that fits the data.** Look at how often it changes, who shares it, how big it is, and how fresh it has to be.
4. **Think in layers, for reads and writes separately.** Caches speed up reads; queues, sharding, and batching help writes.
5. **Measure first.** Find the bottleneck, then decide whether it calls for a cache, a queue, or something else entirely.

Knowing how to use Redis or Kafka is a good skill. Knowing which problem each one solves, and where it belongs, is what actually makes a service fast.
