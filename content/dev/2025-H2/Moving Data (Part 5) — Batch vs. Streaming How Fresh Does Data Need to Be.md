---
title: "Moving Data (Part 5) — Batch vs. Streaming: How Fresh Does Data Need to Be?"
labels: ["Data Platform Series","Streaming Data","Batch Processing","Real-Time","Data Pipeline","Data Engineering","Kafka","Archive"]
published: true
date: 2025-12-02T19:02:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "5697565782198271270"
source: "archive"
archivePath: "_archive/data/11-pipeline-5-streaming.md"
---

**Data Platform Series · 11/15** · Moving Data 5/5

> This is the last part of the series, and it's an axis that cuts across everything before it. Every pipeline runs on one of two rhythms: it either processes data in defined chunks, or it processes each event the moment it arrives. That's the choice between batch and streaming, and getting it right (or wrong) determines your cost, your complexity, and how fresh your data is.

## 1. Two Rhythms

We've mentioned this distinction since Part 1; now let's deal with it properly. The question is simple: **does your pipeline process data in periodic chunks, or continuously as it arrives?**

- **Batch processing** — collect data over a period of time, then process the whole group at once on a fixed schedule. "Process the day's orders every night at 2 a.m." is an example.
- **Stream processing** — process each event individually, the moment it's produced. "Process each order as soon as it happens" is an example.

```
BATCH:    [····collect····] ──► process chunk ──► (wait) ──► [····collect····] ──► process
          runs on a schedule; data is hours/a day old

STREAM:   event─►process  event─►process  event─►process  event─►process
          runs continuously; data is seconds old
```

Neither one is "better." They're optimized for different needs, and most real platforms use **both**: batch for the bulk of analytics, streaming for the handful of things that genuinely need to be fresh.

---

## 2. Batch: The Reliable Workhorse

Batch is how most data processing has always worked, and it's still the right default for the majority of analytics work. Think nightly reports, daily warehouse loads, monthly billing.

**Why batch is a sensible default:**

- **It's simpler** — run a job, process a defined set of data, done. Easy to understand, easy to test, easy to rerun.
- **It's cheaper** — compute is used in concentrated bursts instead of running 24/7.
- **It's more efficient** — processing a million rows at once is far more efficient per row than processing them one at a time.
- **It's easy to recover** — a batch failed? Run it again. The boundaries are clean.

**The trade-off is *latency*.** Your data is only as fresh as the last run. If the pipeline runs once a night, your dashboard can be up to a day behind. But for most reporting — "how did we do last month?" — that's perfectly fine. Nobody needs last month's revenue to the second.

> The intuition worth internalizing: **if the business can tolerate the delay, batch is almost always the right choice.** It's simpler and cheaper, and simplicity is a feature in its own right.

---

## 3. Streaming: When Freshness Is the Point

Some use cases lose their value once the data goes stale. In those cases, streaming is worth the extra complexity.

- **Fraud detection** — catching a fraudulent transaction *tomorrow* is useless. You need to catch it *now*.
- **Real-time dashboards and monitoring** — operations teams watching system or business metrics live.
- **Real-time personalization** — recommending something based on what a user did a few seconds ago.
- **Alerting** — reacting the instant something happens, like a sensor crossing a threshold or a spike in errors.

With streaming, data is processed within **seconds or milliseconds** of being produced. The technology that makes this possible is usually a **message/event streaming platform**, with Apache Kafka as the best-known example. These platforms act as a pipe for continuous, ordered event streams that processors subscribe to.

In practice the stack usually splits into two pieces. Events flow through a platform like Apache Kafka (which handles storage and delivery), and the actual processing is done by a **stream processor** on top of it — Apache Flink, Spark Structured Streaming, and Kafka Streams are the usual choices. If Kafka is "the conveyor belt that carries the data," the stream processor is "the workbench" where aggregations, joins, and filters happen.

```
producers ──► [ event stream (e.g., Kafka) ] ──► stream processors ──► destinations
(apps emit     a continuous, ordered log          (Flink / Spark /        (live dashboards,
 events)       of events                            Kafka Streams)          alerts, stores)
```

This is where **Change Data Capture** (Part 2) shines. CDC turns database changes into exactly this kind of event stream, letting analytical systems react to changes in operational data in near real time.

---

## 4. Windows and Watermarks: Handling Infinite Streams

Because a stream never ends, computing something like "hourly totals" requires a **window** that slices the endless flow into chunks of time. There are two main kinds:

- **Tumbling window** — fixed, non-overlapping intervals. Like "one hour starting on the hour," each event belongs to exactly one window.
- **Sliding window** — overlapping intervals. Like "the last hour, recomputed every 5 minutes," a single event gets counted across several windows.

Counting "orders per hour" with a tumbling window looks roughly like this in a SQL-based stream processor (e.g., Flink SQL):

```sql
SELECT TUMBLE_START(order_time, INTERVAL '1' HOUR) AS hour,
       COUNT(*) AS orders
FROM order_events
GROUP BY TUMBLE(order_time, INTERVAL '1' HOUR);
```

That leaves one key question: **"When do you close a window and emit the result?"** Events don't always arrive on time or in order. The mechanism for handling this is the **watermark**. A watermark is the system's judgment line — "we consider events up to this point to have (mostly) arrived" — and once the watermark passes the end of a window, that window is closed and its aggregate is finalized. For late events, you need a policy that decides whether to drop them or correct for them separately.

You also need to decide on a delivery guarantee. **At-least-once** can process the same event twice after a failure, which can inflate your aggregates; **exactly-once** prevents duplicates but comes with the cost of state storage and checkpoints. The practical deciding factor is: "Do the counts have to be exact, or can we tolerate a little error?"

---

## 5. Why Streaming Is Harder

Streaming's freshness comes with a clear price: complexity. It's worth being honest about why — this is exactly why streaming shouldn't be your default.

- **It has to be always on** — a streaming system runs 24/7 and has to stay healthy the whole time. A batch job that fails at 2 a.m. can just be rerun at 8 a.m., but a stream processor that falls behind is an incident in progress right now. In other words, it translates directly into someone's **on-call** burden.
- **Reprocessing (backfill) is much trickier** — after fixing a logic bug, "recompute the last month" is just one more job run in batch. In streaming, you have to replay past events while keeping watermarks, windows, and state all consistent. Even keeping production traffic and backfill traffic from mixing takes its own design work.
- **Out-of-order and late-arriving data** — events don't always arrive in the order they happened. Handling "this event is from 10 minutes ago but just showed up" is a hard problem area in its own right (partly mitigated by the watermarks we just covered).
- **There are no clean boundaries** — batch has tidy boundaries like "today's data," but a stream is infinite. Even where "today" ends has to be defined explicitly with windows and watermarks.
- **It's harder to reason about and recover** — reprocessing "the last hour of a stream" is much messier than rerunning a batch job.

> The honest rule: **streaming is not "better batch." It's a different tool with a higher operational cost.** Adopt it not because real-time sounds cool, but when the *business value of freshness* clearly justifies that cost.

---

## 6. Batch and Streaming, Side by Side

| | Batch | Streaming |
|---|-------|-----------|
| **Unit of processing** | Scheduled chunks | Each event as it arrives |
| **Data freshness** | Minutes to a day old | Within seconds |
| **Complexity** | Low | High |
| **Cost pattern** | Concentrated bursts | Always on + on-call |
| **Reprocessing/recovery** | Rerun the batch | Messier (backfill, windows, ordering) |
| **Typical stack** | Scheduler + SQL/warehouse | Kafka + Flink / Spark Structured Streaming / Kafka Streams |
| **Good for** | Reporting, most analytics | Fraud, alerting, live dashboards, personalization |
| **As a default?** | Yes, in most cases | Only when freshness truly matters |

---

## 7. The Modern Reality: Both Together

In practice, you don't pick one for the whole platform. You choose per use case, and most mature platforms run a mix. The bulk of analytics goes through reliable, cheap batch pipelines, and only the few genuinely time-sensitive cases use streaming. On top of that, the *same* tools and storage (especially the lakehouse) can increasingly handle both, blurring the old line between "batch systems" and "streaming systems."

Still, the decision framework stays simple. For any pipeline, ask: **"What does it cost us if this data is an hour stale?"** If the answer is "not much," use batch. If the answer is "we lose money / miss fraud / make bad real-time decisions," that's exactly where streaming earns its keep. The pragmatic conclusion: **go batch for most things, and layer streaming on top only for the few cases where freshness actually pays.**

**Decision checklist:**

- [ ] If this data is an hour (or a day) late, what exactly do we lose, and how much?
- [ ] Does that cost justify the 24/7 operations and on-call burden?
- [ ] Is a backfill (reprocessing past data) scenario realistically feasible with this design?
- [ ] Do the aggregates have to be exact (exactly-once), or can we tolerate a little error (at-least-once)?
- [ ] Have we decided how to handle late or out-of-order events (watermarks and a late-event policy)?

---

## 8. Key Takeaways — and Wrapping Up the Series

Batch processes data in scheduled chunks (simpler, cheaper, and the right default for most analytics). Streaming processes each event as it arrives (fresher, but always on and harder). Carry events with Kafka and handle windows and watermarks with processors like Flink, Spark Structured Streaming, or Kafka Streams — but choose per use case by asking how much data freshness is actually worth, and expect to run both.

That wraps up the **Moving Data series**. Let's step back and look at the whole journey we've followed.

```
Part 1  Pipeline overview  — extract, transform, load; the skeleton
Part 2  Ingestion          — getting data in (batch/stream, full/incremental, CDC)
Part 3  ETL vs. ELT        — transform before or after loading
Part 4  Integration        — making many sources agree on one truth
Part 5  Batch vs. streaming— how fresh, at what cost
```

Put together, it's the complete story of *how data moves* from where it's born to where it's stored. It feeds the warehouses, lakes, and lakehouses of the storage track, is overseen by the governance layer, and ultimately serves the dashboards and decisions of business intelligence.
