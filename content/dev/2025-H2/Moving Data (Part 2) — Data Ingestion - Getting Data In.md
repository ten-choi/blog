---
title: "Moving Data (Part 2) — Data Ingestion: Getting Data In"
labels: ["Data Platform Series","Data Ingestion","Data Pipeline","Change Data Capture","Data Engineering","Streaming","Archive"]
published: true
date: 2025-11-13T16:13:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7561127865041087041"
source: "archive"
archivePath: "_archive/data/08-pipeline-2-ingestion.md"
---

**Data Platform Series · 08/15** · Moving Data 2/5

> In Part 1 we looked at the big picture of a pipeline: extract, transform, load. This part zooms in on the first step, **data ingestion** — *getting* data out of its sources and into the platform. It looks simple. It isn't.

## 1. Ingestion Is the Front Door

Every pipeline starts with the same problem: the data you want lives in someone else's system. Your app's production database, a third-party API, a stream of user events, a pile of files on a server. Data ingestion is the process of gathering that data and bringing it into your data platform.

> **Data ingestion = extracting data from its sources and taking it into a storage or processing system.**

It's the front door of the whole platform. And like any front door, if it's shaky, everything behind it suffers. No amount of clever downstream processing can fix data that never arrived, or arrived wrong.

Here's the catch. Ingestion *feels simple* — "just read the data" — but sources are uncooperative in dozens of ways. They go down, they impose rate limits, they change formats without warning. They can be enormous, or live systems you mustn't slow down. Good ingestion is mostly about dealing with those realities.

---

## 2. The Two Rhythms Again: Batch and Streaming Ingestion

The batch vs. streaming distinction from Part 1 shows up first at the ingestion step.

- **Batch ingestion** — pulls data in chunks on a schedule, as in "every night at 2 a.m., fetch all of today's orders." It's simple and efficient, and it's enough when data doesn't need to be fresh to the minute.
- **Streaming ingestion** — continuously captures each event as soon as it's produced, as in "ingest the order the moment it happens." It's needed when freshness matters (real-time dashboards, fraud detection, real-time personalization). It usually runs on top of a message stream such as Kafka.

Most ingestion is batch, because most analytics can tolerate a few hours of delay and batch is far simpler to operate. Choose streaming when the *business value* of fresher data clearly justifies the added complexity. We'll come back to this in Part 5.

---

## 3. The Key Question: Full Load or Incremental?

Now for the decision that defines the character of an ingestion job — and the one beginners most often get wrong. When you ingest from a source repeatedly, do you fetch *everything* each time, or only *what's new*?

### Full Load

Fetch the entire dataset on every run.

- **Pros:** As simple as it gets. The destination is always a complete, accurate copy.
- **Cons:** Wasteful and slow as data grows. Re-copying a 500-million-row table every night to catch a few thousand changes is absurd.

Full loads suit small tables, or the initial "seed" phase when you're populating data for the first time.

### Incremental Load

Fetch only the data that changed since last time.

- **Pros:** Efficient — you move a small amount of data instead of everything. Essential at scale.
- **Cons:** Harder. You need a reliable way to know *what* changed. The usual approach filters on a column like `updated_at` ("give me rows changed since the last run"), which assumes the source keeps that column honest.

A common approach in practice is to store the last run time as a **watermark** and, on the next run, pull only the rows after it.

```sql
-- Inject the previous run time (watermark) as a parameter
SELECT * FROM orders
WHERE updated_at > '{{ last_run_ts }}'
```

```
Full load:        [■■■■■■■■■■]  copy everything, every time
Incremental:      [········▣▣]  copy only what's new since last run
```

It looks clean, but there are real-world pitfalls hiding here.

- **Late-arriving or later-modified rows** — if a transaction commits late or an old record is modified, it can slip just past the watermark boundary and get missed.
- **Clock skew** — if the clocks on the source DB and the ingestion job drift slightly apart, you can miss whole sets of rows near the boundary.
- That's why, in practice, you re-pull with **a small overlap window**, like `updated_at > '{{ last_run_ts }}' - INTERVAL '5 minutes'`. The trade-off is that the same row can arrive twice, so idempotent loading is a prerequisite (see the checklist in section 7).
- **Deletes aren't captured** — a deleted row leaves no "updated" timestamp behind, so timestamp-based incremental loads never see deletes. That's exactly why the next section's CDC is needed.

The rule of thumb: **start with full loads for small or static data, and move to incremental loads the moment volume grows enough that full loads become a burden.** A more concrete decision rule:

> **Decision rule:** Small enough to copy in one go without strain → full load. Data is large enough that copying it all each time is wasteful, and you have a trustworthy `updated_at` → incremental load. You need deletes reflected accurately, or near-real-time freshness → CDC (next section).

Incremental loading is one of the core skills that defines real-world data engineering.

---

## 4. Change Data Capture (CDC): Incremental Done Right

Incremental loading via an `updated_at` column has gaps. It can miss deletes (a deleted row has no "updated" timestamp), and it depends on the source maintaining that column perfectly. The more robust technique is **Change Data Capture (CDC)**.

CDC works by reading the database's own **transaction log** — the internal ledger where every database records every insert, update, and delete. Instead of *asking* the database "what changed?", CDC *watches* the log and captures every change in the order it happened.

```
  source DB writes  ──►  transaction log  ──►  CDC reads the log  ──►  your platform
  (insert/update/delete)  (DB's own record)     (captures every change)
```

Here's why it's powerful:

- **It catches everything** — including the deletes that timestamp-based approaches miss.
- **It's near-real-time** — changes flow in as they're committed, enabling streaming ingestion.
- **It has little impact on the source** — reading the log doesn't hammer the live database with queries.

The tool you'll run into most often in practice is **Debezium**. It reads a database's transaction log and streams change events into Kafka, usually run as connectors on top of **Kafka Connect**. Building and operating that stack yourself is no small burden, though, so many teams *buy* managed connectors like **Fivetran** or **Airbyte** to get started quickly. Either way, the core idea is the same: read the log and stream the changes as they are.

There are two practical points worth knowing. First, CDC usually **starts in two phases.** Since the transaction log only holds recent changes, you first take an **initial snapshot** — a one-time copy of all existing data — and then stream the log from that point onward. Second, **schema changes in the source flow straight through into the change events.** When a column is added to a source table, the shape of the events changes from that point on, so you need to design downstream consumers not to break silently when they hit a new column. ("Prepare for schema changes" in the section 7 checklist isn't optional with CDC — it's mandatory.)

CDC is how modern platforms keep an analytical copy of an operational database continuously in sync. It's more complex to set up than a single nightly query, but it's the canonical answer for keeping a data warehouse or lake mirrored to a live database. The term comes up constantly, so make sure you know it.

---

## 5. The Variety of Sources

"Ingestion" covers a wide range of source types, each with its own quirks.

| Source type | How you ingest | What to watch for |
|-------------|----------------|---------------|
| **Databases** | Queries, or CDC from the log | Don't overload the live DB |
| **APIs** | HTTP requests, pagination | Rate limits, auth, pagination |
| **Files** | Read from object storage / FTP | Format changes, partial uploads |
| **Event streams** | Subscribe to the stream | Ordering, duplicates, backpressure |

There's a recurring theme: we rarely *control* the source. A source is someone else's system, with its own rules, reliability, and surprises. Robust ingestion assumes the source will misbehave — that it will go down temporarily, return malformed records, and change its schema — and handles those cases instead of trusting only the happy path.

---

## 6. Land the Raw Data First, Transform Later

Here's a best practice worth internalizing: when ingesting, **land the raw data exactly as it arrived before you transform it.** This ties directly to the "raw zone" from the data lake series.

Why?

- If your transform has a bug, the raw data is still there and you can reprocess it. Nothing is lost.
- Ingestion and transformation become independent steps that can fail and be retried separately.
- You get a faithful historical record of what the source actually sent.

This "land raw first, transform later" instinct lines up exactly with why **ELT** displaced ETL on modern platforms — and that's the topic of Part 3.

---

## 7. Ingestion Checklist

A short checklist to keep in mind when building a new ingestion job.

- [ ] **Load raw first** — did you land the data as it arrived, in raw form, before transforming it?
- [ ] **Idempotent loading** — does ingesting the same data twice avoid duplicates or corruption? (Essential once you account for overlap windows and retries.)
- [ ] **Prepare for schema changes** — does the pipeline avoid breaking silently when the source adds, drops, or changes columns?
- [ ] **Don't overload the source** — are you avoiding load on live DBs and APIs? (Respect rate limits; use read replicas or log-based CDC.)

---

## 8. Key Takeaways

Ingestion is the front door of the data platform: reliably getting data out of uncooperative sources and into your systems. Its defining decisions are **batch vs. streaming** (how fresh?) and **full vs. incremental** (how much each time?), and **Change Data Capture** is the robust way to keep a live database and its analytical copy continuously in sync. And the golden rule is to **land the raw data first**, then transform.

Next up is **Part 3: ETL vs. ELT**. Now that the data is in, *when* should you transform it — before loading or after? The answer flipped over the past decade, and understanding why explains a lot about how modern data platforms are built.
