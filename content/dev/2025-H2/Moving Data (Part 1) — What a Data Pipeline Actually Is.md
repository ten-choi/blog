---
title: "Moving Data (Part 1) — What a Data Pipeline Actually Is"
labels: ["Data Platform Series","Data Pipeline","Data Engineering","ETL","Data Integration","Big Data","Archive"]
published: true
date: 2025-11-07T13:45:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7229787233617606638"
source: "archive"
archivePath: "_archive/data/07-pipeline-1-overview.md"
---

**Data Platform Series · 07/15** · Moving Data 1/5

> Data is born in one place and analyzed in another. The system that carries it across that gap — cleaning and reshaping it along the way — is the data pipeline. This series is about that journey. In Part 1, we start by drawing the big picture.

## 1. Why Pipelines Exist: The Gap

In the platform overview, we followed a piece of data from where it's *created* (apps, APIs, events) to where it's *analyzed* (warehouses, dashboards, models). Those two places are almost always different systems, and data almost never arrives in a ready-to-use shape. So something has to:

- pull the data out of the source,
- clean it, reshape it, and combine it with other data,
- deliver it to the destination,
- and do all of that on a schedule or continuously, reliably, without a human touching it.

That "something" is the **data pipeline**.

> A **data pipeline** is an automated series of steps that moves data from one or more sources to a destination, transforming it along the way.

The key word is *automated*. Anyone can export a CSV and clean it up by hand once. A pipeline does that same work **repeatedly and reliably** — every hour, every night, or every second — without a human in the loop, and it tells you when something goes wrong. In practice, the moment a "script I ran by hand once" gets promoted to "something that absolutely has to have run by 8 a.m. every day" is the moment you move it into a pipeline.

---

## 2. Anatomy of a Pipeline

However fancy a pipeline is, almost every one is made of the same three kinds of steps.

```
 SOURCE ──►  [ extract ] ──► [ transform ] ──► [ load ]  ──► DESTINATION
              pull data       clean & reshape   deliver       (warehouse,
              out             it                it            lake, etc.)
```

- **Extract** — read data out of the source (a database, API, files, an event stream).
- **Transform** — turn raw data into useful data: clean bad values, convert formats, join with other sources, aggregate, and apply business rules.
- **Load** — write the result to the destination where it will actually be used. That's usually a warehouse like Snowflake or BigQuery, or a data lake.

As you've probably noticed, the initials of those three words spell **ETL** (Extract, Transform, Load). ETL is the classic name for this overall shape. Whether the transform happens before or after the load — ETL or **ELT** — is an important enough variation that it gets its own post in this series (Part 3). For now, just keep this three-step skeleton in your head.

---

## 3. Two Rhythms: Batch and Streaming

A pipeline fundamentally runs in one of two rhythms, and that choice shapes everything else about it.

- **Batch** — runs on a schedule and processes data in *chunks* at a time (e.g., "every night, process today's orders"). It's simpler and cheaper, and it's the right default for most reporting.
- **Streaming** — runs continuously and processes each event *as soon as it arrives* (e.g., "update the real-time dashboard the moment an order happens"). The data is fresher, but complexity and cost are higher.

Most of the world runs on batch, with streaming reserved for cases where freshness really matters. A common pitfall in practice is choosing streaming out of a vague wish that "real-time would be nice" — while the dashboard only gets looked at once a day. This distinction is important enough to get all of Part 5. For now, just know that the question "how often does this pipeline run?" has two broad answers, and they lead to very different designs.

---

## 4. Beyond Just Working: What Makes a *Good* Pipeline

A pipeline that moves data once is easy. A pipeline you can *trust* in production has to cope with the messy reality of data, and these qualities separate the toys from the real thing:

- **Reliability** — it runs on schedule and recovers from failure. If last night's run died, tonight's run must not silently skip a day of data.
- **Idempotency** — running it twice produces the same result, not duplicate rows. Reruns happen constantly, so a pipeline has to be safe to repeat. In practice there are two main ways to guarantee this. One is **partition overwrite** — rewriting that day's partition wholesale. The other is a key-based **MERGE/upsert**.

  ```sql
  -- Update when the key matches, insert when it doesn't (no duplicates on rerun)
  MERGE INTO orders t USING staging s ON t.order_id = s.order_id
  WHEN MATCHED THEN UPDATE SET ...
  WHEN NOT MATCHED THEN INSERT ...
  ```

  If you load with a plain `INSERT INTO ... SELECT`, a single rerun stacks up another full copy of yesterday's rows.
- **Monitoring and alerting** — when something goes wrong, the owner finds out *before* stakeholders notice the dashboard is wrong. In practice, the things you actually alert on are fairly standard: **run failures** (a job dies or times out), **freshness SLA breaches** (e.g., "yesterday's data hasn't arrived by 9 a.m."), and **sudden row-count changes** (normally 1 million rows, but 0 today — or 10x).
- **Data quality validation** — bad data is caught in transit, not after it has polluted a report. (This is the data quality discipline, covered in detail later in the data governance series, applied inside the pipeline.)
- **Scalability** — it keeps working when data volume grows 10x.

> One useful intuition: pipelines fail at the edges, not on the happy path. A source that's briefly down, a malformed record, a run that overlaps with the previous one. Most of good pipeline design is about handling exactly those cases gracefully.

**Checklist for a trustworthy pipeline**

- [ ] Is it safe to rerun? (partition overwrite or key-based MERGE/upsert)
- [ ] If last night's run died, does it catch up automatically — or at least not leave a gap?
- [ ] Are alerts set up for failures, freshness SLA breaches, and sudden row-count changes?
- [ ] Does it validate basic input quality (required columns, row-count range) *before* loading?
- [ ] Will it work the same way when the data grows 10x?

---

## 5. Orchestration: Pipelines Need a Conductor Too

A single pipeline is simple. But a real platform has *dozens* of pipelines with dependencies between them: "Load orders, but *only after customers are loaded*; then build the revenue report, but only after both are done."

Managing these dependencies, schedules, retries, and failures is the job of an **orchestrator** — a tool that knows what has to run in what order and keeps the whole web of pipelines on track. The best-known tool is **Apache Airflow**. In Airflow, you declare the dependencies between tasks as a **DAG** (directed acyclic graph).

```python
# Declare the "customers → orders → revenue" order and the orchestrator handles the rest
load_customers >> load_orders >> build_revenue
```

Once you declare what depends on what, the system sequences the work, retries on failure, and tracks partial runs. (Besides Airflow there are alternatives like **Dagster** and **Prefect**, all built on the same idea.) You don't need a specific product to understand the concept. Something has to play conductor; otherwise your pipelines become a tangle of cron jobs that nobody can keep track of in their head. In practice, the culprit behind "why is this report empty?" is surprisingly often two cron jobs whose run times drifted out of sync. An orchestrator replaces that time-based dependency with one based on *completion*.

---

## 6. Where This Series Is Headed

Now you have the skeleton. A pipeline **extracts, transforms, and loads** data from a source to a destination, runs in a **batch or streaming** rhythm, and earns trust through **reliability, idempotency, monitoring, and quality validation**. And an **orchestrator** coordinates all of it.

The rest of the series zooms in on each part of that journey.

- **Part 2 — Data ingestion.** A deep dive into the "extract" step: how you actually *get* data out of sources, and the patterns for doing it well (including change data capture).
- **Part 3 — ETL vs. ELT.** The big debate of the transform step: transform *before* loading or *after*, and why the answer flipped over the past decade or so.
- **Part 4 — Data integration.** Combining many messy sources into one consistent view — the hardest part of the "transform" step.
- **Part 5 — Batch vs. streaming.** A deep look at the two rhythms and how to choose between them.

> Data modeling — designing the *shape* the data lands in (normalization/denormalization, dimensional modeling, star schema) — is covered in Parts 1 and 2 of the data warehouse posts in the storage and architecture track.

By the end of this series, you'll see a pipeline not as a black box but as a series of deliberate choices — and you'll know how to make each one.
