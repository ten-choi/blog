---
title: "Understanding the Data Lake (Part 2) — Zones, Storage, and File Formats"
labels: ["Data Platform Series","Data Lake","Data Engineering","Parquet","Object Storage","Big Data","File Formats","Archive"]
published: true
date: 2025-10-25T17:02:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7567955714131471450"
source: "archive"
archivePath: "_archive/data/05-lake-2-zones-storage-formats.md"
---

**Data Platform Series · 05/15** · Storage and Architecture — The Data Lake 2/3

> Part 1 explained why the data lake exists. In this post, we lift the lid: how a lake is actually organized inside, what it's built on, and how your choice of file format can make queries ten times faster — or slower.

## 1. A lake needs zones, or it becomes a swamp

Part 1 closed with a warning about the "data swamp" — a lake where nobody can find or trust anything. The first line of defense against it is structure, and the standard structure is to divide the lake into several **zones** (also called layers, and sometimes named after metals or temperatures). Data flows from one zone to the next, getting cleaner and more refined at each step.

The commonly used three-zone model looks like this:

| Zone | Other names | What it holds | Who uses it |
|------|-------------|--------------|-------------|
| **Raw** | landing, bronze | Data exactly as it arrived, untouched | Pipelines, the occasional deep investigation |
| **Cleansed** | staging, silver | Validated, deduplicated, standardized data | Engineers, data scientists |
| **Curated** | serving, gold | Business-ready, aggregated and modeled data | Analysts, dashboards, ML features |

The flow looks like this:

```
sources ──► [ RAW ] ──► [ CLEANSED ] ──► [ CURATED ] ──► dashboards / ML
            untouched    cleaned          business-ready
```

Two principles make this work.

**Never throw away the raw zone.** Storage is cheap (that's the whole case for the lake), and keeping the original data means you can always reprocess it when you find a bug or think of a new use. The raw zone is your safety net and your single source of truth.

**Each zone is derived from the one before it.** Curated data is built from cleansed, and cleansed from raw. If something looks wrong downstream, you can walk back up through the zones to find where it went off. It's lineage in physical form.

In practice, you nail these two principles down with bucket boundaries: put write-only, read-restricted permissions on the raw zone (so nobody can touch it directly), and make all cleansing logic jobs that *regenerate* cleansed/curated. One common trap: the moment someone starts editing raw data directly because "it's urgent," the single source of truth collapses and the lake starts heading back toward the swamp.

---

## 2. What a lake is actually built on: object storage

In Part 1, I described the lake as "a huge, cheap folder." Let's make that more precise. Modern data lakes are built on **object storage** — systems like Amazon S3, Google Cloud Storage, and Azure Data Lake Storage. (The concepts are the same across providers; this isn't tied to any one of them.)

Object storage differs from the file systems you're used to in the following ways, and those differences matter for a lake.

- **It's flat, not hierarchical.** There are no real folders. You store *objects* (files) under keys like `raw/orders/2026/06/09/data.parquet`. A "folder" is just a naming convention in the key — but it matters, because tools rely heavily on that convention.
- **It's cheap and effectively unlimited.** You pay per gigabyte stored and per request, at a tiny fraction of the cost of database storage. Scaling to petabytes isn't an architecture project; it's just a line on the bill.
- **Storage and compute are separated.** The data just sits there, and any number of separate compute engines can read it. This decoupling is the key economic advantage over a warehouse, where storage and compute are bolted together.

That last point is worth chewing on. Because storage and compute are separate, you can point a SQL engine, a Spark job, and an ML training run at *the same files* at the same time without copying them, and you only pay for compute while something is actually running.

That said, the "flat" part often becomes a trap in practice. Because you're billed per request, once a flat key space piles up with countless tiny objects, even the cost of simply listing "what's there" stops being negligible. The partitioning and file-size discussion in the next section ties directly into this cost.

---

## 3. Partitioning: the cheapest performance win

Since a lake is ultimately just files sitting under keys, *how you lay out the files* directly affects query speed. The core technique is **partitioning**: organizing files into subfolders by a column you frequently filter on (most commonly, a date).

```
raw/orders/year=2026/month=06/day=09/data.parquet
raw/orders/year=2026/month=06/day=10/data.parquet
```

Now a query looking for "orders on 2026-06-09" can skip every other folder entirely. Instead of scanning years of data, it reads only one day's files. This is called **partition pruning**, and it's often the single biggest performance lever in a lake.

One caution: don't over-partition. Splitting by a high-cardinality column (e.g., `user_id`) creates millions of tiny files, and tiny files are slow to list and read. Partition by something you actually filter on that has moderate cardinality. A date is the classic safe choice.

### The small files problem

The trap people hit most often in practice is the **small files problem**. Lake engines pay a fixed cost per file — reading its metadata, opening it, closing it, scheduling it. So the same 1 GB scattered across tens of thousands of 1–10 KB files is far slower and more expensive than the same data bundled into a few reasonably sized files — even though not a single extra row of data is read. On top of that, object storage listing and request costs explode.

The rule of thumb is simple: **aim for a target file size of roughly a few hundred MB** (it lines up well with engines' block sizes). And remember that partitioning by a high-cardinality column like the `user_id` example above produces millions of tiny files with a handful of records per partition. That's the most common cause of the small files problem.

If small files have already piled up, the practical remedy is **compaction** (merging small files): periodically running a job that rewrites many small files in a partition into a single properly sized file. In pipelines where small files keep flowing in, such as streaming, compaction is often put on the schedule as a recurring job.

---

## 4. File formats: where queries win or lose

This is the part engineers get wrong most often, because the default — just dumping everything as CSV or JSON — quietly costs you a lot. The file format decides how much data gets read off disk and how fast it can be processed. The key fork here is **row-based vs. columnar**.

### Row-based: CSV, JSON, Avro

These store data one record at a time, with all the fields of a row together. They're great for writing records or moving entire rows around. The problem for analytics is that to compute `SUM(amount)`, the engine has to read *every column of every row* just to get at the one column it needs.

- **CSV / JSON** — Human-readable and universal, but bulky and slow to query. Fine for small data and interchange, but a poor choice for large analytical tables.
- **Avro** — A compact binary row format with strong support for schema evolution. Common in streaming and messaging pipelines that constantly write whole records.

### Columnar: Parquet, ORC

These store data one *column* at a time — all the `amount` values together, all the `country` values together. For analytics, this changes the game.

- **You read only the columns you need.** `SUM(amount)` reads only the `amount` column and ignores the rest. On wide tables, this alone can cut the data read by 10x.
- **Compression is far better.** Values within a column are similar to each other (all amounts, all dates), and similar data compresses dramatically better than mixed rows.
- **Statistics are built in.** Each chunk stores its min/max values, so the engine can skip whole blocks that can't possibly match a filter. That also slashes how much gets read.

**Apache Parquet** is the de facto standard for analytical data in the lake, and **ORC** is comparable and common in the Hadoop/Hive ecosystem. For any analytical table of real size, columnar is almost always the right choice.

| Format | Layout | Good for | Avoid for |
|--------|--------|----------|-----------|
| CSV / JSON | row | Interchange, small data, debugging | Large analytical tables |
| Avro | row | Streaming, record-at-a-time writes | Column-selective analytics |
| Parquet / ORC | columnar | Analytics, large tables, aggregation | Tiny files, constant single-row reads |

### A real-world pipeline pattern: keep raw as-is, convert to Parquet in the transform step

There's a textbook pattern for handling this in practice. **Keep the raw zone in the form it arrived in (CSV/JSON)** — exactly the "don't touch the originals" principle from Section 1 — and convert to Parquet for cleansed/curated in a separate **transform step**. That way you get fast downstream queries *while still keeping* the originals as they were.

That transform step usually comes down to a one-liner like this: write in a columnar format and specify the partition key at the same time.

```python
# Read raw (JSON) and write it out as Parquet partitioned by date
df = spark.read.json("s3://lake/raw/orders/2026/06/09/")
df.write.partitionBy("dt").parquet("s3://lake/cleansed/orders/")
```

Here, `partitionBy("dt")` handles the date partitioning from Section 3 and `.parquet(...)` handles the columnar storage from this section, in one go. But this one line can easily create a small files problem of its own (with many partitions and tasks, the output gets chopped into tiny pieces), so don't forget to coalesce the data into properly sized chunks before writing.

### Zone design checklist

Quick items to check when designing a new lake or a new dataset:

- [ ] **Raw preserved** — Is the raw zone kept exactly as it arrived, with direct edits blocked?
- [ ] **Each zone derived** — Are cleansed/curated produced only by jobs that *regenerate* them from the previous zone?
- [ ] **Converted to Parquet** — Is analytical data (cleansed/curated) stored as columnar (Parquet/ORC)?
- [ ] **Sensible partition key** — Is it partitioned by a moderate-cardinality column you actually filter on (usually a date), with a target file size of a few hundred MB?

---

## 5. Putting the picture together

A well-run lake isn't a pile of files. It is:

1. **Zoned** — raw → cleansed → curated, so data becomes progressively more trustworthy and the raw originals never disappear.
2. **Built on object storage** — cheap, nearly infinite, with storage decoupled from compute.
3. **Partitioned** — laid out so queries can skip data they don't need, and kept at sensible file sizes to avoid the small files problem.
4. **Stored as columnar** — anything analytical goes into Parquet/ORC, so queries read less and run faster.

Get these four right and you have a fast, cheap, scalable foundation. But notice what's still missing: there's no concept of a *transaction* here. If two jobs write to the same data at once, or a job fails halfway through, you can end up with corrupted or half-written results. Plain files don't protect you from that.

**That gap is the subject of Part 3** — the **lakehouse** and open table formats (Delta Lake, Iceberg, Hudi). They add warehouse-grade reliability (ACID transactions, schema enforcement, time travel) on top of the very same cheap object storage we just described.
