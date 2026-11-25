---
title: "Understanding the Data Lake (Part 3) — The Lakehouse and Open Table Formats"
labels: ["Data Platform Series","Data Lake","Lakehouse","Apache Iceberg","Delta Lake","Apache Hudi","Data Engineering","Archive"]
published: true
date: 2025-11-01T09:47:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4602550724696742381"
source: "archive"
archivePath: "_archive/data/06-lake-3-lakehouse-table-formats.md"
---

**Data Platform Series · 06/15** · Storage and Architecture — Data Lake 3/3

> This is the final part. In Part 1 we framed the lake vs. warehouse picture, and in Part 2 we looked inside the lake: its zones, storage, and file formats. We ended on one problem: plain files sitting in object storage have no transactions. This part is about how the industry solved that problem, and why the "lakehouse" became the destination everyone is heading toward.

## 1. The Problem with a Lake That's Just Files

Part 2 left us with a lake that's fast, cheap, and scalable. It also left us with a quiet hazard. When your "table" is really just a pile of Parquet files in a folder, you lose everything a database used to do for you behind the scenes.

- **No transactions.** A job fails halfway through writing a batch of files. Now half the new files exist and half don't. Readers see a messy, partially written table.
- **No isolation.** One job reads a table while another job rewrites it. The reader gets a mix of old and new files — a result that never actually existed as a consistent state.
- **No schema enforcement.** Nothing stops someone from dropping a file with the wrong columns into the folder. The "table" silently drifts into inconsistency.
- **No easy updates or deletes.** Want to delete one user's rows (exactly what the "right to be forgotten," covered later in the governance series, requires)? You have to rewrite the files by hand.
- **No history.** Overwrite the data and yesterday's version is gone. There's no way to ask, "What did this look like last Tuesday?"

> **Real-world pitfall.** "If I just stack Parquet files in folders in an S3 bucket, isn't that a table?" That's true as long as you're only reading. But it breaks the moment two jobs write to the same folder at once, or a job dies halfway through. What you're left with is partially written files and queries that happily read them as if they were valid data. A "table" without transactions looks fine most of the time, then falls apart at the worst possible moment. This is exactly why table formats exist.

Warehouses never had these problems, because they had **ACID transactions**. The lake gave those up in exchange for cheap, flexible storage. The lakehouse is the attempt to have both.

---

## 2. The Lakehouse Idea

> A **lakehouse** is an architecture that puts a database-like transactional layer *on top of* cheap object storage, giving you the reliability of a warehouse and the economics of a lake at the same time.

You still store Parquet files in object storage, exactly as described in Part 2. The new ingredient is the **open table format**: a metadata layer that sits on top of those files and tracks, transactionally, which files make up the table at any given moment. That metadata layer is what gives a plain pile of files back its transactions, schema enforcement, and history.

The result is a single system — one that can serve both analysts who want reliable SQL and data scientists who want raw flexibility, without copying the data into a separate warehouse.

---

## 3. How a Table Format Works (the Core Trick)

You don't need to know the deep internals, but the central mechanism is worth understanding, because it explains every feature that follows.

Instead of defining a table as "every file in this folder," a table format maintains a **metadata log** that explicitly lists which files are part of the table *right now*. A write goes roughly like this:

1. A job writes new Parquet data files. While they're being written, those files are not yet part of the table.
2. When the job finishes successfully, it commits a new entry to the metadata log: "the table now consists of these files."
3. Readers always consult the metadata to find the current set of files. They never see a half-written state.

This single indirection — *the metadata defines the table, not the folder contents* — is what produces the headline features:

- **ACID transactions** — a write becomes visible only when its commit lands, and it's all-or-nothing. No more half-written tables.
- **Snapshot isolation** — readers see a consistent snapshot even while a writer is in the middle of its work.
- **Time travel** — because each commit is a versioned snapshot, you can query the table *as of* a past version or point in time. ("Show me the table as it was yesterday.") This isn't abstract; in Spark or Trino it's a one-line query like this:

  ```sql
  -- Query as of a specific version
  SELECT * FROM orders VERSION AS OF 42;
  -- Query as of a specific point in time (e.g., reproducing the state right before a deploy)
  SELECT * FROM orders TIMESTAMP AS OF '2026-06-08 09:00:00';
  ```

- **Schema evolution** — you can add, rename, or drop columns safely, tracked in metadata, without rewriting everything.
- **Efficient updates and deletes** — because the format knows exactly which files hold which rows, deleting specific records (say, one user's data) becomes a managed operation rather than a manual file hunt. Instead of digging through folders and rewriting files, it's one line:

  ```sql
  DELETE FROM users WHERE id = 'user-12345';
  ```

  This is the moment the "right to be forgotten" from the governance series stops being an operational procedure and becomes a single, actually executable line of SQL.

---

## 4. The Three Open Table Formats

Three formats dominate, solving the same problem with different emphases. You'll hear all three names, so it's worth knowing what each is known for.

| | Apache Iceberg | Delta Lake | Apache Hudi |
|---|----------------|------------|-------------|
| **Origin** | Netflix | Databricks | Uber |
| **Known for** | Engine-neutral design, huge tables, clean evolution | Tight Spark integration, simple and widely adopted | Fast upserts, streaming/incremental loads |
| **Sweet spot** | Large-scale, open, multi-engine analytics | Spark-centric platforms | Write-heavy, frequently updated data |

- **Apache Iceberg** was designed from the start to be **engine-neutral**. No single processing engine owns it, which is why it has become the common interoperability standard. It's strong on very large tables and clean schema/partition evolution.
- **Delta Lake** comes from the Spark world and is the smoothest choice if your stack is Spark-centric. It's known for a simple mental model, maturity, and very broad usage.
- **Apache Hudi** was built around **upserts** — efficiently updating and inserting records — which makes it a natural fit for streaming and constantly changing data.

### Which Format to Pick

For learning purposes, the shared idea matters more than these differences: **all three turn a folder of Parquet files into a real transactional table.** For basic use, you can't go far wrong with any of them. But if you actually have to pick one in practice, the starting point usually looks like this:

- **Spark-centric** and you want to keep it simple → **Delta Lake**.
- You need **engine neutrality** or deal with **very large tables** → **Apache Iceberg**.
- **Frequent upserts and streaming/incremental loads** are central → **Apache Hudi**.

Realistically, this choice often follows **your query engine (Spark/Trino/Flink) and managed platform** more than personal taste. Which engines and managed services support which format as a first-class citizen ends up deciding the lowest-friction choice.

---

## 5. Why This Ties the Whole Story Together

The lakehouse isn't just a performance trick. It's what makes the lake *governable*, which connects it to the data governance series.

- **Schema enforcement** keeps the lake from silently degrading into a swamp.
- **Time travel** provides auditability and the ability to reproduce past results.
- **Row-level deletes** make privacy requests (the "right to be forgotten") actually executable.
- **Transactional metadata** is exactly the kind of thing data catalog and lineage tools can hook into.

> **Real-world pitfall.** Transactions aren't free. Streaming or frequent small commits produce an endless stream of **small files**, which bloats the metadata and drags down both query planning and read performance. That's why operations need periodic **compaction/optimize**: merging small files into larger ones and cleaning up old snapshots. Keep it in mind as a short checklist: (1) Are small files piling up? (2) Are you running compaction/optimize on a schedule? (3) Are you expiring old snapshots you no longer need? Skip these, and you've found the cause of almost every "slow lakehouse."

A plain lake gives you cheap storage with no guarantees. A lakehouse gives you cheap storage *with* guarantees. That's why, today, when people say "we're building a data lake," they very often actually mean a lakehouse, even if they don't use the word.

---

## 6. The Series in One Picture

```
Warehouse  : structure-first, fast, reliable, expensive, structured-only   (Part 1)
Data Lake  : store-anything, cheap, flexible — but no guarantees           (Part 1–2)
   built on: object storage + zones + Parquet/columnar formats             (Part 2)
Lakehouse  : the lake + a transactional metadata layer (Iceberg/Delta/Hudi)(Part 3)
           = cheap & flexible AND reliable & governable
```

The trajectory of this field has been to stop choosing between the reliability of a warehouse and the economics of a lake, and to build something that delivers both. That's the lakehouse, and it's also why the line between "warehouse" and "lake" gets blurrier every year.

If you've read all three parts, you now understand not just *what* a data lake is, but *why* its architecture looks the way it does and where it's heading. That's the foundation everything else in modern data engineering is built on.
