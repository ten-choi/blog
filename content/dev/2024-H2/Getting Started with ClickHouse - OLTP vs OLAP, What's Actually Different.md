---
title: "Getting Started with ClickHouse - OLTP vs OLAP, What's Actually Different"
labels: ["Database","ClickHouse","OLAP","MergeTree","Column Store","Archive"]
published: true
date: 2024-12-08T18:49:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7760821288398810318"
source: "archive"
archivePath: "_archive/dev/database/clickhouse-oltp-vs-olap-notes.md"
---

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/database_banner.webp)

> If you've only ever used MySQL, your first encounter with ClickHouse hits you with "Why is this so fast?" and "What is going on with UPDATE?" at the same time.
>
> Both answers come from one sentence: **OLTP and OLAP exist for fundamentally different purposes.**

# Getting Started with ClickHouse — OLTP vs OLAP

## 1. The Two Worlds Have Different Goals

### OLTP — Handling the Transaction Happening Right Now

**OLTP (Online Transaction Processing)** is a way of processing data that **creates, updates, and reads** user data in real time.

- Placing an order, editing your profile, viewing your order history — the backend of the services we use every day
- Think of it as the **home turf of the RDBs we know (MySQL/InnoDB, PostgreSQL, Oracle)**
- Characteristics: it touches **a handful of rows at a time**, needs **every column** of those rows, and lives or dies by **millisecond-level responses** and **full ACID transactions**

### OLAP — Analyzing Accumulated Data from Every Angle

**OLAP (Online Analytical Processing)** is technology that **analyzes** large volumes of data **quickly and from multiple angles** across dimensions (time, region, product, etc.) to support business decisions.

- It's the side that answers questions like "daily revenue by region over the last 90 days" or "conversion rate by product category"
- **ClickHouse** is a flagship player in this space
- Characteristics: it **scans hundreds of millions of rows**, reads **only a few columns** of them, and returns a single aggregated result

> 💡 A quick way to get a feel for it: ClickHouse also speaks SQL, so thinking of it as **"doing the same stuff you did in an RDB, just picking only a few columns"** is roughly right. The underlying structure is completely different, though, so what it's good and bad at is the exact opposite.

---

## 2. Storage Layout — Lay It Down in Rows, or Stand It Up in Columns

Even the same `orders` table looks different once it lands on disk.

```
Row store (InnoDB)               Column store (ClickHouse)
┌────────────────────┐          ┌─────────┐ ┌─────────┐ ┌─────────┐
│ id·date·region·amt │ ← row1   │ id file │ │date file│ │amt file │
│ id·date·region·amt │ ← row2   │ 1       │ │ 01-01   │ │ 1000    │
│ id·date·region·amt │ ← row3   │ 2       │ │ 01-01   │ │ 2500    │
└────────────────────┘          │ 3       │ │ 01-02   │ │  800    │
  whole rows in 16KB pages       └─────────┘ └─────────┘ └─────────┘
                                  one file per column + compressed blocks
```

- **InnoDB**: **whole rows are stored contiguously** inside 16KB pages → "everything about order id=3" comes back with a single page read. Optimized for few rows × all columns.
- **ClickHouse (MergeTree)**: **each column is stored in its own file** → for `SELECT sum(amt)`, it reads **just the amt file** and it's done. The other columns are never touched on disk. Optimized for all rows × few columns.

The bonus of column storage is **compression**. When values from the same column sit together, similar values run in sequence, so compression works incredibly well — typically shrinking data **5–20x**. The amount of data to read drops to about 1/10, which makes it that much faster again.

---

## 3. Indexes — Dense B-Tree vs Sparse Index

- **InnoDB's B-Tree** is a dense index that can point to **every single row**. It's the king of point lookups — pinpointing "the one row where id=42."
- **ClickHouse's primary index is a sparse index**. Data is stored in sort-key order, and it leaves **only one index entry per 8192 rows (a granule)**.

```
B-Tree:  a dense path to every individual row   → strong at "give me row 42"
Sparse:  only signposts every 8192 rows         → strong at "give me January through March"
```

A sparse index can't tell you "exactly where that row is," but by glancing at a few signposts it immediately knows **"this range lives between these granules."** That makes ClickHouse **specialized for range queries** — which is why it's overwhelmingly strong at queries that "slice by time period and scan," like time-series and log analysis.

> ⚠️ Flip that around: in ClickHouse, a point lookup like `WHERE id = 42` has to read an entire granule (8192 rows). **If point lookups are your main workload, just use an RDB.**

---

## 4. Execution Model — Row at a Time vs Block at a Time

- **InnoDB** basically processes **row by row**: read a row, evaluate the condition, move to the next row.
- **ClickHouse** bundles thousands of column values into **blocks for vectorized execution**, and uses CPU **SIMD** instructions to compute on many values at once. This is the core engine behind aggregate queries running orders of magnitude faster.

```sql
-- This kind of query is ClickHouse's home ground
SELECT region, toDate(created_at) AS d, sum(amount)
FROM   orders
WHERE  d BETWEEN '2026-05-01' AND '2026-07-31'
GROUP  BY region, d;
-- Even with hundreds of millions of rows: it reads only the region, created_at, and amount column files, and only the granules in that date range
```

---

## 5. What It Gave Up — UPDATE, Transactions, Concurrency

In exchange for fast analytics, ClickHouse (MergeTree) gave up a good chunk of OLTP's virtues.

- **UPDATE/DELETE is heavy** — InnoDB just fixes the affected rows in place and it's done, but in MergeTree, `ALTER TABLE ... UPDATE/DELETE` runs as an **asynchronous mutation** that **rewrites entire data parts**. It's not the place for data you modify often. (Instead of modifying, the usual pattern is to **append a new version of the row** and clean up with something like `ReplacingMergeTree`.)
- **Transactions are effectively absent** — don't expect full ACID. That's why you shouldn't put something like bank transfers on ClickHouse.
- **Concurrency works at a different scale** — InnoDB is designed to withstand **thousands of connections** firing off small queries, while ClickHouse assumes **a few dozen heavy analytical queries** sharing the CPU.
- **The data model is reversed too** — normalization is the default in an RDB, but in OLAP, **denormalization (one big wide table)** is the default, to cut down on joins.

---

## 6. Summary at a Glance

| | OLTP (InnoDB) | OLAP (ClickHouse MergeTree) |
|---|---|---|
| Storage unit | 16KB pages, contiguous rows | Per-column files, compressed blocks |
| Best-fit query | Few rows × all columns | All rows × few columns |
| Index | B-Tree, per row | Sparse, per 8192 rows (granule) |
| Execution | Row by row | Vectorized blocks + SIMD |
| Compression | Low | 5–20x |
| UPDATE/DELETE | Immediate, cheap | Async mutation, part rewrite |
| Transactions | Full ACID | Effectively none |
| Concurrency | Thousands of connections | Dozens of queries |
| Data model | Normalized | Denormalized |
| Latency target | 1ms | 100ms–1s |

---

## 7. So When Do You Use Which?

- **The service's source-of-truth (ledger) data** — orders, payments, members: **OLTP (RDB)**. Transactions and point lookups are everything.
- **Log, event, and time-series analysis, dashboards, reports**: **OLAP (ClickHouse)**. Queries that slice by time range and aggregate are the main workload.
- The standard practice is to use **both** — the RDB takes the transactions, that data flows into ClickHouse via CDC or batch jobs, and analysis happens there. The moment you try to make one system do both well, it ends up mediocre at both.

---

### 📝 One-Line Summary

> **"OLTP does 'this one row, right now' perfectly; OLAP does 'everything, across a few columns' fast — ClickHouse is a range-query-specialized column store that bet everything on the latter."**
