---
title: "Understanding the Data Lake (Part 1) — Lake vs. Warehouse, and Why Both Exist"
labels: ["Data Platform Series","Data Lake","Data Warehouse","Data Engineering","Big Data","Analytics","Archive"]
published: true
date: 2025-10-20T13:20:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "5477003041906608365"
source: "archive"
archivePath: "_archive/data/04-lake-1-vs-warehouse.md"
---

**Data Platform Series · 04/15** · Storage and Architecture — The Data Lake 1/3

> "Should this go in the warehouse or the lake?" That question trips up a lot of engineers, because the difference is rarely explained clearly. This series fixes that. Part 1 starts at the most fundamental fork in the road.

## 1. Start with the warehouse, because it came first

Before the phrase "data lake" existed, analytics ran on the **data warehouse** (covered in detail in The Data Warehouse Parts 1–2). And understanding the warehouse is the fastest way to understand why the lake came along.

A data warehouse is a database purpose-built for analytics. Its defining trait is **schema-on-write**: before any data goes in, you define the structure (tables, columns, types) first, and incoming data is cleaned and reshaped to fit it. The data gets modeled on its way *in*. In practice, a cloud warehouse like `Snowflake` or `BigQuery` usually plays this role.

This design has clear strengths.

- Queries are **fast and predictable**, because the data is already structured and optimized.
- The data is **clean and consistent**, because nothing gets in unless it fits the schema.
- It's **easy to work with** for analysts, who get clean tables and trustworthy SQL.

And it has one clear limitation — which is the whole reason the lake exists.

> Everything has to be structured and modeled *before* it's stored. That's expensive, slow to change, and simply doesn't work for data without a fixed shape (raw logs, images, blobs of JSON, sensor streams).

---

## 2. The data lake: store it now, structure it later

A **data lake** flips the warehouse's core premise. Instead of schema-on-write, it uses **schema-on-read**: it stores data in its raw, original form (any format, structured or not), and applies structure *only at the moment you read it* for a particular purpose.

The mindset shift is from "shape it, then store it" to **"store everything, and shape it per use."**

A lake is built to hold:

- **Structured** data — database exports, CSVs.
- **Semi-structured** data — JSON, XML, logs.
- **Unstructured** data — images, audio, video, free-form text, PDFs.

Physically, a data lake is usually just files sitting in **object storage** (cloud storage like `S3`, `GCS`, or `ADLS` — think of it as a huge, cheap, effectively unlimited folder), with various engines reading those files when needed. In practice, most of the analytical data in there is dropped as columnar `Parquet`, because the difference in read performance and compression is huge. Paths are usually organized so their purpose is obvious at a glance:

```
s3://my-lake/raw/events/dt=2026-06-09/part-0001.parquet
```

Why object storage is the foundation of the lake, and how to choose file formats, are covered in depth in Part 2.

Its strengths are a mirror image of the warehouse's limitations.

- It **stores anything**, even data you haven't yet decided how to use.
- It's **cheap at scale** — object storage costs roughly an order of magnitude less per TB than warehouse storage, which makes "just store everything" an actually affordable strategy.
- It's **flexible** — the same raw data can be read in different ways by different teams (analysts, data scientists, ML pipelines).

---

## 3. Side by side

| | Data Warehouse | Data Lake |
|---|----------------|-----------|
| **Schema** | On write (structure first) | On read (structure later) |
| **Data types** | Structured | Structured, semi-structured, unstructured |
| **When processing happens** | Before loading | At read time |
| **Cost per TB** | High | Low |
| **Query speed** | Fast and optimized | Varies; needs the right engine |
| **Main users** | Analysts, BI | Data scientists, engineers, ML |
| **Best for** | Well-defined questions, reporting | Exploration, preserving raw data, ML |

The one row that captures the whole philosophy is *when processing happens*. The warehouse pays the cost of structuring up front and gets speed and tidiness in return. The lake defers that cost and gets flexibility and cheap storage. Neither is "better" — they're simply optimized for different moments.

---

## 4. So which should you use? (Usually: both)

The "warehouse *vs.* lake" framing is a bit misleading. In practice, most mature organizations run **both**, and data often flows between them.

- Raw events, logs, and files land in the **lake** (object storage) first — cheap, no up-front modeling needed, nothing lost.
- The subset that supports regular reporting is cleaned, modeled, and loaded into the **warehouse**, where analysts get fast, trustworthy SQL.

In other words, the lake is "where everything is kept," and the warehouse is "where the core things you look at every day are curated." Here's a quick rule of thumb from the field.

**Choose the warehouse when:**

- The questions are known in advance — financial reporting, executive dashboards, standard KPIs.
- You need fast, controlled, trustworthy answers with clean tables and SQL.
- You run the same queries over and over, daily or weekly.

**Choose the lake when:**

- You don't know yet what you'll ask — exploratory analysis comes first.
- The data is large, messy, or comes in all shapes (logs, JSON, images).
- You need to feed raw data as-is into machine learning pipelines.
- You need to keep the originals even if you won't use them right now.

When in doubt, keeping the originals in the lake and promoting only the regularly used parts to the warehouse is usually a safe default.

---

## 5. The trap: lakes can rot

There's one failure mode you should know about up front, because it's the most common way data lakes go wrong: the **data swamp**.

Because a lake accepts anything without up-front structure, it's dangerously easy for it to end up as a vast pile of files that nobody can find, understand, or trust. A common scenario: over a year or two, various teams each drop their files in, and one day an analyst comes in to find hundreds of files of unknown origin. There are names like `final_v2_real.csv`, but nobody knows who made them, when, or whether they can be trusted. Eventually everyone stops trusting the lake, and everyone starts making their own copies again. "Store everything" quietly turns into "store everything and lose track of all of it." A swamp is a lake without governance.

The practical prevention is simple: **bring in a catalog and ownership from day one.**

- Name an **owner** for every dataset — don't create datasets that nobody is responsible for.
- Register schemas, sources, descriptions, and lineage in a **catalog** like `DataHub` or `OpenMetadata`, so anyone can search for data and trust it.
- Make this part of the ingestion pipeline, not something done *after* loading. Trying to clean it up retroactively is already too late.

This is exactly why the Data Governance series (cataloging, ownership, lineage) and the Data Lake series are two sides of the same story. The lake provides cheap, flexible storage, and governance keeps it from becoming a swamp. A lake without a catalog is just a folder full of mystery files.

---

## 6. Coming up next

You now have the core distinction: the warehouse structures data on the way in, the lake structures it on the way out, and serious platforms use both.

- **Part 2 — Inside the lake.** The actual architecture: the raw / cleansed / curated zone model, why object storage is its foundation, and the file formats that make or break performance (CSV and JSON vs. columnar Parquet and ORC).
- **Part 3 — The lakehouse.** How open table formats (Delta Lake, Apache Iceberg, Apache Hudi) added warehouse-grade reliability *on top of* lake-style storage, and how the "lakehouse" became the direction the whole field is heading.
