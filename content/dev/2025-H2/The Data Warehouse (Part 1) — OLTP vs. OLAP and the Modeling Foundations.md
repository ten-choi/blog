---
title: "The Data Warehouse (Part 1) — OLTP vs. OLAP and the Modeling Foundations"
labels: ["Data Platform Series","Data Warehouse","Data Modeling","OLTP","OLAP","Normalization","Analytics","Data Engineering","Archive"]
published: true
date: 2025-10-07T17:30:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8715312600187839644"
source: "archive"
archivePath: "_archive/data/02-warehouse-1-oltp-olap-modeling.md"
---

**Data Platform Series · 02/15** · Storage and Architecture — The Data Warehouse 1/2

> Data lakes get the spotlight, but almost all of the world's reporting is quietly held up by the data warehouse. In Part 1, we cover why warehouses exist (OLTP vs. OLAP), what makes a warehouse a warehouse, and the data modeling foundations underneath it all — the three levels (conceptual/logical/physical) and the fundamental choice between normalization and denormalization. In Part 2, we build star schemas, slowly changing dimensions (SCDs), and data marts on top of that foundation.

## 1. Why not just query the application database? — OLTP vs. OLAP

Let's start with the obvious question. Your application already has a database full of data. So why build something separate just to analyze it?

Because the two jobs are fundamentally different, and a database tuned for one is terrible at the other.

| | Operational database (OLTP) | Data warehouse (OLAP) |
|---|------------------------------|------------------------|
| **Role** | Runs the business | Analyzes the business |
| **Typical query** | "Look up order #4521" | "Total revenue by region over the last 12 months" |
| **Pattern** | Lots of small reads/writes | A few huge reads |
| **Optimized for** | Fast single-row transactions | Fast aggregation over millions of rows |
| **Data** | Current state | Full history |

These have names worth knowing. **OLTP** (online transaction processing) is your application's database, built for fast, frequent, small transactions. **OLAP** (online analytical processing) is the warehouse, built to handle huge aggregate queries.

Running heavy analytics directly against an OLTP database causes two problems at once: the analysis is slow (you're using the wrong tool), *and* it slows down the live application by competing for resources. In practice, teams usually start with a stopgap — pointing analytical queries at a read replica of the operational database — but once the data grows, even the replica buckles. The warehouse exists to give analytics a home of its own: optimized for analytical work and isolated from production.

> One-line definition: **A data warehouse is a central database purpose-built for analyzing large volumes of historical, structured data from across the organization.**

---

## 2. The defining traits of a warehouse

A few traits make a warehouse a warehouse.

- **Subject-oriented** — It's organized around business subjects (customers, sales, products), not around the applications that produced the data.
- **Integrated** — Data from multiple source systems is cleaned and conformed to consistent formats and definitions. (This is where the "data integration" work covered in the Moving Data series shines.)
- **Historical** — It keeps history. Your application database might only know your *current* address, but the warehouse remembers every address you've ever had.
- **Structured** — Everything is modeled into tables with a defined schema. Deciding the structure *before* loading is called schema-on-write, and you'll meet it again in the data lake posts.

That last one is the key difference from a data lake. A warehouse insists on structure *before* loading. You pay that cost up front, and in return you get speed, consistency, and reliability.

These days the warehouse usually runs in the cloud. The names you'll run into most often in practice are Snowflake, BigQuery, and Redshift, which separate storage from compute so that queries stay fast even as the data grows.

---

## 3. The three levels of data modeling — conceptual / logical / physical

A warehouse isn't fast by magic. It's fast because the data has been deliberately **modeled** for analysis. So what exactly is modeling?

> **Data modeling is the work of designing the structure of data (tables, fields, types, relationships) to fit how that data will be used.**

The key phrase there is "how it will be used." The same raw data needs to be modeled *differently* depending on whether it powers a live application or feeds analytics, because those two uses ask completely different questions. Get the model right and queries become simple and fast; get it wrong and every query afterward is a slog.

Modeling is usually discussed at three levels of detail, from abstract to concrete. Knowing these terms helps you place any modeling discussion.

| Level | Question it answers | Example |
|-------|---------------------|---------|
| **Conceptual** | What things exist and how do they connect? | "Customers place Orders for Products" |
| **Logical** | What are the exact entities, attributes, and keys? | `Customer(id, name, email)`, `Order(id, customer_id, total)` |
| **Physical** | How is it actually built in this system? | Table types, indexes, partitioning, data types |

You move from a business-level picture (conceptual), through a precise but technology-neutral design (logical), to the actual implementation in a specific database (physical). Most day-to-day "modeling" work lives at the logical and physical levels.

---

## 4. The fundamental tension: normalize or denormalize?

This is the most central decision in all of data modeling, and it's a genuine trade-off, not a question of right and wrong. This single decision also explains exactly why OLTP databases and warehouses have opposite shapes.

### Normalization — split data apart to avoid duplication

**Normalization** means organizing data so that each fact is stored exactly once, splitting it into multiple related tables to eliminate duplication. Customer information goes in a `customer` table, and an order references the customer by ID instead of repeating their name and address.

- **Pros:** No duplication, so updates are safe and consistent. Change a customer's address in one place and every order reflects it. There's no risk of contradictory copies.
- **Cons:** Answering a question often means joining several tables, which is slower and more complex.

This is the right model for an **operational database (OLTP)**, where safe, consistent writes come first.

### Denormalization — combine data for fast reads

**Denormalization** deliberately accepts duplication, pre-joining or repeating data so that reads are fast and simple. Fewer joins, and everything you need is in one place.

- **Pros:** Queries are fast and simple. Ideal for analytics that scan and aggregate huge amounts of data.
- **Cons:** You have to keep the duplicated data in sync, and it takes more storage.

This is the right model for **analytical stores (OLAP)** — warehouses, marts, and lakehouses — where fast reads come first.

```
Normalized (OLTP):  customer ──< orders >── products      (many tables, join to read)
                    no duplication, safe writes

Denormalized (OLAP): one wide table / star schema          (few joins, fast reads)
                     some duplication, fast aggregation
```

> The rule that ties it all together: **Normalize for writes, denormalize for reads.** The application database normalizes to protect write consistency; the warehouse denormalizes to make analytical reads fast. Same data, opposite shapes — because the two jobs are opposites.

---

## 5. How data gets into the warehouse

A warehouse doesn't fill itself. Data arrives through **pipelines** (covered in detail in the Moving Data series) that pull data from source systems, clean and conform it, and load it into modeled tables. Whether the transformation happens *before* loading (**ETL**) or *after* (**ELT**) is a design choice, and one that has shifted over the years as warehouses themselves became powerful enough to do the transforming. In practice, these pipelines are often scheduled and their dependencies managed with an orchestration tool like **Airflow**, so they run at a fixed time every day.

The important point is this: the warehouse sits at the *end* of the movement stage and the *start* of the consumption stage. Pipelines feed the warehouse, and BI tools and analysts drink from it.

---

## 6. Key takeaways — and a preview of Part 2

The reason the data warehouse is the backbone of analytics is simple: it's purpose-built for the one thing operational databases are bad at — fast, aggregate, historical analysis over structured data.

- **OLTP runs the business; OLAP analyzes it.** The two jobs are opposites, which is why they need separate stores.
- A warehouse is defined by being **subject-oriented, integrated, historical, and structured (schema-on-write)**.
- Its power comes less from technology than from **modeling discipline** — designing structure to fit how the data will be used, across three levels: **conceptual, logical, and physical**.
- The most central decision is the choice between **normalization (safe writes, OLTP)** and **denormalization (fast reads, OLAP)**.

But in the analytics world, the "denormalize for reads" rule has hardened into a very specific form: facts and dimensions, and the famous **star schema**. In **Part 2**, we'll build up this dimensional modeling step by step, and cover **slowly changing dimensions (SCDs)** for handling change over time, plus **data marts**, where a team carves out its own slice of the warehouse.
