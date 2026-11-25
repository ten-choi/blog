---
title: "Moving Data (Part 3) — ETL vs. ELT: Where Should You Transform?"
labels: ["Data Platform Series","ETL","ELT","Data Pipeline","Data Warehouse","Data Lake","Data Engineering","Archive"]
published: true
date: 2025-11-20T17:58:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "128931964584336896"
source: "archive"
archivePath: "_archive/data/09-pipeline-3-etl-vs-elt.md"
---

**Data Platform Series · 09/15** · Moving Data 3/5

> Two of the most frequently mentioned acronyms in the data world, and the difference between them is exactly one letter changing places. This part explains what ETL and ELT are, why the industry moved en masse from one to the other, and how to choose.

## 1. The Same Three Steps, a Different Order

Recall the pipeline skeleton from Part 1: **Extract, Transform, Load.** ETL and ELT are built from exactly these three steps. The *only* difference is **where Transform sits relative to Load**. And that one swap changes the entire architecture.

```
ETL:   Extract ──► Transform ──► Load        (transform BEFORE loading)
                   ▲
                   on a separate processing system

ELT:   Extract ──► Load ──► Transform        (transform AFTER loading)
                            ▲
                            inside the destination itself
```

- **ETL (Extract → Transform → Load):** Pull the data out, transform it on a *separate* processing system, and load only the finished, clean result into the destination.
- **ELT (Extract → Load → Transform):** Pull the data out, load it *as-is* straight into the destination, and transform it *there* using the destination's own compute.

Read literally: ETL cooks the meal in a separate kitchen and brings it to the table; ELT brings the ingredients to the table and cooks right where you'll eat.

---

## 2. ETL: The Traditional Way, and Why It Made Sense

ETL came first, and for good historical reasons. Decades ago, compute in a data warehouse was **expensive and limited**. You did *not* want to waste that precious processing power on the heavy work of cleaning and restructuring data. So you transformed data *outside* the warehouse, on dedicated ETL servers, and loaded only the polished final result.

```
sources ──► [ ETL server: clean, join, aggregate ] ──► warehouse (only clean data lands)
```

This had real advantages, some of which still hold:

- **The warehouse holds only clean, modeled data** — tidy and storage-efficient.
- **Sensitive data can be filtered out or masked before it's loaded** — a win for privacy (covered in detail later in the data governance series).
- **The transformation load stays off that precious warehouse.**

And it had real drawbacks:

- **It's inflexible** — you transform the data into one predetermined shape *before* storing it. Want to ask a new question that needs the raw data? It's gone. You only kept the transformed version.
- **A separate ETL system** is one more thing to build, scale, and maintain.

---

## 3. ELT: What Changed, and Why It Took Over

Then the landscape shifted. Modern cloud warehouses and lakehouses became **enormously powerful and cheap to scale**. Storage got cheap (the core premise of the data lake series), and suddenly the old constraint — "don't waste warehouse compute" — evaporated. Now the destination could handle the transformation *itself*, faster and at larger scale than a separate server.

So the logic flipped: **load the raw data first, and transform it inside the destination as needed.**

```
sources ──► warehouse/lake (raw data lands first) ──► transform inside it, as needed
```

Here's why this approach won in most modern stacks:

- **Flexibility** — because you keep the raw data as-is, you can transform it differently later when new questions come up. Nothing is thrown away. (This is the "land raw first" habit from Part 2, elevated to the level of architecture.)
- **Faster loading** — data is available immediately; transformation happens later.
- **It uses cheap, scalable destination compute** — no fleet of separate ETL servers to run.
- **It fits the lake/lakehouse model perfectly** — start in the raw zone and build up cleansed and curated zones through transformation.

There are trade-offs you have to accept in return:

- **Raw (potentially sensitive) data lands in the destination before it's transformed** — so access control and governance at the destination become more important.
- **Storage costs more** — you keep both the raw *and* the transformed data. Cheap storage makes this a trade well worth making, though.

### In Practice, ELT Has Settled into "EL + dbt"

To be concrete about what abstract ELT actually looks like in the field: most teams starting fresh today split it into **managed connectors for EL and dbt for T**.

- **EL (Extract + Load):** A managed connector like Fivetran or Airbyte pulls data from the source and drops it *as-is* into a warehouse like Snowflake or BigQuery. The burden of writing and maintaining your own extraction scripts goes away.
- **T (Transform):** dbt handles transformation on top of that. The key point is that **transformation is just SQL running inside the warehouse**. With no separate processing engine, you run SQL on the warehouse's compute to build up your models.

In dbt, a single model is ultimately just one `SELECT`:

```sql
-- models/staging/stg_orders.sql
select
    order_id,
    customer_id,
    cast(amount as numeric)        as amount,
    cast(created_at as timestamp)  as created_at
from {{ source('raw', 'orders') }}
where amount is not null
```

These SQL models are **version-controlled (Git)**, get **tests** attached (not null, unique, etc.), and run in order based on their dependencies. This division of labor — extract/load to connectors, transform to SQL and dbt — is the de facto standard stack today.

> **Real-world pitfall #1** — In ELT, raw data (potentially mixed with PII) lands in the destination as-is, *before* transformation. In other words, your chance to filter it out with masking or filtering is pushed to after the load. That's why **access control and masking at the destination matter far more** than they did in the ETL days — narrow the permissions on the raw schema, apply masking policies to sensitive columns, and so on. (This is where it connects directly to the data governance series.)
>
> **Real-world pitfall #2** — ELT costs come not from storage but from *the compute of your transformation queries*. Storage is cheap, but indiscriminate full refreshes that rescan all the data every time are surprisingly expensive. For large models that run often, consider switching to **incremental models** that process only new or changed rows.

---

## 4. Side-by-Side Comparison

| | ETL | ELT |
|---|-----|-----|
| **When it transforms** | Before loading, on a separate system | After loading, inside the destination |
| **What lands in the destination** | Only clean, transformed data | Raw data + transformed results |
| **Flexibility** | Low (shape decided up front) | High (re-transform the raw data anytime) |
| **Driving factor** | Scarce, expensive compute | Cheap, scalable cloud compute & storage |
| **Best fit** | Strict cleansing/privacy requirements before load | Modern cloud warehouses, lakes, lakehouses |
| **Era** | Traditional default | Modern default |

---

## 5. So Which Should You Use?

For most new platforms today, **ELT is the sensible default**. It fits cheap cloud storage and compute, keeps the raw data around for future questions, and matches the lake/lakehouse architecture most teams are building on. If you're starting fresh, start with ELT — specifically, the **EL (Fivetran/Airbyte) + dbt** combination.

**ETL still earns its keep** in cases like these:

- Raw sensitive data **must not** land in the destination (strict privacy or compliance — transform or mask it *before* loading).
- The destination genuinely can't handle the transformation load (rare now, but a real concern in some on-prem environments or heavily constrained systems).
- You're feeding a classic, rigidly structured warehouse where data must be fully modeled before it's loaded.

A quick checklist to run through before choosing:

- Even if raw PII *lands* in the destination, can you control it with access control/masking? → If so, ELT.
- Can your transformations be expressed in SQL, and can the warehouse handle that compute? → If so, ELT (+ dbt).
- Are there compliance constraints that require filtering *before* loading? → If so, keep ETL.

> Don't treat this like a religion. The deeper point is that the choice follows *the economics of compute and storage*. When compute was scarce, ETL made sense; once it became cheap and elastic, ELT did. The right answer is whichever fits your constraints — and for most people today, those constraints tilt toward ELT.

---

## 6. Key Takeaways

ETL and ELT are the same three steps — Extract, Transform, Load — differing only in whether Transform comes before or after Load. ETL transforms *outside* the destination and loads only clean data (the traditional approach, born of expensive compute). ELT loads the raw data *first* and then transforms it *inside* a cheap, powerful modern destination (today's default, and a natural fit for lakes and lakehouses). In practice, ELT is usually implemented with **connectors like Fivetran/Airbyte for EL, and dbt SQL running inside Snowflake/BigQuery for T**.

Both approaches only describe the fact *that* you transform. Next, in **Part 4 — Data integration**, we tackle the hardest part of transformation: combining many messy sources into one consistent view. (Data modeling — designing the *shape* the data should ultimately take — is covered in Parts 1 and 2 of the data warehouse posts in the storage and architecture track.)
