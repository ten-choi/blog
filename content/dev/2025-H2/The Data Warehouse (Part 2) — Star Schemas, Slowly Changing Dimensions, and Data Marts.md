---
title: "The Data Warehouse (Part 2) — Star Schemas, Slowly Changing Dimensions, and Data Marts"
labels: ["Data Platform Series","Data Warehouse","Dimensional Modeling","Star Schema","Slowly Changing Dimension","Data Mart","Analytics","Data Engineering","Archive"]
published: true
date: 2025-10-14T14:44:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "5646301954839810417"
source: "archive"
archivePath: "_archive/data/03-warehouse-2-star-schema-scd-marts.md"
---

**Data Platform Series · 03/15** · Storage and Architecture — The Data Warehouse 2/2

> Part 1 ended with the rule "normalize for writes, denormalize for reads." This part covers the concrete shape that rule has hardened into in the analytics world: the star schema built from facts and dimensions, slowly changing dimensions (SCDs) for handling change over time, and data marts, where a team carves out its own slice of the warehouse — the most important modeling concepts in the warehouse.

## 1. Dimensional modeling and the star schema

For analytics specifically, the dominant approach that best embodies Part 1's "denormalize for reads" is dimensional modeling, and its signature form is the star schema. This is the single most important concept in the warehouse, so let's build it up step by step.

Dimensional modeling splits data into two kinds of tables.

- **Fact table** — The *measurements* or *events*. One row per thing that happened, full of numbers you'll sum and count. A `sales_fact` table has one row per sale, with columns like `amount` and `quantity`.
- **Dimension table** — The *context* that describes the facts: who, what, where, when. A `customer` dimension, a `product` dimension, a `date` dimension, and so on.

Put a single fact table in the middle and surround it with dimensions, and you get a star shape.

```
        ┌───────────┐
        │  date     │
        │ dimension │
        └─────┬─────┘
              │
┌──────────┐  │   ┌──────────┐
│ customer ├──┼───┤ product  │
│dimension │  │   │dimension │
└──────────┘  │   └──────────┘
        ┌─────┴──────┐
        │ SALES FACT │   ← the center: amount, quantity, ...
        │  (events)  │
        └─────┬──────┘
              │
        ┌─────┴─────┐
        │  store    │
        │ dimension │
        └───────────┘
```

Why this shape? Because the questions analysts ask are almost always *"a number, sliced by some context."* Revenue (fact) by region (dimension), by month (dimension), by product category (dimension). In a star schema, those questions all turn into queries of nearly the same shape: pick one fact, join the two or three dimensions you want to slice by, aggregate, done.

```sql
SELECT  d.year_month, p.category, SUM(f.amount) AS revenue
FROM    sales_fact f
JOIN    date_dimension     d ON f.date_key     = d.date_key
JOIN    product_dimension  p ON f.product_key  = p.product_key
WHERE   d.year = 2025
GROUP BY d.year_month, p.category;
```

Facts are narrow and long (just numbers and keys), and dimensions are small and descriptive. So the engine only has to scan the huge fact once and lightly attach the small dimensions. That shape is exactly why the star schema is a *deliberately denormalized* design, and why its queries are simple and fast.

In practice, you don't build these models in one go with hand-written SQL; you build them in layers with a tool like **dbt**. Declare the dependencies in order — staging models that lightly clean up the sources → dimension/fact models carved out of those → mart models that teams consume — and your transformation logic becomes version-controlled and re-runnable along with its tests. Where these models actually run is the warehouse from Part 1: Snowflake/BigQuery/Redshift.

> **Real-world trap — don't blur the grain.** The first thing to decide when designing a fact table is "what exactly does one row mean?" — its **grain**. One order? One order line? One daily aggregate? Mix rows of different grains in one table and `SUM` silently double-counts, inflating revenue without anyone ever seeing an error. Nail it down as a rule: one fact table = one grain.

### Star schema vs. snowflake schema

You'll also hear the term "snowflake schema." It's a star schema whose dimension tables have been normalized further into sub-tables (e.g., `product` → `product` + `category` + `brand`). It saves a little storage in exchange for more joins. In practice, **the star schema usually wins** for analytics: fewer joins mean faster, simpler queries, and storage is cheap. Know the term, but only reach for a snowflake when you have a specific reason.

---

## 2. Handling change over time — slowly changing dimensions (SCD)

One modeling problem comes up so often it's worth calling out: data changes, and sometimes you need not just the current value but the *history* of those changes. A customer moves to another city. Do you overwrite the old city, or remember that they used to live somewhere else so that last year's sales are still attributed correctly?

This is the **slowly changing dimension (SCD)** problem. In practice, the options you'll face narrow down to two.

- **SCD Type 1 (overwrite)** — Just overwrite it. Simple, and the dimension stays small, but you lose history. Use it for attributes where "only the current value needs to be right."
- **SCD Type 2 (versioned rows)** — Add a new row every time the value changes, giving each version a validity range (`valid_from` / `valid_to`) and a stable surrogate key that pins which version each fact points to. It preserves history, but the dimension grows and queries get a bit more complex.

```
customer_key | customer_id | city  | valid_from | valid_to   | is_current
       1001  |     42      | Seoul | 2023-01-01 | 2025-05-31 | false
       1042  |     42      | Busan | 2025-06-01 | 9999-12-31 | true
```

It's the same customer (`customer_id = 42`), but they live on as two rows with different `customer_key`s, so last year's orders are still correctly attributed to Seoul and this year's to Busan. "Do we keep history for this attribute (Type 2), or is the current value enough (Type 1)?" is a modeling decision you'll face constantly — and choosing wrong quietly breaks your historical reports.

One practical tip: if you use dbt, its **snapshot** feature automates exactly this Type 2 row versioning (filling in `valid_from`/`valid_to`, detecting changes). It's worth a look before you hand-write MERGE logic.

---

## 3. Data marts — why teams get their own slice of the warehouse

### The problem: the warehouse is too big for any one team

Picture a company's data warehouse. It holds *everything* — sales, marketing, finance, HR, logistics, support — modeled across hundreds of tables. But the finance team just wants to build a monthly report. For them, that huge warehouse is nothing but a burden.

- They have to wade through hundreds of tables to find the dozen they actually need.
- Because the warehouse is serving the whole company at once, queries aren't as fast as they'd like.
- They don't want to accidentally touch — or even see — HR data or other sensitive data.

The fix is to give the finance team **a smaller, focused store that holds only the data they need, shaped the way they think about it**. That's a data mart.

> **A data mart is a subset of a data warehouse, scoped to a single subject area, team, or business function.**

If the warehouse is a big-box store that has everything, data marts are specialty shops — a finance mart, a marketing mart, a sales mart — each stocking only what its own customers come in for.

### Warehouse vs. mart, side by side

| | Data Warehouse | Data Mart |
|---|----------------|-----------|
| **Scope** | The whole organization | One team / one subject |
| **Size** | Large | Small and focused |
| **Audience** | Everyone | A specific group |
| **Tables** | Hundreds | A curated few |
| **Built by** | Central data team | Central or local team |
| **Purpose** | Single source of truth | Fast, easy access for one use |

A mart isn't a different *technology* — it usually uses the same warehouse technology, just as a smaller, purpose-built set of tables (the same facts and dimensions we covered above, filtered and pre-aggregated for one subject). On a team using dbt, marts usually show up as bundles of models split into directories like `marts/finance/` and `marts/marketing/`.

### Two ways to build marts: top-down vs. bottom-up

There's a classic architecture debate here, and knowing both sides explains a lot about real-world data platforms. The crux is *what you build first* — the warehouse or the marts.

#### Top-down (the Inmon approach)

Build the large, integrated **enterprise warehouse first** as the single source of truth. Then **carve marts out of it** as needed.

```
sources ──► enterprise warehouse ──► finance mart
         (build this first)      ├─► marketing mart
                                 └─► sales mart
```

- **Pros:** Every mart derives from one consistent, governed source — so the numbers always match.
- **Cons:** Slow to start. You have to build the whole warehouse before anyone gets value.

#### Bottom-up (the Kimball approach)

Build **marts first**, one subject at a time, and let the collection of marts — sharing common "conformed" dimensions — effectively *become* the warehouse.

```
sources ──► finance mart   ┐
         ├─► marketing mart ├─► (together form the warehouse)
         └─► sales mart     ┘
```

- **Pros:** Fast time to value. Each team gets a useful mart quickly.
- **Cons:** Without discipline, the marts start drifting apart, and you end up with the "five different numbers" problem covered in detail in the Data Governance series — unless you genuinely keep the shared dimensions consistent.

> Most real organizations land somewhere in between, and the debate isn't as heated as it once was. The lasting lesson is the trade-off itself — **slower because consistency comes first, or faster because value comes first.** The same tension shows up all over data architecture.

### A caution: marts can fragment the truth

The strength of a data mart — giving a team its own clean slice — is also its risk. Build marts independently, each with its own definitions, and you recreate exactly the chaos governance is meant to prevent. Finance's "active customer" quietly diverges from marketing's, and the numbers in their two reports stop matching.

The safeguard is the **conformed dimension**: an agreed-upon, shared dimension definition (one standard `customer`, one standard `date`) that every mart uses identically. When marts share conformed dimensions, they stay comparable; when they don't, they fragment. This is governance (consistent definitions) showing up at the storage layer.

> **Real-world trap — mart drift.** If you only agree verbally to "share" conformed dimensions without enforcing it, each team quietly starts copying its own dimension and tweaking it a little. Six months later, a `customer` dimension with the same name exists in every mart with a different definition, and the numbers on the executive dashboard start disagreeing team by team. If you use dbt, the most practical defense is to keep the shared dimensions in one place (`models/marts/core/`) and have every mart reference them via `ref()`, blocking duplication at the code level.

### Do you even need marts?

A word from the modern perspective. Marts came about partly because warehouses used to be slow and expensive, so giving each team a smaller copy genuinely helped performance. Today's cloud warehouses and lakehouses are fast enough that performance alone isn't as strong a reason as it used to be.

So when do marts still earn their keep?

- **Clarity** — A small, curated set of tables is far easier for non-technical teams to work with than the entire warehouse.
- **Access control** — A mart naturally draws the boundary "this team sees only this data."
- **Performance** — Pre-aggregated, focused tables still make repeated heavy queries fast.
- **Ownership** — A mart gives a team something clearly theirs to own and maintain.

If none of these apply — a small company, a single analytics team, a fast warehouse — you may not need formal marts at all. Well-organized schemas inside the warehouse can do the job. As always, don't add a layer because it's in the textbook. Add it when it solves a problem you actually have.

---

## 4. Where the warehouse sits among the lake and the lakehouse

We'll cover this in detail in the data lake posts starting with the next one, but since this is the comparison people most want spelled out, let's preview how the three relate.

- **Warehouse** — Structured, modeled, fast, and reliable. Best for well-defined questions and trustworthy reporting. More expensive, and holds only structured data.
- **Lake** — Raw, any format, cheap, and flexible. Best for exploration, ML, and keeping everything. Without governance, it risks turning into a swamp.
- **Lakehouse** — A lake plus a transactional layer, aiming to do both jobs in one place.

The honest summary: the lakehouse is trying to *absorb* the warehouse's role, and in many modern stacks it actually does. But the warehouse's core *ideas* — dimensional modeling, star schemas, clean structured tables for fast analytics — aren't going away. They get applied *inside* the lakehouse. So learning the warehouse isn't learning a legacy system; it's learning the modeling discipline that underpins every analytical store.

---

## 5. Key takeaways

A warehouse's power comes less from the technology itself than from **modeling discipline**. This part covered the core of that discipline.

- In analytics, **dimensional modeling** with a **star schema** made of facts and dimensions is the standard. Pinning each fact table to a single **grain** is rule number one.
- Change over time is handled with **slowly changing dimensions (SCDs)** — overwrite (Type 1), or preserve history with versioned rows (Type 2). In practice, dbt snapshots automate Type 2.
- In practice, these models are built in dbt as staging → dimension/fact → marts layers and run on a warehouse like Snowflake/BigQuery/Redshift.
- A warehouse that's too big for one team can be carved into **data marts** — either build the warehouse first and carve out marts (top-down, Inmon), or build marts first and let them add up to the warehouse (bottom-up, Kimball). Either way, what keeps marts honest is **conformed dimensions**.

That completes the picture of storage and modeling. How data gets *into* these stores in the first place — ingestion, ETL/ELT, integration, streaming — is covered in the Moving Data series, and the governance that holds up consistent definitions and trust is covered in the Data Governance series. In the next post, we move on to the warehouse's partner and counterpart: the **data lake**.
