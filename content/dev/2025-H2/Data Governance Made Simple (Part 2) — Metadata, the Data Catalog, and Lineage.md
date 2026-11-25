---
title: "Data Governance Made Simple (Part 2) — Metadata, the Data Catalog, and Lineage"
labels: ["Data Platform Series","Data Governance","Metadata","Data Catalog","Data Lineage","Data Engineering","Archive"]
published: true
date: 2025-12-13T17:28:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "5387143867367428572"
source: "archive"
archivePath: "_archive/data/13-governance-2-metadata-catalog-lineage.md"
---

**Data Platform Series · 13/15** · Data Governance 2/3

> Part 1 covered what data governance is and why teams need it. This part covers the machinery that makes governance actually work day to day: knowing what data you have, what it means, and where it came from.

## 1. The Two Questions That Eat the Most Time

Go to any data team and you'll hear the same two questions over and over:

1. *"Is there already a table that has this?"*
2. *"Wait, where on earth did this number come from?"*

The first is a **discovery** problem. The second is a **lineage** problem. Both are solved on the same foundation: metadata. Get your metadata right, and an enormous amount of daily friction simply disappears.

---

## 2. Metadata: Data About Data

Metadata isn't the data itself — it's just descriptive information *about* a dataset. Different people care about different kinds, so it's easier to understand when split into three:

| Kind | What it describes | Examples | Who cares |
|------|-------------------|---------|-----------|
| **Technical** | Structure and storage | Column types, table size, partition key, file format | Engineers |
| **Business** | Meaning in plain language | "`arpu` = average monthly revenue per paying user" | Analysts, stakeholders |
| **Operational** | Runtime behavior | Last refresh time, row counts over time, the pipeline that produced it | Everyone, during an incident |

The mistake most teams make is collecting only **technical** metadata. It's the easiest kind, since the database hands it to you for free. But the metadata that actually *prevents* the "five different active-user counts floating around" problem from Part 1 is **business** metadata — and a person (a steward) has to write it in.

This distinction matters most in practice because the two kinds are **collected in completely different ways**. Technical and operational metadata get scraped automatically by tools. Business metadata has to be filled in by hand. The catalog discussion in the next section is really just that one sentence repeated.

---

## 3. The Data Catalog: A Search Engine for Your Data

A **data catalog** is a system that collects metadata and makes it searchable. Think of it as a search engine plus a dictionary for everything your organization stores.

A useful catalog typically provides:

- **Search & discovery** — find tables by name, column, or business term, so people stop rebuilding datasets that already exist.
- **Business glossary** — canonical definitions. "Active user" is defined *once*, and every dataset that uses the term links to that definition.
- **Ownership and contact info** — each important dataset shows its steward, so "who do I ask?" has an answer.
- **Usage signals** — shows which tables are queried often (probably trustworthy) and which haven't been touched in a year (probably abandoned).

> The glossary is a quietly powerful feature. Most "data arguments" aren't arguments about numbers — they're two people using the same word to mean different things. A single source of definitions settles a surprisingly large share of those arguments.

### How It Actually Gets Filled: Half Automatic, Half Human

The first time you switch on a catalog tool, it looks like magic. Connect a connector to your warehouse, and the tool crawls the schemas and automatically ingests every table, column, type, and row count as **technical metadata**. Seeing thousands of tables become searchable within days makes it feel like you're done.

But that's as far as the automatic part goes. **Business metadata (definitions, owners) is something the tool has no way of knowing, so people have to fill it in.** Exactly what a column called `usr_actv_30d` counts, and who's accountable for it, stays blank forever unless a steward writes it down. In other words, the real labor of a catalog isn't "installing the tool" — it's "the ongoing work of people filling in the blanks."

If you're choosing a tool, they roughly split like this:

- **OSS** — DataHub, OpenMetadata, Amundsen. You run them yourself, but there's no license cost or lock-in.
- **Enterprise** — Collibra, Alation. Rich governance workflows and approval processes, with support included.

That said, you don't need to buy a heavyweight platform to get started. **Even without a tool, one well-maintained wiki page or spreadsheet is a catalog.** A four-column table — table name, one-line definition, owner, notes — is plenty as a starting point. The key is that the metadata is written down somewhere durable and findable, not locked in someone's memory. Start small, and bring in a tool when the spreadsheet can't keep up.

### Real-World Trap: A Catalog You Can Search but Not Understand

The two most common failures:

- **An empty catalog with only auto-ingestion turned on** — thousands of tables are searchable, but every definition is blank. People have to guess meaning from column names, so it's really just a searchable schema dump, not a governance tool.
- **A catalog that goes stale** — it gets filled in enthusiastically at first, then nobody maintains it, so definitions drift from the code and the listed owners have already left the company. Once the perception "you can't trust anything written here" sets in, nobody looks at it anymore.

Both traps have the same fix: **a catalog stays alive only if it has owners and stewards.**

**How to keep a catalog alive (checklist)**

- [ ] Every core table has an **owner** assigned (if it's blank, that table is abandoned).
- [ ] **Writing definitions is part of the release process** when creating a new dataset (PR checklist, merge requirements, etc.).
- [ ] Glossary definitions are generated from **a single source in code** (e.g., dbt model descriptions) to prevent drift.
- [ ] **Stale signals are surfaced** — periodically report tables not refreshed/used for N+ days and tables without definitions.
- [ ] There's a **feedback path** for search and definitions (a one-click "this definition is wrong").

---

## 4. Data Lineage: A Map of How Data Flows

**Lineage** answers this question: *for any piece of data, where did it come from, and what depends on it?* Lineage traces the path from the raw source, through every transformation, to the final dashboard or model.

Lineage is read in two directions, and both are valuable:

- **Upstream (where did this come from?)** — a number looks off. You walk back through the transformations to the source table and find the bug. Without lineage this is an archaeological dig; with it, it's one click.
- **Downstream (what depends on this?)** — you want to change a column. Lineage shows you every report, model, and pipeline that will break as a result. That's the difference between a confident change and a Friday-afternoon outage.

Here's a simple flow:

```
[orders table] ─┐
                ├─► [daily_revenue (transform)] ─► [finance_dashboard]
[refunds table]─┘                               └─► [revenue_forecast model]
```

If `orders` changes, lineage immediately tells you that both the finance dashboard *and* the forecast model are affected. That single capability is exactly what people most wished they'd had during the last incident.

### In Practice: You Don't Draw It by Hand

Lineage used to be drawn as diagrams by people, and it started going stale the moment it was drawn. In today's modern stack, lineage comes almost **for free**.

- **dbt** — when you write transformations in SQL and reference other models with `ref()`, dbt reads that `ref()` graph and builds table-level lineage automatically. In other words, the transformation code itself is the source of lineage. Just referencing them as below creates the `orders`/`refunds` → `daily_revenue` edges.

```sql
-- models/daily_revenue.sql
select
    o.order_date,
    sum(o.amount) - sum(coalesce(r.amount, 0)) as revenue
from {{ ref('orders') }} o
left join {{ ref('refunds') }} r using (order_id)
group by 1
```

- **OpenLineage** — a **standard** for pulling together lineage that otherwise lives separately in each tool. When Airflow, Spark, dbt, and others emit run events in the OpenLineage format, a catalog (DataHub, OpenMetadata, etc.) receives them and assembles lineage across the whole stack. Instead of drawing it by hand, the pipelines report their own lineage as they run.

The point is clear: lineage isn't a separate artifact you "draw." The goal is to have it **flow out automatically from your transformation code and pipeline runs.**

### Column-Level vs. Table-Level

Lineage comes in two resolutions. **Table-level** lineage ("dashboard X uses table Y") is easy to capture and good enough for most impact analysis. **Column-level lineage** ("this dashboard's revenue figure comes specifically from `orders.amount` minus `refunds.amount`") is harder to build but extremely useful for debugging and compliance — for example, tracing exactly where a particular piece of PII flows.

---

## 5. A Close Relative: Master Data Management

While we're here, one related term is worth knowing. **Master data management (MDM)** deals with the core entities the business references everywhere: customers, products, locations. The problem MDM solves is this: the same customer exists as three slightly different records in three systems, so "how many customers do we have?" has no clean answer.

MDM establishes a single authoritative version of each core entity. You can think of it as governance applied specifically to the most widely shared, most heavily referenced "nouns." It's a deep topic in its own right, so for now it's enough to know the term and the problem it addresses.

---

## 6. How It All Fits Together

Metadata, catalogs, and lineage aren't three separate projects. They're layers of a single capability.

1. **Metadata** is the raw information about your data.
2. **The catalog** makes that metadata searchable, so people can *find and understand* data.
3. **Lineage** connects metadata across systems, so people can *trace and trust* data.

Together, they turn an opaque pile of tables into something navigable. And that navigability is what lets the governance *roles* from Part 1 actually do their jobs — a steward can't maintain definitions nobody can see, and an owner can't assess impact without lineage. And as we saw, what keeps this capability alive isn't the tools but **the people who fill in the blanks and fix what's gone stale.**

**Next — Part 3:** the enforcement side of governance. We'll look at how to measure data quality (rather than just claim it), how access control and masking actually protect data, and what privacy regulations really demand of engineers.
