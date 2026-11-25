---
title: "The Modern Data Platform — A Map of How the Pieces Fit Together"
labels: ["Data Platform Series","Data Platform","Data Architecture","Data Engineering","Data Warehouse","Data Lake","Big Data","Archive"]
published: true
date: 2025-10-02T14:21:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "6122738343482648358"
source: "archive"
archivePath: "_archive/data/01-platform-overview.md"
---

**Data Platform Series · 01/15** · The Big Map (start here)

> If you've ever felt lost in the alphabet soup of data terms — warehouse, lake, ETL, ELT, pipeline, catalog, lineage, BI — this post is the map. It doesn't go deep on any one of them. Instead, it shows how they all connect, so the rest of the topics have a place to land.

## 1. The question this post answers

You keep hearing these words in meetings and job postings: *data platform, data warehouse, data lake, data pipeline, ETL, data governance, business intelligence.* Each one gets explained on its own, and you end up with a pile of definitions but no sense of how they relate to each other.

The fix is to stop memorizing terms and start following **the journey of a single piece of data** — from the moment it's created somewhere to the moment someone makes a decision with it. Almost every term in the data world is just a stage, a tool, or a safeguard along that journey.

---

## 2. What a "data platform" actually is

> A **data platform** is the entire system an organization uses to collect, store, process, manage, and consume its data.

It's an umbrella term, not a single product. When someone says "we're building a data platform," they mean they're assembling these capabilities into one coherent whole, instead of leaving data scattered across disconnected tools.

And **data architecture** is simply the *design* of that platform: the deliberate decisions about how data flows, where it's stored, how it's protected, and how the pieces connect. If the platform is the *what*, the architecture is *how it's laid out*.

---

## 3. The journey of a piece of data

Here's the whole platform as a single flow. Every topic in this series sits somewhere on this line.

```
  SOURCES          MOVEMENT            STORAGE              CONSUMPTION
 ┌────────┐      ┌──────────┐       ┌────────────┐        ┌──────────┐
 │ apps   │      │ ingestion│       │ data lake  │        │ BI /     │
 │ DBs    │ ───► │ ETL/ELT  │ ────► │ warehouse  │ ─────► │dashboards│
 │ APIs   │      │ pipelines│       │ lakehouse  │        │ ML       │
 │ events │      │ streaming│       │ data marts │        │ reports  │
 └────────┘      └──────────┘       └────────────┘        └──────────┘
                        │                  │                   │
                        └──────────────────┴───────────────────┘
                                           │
                              ┌────────────────────────┐
                              │     GOVERNANCE          │
                              │ catalog · lineage ·     │
                              │ quality · security      │
                              └────────────────────────┘
                          (a layer underneath everything)
```

Read it left to right. Data is **created** at the sources, **moved** through pipelines, **stored** in a warehouse/lake/lakehouse, and **consumed** by dashboards, reports, and ML. Underneath all of it sits **governance** — the layer that keeps the whole thing findable, trustworthy, secure, and legal.

Now let's walk through each stage and name the terms you'll meet along the way.

---

## 4. The four stages, term by term

### Stage 1 — Sources (where data is born)

Data starts in operational systems: your application's databases, third-party APIs, event streams from user activity, files, sensors. These systems are built to *run the business*, not to analyze it — which is exactly why we move the data somewhere else for analysis.

### Stage 2 — Movement (getting data from there to here)

This is the plumbing, and it makes up a big chunk of a data engineer's job.

- A **data pipeline** is an automated path that carries data from a source to a destination, transforming it along the way.
- **Data ingestion** is the first step: pulling data *in* from the sources.
- **ETL** and **ELT** are two strategies for *when* to transform the data (before loading or after). Everyone mixes these up, so they get a post of their own.
- **Data integration** is the broader act of combining data from multiple sources into one consistent view.
- **Streaming** handles data that arrives continuously and needs to be processed in near real time, as opposed to **batch** processing, which runs on a fixed schedule.

In practice, this stage usually splits into two kinds of tools. The part that *moves* data out of the sources is handled by managed connectors like Fivetran/Airbyte, or by CDC tools that capture database changes (Debezium, Kafka Connect). Deciding *when and in what order* those pipelines run is the job of an orchestrator like Apache Airflow (or alternatives such as Dagster/Prefect). Only when you actually need real time does a streaming stack like Kafka + Flink/Spark enter the picture.

*(This entire stage maps to the Moving Data series in this curriculum.)*

### Stage 3 — Storage (where data lives for analysis)

This is where the famous storage terms live — and they are *not interchangeable*.

- A **data warehouse** stores clean, structured, modeled data optimized for fast analytical queries. It's the backbone of reporting. (Snowflake/BigQuery/Redshift are the typical examples.)
- A **data lake** stores raw data of any kind cheaply and applies structure later. (Usually files in a format like Parquet sitting on object storage.)
- A **data lakehouse** combines the two: the economics of a lake with the reliability of a warehouse. (Open table formats like Iceberg/Delta/Hudi make this possible.)
- A **data mart** is a small, focused slice of the warehouse built for one team or subject (e.g., a finance mart).
- **Data modeling** is the work of *designing* how data is structured in these stores (tables, relationships, schemas). In practice, the transformation and modeling layer is often written and version-controlled in dbt.

*(Storage and modeling are covered in The Data Warehouse Parts 1–2 and Understanding the Data Lake Parts 1–3 in this series.)*

### Stage 4 — Consumption (turning data into decisions)

This is the whole reason the platform exists.

- **Business intelligence (BI)** is the dashboards, reports, and analysis that let people explore data and make decisions. (You put a commercial tool like Looker/Tableau/Power BI or an OSS tool like Metabase/Superset on top.)
- Beyond BI sits **machine learning**, which consumes the same data to power predictions and products.

### The layer underneath — Governance

Across every stage, **data governance** makes sure the data is trustworthy and secure. A **catalog** makes data findable, **metadata** describes it, **lineage** tracks where it came from, **quality** checks keep it reliable, and **security** controls who can see what. (Catalog/lineage is handled by OSS tools like DataHub/OpenMetadata/Amundsen or enterprise tools like Collibra/Alation; quality checks by dbt tests/Great Expectations/Soda.)

*(This maps to the Data Governance series in this curriculum.)*

---

## 5. One real example, end to end

Let's make it concrete. A user buys something in your app.

1. **Source** — The purchase is recorded in the app's operational database.
2. **Movement** — Overnight (batch) or within seconds (streaming), a **pipeline ingests** the order and **transforms** it into a shape suited for analysis. At first a single nightly batch is usually enough; you only start looking at streaming once "yesterday's revenue is fast enough" stops being true.
3. **Storage** — The order lands in the **data lake** as raw history, and a clean, modeled version goes into the **warehouse**. The finance team's **data mart** rolls it up into revenue figures.
4. **Consumption** — A **BI dashboard** shows today's revenue, and an **ML model** uses order history to recommend products.
5. **Governance** — Throughout all of this, the **catalog** helps analysts find the revenue table, **lineage** proves where the numbers came from, **quality checks** catch a bad batch, and **access control** keeps customer information restricted.

Every buzzword you've heard is just one of these moments. That's the whole field, in one paragraph.

---

## 6. So where do you start? (The realistic version)

The most common misreading of the map above is "we have to build every one of these layers from day one." That's not how it works in practice. Almost every team **starts with a single source**. They pick the one question that most urgently needs an answer (e.g., "How much did we sell yesterday?") and build only the **minimum path** needed to answer it.

A typical first step looks like this:

1. **Pick one source** — one thing that directly touches the question, like the operational DB or payment data.
2. **Land it** — load it as-is into a warehouse with a managed connector (Fivetran/Airbyte).
3. **A warehouse + a few dashboards** — put a handful of lightweight dbt models on a warehouse like Snowflake/BigQuery, and bring up dashboards in Metabase/Looker.

That alone is already a useful platform. Things like a data lake, streaming, or a full-blown catalog/lineage setup get added **when you actually need them**: a lake once you have a reason to keep raw data, streaming once freshness becomes a problem, a catalog once there are so many tables that nobody can find anything.

> **Real-world trap — over-engineering the platform before you have questions to answer.** If you lay down a lake, streaming, and a mesh architecture in advance for questions nobody has asked, that complexity quickly comes back as operational, on-call, and cognitive cost. **Complexity is a cost, not a sign of sophistication.** Add layers when the questions pull them in.

---

## 7. Architecture is about trade-offs

One last idea before we move on, because it's what separates "knowing the terms" from "designing a platform." There is no single correct architecture. Designing an architecture means making trade-offs.

- **Batch vs. streaming** — simpler and cheaper, or fresher but more complex?
- **ETL vs. ELT** — transform before storing (control), or after storing (flexibility)?
- **Warehouse vs. lake vs. lakehouse** — structured and fast, raw and cheap, or both?
- **Centralized vs. decentralized** — does one team own all the data, or does each domain own its own?

A good data architecture isn't the one with the most tools — it's the one whose trade-offs fit the organization's real needs. Complexity you don't need is a cost, not a sign of sophistication.

---

## 8. How to use the rest of this series

You now have the map. Each of the remaining posts zooms into one of the stages we've just walked through. As a single, unified **Data Platform Series**, here is the reading order by track.

(This post is the starting point. Just read the rest in the numbered order below.)

**① Storage and Architecture (Storage)**
- **02.** *The Data Warehouse (Part 1)* — OLTP vs. OLAP, the three levels of modeling, normalization/denormalization (the foundation of the storage track)
- **03.** *The Data Warehouse (Part 2)* — dimensional modeling and the star schema, SCDs, data marts
- **04.** *Understanding the Data Lake (Part 1)* — lake vs. warehouse, and why both exist
- **05.** *Understanding the Data Lake (Part 2)* — zones, object storage, file formats
- **06.** *Understanding the Data Lake (Part 3)* — the lakehouse and open table formats

**② Moving Data**
- **07.** *Part 1* — what a data pipeline is
- **08.** *Part 2* — data ingestion
- **09.** *Part 3* — ETL vs. ELT
- **10.** *Part 4* — data integration
- **11.** *Part 5* — batch vs. streaming

**③ Data Governance (Governance)**
- **12.** *Part 1* — what governance is, and why every team ends up needing it
- **13.** *Part 2* — metadata, data catalogs, lineage
- **14.** *Part 3* — quality, security, compliance

**④ Using Data (Consumption)**
- **15.** *Business Intelligence* — from data to decisions

Whenever a new term shows up, come back to the diagram in Section 3 and ask: *Which stage is this, and where on the journey is the data?* Once you can answer that, almost everything in the data world falls into place.
