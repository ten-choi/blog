---
title: "Moving Data (Part 4) — Data Integration: Making Many Sources Agree"
labels: ["Data Platform Series","Data Integration","Data Pipeline","Data Quality","Master Data Management","Data Engineering","Archive"]
published: true
date: 2025-11-24T21:25:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8059592165565156624"
source: "archive"
archivePath: "_archive/data/10-pipeline-4-integration.md"
---

**Data Platform Series · 10/15** · Moving Data 4/5

> A single source is easy. But a real organization has dozens of sources, each with its own formats and IDs — and even its own definition of what a "customer" is. **Data integration** is the work of making them agree. It's the hardest, least glamorous, and most valuable part of the transform step.

## 1. The Problem: Data Is Scattered and Inconsistent

No real business keeps its data in one place. Sales data lives in the CRM, payments in the billing system, support in a ticketing tool, web activity in an analytics platform, and core records in the app database. Answering even a simple question like *"What's this customer's lifetime value?"* means combining data from several of these sources.

And the moment you actually try to combine them, you discover they don't agree.

- The CRM calls a customer `customer_id`, billing calls it `account_no`, and support uses the email address.
- One system stores dates as `2026-06-09`, another as `06/09/2026`, and yet another as Unix timestamps.
- The CRM says the customer is in "USA," billing says "United States," and support says "US."
- The same person exists as three slightly different records across three systems.

> **Data integration is the process of combining data from multiple disparate sources into a single, consistent, unified view.**

It's the connective tissue of the whole platform. Without integration you get data silos: islands that each tell part of the story, none of which you can trust with the whole story.

---

## 2. Why It's Genuinely Hard

Integration is much trickier than it looks, because the conflicts are endless and subtle. The main categories:

**(1) Different identifiers.** The same real-world entity has different keys in each system. If the join keys don't match, you simply can't join the tables. Deciding "these three records are the same customer" is a discipline in its own right (see §4).

**(2) Different formats and units.** Dates, currencies, units, and encodings all differ. Integration means converting everything to a common standard so the values are actually comparable.

**(3) Different semantics.** This is the deepest problem. Two systems use the same *word* for different *things*. Does "revenue" include tax? Refunds? Does "active user" mean someone who logged in this month, or someone who has ever made a purchase? Blindly combine fields that share a name but not a meaning, and you get numbers that are confidently wrong.

**(4) Different quality and freshness.** One source updates in real time, another in a nightly batch. One is clean; another is full of nulls and typos. Integrated data is only as trustworthy as its messiest input.

> The hardest integration problems aren't technical — they're *agreement on meaning*. This is where data integration meets data governance. You can't integrate "revenue" from five systems until the organization agrees on what "revenue" means. The business glossary, covered later in the data governance series, is exactly what makes integration possible.

**Real-world pitfall — the real incidents come from semantic mismatches.** Format differences are visible, and they eventually get fixed. Semantic mismatches, though, quietly produce wrong numbers. If one team calculates `revenue` including tax and net of refunds, and another calculates it excluding tax and ignoring refunds, both numbers are "correct" — and they'll never match. SQL can't fix this. The organization has to agree on the definitions *before* integration begins (business glossary, governance), and pin that agreement down in the column definitions.

Another common pitfall is **integrating on the wrong join key**. If the join keys are subtly mismatched (e.g., normalized email on one side, raw mixed-case email on the other), rows get silently dropped or duplicated without any error. After integrating, always check output row counts against input. If they suddenly shrink or balloon, your keys are misaligned.

---

## 3. What Integration Work Looks Like

In practice, combining sources is a series of reconciliation steps performed in the transform stage.

```
  source A ─┐
  source B ─┼─► [ standardize formats ]
  source C ─┘        │
                     ▼
            [ match & resolve entities ]   ← same customer across sources
                     │
                     ▼
            [ reconcile definitions ]      ← one agreed meaning per field
                     │
                     ▼
            [ unified, consistent dataset ]
```

1. **Standardize** — bring every source to common formats, units, and encodings.
2. **Match entities** — figure out which records across sources refer to the same real-world thing.
3. **Reconcile definitions** — apply one agreed meaning to each field being combined.
4. **Produce a unified dataset** — build a dataset downstream consumers can trust as a single view.

Standardization sounds abstract but is actually very concrete. The "USA"/"United States"/"US" problem from earlier is a matter of mapping to a single canonical value.

```sql
SELECT
  CASE upper(trim(country))
    WHEN 'USA'           THEN 'US'
    WHEN 'UNITED STATES' THEN 'US'
    WHEN 'US'            THEN 'US'
    ELSE upper(trim(country))   -- leave unhandled values as-is and review them later
  END AS country_code
FROM raw_customers;
```

The key is that the ELSE branch keeps unknown values instead of discarding them. That way, when a new spelling ("U.S.A.", "America") shows up, it stands out instead of quietly disappearing. As the mappings grow, this kind of code is usually pulled out into a separate reference table or a dbt seed.

---

## 4. Entity Resolution and Master Data

The trickiest piece — matching records that represent the same real-world thing — has a name: **entity resolution** (also called record linkage or deduplication). "John Smith, jsmith@example.com" in the CRM and "J. Smith, same email" in billing are *probably* the same person. Deciding that reliably across millions of records riddled with typos and missing fields is hard.

In practice, it's usually approached in two stages:

1. **Deterministic matching first** — join exactly on trustworthy keys like normalized email or phone number. If the emails match after lowercasing and trimming whitespace, treat them as the same person. Most records resolve cleanly here. It's fast, explainable, and reproducible.
2. **Fuzzy/probabilistic matching for what's left** — for the remainder that lack a deterministic key or don't line up, score name similarity, address, date of birth, and so on to estimate the probability that they're the same entity. Set thresholds to split them into auto-merge, hold, and manual review.

Give each group of matched records one **stable dedup key** — for example, a hash of the normalized email — something that assigns the same key to the same group on every rerun. If you use a key that changes every time, downstream joins break. This deterministic → probabilistic flow and stable key assignment is exactly what MDM tools automate.

This connects to a term you'll meet again in the governance series: **master data management, or MDM**. MDM is the discipline of establishing a single, authoritative version of core entities like customers, products, and locations, so the whole organization shares one standard answer to "who is this customer?" Integration shows *why* MDM is needed: without one agreed master record, every integration has to re-argue "are these the same thing?" from scratch.

---

## 5. Common Integration Patterns

You don't always integrate the same way. The main approaches:

- **Consolidation — the most common** — physically copy data from all sources into one place (a warehouse or lake) and combine it there. This is exactly what your pipelines do, and it's the default for analytics.
- **Virtualization / federation** — leave the data in the sources and query across them on demand, providing a unified view without copying. It avoids duplication and staleness, but it's constrained by the sources' performance and availability. Useful when copying is impractical.
- **Propagation** — push data from one system to another whenever it changes (often via the streaming/CDC techniques from Part 2), keeping systems in sync.

For analytics platforms, **consolidation into a warehouse or lake is overwhelmingly the standard**, because it gives you a fast, stable, unified copy you can analyze without burdening the source systems.

---

## 6. The Payoff: A Single Source of Truth

Why endure all this difficulty? Because the goal is the very thing every data organization is chasing: a **single source of truth** — one unified, consistent, trustworthy view of the business that everyone uses.

In practice, that single view is usually materialized as a **conformed model** built once. You take the result of all the standardization, entity resolution, and definition agreement, lock it into a single model like `dim_customer`, and every team uses that instead of rewriting its own joins. With a tool like dbt, you can define this conformed model as version-controlled code and protect key uniqueness, nulls, and row counts with tests. The point isn't the tool; it's that the integration logic lives in *one place* rather than in ad hoc queries in people's heads.

When integration is done well, finance, marketing, and product all pull the same customer count and the same revenue figure — and they *match*. When integration is sloppy or skipped entirely, you get the nightmare that keeps recurring throughout this curriculum: five dashboards, five different numbers, and nobody able to say which one is right.

Integration isn't glamorous. It rarely shows up in demos. But more than any single tool, integration is what separates a data platform people trust from one they quietly work around.

**Integration checklist**

1. **Standardize** — have you mapped dates, currencies, country codes, etc. to canonical values? Are unhandled values left visible instead of discarded?
2. **Match entities** — did you join on deterministic keys first and fuzzy-match the rest? Did you assign dedup keys that stay stable across reruns?
3. **Agree on definitions** — has the organization agreed on the meaning of each metric being combined, and pinned it down in the glossary/column definitions?
4. **Single view** — did you lock the result into one conformed model and validate row counts before and after integration?

---

## 7. Key Takeaways

Data integration is the work of combining many different, inconsistent sources into one unified, trustworthy view. The technical conflicts — mismatched IDs, formats, duplicate records (solved with entity resolution and master data) — are real, but the deepest challenge is **agreement on meaning**, and that's where integration leans on governance. Most analytics platforms integrate by **consolidating** everything into a warehouse or lake, and the payoff is a **single source of truth**, materialized as a conformed model.

So far we've covered getting data in (Part 2), when to transform (Part 3), and combining sources (Part 4). (Data modeling — designing the *shape* integrated data should take — is covered in Parts 1 and 2 of the data warehouse posts in the storage and architecture track.) Next, in **Part 5: Batch vs. Streaming**, we look at whether all of this happens on a fixed schedule or continuously.
